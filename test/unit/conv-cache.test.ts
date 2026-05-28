/**
 * ConvCache unit tests drive the cache against a mock HttpClient
 * that returns scripted `/conversations/:id` payloads
 */

import { describe, it, expect, vi } from 'vitest'
import { ConvCache } from '../../src/flow/conv-cache.js'


function mockHttp(handler: (url: string) => unknown) {
    return {
        get: vi.fn(async (url: string) => ({ data: handler(url) })),
    } as unknown as Parameters<typeof ConvCache.prototype['load']>[0] extends never
        ? never
        : ConstructorParameters<typeof ConvCache>[1]
}


describe('ConvCache.load', () => {
    it('caches and returns ConvInfo for a vanilla GROUP', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: true,
            },
            members: [
                { userId: 100, role: 'owner',  canPost: null },
                { userId: 42,  role: 'member', canPost: null },
            ],
            myRole: 'member',
        }))
        const cache = new ConvCache(42, http)
        const info = await cache.load(7)
        expect(info).not.toBeNull()
        expect(info!.isChannel).toBe(false)
        expect(info!.isGroup).toBe(true)
        expect(info!.canPost).toBe(true)             // default true, no override
        expect(info!.myRole).toBe('member')
        expect(info!.commentsEnabled).toBe(true)
    })

    it('treats admin-myRole as canPost=true regardless of defaults', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: false,
            },
            members: [
                { userId: 42, role: 'admin', canPost: null },
            ],
            myRole: 'admin',
        }))
        const info = await new ConvCache(42, http).load(7)
        expect(info!.canPost).toBe(true)
    })

    it('treats owner-myRole as canPost=true regardless of defaults', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: false,
            },
            members: [{ userId: 42, role: 'owner', canPost: null }],
            myRole: 'owner',
        }))
        const info = await new ConvCache(42, http).load(7)
        expect(info!.canPost).toBe(true)
    })

    it('treats moderator-myRole as non-privileged (uses default / override)', async () => {
        // Server's roleRank treats moderator < admin for defaultCanPost
        // gates. SDK must not auto-bypass moderators, they fall through
        // to defaultCanPost / member override, same as 'member'
        const http = mockHttp(() => ({
            conversation: {
                id: 7, type: 'GROUP', isChannel: true, commentsEnabled: true, defaultCanPost: false,
            },
            members: [{ userId: 42, role: 'moderator', canPost: null }],
            myRole: 'moderator',
        }))
        const info = await new ConvCache(42, http).load(7)
        expect(info!.canPost).toBe(false)        // honours defaultCanPost=false
        expect(info!.myRole).toBe('moderator')
    })

    it('honours member-level canPost override over default', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 9, type: 'GROUP', isChannel: true, commentsEnabled: true, defaultCanPost: false,
            },
            members: [{ userId: 42, role: 'member', canPost: true }],
            myRole: 'member',
        }))
        const info = await new ConvCache(42, http).load(9)
        expect(info!.canPost).toBe(true)
    })

    it('falls back to defaultCanPost when member.canPost is null', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 9, type: 'GROUP', isChannel: true, commentsEnabled: false, defaultCanPost: false,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }))
        const info = await new ConvCache(42, http).load(9)
        expect(info!.canPost).toBe(false)
        expect(info!.isChannel).toBe(true)
        expect(info!.commentsEnabled).toBe(false)
    })

    it('returns null on HTTP failure', async () => {
        const http = {
            get: vi.fn(async () => { throw new Error('network down') }),
        } as unknown as ConstructorParameters<typeof ConvCache>[1]
        const cache = new ConvCache(42, http)
        const info = await cache.load(13)
        expect(info).toBeNull()
        expect(cache.peek(13)).toBeNull()
    })

    it('returns null on malformed body', async () => {
        const http = mockHttp(() => ({ surprise: true }))
        expect(await new ConvCache(42, http).load(13)).toBeNull()
    })

    it('coalesces concurrent loads into one HTTP request', async () => {
        const httpSpy = vi.fn(async () => ({ data: {
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: true,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }}))
        const http = { get: httpSpy } as unknown as ConstructorParameters<typeof ConvCache>[1]
        const cache = new ConvCache(42, http)
        const [a, b, c] = await Promise.all([cache.load(7), cache.load(7), cache.load(7)])
        expect(a!.canPost).toBe(true)
        expect(b).toBe(a)
        expect(c).toBe(a)
        expect(httpSpy).toHaveBeenCalledTimes(1)
    })

    it('serves second `load` from cache without a new HTTP hit', async () => {
        const httpSpy = vi.fn(async () => ({ data: {
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: true,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }}))
        const http = { get: httpSpy } as unknown as ConstructorParameters<typeof ConvCache>[1]
        const cache = new ConvCache(42, http)
        await cache.load(7)
        await cache.load(7)
        expect(httpSpy).toHaveBeenCalledTimes(1)
    })

    it('refetches when `force: true`', async () => {
        const httpSpy = vi.fn(async () => ({ data: {
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: true,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }}))
        const http = { get: httpSpy } as unknown as ConstructorParameters<typeof ConvCache>[1]
        const cache = new ConvCache(42, http)
        await cache.load(7)
        await cache.load(7, { force: true })
        expect(httpSpy).toHaveBeenCalledTimes(2)
    })
})


describe('ConvCache.invalidate / drop', () => {
    it('invalidate() forces the next load to refetch', async () => {
        const httpSpy = vi.fn(async () => ({ data: {
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: true,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }}))
        const http = { get: httpSpy } as unknown as ConstructorParameters<typeof ConvCache>[1]
        const cache = new ConvCache(42, http)
        await cache.load(7)
        cache.invalidate(7)
        await cache.load(7)
        expect(httpSpy).toHaveBeenCalledTimes(2)
    })

    it('drop() removes the cached entry', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 7, type: 'GROUP', isChannel: false, commentsEnabled: true, defaultCanPost: true,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }))
        const cache = new ConvCache(42, http)
        await cache.load(7)
        expect(cache.peek(7)).not.toBeNull()
        cache.drop(7)
        expect(cache.peek(7)).toBeNull()
    })
})


describe('ConvCache.peek', () => {
    it('returns null before any load', () => {
        const http = mockHttp(() => ({})) as unknown as ConstructorParameters<typeof ConvCache>[1]
        const cache = new ConvCache(42, http)
        expect(cache.peek(7)).toBeNull()
    })

    it('returns cached entry after a successful load', async () => {
        const http = mockHttp(() => ({
            conversation: {
                id: 7, type: 'GROUP', isChannel: true, commentsEnabled: true, defaultCanPost: true,
            },
            members: [{ userId: 42, role: 'member', canPost: null }],
            myRole: 'member',
        }))
        const cache = new ConvCache(42, http)
        await cache.load(7)
        const peeked = cache.peek(7)
        expect(peeked).not.toBeNull()
        expect(peeked!.isChannel).toBe(true)
    })
})
