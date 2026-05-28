/**
 * BotSessions unit tests, time-injected via `now` option
 */

import { describe, it, expect } from 'vitest'

import { BotSessions } from '../../src/sessions.js'


function fakeClock(start = 0): { now: () => number; advance: (ms: number) => void } {
    let t = start
    return { now: () => t, advance: (ms) => { t += ms } }
}


interface Flow {
    step: 'name' | 'email'
    name?: string
    email?: string
}


describe('basic set/get/delete', () => {
    it('returns undefined for unknown key', () => {
        const s = new BotSessions<Flow>()
        expect(s.get(1)).toBeUndefined()
        expect(s.has(1)).toBe(false)
    })

    it('set + get round-trips', () => {
        const s = new BotSessions<Flow>()
        s.set(1, { step: 'name' })
        expect(s.get(1)).toEqual({ step: 'name' })
        expect(s.has(1)).toBe(true)
    })

    it('set overrides previous state', () => {
        const s = new BotSessions<Flow>()
        s.set(1, { step: 'name' })
        s.set(1, { step: 'email', name: 'alice' })
        expect(s.get(1)).toEqual({ step: 'email', name: 'alice' })
    })

    it('delete is idempotent', () => {
        const s = new BotSessions<Flow>()
        s.set(1, { step: 'name' })
        s.delete(1)
        expect(s.has(1)).toBe(false)
        s.delete(1)
        expect(s.has(1)).toBe(false)
    })

    it('clear wipes everything', () => {
        const s = new BotSessions<Flow>()
        s.set(1, { step: 'name' })
        s.set(2, { step: 'email' })
        s.clear()
        expect(s.size).toBe(0)
    })
})


describe('update()', () => {
    it('shallow-merges patch into state', () => {
        const s = new BotSessions<Flow>()
        s.set(1, { step: 'name' })
        const after = s.update(1, { step: 'email', name: 'alice' })
        expect(after).toEqual({ step: 'email', name: 'alice' })
        expect(s.get(1)).toEqual({ step: 'email', name: 'alice' })
    })

    it('throws when no current state', () => {
        const s = new BotSessions<Flow>()
        expect(() => s.update(1, { step: 'email' })).toThrow(/no session/)
    })
})


describe('TTL expiry', () => {
    it('returns undefined past ttlMs', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        clock.advance(999)
        expect(s.get(1)).toEqual({ step: 'name' })
        clock.advance(2)
        expect(s.get(1)).toBeUndefined()
    })

    it('lazy-deletes expired entry on get', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        clock.advance(1500)
        expect(s.get(1)).toBeUndefined()
        expect((s as unknown as { map: Map<number, unknown> }).map.has(1)).toBe(false)
    })

    it('set resets the TTL clock', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        clock.advance(700)
        s.set(1, { step: 'email' })            // resets
        clock.advance(700)                      // total 1400 from first set, 700 from second
        expect(s.get(1)).toEqual({ step: 'email' })
    })

    it('update resets the TTL clock', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        clock.advance(700)
        s.update(1, { step: 'email' })
        clock.advance(700)
        expect(s.get(1)).toEqual({ step: 'email' })
    })

    it('update on expired session throws', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        clock.advance(1500)
        expect(() => s.update(1, { step: 'email' })).toThrow(/expired/)
    })

    it('ttlMs=0 disables expiry', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 0, now: clock.now })
        s.set(1, { step: 'name' })
        clock.advance(1_000_000_000)
        expect(s.get(1)).toEqual({ step: 'name' })
    })
})


describe('size + prune', () => {
    it('size counts only non-expired with TTL', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        s.set(2, { step: 'name' })
        clock.advance(1500)
        s.set(3, { step: 'name' })
        expect(s.size).toBe(1)
    })

    it('prune drops expired entries', () => {
        const clock = fakeClock()
        const s = new BotSessions<Flow>({ ttlMs: 1000, now: clock.now })
        s.set(1, { step: 'name' })
        s.set(2, { step: 'name' })
        clock.advance(1500)
        s.set(3, { step: 'name' })
        const dropped = s.prune()
        expect(dropped).toBe(2)
        expect(s.size).toBe(1)
    })

    it('prune is a no-op when ttlMs=0', () => {
        const s = new BotSessions<Flow>({ ttlMs: 0 })
        s.set(1, { step: 'name' })
        expect(s.prune()).toBe(0)
        expect(s.size).toBe(1)
    })
})


describe('string keys', () => {
    it('works with custom key type', () => {
        const s = new BotSessions<Flow, string>()
        s.set('alice', { step: 'name' })
        expect(s.get('alice')?.step).toBe('name')
    })
})
