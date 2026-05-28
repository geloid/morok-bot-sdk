/**
 * In-memory cache of conversation metadata (isChannel, canPost, commentsEnabled)
 * Invalidated by events, never persisted, and concurrent load() callers share one in-flight request
 */

import type { HttpClient } from '../transport/http.js'
import type { SdkLogger }  from '../types.js'

// Backstop TTL. Entries are normally invalidated by events. This caps how long a missed event can keep a stale entry
const CONV_CACHE_TTL_MS = 5 * 60_000

// Max cached conversations, evict oldest
const CONV_CACHE_MAX = 1024


export interface ConvInfo {
    conversationId:  number
    isChannel:       boolean
    isGroup:         boolean
    commentsEnabled: boolean
    myRole:          'owner' | 'admin' | 'member' | string
    /** Resolved post permission (admin/owner bypass, member override, default) */
    canPost:         boolean
    fetchedAt:       number
}


interface ConvMemberRow {
    userId:  number
    role:    string
    canPost: unknown
}

interface ConvResponse {
    conversation: {
        id:                 number
        type:               string
        isChannel:          unknown
        commentsEnabled:    unknown
        defaultCanPost:     unknown
    }
    members: ConvMemberRow[]
    myRole:  unknown
}


export class ConvCache {
    private readonly entries  = new Map<number, ConvInfo>()
    private readonly inflight = new Map<number, Promise<ConvInfo | null>>()


    constructor(
        private readonly botUserId: number,
        private readonly http:      HttpClient,
        private readonly logger?:   SdkLogger,
    ) {}


    /** Synchronous read, null if not cached */
    peek(conversationId: number): ConvInfo | null {
        return this.entries.get(conversationId) ?? null
    }


    /** Cached entry or one fetch. Concurrent callers share the in-flight request. Returns null on error/403 */
    async load(conversationId: number, opts: { force?: boolean } = {}): Promise<ConvInfo | null> {
        if (!opts.force) {
            const cached = this.entries.get(conversationId)
            if (cached && Date.now() - cached.fetchedAt < CONV_CACHE_TTL_MS) return cached
        }
        const inflight = this.inflight.get(conversationId)
        if (inflight) return inflight
        const p = this.doLoad(conversationId).finally(() => {
            if (this.inflight.get(conversationId) === p) {
                this.inflight.delete(conversationId)
            }
        })
        this.inflight.set(conversationId, p)
        return p
    }


    private async doLoad(conversationId: number): Promise<ConvInfo | null> {
        let body: ConvResponse
        try {
            const res = await this.http.get<ConvResponse>(`/conversations/${conversationId}`)
            body = res.data
        } catch (err) {
            this.logger?.warn(
                { conversationId, err: (err as Error).message },
                '[conv-cache] /conversations/:id fetch failed',
            )
            return null
        }
        if (!body || !body.conversation || !Array.isArray(body.members)) {
            this.logger?.warn({ conversationId }, '[conv-cache] malformed /conversations/:id body')
            return null
        }

        const conv    = body.conversation
        const myMember = body.members.find(m => m.userId === this.botUserId) ?? null
        const myRole   = typeof body.myRole === 'string' ? body.myRole : (myMember?.role ?? 'member')

        // Admin/owner always allowed. Else member override if set, else conv default
        const isPrivileged = myRole === 'owner' || myRole === 'admin'
        const memberOverride = myMember?.canPost
        const canPost = isPrivileged
            ? true
            : (memberOverride === null || memberOverride === undefined
                ? conv.defaultCanPost === true
                : memberOverride === true)

        const info: ConvInfo = {
            conversationId,
            isChannel:        conv.isChannel === true,
            isGroup:          conv.isChannel !== true,
            commentsEnabled:  conv.commentsEnabled !== false,
            myRole,
            canPost,
            fetchedAt:        Date.now(),
        }
        this.entries.set(conversationId, info)
        // Evict oldest over the cap
        while (this.entries.size > CONV_CACHE_MAX) {
            const oldest = this.entries.keys().next().value
            if (oldest === undefined) break
            this.entries.delete(oldest)
        }
        return info
    }


    /** Invalidate one entry */
    invalidate(conversationId: number): void {
        this.entries.delete(conversationId)
    }


    /** Drop entry and in-flight, on conversation_kicked */
    drop(conversationId: number): void {
        this.entries.delete(conversationId)
        this.inflight.delete(conversationId)
    }
}
