/**
 * Per-user in-memory session store for multi-step bot flows
 * A Map<key, State> with optional TTL and a shallow update helper, non-persistent, a process restart wipes everything
 * For durable sessions, back it with your own disk or Redis store
 */

export interface BotSessionsOptions {
    /** Sessions idle this many ms read as missing. Default off (no expiry) */
    ttlMs?: number
    /** Test injection. Default Date.now */
    now?:   () => number
}


interface Entry<S> {
    state:        S
    lastTouchMs:  number
}


export class BotSessions<S, K = number> {
    private readonly ttlMs: number
    private readonly now:   () => number
    private readonly map:   Map<K, Entry<S>> = new Map()


    constructor(opts: BotSessionsOptions = {}) {
        this.ttlMs = opts.ttlMs ?? 0
        this.now   = opts.now ?? Date.now
    }


    /** Replace the entire state for `key`. Resets the TTL clock */
    set(key: K, state: S): void {
        this.map.set(key, { state, lastTouchMs: this.now() })
    }


    /** Read the state for `key`. undefined if missing or past TTL, which is deleted lazily on read */
    get(key: K): S | undefined {
        const e = this.map.get(key)
        if (e === undefined) return undefined
        if (this.ttlMs > 0 && this.now() - e.lastTouchMs > this.ttlMs) {
            this.map.delete(key)
            return undefined
        }
        return e.state
    }


    /** Shallow-merge `patch` into the current state. Throws if there is none, call set() first */
    update(key: K, patch: Partial<S>): S {
        const e = this.map.get(key)
        if (e === undefined) {
            throw new Error(`BotSessions.update: no session for key ${String(key)}, call set() first`)
        }
        if (this.ttlMs > 0 && this.now() - e.lastTouchMs > this.ttlMs) {
            this.map.delete(key)
            throw new Error(`BotSessions.update: session for key ${String(key)} expired`)
        }
        e.state       = { ...e.state, ...patch }
        e.lastTouchMs = this.now()
        return e.state
    }


    /** True if a non-expired entry exists */
    has(key: K): boolean {
        return this.get(key) !== undefined
    }


    /** Remove one entry. Idempotent */
    delete(key: K): void {
        this.map.delete(key)
    }


    /** Remove every entry */
    clear(): void {
        this.map.clear()
    }


    /** Count non-expired entries. O(n) when ttlMs>0, use sparingly in hot paths */
    get size(): number {
        if (this.ttlMs === 0) return this.map.size
        const cutoff = this.now() - this.ttlMs
        let n = 0
        for (const e of this.map.values()) {
            if (e.lastTouchMs > cutoff) n++
        }
        return n
    }


    /** Purge expired entries. Optional, get() already does this lazily per key */
    prune(): number {
        if (this.ttlMs === 0) return 0
        const cutoff = this.now() - this.ttlMs
        let dropped = 0
        for (const [key, e] of this.map) {
            if (e.lastTouchMs <= cutoff) {
                this.map.delete(key)
                dropped++
            }
        }
        return dropped
    }
}
