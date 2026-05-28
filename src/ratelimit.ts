/**
 * Per-key token-bucket rate limiter, constant memory per key and O(1) tryAcquire()
 * A bucket refills at `refillPerSec` up to `capacity`, tryAcquire consumes one token and returns false when empty
 * Stale buckets (full and idle) are pruned during tryAcquire to keep the map bounded
 * Not safe across processes, use Redis for cross-instance limits
 */

export interface RateLimiterOptions {
    /** Bucket size. Burst tolerance. Default 5 */
    capacity?:        number
    /** Tokens added per second. Sustained throughput. Default 1 */
    refillPerSec?:    number
    /** Buckets idle for this many ms are eligible for pruning. Default 600_000 (10 min) */
    pruneMs?:         number
    /** Test injection. Default Date.now */
    now?:             () => number
}


interface Bucket {
    tokens:        number
    lastRefillMs:  number
}


export class RateLimiter<K = number | string> {
    private readonly capacity:     number
    private readonly refillPerMs:  number
    private readonly pruneMs:      number
    private readonly now:          () => number
    private readonly buckets:      Map<K, Bucket> = new Map()
    /** Lazy prune cursor. Pruning piggybacks on tryAcquire so it stays amortized and avoids racing bot.stop() teardown */
    private opsSinceLastPrune = 0


    constructor(opts: RateLimiterOptions = {}) {
        const capacity     = opts.capacity     ?? 5
        const refillPerSec = opts.refillPerSec ?? 1
        if (!(capacity >= 1) || !Number.isFinite(capacity)) {
            throw new Error(`RateLimiter: capacity must be >= 1, got ${capacity}`)
        }
        if (!(refillPerSec > 0) || !Number.isFinite(refillPerSec)) {
            throw new Error(`RateLimiter: refillPerSec must be > 0, got ${refillPerSec}`)
        }
        this.capacity    = capacity
        this.refillPerMs = refillPerSec / 1000
        this.pruneMs     = opts.pruneMs ?? 600_000
        this.now         = opts.now ?? Date.now
    }


    /** Consume `cost` tokens from `key`'s bucket. Returns true if it had enough, false otherwise. Default cost 1 */
    tryAcquire(key: K, cost = 1): boolean {
        if (cost <= 0 || cost > this.capacity || !Number.isFinite(cost)) {
            throw new Error(`RateLimiter.tryAcquire: cost must be 1..${this.capacity}, got ${cost}`)
        }
        const tNow = this.now()
        this.maybePrune(tNow)

        const b = this.buckets.get(key)
        if (b === undefined) {
            // Fresh key starts full, immediately spend `cost`
            const tokens = this.capacity - cost
            this.buckets.set(key, { tokens, lastRefillMs: tNow })
            return true
        }
        // Refill since last touch, capped at capacity
        const elapsed = tNow - b.lastRefillMs
        const filled  = Math.min(this.capacity, b.tokens + elapsed * this.refillPerMs)
        if (filled >= cost) {
            b.tokens       = filled - cost
            b.lastRefillMs = tNow
            return true
        }
        // Not enough. Record the partial refill so the next call doesn't double-count elapsed time
        b.tokens       = filled
        b.lastRefillMs = tNow
        return false
    }


    /** Tokens available right now (after refill) without consuming any */
    available(key: K): number {
        const tNow = this.now()
        const b = this.buckets.get(key)
        if (b === undefined) return this.capacity
        const elapsed = tNow - b.lastRefillMs
        return Math.min(this.capacity, b.tokens + elapsed * this.refillPerMs)
    }


    /** Erase a key's bucket. Next tryAcquire starts from full */
    reset(key: K): void {
        this.buckets.delete(key)
    }


    /** Erase every bucket */
    clear(): void {
        this.buckets.clear()
    }


    /** For tests / debugging. Don't iterate this in hot paths */
    size(): number {
        return this.buckets.size
    }


    /** Walks the map at most once per pruneMs/4 tryAcquire calls and drops buckets that are full and idle past pruneMs
     *  A full bucket is safe to drop, a future tryAcquire reconstructs it from capacity */
    private maybePrune(tNow: number): void {
        const interval = Math.max(64, Math.floor(this.pruneMs / 4))
        if (++this.opsSinceLastPrune < interval) return
        this.opsSinceLastPrune = 0
        for (const [key, b] of this.buckets) {
            const elapsed = tNow - b.lastRefillMs
            const filled  = Math.min(this.capacity, b.tokens + elapsed * this.refillPerMs)
            if (filled >= this.capacity && elapsed >= this.pruneMs) {
                this.buckets.delete(key)
            }
        }
    }
}
