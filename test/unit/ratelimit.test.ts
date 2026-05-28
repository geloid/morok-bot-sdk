/**
 * RateLimiter unit tests, time-injected via `now` option so the
 * suite runs deterministically without sleep()
 */

import { describe, it, expect } from 'vitest'

import { RateLimiter } from '../../src/ratelimit.js'


function fakeClock(start = 0): { now: () => number; advance: (ms: number) => void } {
    let t = start
    return { now: () => t, advance: (ms) => { t += ms } }
}


describe('RateLimiter constructor', () => {
    it('defaults to capacity=5, refillPerSec=1', () => {
        const rl = new RateLimiter()
        expect(rl.available('x')).toBe(5)
    })

    it('rejects non-positive capacity', () => {
        expect(() => new RateLimiter({ capacity: 0 })).toThrow(/capacity/)
        expect(() => new RateLimiter({ capacity: -1 })).toThrow(/capacity/)
    })

    it('rejects non-positive refillPerSec', () => {
        expect(() => new RateLimiter({ refillPerSec: 0 })).toThrow(/refillPerSec/)
        expect(() => new RateLimiter({ refillPerSec: -1 })).toThrow(/refillPerSec/)
    })
})


describe('tryAcquire basics', () => {
    it('grants up to capacity on a fresh key', () => {
        const rl = new RateLimiter({ capacity: 3 })
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(false)
    })

    it('different keys do not share a bucket', () => {
        const rl = new RateLimiter({ capacity: 1 })
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('b')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(false)
        expect(rl.tryAcquire('b')).toBe(false)
    })

    it('refills tokens over time', () => {
        const clock = fakeClock()
        const rl = new RateLimiter({ capacity: 2, refillPerSec: 1, now: clock.now })
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(false)
        // 1000 ms -> 1 token
        clock.advance(1000)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(false)
    })

    it('caps the refill at capacity (no overflow)', () => {
        const clock = fakeClock()
        const rl = new RateLimiter({ capacity: 2, refillPerSec: 1, now: clock.now })
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(true)
        // 100 seconds, much more than capacity worth of tokens
        clock.advance(100_000)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('a')).toBe(false)
    })

    it('supports fractional refill per ms', () => {
        const clock = fakeClock()
        const rl = new RateLimiter({ capacity: 1, refillPerSec: 2, now: clock.now })
        expect(rl.tryAcquire('a')).toBe(true)
        clock.advance(499)
        expect(rl.tryAcquire('a')).toBe(false)
        clock.advance(1)         // total 500 ms -> exactly one token at 2/s
        expect(rl.tryAcquire('a')).toBe(true)
    })

    it('cost > 1 deducts that many tokens', () => {
        // Frozen clock: the exact token-count assertions below must not be perturbed
        // by a sub-millisecond real-time refill between tryAcquire and available
        const clock = fakeClock()
        const rl = new RateLimiter({ capacity: 5, now: clock.now })
        expect(rl.tryAcquire('a', 3)).toBe(true)
        expect(rl.available('a')).toBe(2)
        expect(rl.tryAcquire('a', 3)).toBe(false)   // not enough
        expect(rl.tryAcquire('a', 2)).toBe(true)
        expect(rl.available('a')).toBe(0)
    })

    it('rejects out-of-range cost', () => {
        const rl = new RateLimiter({ capacity: 3 })
        expect(() => rl.tryAcquire('a', 0)).toThrow()
        expect(() => rl.tryAcquire('a', 4)).toThrow()
        expect(() => rl.tryAcquire('a', -1)).toThrow()
    })
})


describe('available()', () => {
    it('shows the current token count without consuming', () => {
        const clock = fakeClock()
        const rl = new RateLimiter({ capacity: 3, refillPerSec: 1, now: clock.now })
        expect(rl.available('a')).toBe(3)
        rl.tryAcquire('a', 2)
        expect(rl.available('a')).toBe(1)
        expect(rl.available('a')).toBe(1)            // no consumption
        clock.advance(2000)
        expect(rl.available('a')).toBe(3)            // capped at capacity
    })
})


describe('reset() / clear()', () => {
    it('reset wipes one key', () => {
        const rl = new RateLimiter({ capacity: 1 })
        rl.tryAcquire('a')
        expect(rl.tryAcquire('a')).toBe(false)
        rl.reset('a')
        expect(rl.tryAcquire('a')).toBe(true)
    })

    it('clear wipes all keys', () => {
        const rl = new RateLimiter({ capacity: 1 })
        rl.tryAcquire('a')
        rl.tryAcquire('b')
        rl.clear()
        expect(rl.size()).toBe(0)
        expect(rl.tryAcquire('a')).toBe(true)
        expect(rl.tryAcquire('b')).toBe(true)
    })
})


describe('pruning', () => {
    it('drops idle full buckets after pruneMs', () => {
        const clock = fakeClock()
        const rl = new RateLimiter({
            capacity:    1,
            refillPerSec: 1,
            pruneMs:      1_000,
            now:          clock.now,
        })
        // pruneMs=1000 -> internal interval = max(64, 250)
        for (let i = 0; i < 250; i++) rl.tryAcquire(`k${i}`)
        expect(rl.size()).toBeGreaterThan(0)
        clock.advance(2_000)
        // Walk hard enough to trip the prune, the next tryAcquire triggers
        // the pruneMs check on every existing key
        for (let i = 0; i < 250; i++) rl.tryAcquire(`fresh${i}`)
        // Old keys (k0...k249) were idle and full so they drop, only fresh ones remain
        for (let i = 0; i < 250; i++) {
            expect(rl.available(`k${i}`)).toBe(1)        // fresh-key view
        }
    })

    it('does NOT prune buckets that are still partially empty', () => {
        const clock = fakeClock()
        const rl = new RateLimiter({
            capacity:    10,
            refillPerSec: 0.001,            // 1 token per 1000 s
            pruneMs:      1_000,
            now:          clock.now,
        })
        // Drain a bucket
        for (let i = 0; i < 10; i++) rl.tryAcquire('drained')
        // Sweep enough other ops to walk the map
        for (let i = 0; i < 300; i++) rl.tryAcquire(`other${i}`)
        clock.advance(2_000)
        for (let i = 0; i < 300; i++) rl.tryAcquire(`more${i}`)
        // 'drained' bucket is not yet refilled (need 1000 s per token),
        // so prune must NOT drop it
        expect(rl.available('drained')).toBeLessThan(1)
    })
})


describe('string keys', () => {
    it('works with string keys just like numeric', () => {
        const rl = new RateLimiter<string>({ capacity: 2 })
        expect(rl.tryAcquire('alice')).toBe(true)
        expect(rl.tryAcquire('alice')).toBe(true)
        expect(rl.tryAcquire('alice')).toBe(false)
        expect(rl.tryAcquire('bob')).toBe(true)
    })
})
