/**
 * StateLock unit tests, the pid-based scheme is best-effort, but
 * needs to:
 *   • create the lock file with our pid on acquire,
 *   • refuse acquire when another LIVE pid owns the file,
 *   • adopt the lock when the prior owner pid is dead (ESRCH),
 *   • release cleanly on success
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, readFile, writeFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { StateLock } from '../../src/state-lock.js'


let dir: string


beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'morok-sdk-statelock-'))
})

afterEach(async () => {
    try { await rm(dir, { recursive: true, force: true }) } catch { /* ignore */ }
})


describe('StateLock.acquire', () => {
    it('writes our pid to .bot.lock on a clean dir', async () => {
        const lock = new StateLock(dir)
        await lock.acquire()
        const body = await readFile(join(dir, '.bot.lock'), 'utf8')
        expect(parseInt(body.trim(), 10)).toBe(process.pid)
    })

    it('creates the lock dir if missing (recursive mkdir)', async () => {
        const nested = join(dir, 'nested', 'state')
        const lock = new StateLock(nested)
        await lock.acquire()
        const s = await stat(join(nested, '.bot.lock'))
        expect(s.isFile()).toBe(true)
    })

    it('writes the lock file with mode 0o600', async () => {
        const lock = new StateLock(dir)
        await lock.acquire()
        const s = await stat(join(dir, '.bot.lock'))
        // eslint-disable-next-line no-bitwise
        expect((s.mode & 0o077)).toBe(0)
    })

    it('is idempotent for the same instance', async () => {
        const lock = new StateLock(dir)
        await lock.acquire()
        await lock.acquire()    // no throw
        const body = await readFile(join(dir, '.bot.lock'), 'utf8')
        expect(parseInt(body.trim(), 10)).toBe(process.pid)
    })

    it('refuses acquire when another live pid owns the lock', async () => {
        // Use process.ppid, the parent process of the test runner
        // Almost certainly alive during the test, the kill(pid, 0)
        // probe will return success, triggering the "locked" error
        // (The SDK's adopt-our-own-pid carve-out doesn't fire because
        // process.ppid !== process.pid)
        const livePid = process.ppid
        if (!Number.isInteger(livePid) || livePid <= 0 || livePid === process.pid) {
            // Defensive: tests should never run with ppid == self
            // In that unlikely scenario skip the assertion to avoid a flaky test
            return
        }
        await writeFile(join(dir, '.bot.lock'), `${livePid}\n`)
        const lock = new StateLock(dir)
        await expect(lock.acquire()).rejects.toThrow(/locked by another running bot/i)
    })

    it('adopts a stale lock from a dead pid', async () => {
        // Pick a pid almost certainly not running, on Linux the max
        // pid is /proc/sys/kernel/pid_max (default 4194304), pid 1
        // is reserved (init/systemd), pick something in the
        // ~1_000_000 range that is extremely unlikely to exist
        const stalePid = 999_999
        await writeFile(join(dir, '.bot.lock'), `${stalePid}\n`)
        const lock = new StateLock(dir)
        await lock.acquire()  // should not throw, stale lock adopted
        const body = await readFile(join(dir, '.bot.lock'), 'utf8')
        expect(parseInt(body.trim(), 10)).toBe(process.pid)
    })

    it('adopts an empty / corrupt lock file', async () => {
        await writeFile(join(dir, '.bot.lock'), '')
        const lock = new StateLock(dir)
        await lock.acquire()
        const body = await readFile(join(dir, '.bot.lock'), 'utf8')
        expect(parseInt(body.trim(), 10)).toBe(process.pid)
    })

    it('adopts a lock whose pid is non-numeric', async () => {
        await writeFile(join(dir, '.bot.lock'), 'not-a-pid\n')
        const lock = new StateLock(dir)
        await lock.acquire()
        const body = await readFile(join(dir, '.bot.lock'), 'utf8')
        expect(parseInt(body.trim(), 10)).toBe(process.pid)
    })
})


describe('StateLock.release', () => {
    it('removes the lock file on a clean release', async () => {
        const lock = new StateLock(dir)
        await lock.acquire()
        await lock.release()
        await expect(readFile(join(dir, '.bot.lock'), 'utf8')).rejects.toThrow()
    })

    it('is idempotent', async () => {
        const lock = new StateLock(dir)
        await lock.acquire()
        await lock.release()
        await lock.release()
    })

    it('is a no-op if never acquired', async () => {
        const lock = new StateLock(dir)
        await lock.release()
    })

    it('does NOT delete a lock file owned by a different pid', async () => {
        // Acquire ours, then overwrite the file with a different pid
        // (simulating a successor that claimed after we crashed mid-
        // release), the successor's lock should survive our release
        const lock = new StateLock(dir)
        await lock.acquire()
        await writeFile(join(dir, '.bot.lock'), `${process.pid + 12345}\n`)
        await lock.release()
        const body = await readFile(join(dir, '.bot.lock'), 'utf8').catch(() => '')
        expect(parseInt(body.trim(), 10)).toBe(process.pid + 12345)
    })
})


describe('StateLock acquire → release → acquire', () => {
    it('a fresh lock can be re-acquired after release', async () => {
        const lock = new StateLock(dir)
        await lock.acquire()
        await lock.release()
        const lock2 = new StateLock(dir)
        await lock2.acquire()
        const body = await readFile(join(dir, '.bot.lock'), 'utf8')
        expect(parseInt(body.trim(), 10)).toBe(process.pid)
    })
})
