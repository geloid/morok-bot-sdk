/**
 * Pid-based lock file in stateDir. Two bots sharing one stateDir corrupt each other's Signal and channel-key state
 * Not a hard lock, the kill(pid, 0) probe has a window where two concurrent starts both pass
 * On NFS, mount noac or use a local stateDir
 */

import { promises as fs } from 'node:fs'
import { join }           from 'node:path'

import type { SdkLogger } from './types.js'


export class StateLock {
    private readonly path: string
    private acquired = false

    constructor(stateDir: string, private readonly logger?: SdkLogger) {
        this.path = join(stateDir, '.bot.lock')
    }


    /** Claim the lock. Throws if another live bot owns it. Idempotent on the same instance */
    async acquire(): Promise<void> {
        if (this.acquired) return

        // mkdir first so the lock file lands before stores create their subdirs
        // The two-start race is decided by the read-then-write below
        const lockDir = this.path.replace(/[/\\][^/\\]+$/, '') || '.'
        await fs.mkdir(lockDir, { recursive: true, mode: 0o700 })

        let existing: string | null = null
        try { existing = await fs.readFile(this.path, 'utf8') }
        catch (err) {
            if ((err as { code?: string }).code !== 'ENOENT') throw err
        }
        if (existing !== null) {
            const otherPid = parseInt(existing.trim(), 10)
            if (Number.isInteger(otherPid) && otherPid > 0 && otherPid !== process.pid) {
                let alive = false
                try {
                    // kill(pid, 0) probes liveness. ESRCH = dead, EPERM = alive under a different uid
                    process.kill(otherPid, 0)
                    alive = true
                } catch (err) {
                    const code = (err as { code?: string }).code
                    if (code === 'EPERM') alive = true
                    else if (code !== 'ESRCH') throw err
                }
                if (alive) {
                    throw new Error(
                        `stateDir is locked by another running bot (pid=${otherPid}). ` +
                        `Each bot needs its own stateDir. If pid=${otherPid} is actually ` +
                        `dead, remove ${this.path} and retry.`,
                    )
                }
                this.logger?.warn(
                    { stalePid: otherPid, lockPath: this.path },
                    '[state-lock] stale lock from dead pid, claiming',
                )
            }
        }

        await fs.writeFile(this.path, `${process.pid}\n`, { mode: 0o600 })
        this.acquired = true
    }


    /** Best-effort delete. Idempotent */
    async release(): Promise<void> {
        if (!this.acquired) return
        this.acquired = false
        try {
            // Check ownership before unlink, so a delayed release does not delete a successor's lock
            const content = await fs.readFile(this.path, 'utf8').catch(() => '')
            const owner = parseInt(content.trim(), 10)
            if (owner === process.pid) {
                await fs.unlink(this.path).catch(() => {})
            }
        } catch (err) {
            this.logger?.warn(
                { lockPath: this.path, err: (err as Error).message },
                '[state-lock] release failed',
            )
        }
    }
}
