/**
 * Per-conversation channel-key state on disk at {stateDir}/channel-keys/<conversationId>.json
 *   { "currentEpoch": N, "keys": { "0": "<base64 32 bytes>", ... } }
 *
 * Writes are atomic (tmp + rename). A per-conv in-memory lock serialises read-modify-write so concurrent
 * mergeEpochs don't lose updates. Corrupt JSON is moved to <id>.json.corrupt-<ts> and the SDK refetches
 */

import { mkdir, readFile, rename, writeFile, unlink, readdir } from 'node:fs/promises'
import { randomBytes }                                          from 'node:crypto'
import { join, dirname }                                        from 'node:path'

import { CHANNEL_KEY_BYTES }                                    from './channel-cipher.js'
import type { SdkLogger }                                       from '../types.js'


export interface ChannelKeyState {
    currentEpoch: number
    /** epoch (int as decimal string) -> base64(32 bytes) */
    keys: Record<string, string>
}


export class ChannelKeyStore {
    private readonly dir: string
    private readonly chains = new Map<number, Promise<unknown>>()

    constructor(stateDir: string, private readonly logger?: SdkLogger) {
        this.dir = join(stateDir, 'channel-keys')
    }


    /** Ensure dir exists, sweep stale tmp files from a prior crash */
    async init(): Promise<void> {
        await mkdir(this.dir, { recursive: true, mode: 0o700 })
        let entries: string[] = []
        try { entries = await readdir(this.dir) } catch { return }
        for (const e of entries) {
            if (e.includes('.tmp.')) {
                try { await unlink(join(this.dir, e)) } catch { /* ignore */ }
            }
        }
    }


    async load(conversationId: number): Promise<ChannelKeyState | null> {
        return this.withLock(conversationId, () => this.loadInner(conversationId))
    }


    /** Merge a batch of (epoch, base64-secret) pairs. currentEpoch tracks max. Creates the file if missing */
    async mergeEpochs(
        conversationId: number,
        entries:        Array<{ epoch: number; secretBase64: string }>,
    ): Promise<ChannelKeyState> {
        if (entries.length === 0) {
            const existing = await this.load(conversationId)
            return existing ?? { currentEpoch: -1, keys: {} }
        }
        // Validate before touching disk, one bad entry shouldn't leave a half-written state
        for (const e of entries) {
            if (!Number.isInteger(e.epoch) || e.epoch < 0 || e.epoch > 0xffffffff) {
                throw new Error(`channel-key-store: bad epoch ${e.epoch}`)
            }
            const raw = Buffer.from(e.secretBase64, 'base64')
            if (raw.byteLength !== CHANNEL_KEY_BYTES) {
                throw new Error(
                    `channel-key-store: secret for epoch ${e.epoch} decodes to ${raw.byteLength} bytes; expected ${CHANNEL_KEY_BYTES}`,
                )
            }
        }
        return this.withLock(conversationId, async () => {
            const cur = await this.loadInner(conversationId)
            const next: ChannelKeyState = cur
                ? { currentEpoch: cur.currentEpoch, keys: { ...cur.keys } }
                : { currentEpoch: -1, keys: {} }
            for (const e of entries) {
                next.keys[String(e.epoch)] = e.secretBase64
                if (e.epoch > next.currentEpoch) next.currentEpoch = e.epoch
            }
            await this.saveInner(conversationId, next)
            return next
        })
    }


    /** Returns a fresh 32-byte copy. Caller may mutate / zero it without touching the store's state */
    async getSecret(conversationId: number, epoch: number): Promise<Uint8Array | null> {
        const state = await this.load(conversationId)
        if (!state) return null
        const b64 = state.keys[String(epoch)]
        if (!b64) return null
        const raw = Buffer.from(b64, 'base64')
        if (raw.byteLength !== CHANNEL_KEY_BYTES) return null
        const out = new Uint8Array(CHANNEL_KEY_BYTES)
        out.set(raw)
        return out
    }


    /** Wipe state for a conversation (called on conversation_kicked) */
    async drop(conversationId: number): Promise<void> {
        return this.withLock(conversationId, async () => {
            const p = this.pathFor(conversationId)
            try { await unlink(p) } catch { /* missing is fine */ }
        })
    }


    // Internals

    private pathFor(conversationId: number): string {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`channel-key-store: bad conversationId ${conversationId}`)
        }
        return join(this.dir, `${conversationId}.json`)
    }


    private async loadInner(conversationId: number): Promise<ChannelKeyState | null> {
        const p = this.pathFor(conversationId)
        let raw: string
        try {
            raw = await readFile(p, 'utf8')
        } catch (err: unknown) {
            if ((err as { code?: string })?.code === 'ENOENT') return null
            throw err
        }
        try {
            return this.parseState(raw)
        } catch (err) {
            const quarantined = `${p}.corrupt-${Date.now()}`
            try { await rename(p, quarantined) } catch { /* may be gone */ }
            this.logger?.warn(
                { conversationId, err: (err as Error).message, quarantined },
                '[channel-key-store] quarantined corrupt state',
            )
            return null
        }
    }


    private parseState(raw: string): ChannelKeyState {
        const obj = JSON.parse(raw)
        if (!obj || typeof obj !== 'object') throw new Error('not an object')
        if (typeof obj.currentEpoch !== 'number') throw new Error('missing currentEpoch')
        if (!obj.keys || typeof obj.keys !== 'object') throw new Error('missing keys')
        // Strings only. Base64/length validation happens in getSecret so one junk entry doesn't kill the whole file
        for (const k of Object.keys(obj.keys)) {
            if (typeof obj.keys[k] !== 'string') throw new Error(`epoch ${k} not a string`)
        }
        return obj as ChannelKeyState
    }


    private async saveInner(conversationId: number, state: ChannelKeyState): Promise<void> {
        const p   = this.pathFor(conversationId)
        const tmp = `${p}.tmp.${randomBytes(4).toString('hex')}`
        await mkdir(dirname(p), { recursive: true, mode: 0o700 })
        const json = JSON.stringify(state)
        await writeFile(tmp, json, { mode: 0o600 })
        // rename is atomic on POSIX, on Windows it replaces if the dest exists (MoveFileEx semantics)
        await rename(tmp, p)
    }


    private withLock<T>(conversationId: number, fn: () => Promise<T>): Promise<T> {
        const prev = this.chains.get(conversationId) ?? Promise.resolve()
        const next = prev.then(fn, fn)
        // Drop the chain entry when it's the latest, otherwise the map would grow forever on long-running bots
        const cleanup = next.finally(() => {
            if (this.chains.get(conversationId) === cleanup) {
                this.chains.delete(conversationId)
            }
        })
        this.chains.set(conversationId, cleanup)
        return next
    }
}
