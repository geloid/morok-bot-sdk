/**
 * Per-conversation group_secret state on disk at {stateDir}/group-secrets/<conversationId>.json
 * Same disk layout and locking as channel-key-store, with "version" in place of "epoch"
 * Persisted because the bot needs old versions to re-seal historical epochs after a rotate
 * and to unseal old sealed bundles, a restart re-reads from disk
 *   { "currentVersion": N, "secrets": { "0": "<b64 32 bytes>", ... } }
 */

import { mkdir, readFile, rename, writeFile, unlink, readdir } from 'node:fs/promises'
import { randomBytes }                                          from 'node:crypto'
import { join, dirname }                                        from 'node:path'

import { GROUP_SECRET_BYTES }                                   from './group-secret-cipher.js'
import type { SdkLogger }                                       from '../types.js'


export interface GroupSecretState {
    currentVersion: number
    /** version (int as decimal string) -> base64(32 bytes) */
    secrets: Record<string, string>
}


export class GroupSecretStore {
    private readonly dir: string
    private readonly chains = new Map<number, Promise<unknown>>()

    constructor(stateDir: string, private readonly logger?: SdkLogger) {
        this.dir = join(stateDir, 'group-secrets')
    }


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


    async load(conversationId: number): Promise<GroupSecretState | null> {
        return this.withLock(conversationId, () => this.loadInner(conversationId))
    }


    /** Merge (version, base64-secret) pairs. currentVersion tracks max. Creates the file if missing */
    async mergeVersions(
        conversationId: number,
        entries:        Array<{ version: number; secretBase64: string }>,
    ): Promise<GroupSecretState> {
        if (entries.length === 0) {
            const existing = await this.load(conversationId)
            return existing ?? { currentVersion: -1, secrets: {} }
        }
        for (const e of entries) {
            if (!Number.isInteger(e.version) || e.version < 0 || e.version > 0xffffffff) {
                throw new Error(`group-secret-store: bad version ${e.version}`)
            }
            const raw = Buffer.from(e.secretBase64, 'base64')
            if (raw.byteLength !== GROUP_SECRET_BYTES) {
                throw new Error(
                    `group-secret-store: secret for v${e.version} decodes to ${raw.byteLength} bytes; expected ${GROUP_SECRET_BYTES}`,
                )
            }
        }
        return this.withLock(conversationId, async () => {
            const cur = await this.loadInner(conversationId)
            const next: GroupSecretState = cur
                ? { currentVersion: cur.currentVersion, secrets: { ...cur.secrets } }
                : { currentVersion: -1, secrets: {} }
            for (const e of entries) {
                next.secrets[String(e.version)] = e.secretBase64
                if (e.version > next.currentVersion) next.currentVersion = e.version
            }
            await this.saveInner(conversationId, next)
            return next
        })
    }


    /** Returns a fresh 32-byte copy, or null. Same isolation as ChannelKeyStore.getSecret */
    async getSecret(conversationId: number, version: number): Promise<Uint8Array | null> {
        const state = await this.load(conversationId)
        if (!state) return null
        const b64 = state.secrets[String(version)]
        if (!b64) return null
        const raw = Buffer.from(b64, 'base64')
        if (raw.byteLength !== GROUP_SECRET_BYTES) return null
        const out = new Uint8Array(GROUP_SECRET_BYTES)
        out.set(raw)
        return out
    }


    async drop(conversationId: number): Promise<void> {
        return this.withLock(conversationId, async () => {
            const p = this.pathFor(conversationId)
            try { await unlink(p) } catch { /* missing is fine */ }
        })
    }


    // Internals

    private pathFor(conversationId: number): string {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`group-secret-store: bad conversationId ${conversationId}`)
        }
        return join(this.dir, `${conversationId}.json`)
    }


    private async loadInner(conversationId: number): Promise<GroupSecretState | null> {
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
                '[group-secret-store] quarantined corrupt state',
            )
            return null
        }
    }


    private parseState(raw: string): GroupSecretState {
        const obj = JSON.parse(raw)
        if (!obj || typeof obj !== 'object') throw new Error('not an object')
        if (typeof obj.currentVersion !== 'number') throw new Error('missing currentVersion')
        if (!obj.secrets || typeof obj.secrets !== 'object') throw new Error('missing secrets')
        for (const k of Object.keys(obj.secrets)) {
            if (typeof obj.secrets[k] !== 'string') throw new Error(`v${k} not a string`)
        }
        return obj as GroupSecretState
    }


    private async saveInner(conversationId: number, state: GroupSecretState): Promise<void> {
        const p   = this.pathFor(conversationId)
        const tmp = `${p}.tmp.${randomBytes(4).toString('hex')}`
        await mkdir(dirname(p), { recursive: true, mode: 0o700 })
        const json = JSON.stringify(state)
        await writeFile(tmp, json, { mode: 0o600 })
        await rename(tmp, p)
    }


    private withLock<T>(conversationId: number, fn: () => Promise<T>): Promise<T> {
        const prev = this.chains.get(conversationId) ?? Promise.resolve()
        const next = prev.then(fn, fn)
        const cleanup = next.finally(() => {
            if (this.chains.get(conversationId) === cleanup) {
                this.chains.delete(conversationId)
            }
        })
        this.chains.set(conversationId, cleanup)
        return next
    }
}
