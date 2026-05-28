/**
 * File-backed Signal Protocol stores. Implements libsignal's StorageType on a directory layout
 * Atomic writes (write-then-rename) so a crash mid-update can't corrupt state
 * fsck on boot moves broken session/prekey files to quarantine/ so one bad file doesn't refuse the whole bot
 *
 * Layout under stateDir:
 *   identity.json                              own keypair + reg id + ids
 *   state.json                                 bookkeeping (SPK rotation ts, next ids)
 *   sessions/<userId>.<deviceId>.json          per-peer-device session
 *   prekeys/signed-<keyId>.json                signed prekeys
 *   prekeys/onetime-<keyId>.json               one-time prekeys
 *   identity-cache/<userId>.<deviceId>.json    peer identity for TOFU
 *   quarantine/                                moved here on parse failure
 *
 * Everything created 0o700 / 0o600, anyone with read on this dir can impersonate the bot
 */

import { promises as fs }  from 'node:fs'
import path                from 'node:path'
import { timingSafeEqual, randomUUID } from 'node:crypto'

import type {
    Direction, KeyPairType, SessionRecordType, StorageType,
} from '@privacyresearch/libsignal-protocol-typescript'


interface SerializedKeyPair {
    pub:  string  // base64
    priv: string
}

function toArrayBuffer(b64: string): ArrayBuffer {
    const buf = Buffer.from(b64, 'base64')
    // Copy out of Node's pooled Buffer ArrayBuffer so libsignal gets a clean buffer of the exact length
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
}

function fromArrayBuffer(buf: ArrayBuffer): string {
    return Buffer.from(buf).toString('base64')
}

function serializeKeyPair(kp: KeyPairType): SerializedKeyPair {
    return {
        pub:  fromArrayBuffer(kp.pubKey),
        priv: fromArrayBuffer(kp.privKey),
    }
}

function deserializeKeyPair(s: SerializedKeyPair): KeyPairType {
    return {
        pubKey:  toArrayBuffer(s.pub),
        privKey: toArrayBuffer(s.priv),
    }
}

function constantTimeEqualBytes(a: ArrayBuffer, b: ArrayBuffer): boolean {
    if (a.byteLength !== b.byteLength) return false
    return timingSafeEqual(Buffer.from(a), Buffer.from(b))
}


async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 })
    // Random UUID suffix to avoid a tmp collision when two writes for the same target
    // land in the same millisecond on the same pid
    const tmp = `${filePath}.tmp-${randomUUID()}`
    await fs.writeFile(tmp, JSON.stringify(value), { mode: 0o600 })
    await fs.rename(tmp, filePath)
}

async function readJson<T>(filePath: string): Promise<T | undefined> {
    try {
        const raw = await fs.readFile(filePath, 'utf8')
        return JSON.parse(raw) as T
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined
        throw err
    }
}


export interface PersistedIdentity {
    identityKeyPair:   SerializedKeyPair
    registrationId:    number
    /** Set on first /auth/bot-session, absent before first start */
    userId?:           number
    /** Always 1 for bots */
    deviceId?:         number
    accountSigningKey?: SerializedKeyPair
}

interface PersistedState {
    /** Unix ms of last signed-prekey rotation. 0 = never */
    lastSignedPreKeyRotationMs: number
    /** Next OTPK id to mint. Monotonic */
    nextOneTimePreKeyId:        number
    /** Next signed-prekey id, bumps every rotation */
    nextSignedPreKeyId:         number
}

export interface FsckResult {
    quarantinedSessions: string[]
    quarantinedPreKeys:  string[]
}


const DIRECTION_ENUM = {
    SENDING:   1,
    RECEIVING: 2,
} as const


export class FileSignalStore implements StorageType {
    readonly Direction: typeof DIRECTION_ENUM = DIRECTION_ENUM

    private identityCache?: PersistedIdentity
    private stateCache?:    PersistedState

    constructor(private readonly stateDir: string) {}


    /** Create the directory tree with safe perms. Idempotent */
    async ensureLayout(): Promise<void> {
        for (const sub of ['', 'sessions', 'prekeys', 'identity-cache', 'quarantine']) {
            await fs.mkdir(path.join(this.stateDir, sub), { recursive: true, mode: 0o700 })
        }
    }

    /**
     * Idempotent import of a parsed .morokbot. A no-op if identity.json already exists with matching userId/regId,
     * throws if the stateDir holds a different bot
     *
     * Write order matters: state.json, signed prekey, OTPKs, then identity.json
     * last identity.json is the "import complete" marker, a crash before it lands makes the next start re-import
     */
    async importInitial(opts: {
        botUserId:         number
        registrationId:    number
        deviceId:          number
        identityKeyPair:   SerializedKeyPair
        accountSigningKey?:SerializedKeyPair
        signedPreKey: {
            keyId:     number
            pub:       string
            priv:      string
            signature: string
        }
        oneTimePreKeys: Array<{
            keyId: number
            pub:   string
            priv:  string
        }>
    }): Promise<void> {
        await this.ensureLayout()

        const existing = await readJson<PersistedIdentity>(this.identityFile())
        if (existing) {
            if (existing.userId && existing.userId !== opts.botUserId) {
                throw new Error(
                    `state directory ${this.stateDir} already holds bot user ${existing.userId}; ` +
                    `refusing to overwrite with bot user ${opts.botUserId}. Use a different stateDir.`,
                )
            }
            if (existing.registrationId !== opts.registrationId) {
                throw new Error(
                    `state directory ${this.stateDir} holds registrationId ${existing.registrationId}; ` +
                    `incoming .morokbot has ${opts.registrationId}. The .morokbot likely doesn't ` +
                    `match the imported state. Use a fresh stateDir or restore the matching file.`,
                )
            }
            // Same bot. Backfill userId/deviceId if a prior import committed before /auth/bot-session ran
            if (!existing.userId) {
                await writeJsonAtomic(this.identityFile(), {
                    ...existing,
                    userId:   opts.botUserId,
                    deviceId: opts.deviceId,
                })
                this.identityCache = undefined
            }
            return
        }

        const initState: PersistedState = {
            lastSignedPreKeyRotationMs: Date.now(),
            nextOneTimePreKeyId:        Math.max(...opts.oneTimePreKeys.map(k => k.keyId), 0) + 1,
            nextSignedPreKeyId:         opts.signedPreKey.keyId + 1,
        }
        await writeJsonAtomic(this.stateFile(), initState)

        await writeJsonAtomic(this.signedPreKeyFile(opts.signedPreKey.keyId), {
            keyId:     opts.signedPreKey.keyId,
            pub:       opts.signedPreKey.pub,
            priv:      opts.signedPreKey.priv,
            signature: opts.signedPreKey.signature,
        })

        for (const otp of opts.oneTimePreKeys) {
            await writeJsonAtomic(this.oneTimePreKeyFile(otp.keyId), {
                keyId: otp.keyId,
                pub:   otp.pub,
                priv:  otp.priv,
            })
        }

        // identity.json last (see note above)
        const identity: PersistedIdentity = {
            identityKeyPair: opts.identityKeyPair,
            registrationId:  opts.registrationId,
            userId:          opts.botUserId,
            deviceId:        opts.deviceId,
            accountSigningKey: opts.accountSigningKey,
        }
        await writeJsonAtomic(this.identityFile(), identity)
    }

    /**
     * Walk sessions and prekeys, move anything that fails to parse to quarantine/
     * The bot keeps booting, a lost session re-X3DHs when the peer next sends
     */
    async fsck(): Promise<FsckResult> {
        await this.ensureLayout()
        const quarantinedSessions: string[] = []
        const quarantinedPreKeys:  string[] = []

        for (const entry of await fs.readdir(path.join(this.stateDir, 'sessions')).catch(() => [])) {
            const full = path.join(this.stateDir, 'sessions', entry)
            let bad: boolean
            try {
                const j = await readJson<{ record?: unknown }>(full)
                bad = !j || typeof j.record !== 'string' || j.record.length === 0
            } catch { bad = true }
            if (bad) {
                const dst = path.join(this.stateDir, 'quarantine', `session-${Date.now()}-${entry}`)
                await fs.rename(full, dst).catch(() => {})
                quarantinedSessions.push(full)
            }
        }

        for (const entry of await fs.readdir(path.join(this.stateDir, 'prekeys')).catch(() => [])) {
            const full = path.join(this.stateDir, 'prekeys', entry)
            let bad: boolean
            try {
                const j = await readJson<{ pub?: unknown; priv?: unknown }>(full)
                bad = !j || typeof j.pub !== 'string' || typeof j.priv !== 'string'
            } catch { bad = true }
            if (bad) {
                const dst = path.join(this.stateDir, 'quarantine', `prekey-${Date.now()}-${entry}`)
                await fs.rename(full, dst).catch(() => {})
                quarantinedPreKeys.push(full)
            }
        }

        return { quarantinedSessions, quarantinedPreKeys }
    }


    // Identity

    async getIdentityKeyPair(): Promise<KeyPairType | undefined> {
        const id = await this.loadPersistedIdentity()
        if (!id) return undefined
        return deserializeKeyPair(id.identityKeyPair)
    }

    async getLocalRegistrationId(): Promise<number | undefined> {
        return (await this.loadPersistedIdentity())?.registrationId
    }

    /** TOFU, first sight of a peer's identity key is accepted and later changes are rejected
     * A rejected identity surfaces as a silent decrypt failure, the SDK installs a fresh session
     * from the peer's next PreKeySignalMessage */
    async isTrustedIdentity(
        identifier: string,
        identityKey: ArrayBuffer,
        _direction: Direction,
    ): Promise<boolean> {
        const cached = await this.loadPeerIdentity(identifier)
        if (!cached) return true
        return constantTimeEqualBytes(cached, identityKey)
    }

    async saveIdentity(
        encodedAddress: string,
        publicKey: ArrayBuffer,
        _nonblockingApproval?: boolean,
    ): Promise<boolean> {
        const existing = await this.loadPeerIdentity(encodedAddress)
        if (existing && constantTimeEqualBytes(existing, publicKey)) {
            return false
        }
        await writeJsonAtomic(this.identityCacheFile(encodedAddress), {
            identityKey: fromArrayBuffer(publicKey),
        })
        // libsignal's contract: return true if the identity changed (a different key was stored before),
        // the first save returns false
        return existing !== undefined
    }

    /** Public read of a peer's currently-pinned identity (no TOFU logic), so SignalEngine.decrypt can detect
     *  a silent type-3 re-pin. The vendored libsignal type-3 receiver path doesn't enforce the changed-identity check
     *  (it calls isTrustedIdentity without awaiting), the encrypt path does
     *  Returns undefined for a never-seen peer */
    async peekPeerIdentity(encodedAddress: string): Promise<ArrayBuffer | undefined> {
        return this.loadPeerIdentity(encodedAddress)
    }


    // Sessions

    async loadSession(encodedAddress: string): Promise<SessionRecordType | undefined> {
        const j = await readJson<{ record: string }>(this.sessionFile(encodedAddress))
        return j?.record
    }

    async storeSession(encodedAddress: string, record: SessionRecordType): Promise<void> {
        await writeJsonAtomic(this.sessionFile(encodedAddress), { record })
    }


    // One-time prekeys

    async loadPreKey(keyId: number | string): Promise<KeyPairType | undefined> {
        const id = typeof keyId === 'string' ? Number(keyId) : keyId
        const j = await readJson<SerializedKeyPair>(this.oneTimePreKeyFile(id))
        if (!j) return undefined
        return deserializeKeyPair(j)
    }

    async storePreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
        const id = typeof keyId === 'string' ? Number(keyId) : keyId
        await writeJsonAtomic(this.oneTimePreKeyFile(id), {
            keyId: id,
            ...serializeKeyPair(keyPair),
        })
    }

    async removePreKey(keyId: number | string): Promise<void> {
        const id = typeof keyId === 'string' ? Number(keyId) : keyId
        await fs.unlink(this.oneTimePreKeyFile(id)).catch(err => {
            if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
        })
    }


    // Signed prekeys

    async loadSignedPreKey(keyId: number | string): Promise<KeyPairType | undefined> {
        const id = typeof keyId === 'string' ? Number(keyId) : keyId
        const j = await readJson<SerializedKeyPair>(this.signedPreKeyFile(id))
        if (!j) return undefined
        return deserializeKeyPair(j)
    }

    async storeSignedPreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
        const id = typeof keyId === 'string' ? Number(keyId) : keyId
        // libsignal calls this without the signature, so preserve the existing one if any
        // Replenish writes the full record via storeSignedPreKeyFull below
        const existing = await readJson<{ signature?: string }>(this.signedPreKeyFile(id))
        await writeJsonAtomic(this.signedPreKeyFile(id), {
            keyId: id,
            ...serializeKeyPair(keyPair),
            ...(existing?.signature ? { signature: existing.signature } : {}),
        })
    }

    async removeSignedPreKey(keyId: number | string): Promise<void> {
        const id = typeof keyId === 'string' ? Number(keyId) : keyId
        await fs.unlink(this.signedPreKeyFile(id)).catch(err => {
            if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
        })
    }


    // SDK-only helpers (not StorageType)

    /** Write full SPK record including signature (for replenish) */
    async storeSignedPreKeyFull(rec: {
        keyId:     number
        keyPair:   KeyPairType
        signature: ArrayBuffer
    }): Promise<void> {
        await writeJsonAtomic(this.signedPreKeyFile(rec.keyId), {
            keyId:     rec.keyId,
            ...serializeKeyPair(rec.keyPair),
            signature: fromArrayBuffer(rec.signature),
        })
    }

    async getSignedPreKeyRecord(keyId: number): Promise<{
        keyId: number; pub: string; priv: string; signature?: string
    } | undefined> {
        return readJson(this.signedPreKeyFile(keyId))
    }

    async listOneTimePreKeyIds(): Promise<number[]> {
        const dir = path.join(this.stateDir, 'prekeys')
        const out: number[] = []
        for (const entry of await fs.readdir(dir).catch(() => [])) {
            const m = /^onetime-(\d+)\.json$/.exec(entry)
            if (m) out.push(Number(m[1]))
        }
        return out
    }

    async loadState(): Promise<PersistedState> {
        if (this.stateCache) return this.stateCache
        const s = await readJson<PersistedState>(this.stateFile())
        if (s) {
            this.stateCache = s
            return s
        }
        const init: PersistedState = {
            lastSignedPreKeyRotationMs: 0,
            nextOneTimePreKeyId:        1,
            nextSignedPreKeyId:         1,
        }
        await writeJsonAtomic(this.stateFile(), init)
        this.stateCache = init
        return init
    }

    async patchState(patch: Partial<PersistedState>): Promise<void> {
        const cur = await this.loadState()
        const next: PersistedState = { ...cur, ...patch }
        await writeJsonAtomic(this.stateFile(), next)
        this.stateCache = next
    }


    // Internal: identity load/save

    private async loadPersistedIdentity(): Promise<PersistedIdentity | undefined> {
        if (this.identityCache) return this.identityCache
        const id = await readJson<PersistedIdentity>(this.identityFile())
        if (id) this.identityCache = id
        return id
    }

    private async loadPeerIdentity(encodedAddress: string): Promise<ArrayBuffer | undefined> {
        const j = await readJson<{ identityKey: string }>(this.identityCacheFile(encodedAddress))
        if (!j) return undefined
        return toArrayBuffer(j.identityKey)
    }


    // Path helpers

    private identityFile():      string { return path.join(this.stateDir, 'identity.json') }
    private stateFile():         string { return path.join(this.stateDir, 'state.json') }
    private sessionFile(addr: string): string {
        return path.join(this.stateDir, 'sessions', `${sanitizeAddr(addr)}.json`)
    }
    private identityCacheFile(addr: string): string {
        return path.join(this.stateDir, 'identity-cache', `${sanitizeIdentityAddr(addr)}.json`)
    }
    private signedPreKeyFile(keyId: number): string {
        return path.join(this.stateDir, 'prekeys', `signed-${keyId}.json`)
    }
    private oneTimePreKeyFile(keyId: number): string {
        return path.join(this.stateDir, 'prekeys', `onetime-${keyId}.json`)
    }
}


/** libsignal addresses are "<userId>.<deviceId>". Only digits and a single dot are legitimate,
 * reject everything else so a path-traversal payload can't reach the filesystem */
function sanitizeAddr(addr: string): string {
    if (!/^\d+\.\d+$/.test(addr)) {
        throw new Error(`refusing unsafe session address "${addr}" - expected <userId>.<deviceId>`)
    }
    return addr
}

/** Identity ops can be keyed by a bare <userId> (libsignal hands address.getName() to the identity methods)
 *  or the full <userId>.<deviceId>. Accept both, still digits-and-one-dot only so a path-traversal payload
 *  can't reach the filesystem */
function sanitizeIdentityAddr(addr: string): string {
    if (!/^\d+(\.\d+)?$/.test(addr)) {
        throw new Error(`refusing unsafe identity address "${addr}" - expected <userId> or <userId>.<deviceId>`)
    }
    return addr
}
