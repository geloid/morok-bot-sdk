/**
 * Group-chat / channel flow: fetch channel-keys, decrypt incoming group_messages, send group_messages,
 * rotate channel-key, rotate group_secret, backfill epochs to new joiners
 *
 * Receive side: parse [MAGIC || epoch || iv || ct+tag], pick the right per-epoch secret from the local store,
 * AES-GCM decrypt. On a missing epoch, lazy-fetch once and retry. Mirrors frontend/src/signal/channel.ts
 *
 * Locks: withPeerLock(sharerId, sharerDevice) is shared with the DM ratchet so concurrent DM traffic
 * with the same sharer can't corrupt session state. A per-conv lock inside ChannelKeyStore and GroupSecretStore
 * serialises file writes
 */

import { randomBytes, randomUUID }                      from 'node:crypto'

import type { HttpClient }                              from '../transport/http.js'
import type { WsClient, IncomingFrame }                 from '../transport/ws.js'
import type { SignalEngine }                            from '../crypto/signal.js'
import type { SdkLogger }                               from '../types.js'
import type { ChannelKeyStore }                         from '../crypto/channel-key-store.js'
import type { GroupSecretStore }                        from '../crypto/group-secret-store.js'
import type { ConvCache }                               from './conv-cache.js'
import { SendRejectedError, SendUncertainError }        from './direct.js'
import {
    parseChannelWire, decryptChannelWire, encryptChannelWire,
} from '../crypto/channel-cipher.js'
import { unsealEpochKey, sealEpochKey, GROUP_SECRET_BYTES } from '../crypto/group-secret-cipher.js'


// Server response shape for GET /groups/:id/channel-key
// `keys`: per-device Signal-wrapped channel-key copies
// `sealedBundles`: AES-GCM-sealed bundles under the conv's group_secret of `groupSecretVersion`,
//  letting a joiner unwrap every epoch's key without depending on a specific online sharer,
//  provided it already has the matching group_secret
interface ChannelKeyResponse {
    keys: Array<{
        epoch:            number
        encryptedKey:     string    // Signal envelope body, base64
        messageType:      number    // 1 or 3
        sharedByUserId?:  number
        sharedByDeviceId?: number
    }>
    sealedBundles?: Array<{
        epoch:                 number
        groupSecretVersion:    number
        sealedToGroupSecret:   string   // base64 ct
        sealedToGroupSecretIv: string   // base64 iv (12 bytes)
    }>
    pending?:           boolean
    rotationInFlight?:  boolean
}


interface PendingGroupSend {
    resolve: (messageId: number) => void
    reject:  (err: Error) => void
    timer:   NodeJS.Timeout
    clientMsgId:    string
    conversationId: number
}


// Server's regex on outbound fanoutId is /^[A-Za-z0-9_-]{8,32}$/
function mintFanoutId(): string {
    return randomBytes(12).toString('base64url')    // 16 chars
}

// Server's regex on clientMsgId is /^[A-Za-z0-9_-]{1,64}$/
function mintClientMsgId(): string {
    return randomUUID().replace(/-/g, '')   // 32 hex chars
}


export interface GroupSendOptions {
    sendTimeoutMs?:     number
    replyToId?:         number
    replyToClientMsgId?: string
    threadRootId?:      number
    /** Optional file id from a prior `uploadAttachment`. For a gallery this is the head ref's fileId */
    fileId?:            number
    /** Wire-side render hint matching the server's ALLOWED_MESSAGE_KINDS, including 'gallery' */
    kind?:              'text' | 'file' | 'voice' | 'video_note' | 'gallery'
    /** Gallery-only: file ids 2..N (head is `fileId`). Server caps at 9 extras (10 total including the head) */
    additionalFileIds?: number[]
    /** Disappearing-message TTL. Server-validated */
    expiresInSeconds?:  number
}


export interface GroupSendResult {
    messageId:      number
    clientMsgId:    string
    fanoutId:       string
    conversationId: number
    epoch:          number
}


export class GroupsFlow {
    // Dedup overlapping installFromServer calls by (conv, sinceEpoch). Promises clear themselves on settle
    private readonly inflightInstalls = new Map<string, Promise<number>>()

    // pending send promises keyed by outbound fanoutId. The server's broadcast comes back as type:'message'
    // with messageType=8 and our fanoutId, the listener resolves the match
    private readonly pendingSends = new Map<string, PendingGroupSend>()

    // Dedup installGroupSecret per conv
    private readonly inflightGroupSecret = new Map<number, Promise<void>>()

    // Fire-and-forget auto-backfill promises, dropped on shutdown so they don't keep the process alive
    private readonly inflightBackfills = new Set<Promise<unknown>>()


    constructor(
        private readonly botUserId: number,
        private readonly http:      HttpClient,
        private readonly ws:        WsClient,
        private readonly signal:    SignalEngine,
        private readonly store:     ChannelKeyStore,
        private readonly gsStore:   GroupSecretStore,
        private readonly convCache: ConvCache,
        private readonly logger?:   SdkLogger,
    ) {
        // own-echo / error frames matched by fanoutId, a pendingSends miss means it's a DM own-echo and we ignore it
        this.ws.on('frame', (frame) => { this.onFrame(frame) })
        // A transient drop loses the own-echo, so fail in-flight sends with an uncertain result for the caller to retry
        this.ws.on('close', (info) => { if (info.willReconnect) this.failPendingUncertain() })
    }


    /** Fetch + install all channel-key epochs above sinceEpoch (default -1 = everything), returns the count
     *  Concurrent calls with the same (conv, sinceEpoch) share one HTTP round-trip */
    async installFromServer(
        conversationId: number,
        opts: { sinceEpoch?: number } = {},
    ): Promise<number> {
        const since = opts.sinceEpoch ?? -1
        const cacheKey = `${conversationId}:${since}`
        const inFlight = this.inflightInstalls.get(cacheKey)
        if (inFlight) return inFlight
        const promise = this.doInstall(conversationId, since)
            .finally(() => {
                // Race-safe: only delete if the map still points to us
                if (this.inflightInstalls.get(cacheKey) === promise) {
                    this.inflightInstalls.delete(cacheKey)
                }
            })
        this.inflightInstalls.set(cacheKey, promise)
        return promise
    }


    private async doInstall(
        conversationId: number,
        since:          number,
    ): Promise<number> {
        const res = await this.http.get<ChannelKeyResponse>(
            `/groups/${conversationId}/channel-key`,
            { params: { sinceEpoch: since } },
        )
        const body = res.data
        if (!body || !Array.isArray(body.keys)) {
            this.logger?.warn(
                { conversationId },
                '[groups] /channel-key returned malformed body',
            )
            return 0
        }
        if (body.keys.length === 0) {
            this.logger?.debug(
                { conversationId, since, pending: body.pending },
                '[groups] no new channel-key epochs available',
            )
            return 0
        }

        // Unwrap per-device envelopes sequentially under the shared peer lock. Volume is bounded by missed epochs
        const merged: Array<{ epoch: number; secretBase64: string }> = []
        for (const k of body.keys) {
            if (!Number.isInteger(k.epoch) || k.epoch < 0) {
                this.logger?.warn(
                    { conversationId, entry: k },
                    '[groups] dropping channel-key entry with bad epoch',
                )
                continue
            }
            if (k.messageType !== 1 && k.messageType !== 3) {
                this.logger?.warn(
                    { conversationId, epoch: k.epoch, messageType: k.messageType },
                    '[groups] dropping channel-key entry with non-Signal type',
                )
                continue
            }
            if (typeof k.sharedByUserId !== 'number'
                || typeof k.sharedByDeviceId !== 'number') {
                // Modern shares record sharer coords, without them we can't decrypt. Pre-migration entries
                this.logger?.warn(
                    { conversationId, epoch: k.epoch },
                    '[groups] dropping channel-key entry missing sharer coords',
                )
                continue
            }
            const sharerId     = k.sharedByUserId
            const sharerDevice = k.sharedByDeviceId
            let plaintextBytes: Uint8Array
            try {
                plaintextBytes = await this.signal.withPeerLock(
                    sharerId, sharerDevice,
                    () => this.signal.decrypt(
                        sharerId, sharerDevice,
                        k.messageType, k.encryptedKey,
                    ),
                )
            } catch (err) {
                // Skip a bad wrap, other epochs still install
                this.logger?.warn(
                    {
                        conversationId, epoch: k.epoch,
                        sharerId, sharerDevice, messageType: k.messageType,
                        err: (err as Error).message,
                    },
                    '[groups] channel-key envelope decrypt failed',
                )
                continue
            }
            // Plaintext is UTF-8 base64 of the raw 32-byte secret, the same encoding the FE uses
            const secretBase64 = new TextDecoder('utf-8', { fatal: false })
                .decode(plaintextBytes)
                .trim()
            if (!/^[A-Za-z0-9+/=]+$/.test(secretBase64) || secretBase64.length < 40) {
                this.logger?.warn(
                    { conversationId, epoch: k.epoch },
                    '[groups] channel-key plaintext not a base64 secret',
                )
                continue
            }
            merged.push({ epoch: k.epoch, secretBase64 })
        }

        // Sealed-bundle fallback for epochs we couldn't unwrap per-device, needs the matching group_secret
        // and lazy-installs it once if missing
        const haveEpoch = new Set(merged.map(m => m.epoch))
        const bundles = Array.isArray(body.sealedBundles) ? body.sealedBundles : []
        // DoS guard: cap iteration at 10_000 (matches the protocol's MAX_CHUNK_COUNT)
        // in case a misbehaving server ships a huge array
        const SEAL_BUNDLE_CAP = 10_000
        if (bundles.length > SEAL_BUNDLE_CAP) {
            this.logger?.warn(
                { conversationId, bundleCount: bundles.length, cap: SEAL_BUNDLE_CAP },
                '[groups] sealedBundles array exceeds cap - truncating',
            )
        }
        const interesting = bundles
            .slice(0, SEAL_BUNDLE_CAP)
            .filter(b =>
                Number.isInteger(b.epoch) && b.epoch >= 0 && !haveEpoch.has(b.epoch),
            )
        if (interesting.length > 0) {
            // Lazy-install once if any interesting bundle references a version we don't have
            // Older versions can't be fetched, those bundles are skipped below
            let needFetch = false
            for (const b of interesting) {
                if (Number.isInteger(b.groupSecretVersion)) {
                    const have = await this.gsStore.getSecret(conversationId, b.groupSecretVersion)
                    if (!have) { needFetch = true; break }
                }
            }
            if (needFetch) {
                try {
                    await this.installGroupSecret(conversationId)
                } catch (err) {
                    this.logger?.warn(
                        { conversationId, err: (err as Error).message },
                        '[groups] sealedBundle path: installGroupSecret failed',
                    )
                }
            }

            for (const b of interesting) {
                if (typeof b.sealedToGroupSecret !== 'string'
                    || typeof b.sealedToGroupSecretIv !== 'string'
                    || !Number.isInteger(b.groupSecretVersion)) {
                    this.logger?.warn(
                        { conversationId, bundle: b },
                        '[groups] dropping malformed sealedBundle',
                    )
                    continue
                }
                const secret = await this.gsStore.getSecret(conversationId, b.groupSecretVersion)
                if (!secret) {
                    this.logger?.debug(
                        { conversationId, epoch: b.epoch, version: b.groupSecretVersion },
                        '[groups] sealedBundle skipped: no matching group_secret available',
                    )
                    continue
                }
                try {
                    const epochKey = await unsealEpochKey({
                        ciphertextBase64: b.sealedToGroupSecret,
                        ivBase64:         b.sealedToGroupSecretIv,
                        groupSecret:      secret,
                        conversationId,
                        version:          b.groupSecretVersion,
                        expectedEpoch:    b.epoch,
                    })
                    merged.push({
                        epoch:        b.epoch,
                        secretBase64: Buffer.from(epochKey).toString('base64'),
                    })
                    haveEpoch.add(b.epoch)
                } catch (err) {
                    this.logger?.warn(
                        {
                            conversationId, epoch: b.epoch, version: b.groupSecretVersion,
                            err: (err as Error).message,
                        },
                        '[groups] sealedBundle unseal failed',
                    )
                }
            }
        }

        if (merged.length === 0) return 0
        await this.store.mergeEpochs(conversationId, merged)
        this.logger?.info(
            { conversationId, installed: merged.map(m => m.epoch) },
            '[groups] installed channel-key epochs',
        )
        return merged.length
    }


    /** Decrypt a group-message wire under the right epoch's secret. On a missing epoch, lazy-fetch once and retry,
     *  if still missing it throws. Plaintext is UTF-8 text or the JSON envelope for attachments (caller sniffs) */
    async decryptGroupMessage(
        conversationId: number,
        wireBase64:     string,
    ): Promise<Uint8Array> {
        const wire = Buffer.from(wireBase64, 'base64')
        const parsed = parseChannelWire(new Uint8Array(
            wire.buffer, wire.byteOffset, wire.byteLength,
        ))

        let secret = await this.store.getSecret(conversationId, parsed.epoch)
        if (!secret) {
            // Lazy fetch. since=epoch-1 ensures the response covers the exact epoch we're missing
            // the default sinceEpoch=local_max would skip a hole below the max
            try {
                await this.installFromServer(conversationId, {
                    sinceEpoch: Math.max(-1, parsed.epoch - 1),
                })
            } catch (err) {
                this.logger?.warn(
                    {
                        conversationId, epoch: parsed.epoch,
                        err: (err as Error).message,
                    },
                    '[groups] lazy channel-key fetch failed',
                )
            }
            secret = await this.store.getSecret(conversationId, parsed.epoch)
        }
        if (!secret) {
            throw new Error(
                `[groups] no channel key for epoch ${parsed.epoch} in conv ${conversationId}`,
            )
        }
        return decryptChannelWire(secret, conversationId, parsed)
    }


    /** Drop local channel-key + group-secret state. Called on conversation_kicked */
    async forgetConversation(conversationId: number): Promise<void> {
        await this.store.drop(conversationId)
        await this.gsStore.drop(conversationId)
        this.inflightGroupSecret.delete(conversationId)
    }


    /** Send a group/channel message under the current epoch. Resolves with messageId on own-echo,
     *  rejects on an error frame or after sendTimeoutMs (default 10s)
     *
     *  Wire: plaintext -> AES-GCM under the epoch secret -> [MAGIC | epoch_BE | iv | ct+tag] -> base64 -> WS frame
     *
     *  With no local key for this conv, we install once and bail with a clear error */
    async sendMessage(
        conversationId: number,
        plaintext:      Uint8Array,
        opts:           GroupSendOptions = {},
    ): Promise<GroupSendResult> {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`sendMessage: conversationId must be a positive integer, got ${conversationId}`)
        }

        // canPost preflight. The server enforces this too, the local check turns a server-error round-trip
        // into a clean local throw. No cache means a lazy fetch, if that fails fall through and let the server decide
        let info = this.convCache.peek(conversationId)
        if (!info) {
            info = await this.convCache.load(conversationId).catch(() => null)
        }
        // A channel comment (a reply under a post, replyToId set) is open to every member regardless of canPost
        // The server bypasses the canPost gate for isChannelComment (isChannel && replyToId !== null),
        // so mirror that here. canPost only gates a top-level channel post (and, in groups, every send)
        // Key on replyToId: a comment directly under a post carries replyToId but no threadRootId,
        // so a threadRootId check would miss it
        const isChannelComment = info?.isChannel === true
            && opts.replyToId !== undefined && opts.replyToId !== null
        if (info && !info.canPost && !isChannelComment) {
            const where = info.isChannel ? 'channel' : 'group'
            throw new Error(
                `[groups] bot lacks post permission in ${where} ${conversationId} ` +
                `(myRole=${info.myRole}, canPost=false). Ask an admin to grant /can-post.`,
            )
        }
        // commentsEnabled gate: when the channel owner has closed comments, every comment bounces
        // Key on the same isChannelComment signal as the server (replyToId): a comment directly under a post
        // carries replyToId but no threadRootId, so a threadRootId-only check would miss it
        // (the server rejects it either way)
        if (isChannelComment && info?.commentsEnabled === false) {
            throw new Error(
                `[groups] channel ${conversationId} has comments disabled - ` +
                `cannot post a comment (replyToId=${opts.replyToId})`,
            )
        }

        // Channel-key bootstrap
        let state = await this.store.load(conversationId)
        if (!state || state.currentEpoch < 0) {
            await this.installFromServer(conversationId, { sinceEpoch: -1 })
            state = await this.store.load(conversationId)
        }
        if (!state || state.currentEpoch < 0) {
            throw new Error(
                `[groups] no channel key for conv ${conversationId} - bot may have just joined; ` +
                `wait for channel_key_rotated or ask an admin to share`,
            )
        }
        const epoch = state.currentEpoch
        const secretBase64 = state.keys[String(epoch)]
        if (!secretBase64) {
            // Only happens on corrupt local state
            throw new Error(`[groups] currentEpoch=${epoch} has no key entry in store for conv ${conversationId}`)
        }
        const secret = Buffer.from(secretBase64, 'base64')
        if (secret.byteLength !== 32) {
            throw new Error(`[groups] currentEpoch=${epoch} key is ${secret.byteLength} bytes; expected 32`)
        }
        const secretBytes = new Uint8Array(secret.buffer, secret.byteOffset, secret.byteLength)

        // Encrypt
        const wire = await encryptChannelWire(secretBytes, conversationId, epoch, plaintext)
        const ciphertextBase64 = Buffer.from(wire).toString('base64')

        // Build + send + wait for own-echo
        const fanoutId    = mintFanoutId()
        const clientMsgId = mintClientMsgId()
        const timeoutMs   = opts.sendTimeoutMs ?? 10_000

        return new Promise<GroupSendResult>((resolve, reject) => {
            const timer = setTimeout(() => {
                if (this.pendingSends.delete(fanoutId)) {
                    reject(new Error(
                        `group send timeout after ${timeoutMs}ms (conv=${conversationId})`,
                    ))
                }
            }, timeoutMs)

            this.pendingSends.set(fanoutId, {
                resolve: (messageId) => resolve({ messageId, clientMsgId, fanoutId, conversationId, epoch }),
                reject,
                timer,
                clientMsgId,
                conversationId,
            })

            const frame: Record<string, unknown> = {
                type:           'group_message',
                conversationId,
                ciphertext:     ciphertextBase64,
                messageType:    8,
                fanoutId,
                clientMsgId,
            }
            if (opts.replyToId !== undefined)         frame.replyToId         = opts.replyToId
            if (opts.replyToClientMsgId !== undefined) frame.replyToClientMsgId = opts.replyToClientMsgId
            if (opts.threadRootId !== undefined)       frame.threadRootId       = opts.threadRootId
            if (opts.fileId !== undefined)             frame.fileId             = opts.fileId
            if (opts.kind !== undefined)               frame.kind               = opts.kind
            if (opts.expiresInSeconds !== undefined)   frame.expiresInSeconds   = opts.expiresInSeconds
            if (opts.additionalFileIds !== undefined && opts.additionalFileIds.length > 0) {
                frame.additionalFileIds = opts.additionalFileIds
            }

            this.ws.send(frame)
        })
    }


    /**
     * Encrypt `plaintext` under the conversation's current channel-key epoch and return the base64 wire
     * and the epoch used. Lazy-installs the channel key if the bot just joined and has none yet
     * Used by the reaction path, a group reaction is a channel-key envelope (messageType 8) whose plaintext
     * is the JSON `{ emoji }`, like a group message body
     */
    async encryptForChannel(
        conversationId: number, plaintext: Uint8Array,
    ): Promise<{ ciphertext: string; epoch: number }> {
        let state = await this.store.load(conversationId)
        if (!state || state.currentEpoch < 0) {
            await this.installFromServer(conversationId, { sinceEpoch: -1 })
            state = await this.store.load(conversationId)
        }
        if (!state || state.currentEpoch < 0) {
            throw new Error(
                `[groups] no channel key for conv ${conversationId} - bot may have just joined; ` +
                `wait for channel_key_rotated or ask an admin to share`,
            )
        }
        const epoch = state.currentEpoch
        const secretBase64 = state.keys[String(epoch)]
        if (!secretBase64) {
            throw new Error(`[groups] currentEpoch=${epoch} has no key entry in store for conv ${conversationId}`)
        }
        const secret = Buffer.from(secretBase64, 'base64')
        if (secret.byteLength !== 32) {
            throw new Error(`[groups] currentEpoch=${epoch} key is ${secret.byteLength} bytes; expected 32`)
        }
        const secretBytes = new Uint8Array(secret.buffer, secret.byteOffset, secret.byteLength)
        const wire = await encryptChannelWire(secretBytes, conversationId, epoch, plaintext)
        return { ciphertext: Buffer.from(wire).toString('base64'), epoch }
    }


    /**
     * Mint a fresh channel-key, wrap it to every member device, POST to /channel-key/rotate,
     * install the new epoch locally
     *
     * Server allows any member to rotate, the bot's call is identical to a human admin's
     * Per-device wrap failures (no SPK, bundle fetch fails) are skipped,
     * those devices pick up the new epoch later via /channel-key
     *
     * If the bot has the current group_secret it also attaches a sealed-to-group-secret bundle,
     * so new joiners can unwrap the new epoch through the bundle path. predictedEpoch is localMax+1,
     * if the server's actual epoch differs the receiver's inner check throws and the bundle is ignored
     */
    async rotateChannelKey(conversationId: number): Promise<{ epoch: number }> {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`rotateChannelKey: bad conversationId ${conversationId}`)
        }

        // Members + devices. Server filters to devices with an SPK
        const devsRes = await this.http.get<{
            devices: Record<string, Array<{ deviceId: number }>>
        }>(`/conversations/${conversationId}/peer-devices`)
        const devicesMap = devsRes.data?.devices ?? {}

        type Target = { userId: number; deviceId: number }
        const targets: Target[] = []
        for (const [uidStr, devs] of Object.entries(devicesMap)) {
            const uid = parseInt(uidStr, 10)
            if (!Number.isInteger(uid)) continue
            for (const d of devs) {
                if (typeof d?.deviceId !== 'number') continue
                if (uid === this.botUserId && d.deviceId === 1) continue   // skip self
                targets.push({ userId: uid, deviceId: d.deviceId })
            }
        }

        // Fresh 32-byte secret
        const rawBuf = randomBytes(32)
        const rawBytes = new Uint8Array(rawBuf.buffer, rawBuf.byteOffset, rawBuf.byteLength)
        const keyBase64 = rawBuf.toString('base64')

        // Per-device Signal envelopes under withPeerLock,
        // concurrent DM traffic with a member can't race the ratchet write
        interface Dist {
            recipientId:       number
            recipientDeviceId: number
            encryptedKey:      string
            messageType:       number
        }
        const distributions: Dist[] = []
        const keyPlaintext = new TextEncoder().encode(keyBase64)

        for (const t of targets) {
            try {
                const env = await this.signal.withPeerLock(t.userId, t.deviceId, async () => {
                    if (!(await this.signal.hasOpenSession(t.userId, t.deviceId))) {
                        const bundle = await this.http.get<unknown>(
                            `/prekeys/${t.userId}/${t.deviceId}`,
                        )
                        await this.signal.processPreKeyBundle(bundle.data as Parameters<SignalEngine['processPreKeyBundle']>[0])
                    }
                    return this.signal.encrypt(t.userId, t.deviceId, keyPlaintext)
                })
                if (env.type !== 1 && env.type !== 3) {
                    this.logger?.warn(
                        { target: t, messageType: env.type },
                        '[groups] rotate: signal envelope produced unexpected type, skipping device',
                    )
                    continue
                }
                distributions.push({
                    recipientId:       t.userId,
                    recipientDeviceId: t.deviceId,
                    encryptedKey:      env.body,
                    messageType:       env.type,
                })
            } catch (err) {
                this.logger?.warn(
                    {
                        target: t,
                        err: (err as Error).message,
                    },
                    '[groups] rotate: per-device wrap failed, skipping',
                )
            }
        }

        // Best-effort sealed-to-group-secret bundle. Skip when there's no local group_secret,
        // the server tolerates absence. predictedEpoch = localMax + 1, binds the new epoch into the seal
        // so a relabel on the wire fails on unseal
        interface RotatePayload {
            distributions:          Dist[]
            sealedToGroupSecret?:   string
            sealedToGroupSecretIv?: string
            groupSecretVersion?:    number
        }
        const rotatePayload: RotatePayload = { distributions }
        try {
            const gsState = await this.gsStore.load(conversationId)
            if (gsState && gsState.currentVersion >= 0) {
                const bestVersion = gsState.currentVersion
                const bestSecret  = await this.gsStore.getSecret(conversationId, bestVersion)
                if (bestSecret) {
                    const state = await this.store.load(conversationId)
                    const localMax = state?.currentEpoch ?? -1
                    const predictedEpoch = Math.max(0, localMax + 1)
                    const sealed = await sealEpochKey({
                        epochKey:       rawBytes,
                        groupSecret:    bestSecret,
                        conversationId,
                        version:        bestVersion,
                        predictedEpoch,
                    })
                    rotatePayload.sealedToGroupSecret   = sealed.ciphertext
                    rotatePayload.sealedToGroupSecretIv = sealed.iv
                    rotatePayload.groupSecretVersion    = bestVersion
                }
            }
        } catch (err) {
            // Sealing is opportunistic, per-device wraps still cover every wrappable member if this throws
            this.logger?.warn(
                { conversationId, err: (err as Error).message },
                '[groups] rotate: sealing under group_secret failed (continuing without bundle)',
            )
        }

        // POST. Server picks the epoch, we store locally under it
        const res = await this.http.post<{ success: boolean; epoch: number }>(
            `/groups/${conversationId}/channel-key/rotate`,
            rotatePayload,
        )
        const epoch = res.data?.epoch
        if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 0) {
            throw new Error(`[groups] rotate: server returned malformed epoch ${epoch}`)
        }

        // Install under the server-confirmed epoch
        await this.store.mergeEpochs(conversationId, [{ epoch, secretBase64: keyBase64 }])
        this.logger?.info(
            {
                conversationId, epoch,
                wraps:   distributions.length,
                skipped: targets.length - distributions.length,
                sealed:  rotatePayload.sealedToGroupSecret !== undefined,
            },
            '[groups] channel key rotated',
        )

        // Zero the raw bytes, the base64 in the store is the only persistent reference now
        rawBytes.fill(0)
        return { epoch }
    }


    /**
     * Atomic dual rotation: new group_secret v(N+1) plus a new channel-key epoch sealed under v(N+1),
     * in one server transaction. Per-device Signal wraps to every member plus a sealed bundle,
     * so new joiners can unseal even if every wrapping device goes offline
     *
     * Forward secrecy: after kicking a leaker, a rotate ensures the old group_secret can't unseal any future bundle
     *
     * Server constraints:
     *   - conv type must be GROUP
     *   - conv must be private or the caller must be owner (otherwise 409 NOT_PRIVATE)
     *   - stale expectedCurrentVersion -> 409 SECRET_VERSION_STALE
     *
     * 409 SECRET_VERSION_STALE auto-retry: refresh and retry once, a second stale bubbles to the caller
     * The retry is bounded, so concurrent rotators can't loop forever
     */
    async rotateGroupSecret(conversationId: number): Promise<{ epoch: number; version: number }> {
        try {
            return await this.rotateGroupSecretOnce(conversationId)
        } catch (err) {
            // Stale race: another member rotated. Refresh + retry once. Other codes bubble unchanged
            const code = (err as { response?: { data?: { code?: string } } })?.response?.data?.code
            if (code !== 'SECRET_VERSION_STALE') throw err
            this.logger?.warn(
                { conversationId },
                '[groups] rotateGroupSecret stale, refreshing and retrying once',
            )
            await this.installGroupSecret(conversationId)
            return await this.rotateGroupSecretOnce(conversationId)
        }
    }


    private async rotateGroupSecretOnce(conversationId: number): Promise<{ epoch: number; version: number }> {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`rotateGroupSecret: bad conversationId ${conversationId}`)
        }

        // Need current group_secret version for the CAS check
        let state = await this.gsStore.load(conversationId)
        if (!state || state.currentVersion < 0) {
            await this.installGroupSecret(conversationId)
            state = await this.gsStore.load(conversationId)
        }
        if (!state || state.currentVersion < 0) {
            throw new Error(
                `[groups] rotateGroupSecret: no current group_secret known for conv ${conversationId} - bot may have just joined; wait for installGroupSecret to settle`,
            )
        }
        const expectedCurrentVersion = state.currentVersion

        // Members + devices
        const devsRes = await this.http.get<{
            devices: Record<string, Array<{ deviceId: number }>>
        }>(`/conversations/${conversationId}/peer-devices`)
        const devicesMap = devsRes.data?.devices ?? {}
        type Target = { userId: number; deviceId: number }
        const targets: Target[] = []
        for (const [uidStr, devs] of Object.entries(devicesMap)) {
            const uid = parseInt(uidStr, 10)
            if (!Number.isInteger(uid)) continue
            for (const d of devs) {
                if (typeof d?.deviceId !== 'number') continue
                if (uid === this.botUserId && d.deviceId === 1) continue
                targets.push({ userId: uid, deviceId: d.deviceId })
            }
        }

        // Mint both new secrets
        const newSecretBuf = randomBytes(32)
        const newSecretBytes = new Uint8Array(
            newSecretBuf.buffer, newSecretBuf.byteOffset, newSecretBuf.byteLength,
        )
        const newSecretBase64 = newSecretBuf.toString('base64')

        const newChanKeyBuf = randomBytes(32)
        const newChanKeyBytes = new Uint8Array(
            newChanKeyBuf.buffer, newChanKeyBuf.byteOffset, newChanKeyBuf.byteLength,
        )
        const newChanKeyBase64 = newChanKeyBuf.toString('base64')

        // Double-wrap (group_secret + channel_key) per target under one withPeerLock
        // so the two sequential ratchet steps don't race a concurrent DM
        interface SecretWrap {
            recipientUserId:   number
            recipientDeviceId: number
            encryptedSecret:   string
            messageType:       number
        }
        interface CkDist {
            recipientId:       number
            recipientDeviceId: number
            encryptedKey:      string
            messageType:       number
        }
        const secretWraps:          SecretWrap[] = []
        const channelKeyDistributions: CkDist[]  = []
        const secretPlaintext  = new TextEncoder().encode(newSecretBase64)
        const chanKeyPlaintext = new TextEncoder().encode(newChanKeyBase64)

        for (const t of targets) {
            try {
                const wraps = await this.signal.withPeerLock(t.userId, t.deviceId, async () => {
                    if (!(await this.signal.hasOpenSession(t.userId, t.deviceId))) {
                        const bundle = await this.http.get<unknown>(
                            `/prekeys/${t.userId}/${t.deviceId}`,
                        )
                        await this.signal.processPreKeyBundle(
                            bundle.data as Parameters<SignalEngine['processPreKeyBundle']>[0],
                        )
                    }
                    // Two sequential encrypts under the same lock so the ratchet steps deterministically,
                    // the recipient unwraps in arrival order
                    const sEnv  = await this.signal.encrypt(t.userId, t.deviceId, secretPlaintext)
                    const ckEnv = await this.signal.encrypt(t.userId, t.deviceId, chanKeyPlaintext)
                    return { sEnv, ckEnv }
                })
                if ((wraps.sEnv.type !== 1 && wraps.sEnv.type !== 3)
                    || (wraps.ckEnv.type !== 1 && wraps.ckEnv.type !== 3)) {
                    this.logger?.warn(
                        { target: t, sType: wraps.sEnv.type, ckType: wraps.ckEnv.type },
                        '[groups] rotateGroupSecret: unexpected envelope type, skipping device',
                    )
                    continue
                }
                secretWraps.push({
                    recipientUserId:   t.userId,
                    recipientDeviceId: t.deviceId,
                    encryptedSecret:   wraps.sEnv.body,
                    messageType:       wraps.sEnv.type,
                })
                channelKeyDistributions.push({
                    recipientId:       t.userId,
                    recipientDeviceId: t.deviceId,
                    encryptedKey:      wraps.ckEnv.body,
                    messageType:       wraps.ckEnv.type,
                })
            } catch (err) {
                this.logger?.warn(
                    { target: t, err: (err as Error).message },
                    '[groups] rotateGroupSecret: per-device wrap failed, skipping',
                )
            }
        }

        // Seal the new channel_key under the new group_secret at the predicted version (expectedCurrentVersion + 1)
        const newVersion     = expectedCurrentVersion + 1
        const ckState        = await this.store.load(conversationId)
        const predictedEpoch = Math.max(0, (ckState?.currentEpoch ?? -1) + 1)
        const sealed = await sealEpochKey({
            epochKey:       newChanKeyBytes,
            groupSecret:    newSecretBytes,
            conversationId,
            version:        newVersion,
            predictedEpoch,
        })

        // Re-seal every locally-known historical epoch under the new group_secret
        // so a leaker holding the old secret loses bundle-unwrap access to past epochs too
        // The server swaps the historical sealed_to_group_secret columns atomically
        // Hard cap iteration at 10_000 against corrupt local state
        interface HistoricalReseal {
            epoch:                 number
            sealedToGroupSecret:   string
            sealedToGroupSecretIv: string
        }
        const resealHistorical: HistoricalReseal[] = []
        const HISTORY_CAP = 10_000
        if (ckState) {
            const epochs = Object.keys(ckState.keys)
                .map(s => parseInt(s, 10))
                .filter(n => Number.isInteger(n) && n >= 0)
                .sort((a, b) => a - b)
                .slice(0, HISTORY_CAP)
            for (const e of epochs) {
                const raw = await this.store.getSecret(conversationId, e)
                if (!raw) continue
                try {
                    const oneSealed = await sealEpochKey({
                        epochKey:       raw,
                        groupSecret:    newSecretBytes,
                        conversationId,
                        version:        newVersion,
                        predictedEpoch: e,  // historical epoch, already known
                    })
                    resealHistorical.push({
                        epoch:                 e,
                        sealedToGroupSecret:   oneSealed.ciphertext,
                        sealedToGroupSecretIv: oneSealed.iv,
                    })
                } catch (err) {
                    // Skip a bad reseal, rotation proceeds. The un-resealed epoch keeps its old sealed bundle
                    this.logger?.warn(
                        { conversationId, epoch: e, err: (err as Error).message },
                        '[groups] rotateGroupSecret: per-epoch reseal failed, skipping',
                    )
                }
            }
        }

        // POST. Server CAS-checks expectedCurrentVersion, enforces dist-match, swaps sealed columns atomically
        const res = await this.http.post<{
            success: boolean
            epoch:   number
            version: number
        }>(`/groups/${conversationId}/group-secret/rotate`, {
            expectedCurrentVersion,
            secretWraps,
            channelKeyDistributions,
            sealedToGroupSecret:   sealed.ciphertext,
            sealedToGroupSecretIv: sealed.iv,
            ...(resealHistorical.length > 0 ? { resealHistorical } : {}),
        })
        const epoch   = res.data?.epoch
        const version = res.data?.version
        if (typeof epoch   !== 'number' || !Number.isInteger(epoch)   || epoch   < 0
            || typeof version !== 'number' || !Number.isInteger(version) || version < 1) {
            throw new Error(
                `[groups] rotateGroupSecret: server returned malformed response (epoch=${epoch}, version=${version})`,
            )
        }

        // Install both under the server-echoed numbers
        await this.gsStore.mergeVersions(conversationId, [
            { version, secretBase64: newSecretBase64 },
        ])
        await this.store.mergeEpochs(conversationId, [
            { epoch, secretBase64: newChanKeyBase64 },
        ])

        this.logger?.info(
            {
                conversationId, epoch, version,
                wraps:    secretWraps.length,
                skipped:  targets.length - secretWraps.length,
                resealed: resealHistorical.length,
            },
            '[groups] group_secret + channel_key rotated atomically',
        )

        // Zero raw bytes. Every sealEpochKey call above was awaited,
        // so no half-done seal sees the zeros (we pass newSecretBytes by reference into the seal helper)
        newSecretBytes.fill(0)
        newChanKeyBytes.fill(0)
        return { epoch, version }
    }


    /** Share locally-known epochs with another member's devices,
     *  useful when the bot is the only online member at the time of a join
     *
     *  Server runs a possess-epoch check and a joined_secret_version cut-off so the bot can't leak pre-join history
     *
     *  Chunked at 500 distributions per POST (matches FE). One device * one epoch = one distribution */
    async backfillChannelKeys(
        conversationId: number,
        target:         { userId: number; deviceIds?: number[] },
        opts:           { epochs?: number[] } = {},
    ): Promise<{ accepted: number }> {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`backfillChannelKeys: bad conversationId ${conversationId}`)
        }
        if (!Number.isInteger(target.userId) || target.userId < 1) {
            throw new Error(`backfillChannelKeys: bad target.userId ${target.userId}`)
        }
        if (target.userId === this.botUserId) {
            throw new Error('backfillChannelKeys: cannot backfill to self - use /channel-key sibling-share for own devices')
        }

        // Resolve target's devices if no explicit list passed
        let deviceIds: number[]
        if (Array.isArray(target.deviceIds) && target.deviceIds.length > 0) {
            deviceIds = target.deviceIds.filter(d => Number.isInteger(d) && d >= 1)
        } else {
            const res = await this.http.get<{ deviceIds: number[] }>(
                `/prekeys/${target.userId}/devices`,
            )
            deviceIds = Array.isArray(res.data?.deviceIds) ? res.data.deviceIds : []
        }
        if (deviceIds.length === 0) {
            this.logger?.warn(
                { conversationId, targetUserId: target.userId },
                '[groups] backfill: target has no addressable devices',
            )
            return { accepted: 0 }
        }

        // Default to all local epochs, caller can narrow via opts
        const state = await this.store.load(conversationId)
        if (!state) {
            this.logger?.warn(
                { conversationId },
                '[groups] backfill: no local channel-key state - nothing to share',
            )
            return { accepted: 0 }
        }
        const known = Object.keys(state.keys).map(s => parseInt(s, 10)).filter(Number.isInteger)
        const epochs = Array.isArray(opts.epochs)
            ? opts.epochs.filter(e => Number.isInteger(e) && e >= 0 && known.includes(e))
            : known
        if (epochs.length === 0) return { accepted: 0 }

        interface Dist {
            recipientId:       number
            recipientDeviceId: number
            encryptedKey:      string
            messageType:       number
            epoch:             number
        }
        const distributions: Dist[] = []
        for (const epoch of epochs) {
            const keyBase64 = state.keys[String(epoch)]
            if (!keyBase64) continue
            const keyPlaintext = new TextEncoder().encode(keyBase64)
            for (const deviceId of deviceIds) {
                try {
                    const env = await this.signal.withPeerLock(target.userId, deviceId, async () => {
                        if (!(await this.signal.hasOpenSession(target.userId, deviceId))) {
                            const bundle = await this.http.get<unknown>(
                                `/prekeys/${target.userId}/${deviceId}`,
                            )
                            await this.signal.processPreKeyBundle(
                                bundle.data as Parameters<SignalEngine['processPreKeyBundle']>[0],
                            )
                        }
                        return this.signal.encrypt(target.userId, deviceId, keyPlaintext)
                    })
                    if (env.type !== 1 && env.type !== 3) {
                        this.logger?.warn(
                            { target: { userId: target.userId, deviceId }, epoch, messageType: env.type },
                            '[groups] backfill: unexpected envelope type, skipping',
                        )
                        continue
                    }
                    distributions.push({
                        recipientId:       target.userId,
                        recipientDeviceId: deviceId,
                        encryptedKey:      env.body,
                        messageType:       env.type,
                        epoch,
                    })
                } catch (err) {
                    // Skip per-wrap failure, other devices/epochs still go
                    // The skipped entry catches up later when the target's prekeys land
                    this.logger?.warn(
                        {
                            target: { userId: target.userId, deviceId }, epoch,
                            err: (err as Error).message,
                        },
                        '[groups] backfill: per-wrap failure, skipping',
                    )
                }
            }
        }
        if (distributions.length === 0) return { accepted: 0 }

        // Chunk POSTs. 500 distributions per request mirrors FE (frontend/src/signal/channel.ts:BACKFILL_CHUNK_SIZE)
        const BACKFILL_CHUNK_SIZE = 500
        let totalAccepted = 0
        for (let i = 0; i < distributions.length; i += BACKFILL_CHUNK_SIZE) {
            const chunk = distributions.slice(i, i + BACKFILL_CHUNK_SIZE)
            try {
                const res = await this.http.post<{ success: boolean; acceptedCount?: number; count?: number }>(
                    `/groups/${conversationId}/channel-key/backfill`,
                    { distributions: chunk },
                )
                // Server returns acceptedCount (or count alias on older builds)
                // If neither is present, treat as 0 accepted to avoid overcounting
                let accepted: number
                if (typeof res.data?.acceptedCount === 'number' && res.data.acceptedCount >= 0) {
                    accepted = res.data.acceptedCount
                } else if (typeof res.data?.count === 'number' && res.data.count >= 0) {
                    accepted = res.data.count
                } else {
                    this.logger?.warn(
                        { conversationId, targetUserId: target.userId, chunkLen: chunk.length },
                        '[groups] backfill: server response missing acceptedCount / count - treating as 0 accepted',
                    )
                    accepted = 0
                }
                totalAccepted += accepted
            } catch (err) {
                this.logger?.warn(
                    { conversationId, targetUserId: target.userId, chunkStart: i, err: (err as Error).message },
                    '[groups] backfill: chunk POST failed',
                )
                // Don't abort, other chunks may still go through
            }
        }
        this.logger?.info(
            {
                conversationId, targetUserId: target.userId,
                attempted: distributions.length, accepted: totalAccepted,
                deviceCount: deviceIds.length, epochCount: epochs.length,
            },
            '[groups] channel-key backfill complete',
        )
        return { accepted: totalAccepted }
    }


    /** Fetch and store the bot's per-device wrap of the current group_secret. After this, installFromServer
     *  can unwrap sealed-to-group-secret bundles
     *
     *  Concurrent callers share one in-flight promise. No-op if the conv has no group_secret yet,
     *  or no wrap for the bot's device */
    async installGroupSecret(conversationId: number): Promise<void> {
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`installGroupSecret: bad conversationId ${conversationId}`)
        }
        const inFlight = this.inflightGroupSecret.get(conversationId)
        if (inFlight) return inFlight
        const p = this.doInstallGroupSecret(conversationId).finally(() => {
            if (this.inflightGroupSecret.get(conversationId) === p) {
                this.inflightGroupSecret.delete(conversationId)
            }
        })
        this.inflightGroupSecret.set(conversationId, p)
        return p
    }


    private async doInstallGroupSecret(conversationId: number): Promise<void> {
        // GET /groups/:id/group-secret -> { initialized: false } or
        // { version, encryptedSecret, messageType, sharedByUserId, sharedByDeviceId }
        let body: {
            initialized?:        boolean
            version?:            number
            encryptedSecret?:    string
            messageType?:        number
            sharedByUserId?:     number
            sharedByDeviceId?:   number
        }
        try {
            const res = await this.http.get<typeof body>(`/groups/${conversationId}/group-secret`)
            body = res.data ?? {}
        } catch (err) {
            this.logger?.warn(
                { conversationId, err: (err as Error).message },
                '[groups] /group-secret fetch failed',
            )
            return
        }
        if (body.initialized === false) {
            this.logger?.debug({ conversationId }, '[groups] conv has no group_secret yet - skipping')
            return
        }
        if (typeof body.version !== 'number'
            || typeof body.encryptedSecret !== 'string'
            || (body.messageType !== 1 && body.messageType !== 3)
            || typeof body.sharedByUserId !== 'number'
            || typeof body.sharedByDeviceId !== 'number') {
            this.logger?.warn({ conversationId, body }, '[groups] /group-secret malformed body')
            return
        }
        const version       = body.version
        const sharerId      = body.sharedByUserId
        const sharerDevice  = body.sharedByDeviceId
        const messageType   = body.messageType
        const encryptedKey  = body.encryptedSecret

        let plaintext: Uint8Array
        try {
            plaintext = await this.signal.withPeerLock(
                sharerId, sharerDevice,
                () => this.signal.decrypt(sharerId, sharerDevice, messageType, encryptedKey),
            )
        } catch (err) {
            this.logger?.warn(
                {
                    conversationId, version, sharerId, sharerDevice, messageType,
                    err: (err as Error).message,
                },
                '[groups] group_secret envelope decrypt failed',
            )
            return
        }

        // Plaintext is base64 of the raw secret, same encoding FE uses (channel-key wraps go through the same path)
        const secretBase64 = new TextDecoder('utf-8', { fatal: false })
            .decode(plaintext)
            .trim()
        const raw = Buffer.from(secretBase64, 'base64')
        if (raw.byteLength !== GROUP_SECRET_BYTES) {
            this.logger?.warn(
                { conversationId, version, gotBytes: raw.byteLength },
                `[groups] unwrapped group_secret has wrong length; expected ${GROUP_SECRET_BYTES}`,
            )
            return
        }
        await this.gsStore.mergeVersions(conversationId, [{ version, secretBase64 }])
        this.logger?.info(
            { conversationId, version },
            '[groups] installed group_secret',
        )
    }


    /** Fail in-flight sends after a transient disconnect with an uncertain result */
    private failPendingUncertain(): void {
        for (const [, p] of this.pendingSends) {
            clearTimeout(p.timer)
            p.reject(new SendUncertainError(
                'group send interrupted by a disconnect before the server confirmed',
                p.clientMsgId, p.conversationId,
            ))
        }
        this.pendingSends.clear()
    }


    /** Reject pending sends and drop backfill refs */
    shutdown(): void {
        for (const [fanoutId, p] of this.pendingSends) {
            clearTimeout(p.timer)
            p.reject(new Error(`group send aborted: SDK shutting down (fanoutId=${fanoutId})`))
        }
        this.pendingSends.clear()
        // No AbortController on backfill promises yet, we just drop refs so GroupsFlow can GC and stop() doesn't wait
        this.inflightBackfills.clear()
    }


    /** Register a fire-and-forget backfill. Called from ReceiveFlow's auto-backfill path */
    trackBackfill(p: Promise<unknown>): void {
        this.inflightBackfills.add(p)
        p.finally(() => { this.inflightBackfills.delete(p) }).catch(() => {})
    }


    // WS frame demux for own-echo / error resolution

    private onFrame(frame: IncomingFrame): void {
        const fanoutId = frame.fanoutId
        if (typeof fanoutId !== 'string') return
        const pending = this.pendingSends.get(fanoutId)
        if (!pending) return

        clearTimeout(pending.timer)
        this.pendingSends.delete(fanoutId)

        if (frame.type === 'error') {
            const msg = typeof frame.message === 'string'
                ? frame.message
                : typeof frame.code === 'string'
                    ? frame.code
                    : 'group send rejected by server'
            const codeStr = typeof frame.code === 'string' ? ` (code=${frame.code})` : ''
            // Typed like the DM path (direct.ts) so a caller can branch on `.code`
            // (e.g. recipient_storage_full on a group/channel file send) without string-matching the message,
            // and so instanceof SendRejectedError works for group sends too
            pending.reject(new SendRejectedError(
                `group send rejected: ${msg}${codeStr}`,
                typeof frame.code === 'string' ? frame.code : undefined,
            ))
            return
        }

        // Both DM and group own-echo arrive as type:'message', the messageType discriminates, we expect 8 for groups
        if (frame.type === 'message') {
            if (frame.messageType !== 8) {
                // 1-in-2^96 fanoutId collision with a DM send. Treat as a server bug and reject
                pending.reject(new Error(
                    `unexpected messageType ${frame.messageType} on own-echo (expected 8)`,
                ))
                return
            }
            const id = typeof frame.id === 'number' ? frame.id : null
            if (id === null) {
                pending.reject(new Error('group own-echo missing message id'))
                return
            }
            pending.resolve(id)
            return
        }

        pending.reject(new Error(`unexpected frame type "${frame.type}" for fanoutId ${fanoutId}`))
    }
}
