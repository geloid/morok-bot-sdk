// noinspection JSUnusedGlobalSymbols

/**
 * Public orchestrator. Use MorokBot.fromFile(...) to construct
 * The ctor is private because .morokbot parsing and state-dir setup need IO
 *
 * Lifecycle:
 *   fromFile: parse .morokbot, build modules (no network IO)
 *   start(): import keys, fsck state, /auth/bot-session, WS handshake, prekey replenish + background loop
 *   stop(): prekey loop -> ws -> pending sends -> done
 *
 * `error` fires on recoverable failures (decrypt errors, exceptions thrown by developer handlers)
 * start() itself throws on fatal init errors (bad .morokbot, 401, etc.)
 */

import { EventEmitter }         from 'node:events'

import type {
    BotConfig, MorokbotFile,
    IncomingMessage, CommandInvocation,
    BotStartEvent, BotStopEvent, ReactionEvent, ControlEvent, BotControl,
    ConversationAddedEvent, ConversationKickedEvent,
    DisconnectInfo, SdkLogger,
    AttachmentInput,
} from './types.js'
import { readMorokbotFile }     from './morokbot-file.js'
import { FileSignalStore }      from './crypto/stores.js'
import { SignalEngine }         from './crypto/signal.js'
import { signDeviceCert }       from './crypto/cross-signing.js'
import { ChannelKeyStore }      from './crypto/channel-key-store.js'
import { GroupSecretStore }     from './crypto/group-secret-store.js'
import { StateLock }            from './state-lock.js'
import { HttpClient }           from './transport/http.js'
import { WsClient }             from './transport/ws.js'
import { DirectFlow, type SendResult, uploadAndBuildPayload, uploadGalleryAndBuildPayload } from './flow/direct.js'
import { ReceiveFlow }          from './flow/receive.js'
import { GroupsFlow }           from './flow/groups.js'
import { ConvCache }            from './flow/conv-cache.js'
import { PreKeyManager }        from './flow/prekeys.js'


// Send arguments (public)

export interface SendArgs {
    /**
     * DM target, numeric userId or username (the SDK resolves a username via `GET /users/:username`)
     * Mutually exclusive with `conversation`
     */
    peer?:               number | string
    /**
     * Group-chat / channel target, numeric conversationId. Mutually exclusive with `peer`
     * The bot must already be a member, obtain `conversationId` from a `conversation_added` event,
     * or from an incoming `IncomingMessage.conversationId` when responding to one
     */
    conversation?:       number
    /**
     * Message text. Required when `attachment` is absent
     * Sent alongside a `'file'` attachment, it becomes the caption
     * Ignored (with a debug log) for `'voice'` and `'video_note'` attachments,
     * the FE renderer has no caption slot for those
     */
    text?:              string
    /**
     * Single attachment (file / voice / video_note). Mutually exclusive with `attachments`
     */
    attachment?:        AttachmentInput
    /**
     * Gallery of 2-10 file attachments shipped in one message, the bubble renders as a grid on the FE
     * voice and video_note are not allowed in a gallery
     * (server caps and FE renderer both expect `kind: 'file'` per item). Mutually exclusive with `attachment`
     */
    attachments?:       AttachmentInput[]
    replyToId?:         number
    replyToClientMsgId?: string
    threadRootId?:      number
    /** Disappearing-message TTL in seconds. Server-validated */
    expiresInSeconds?:  number
}

export interface ReplyArgs {
    text?:              string
    attachment?:        AttachmentInput
    attachments?:       AttachmentInput[]
    expiresInSeconds?:  number
}


interface MorokBotEvents {
    message:             (msg: IncomingMessage) => void | Promise<void>
    command:             (cmd: CommandInvocation) => void | Promise<void>
    start:               (e:   BotStartEvent) => void | Promise<void>
    stop:                (e:   BotStopEvent) => void | Promise<void>
    reaction:            (e:   ReactionEvent) => void | Promise<void>
    control:             (e:   ControlEvent) => void | Promise<void>
    conversation_added:  (e:   ConversationAddedEvent) => void | Promise<void>
    conversation_kicked: (e:   ConversationKickedEvent) => void | Promise<void>
    disconnect:          (info: DisconnectInfo) => void | Promise<void>
    error:               (err: Error) => void | Promise<void>
}


// Helpers

function deriveWsUrl(apiBaseUrl: string, wsUrl?: string): string {
    if (wsUrl) return wsUrl
    // app.morok.me/ws, same host, /ws path, swap scheme
    return apiBaseUrl
        .replace(/^http:/i,  'ws:')
        .replace(/^https:/i, 'wss:')
        .replace(/\/+$/,     '')
        + '/ws'
}

function isUsername(s: unknown): s is string {
    return typeof s === 'string' && s.length > 0
}


// MorokBot

export class MorokBot extends EventEmitter {
    private readonly file:      MorokbotFile
    private readonly stateDir:  string
    private readonly apiBaseUrl: string
    private readonly wsUrlVal:  string
    private readonly logger?:   SdkLogger
    private readonly bgIntervalMs:       number
    private readonly replenishThreshold: number
    private readonly replenishTarget:    number
    private readonly autoBackfillOnJoin: boolean
    private readonly serveBackfillRequests: boolean

    private signal?:   SignalEngine
    private http?:     HttpClient
    private ws?:       WsClient
    private direct?:   DirectFlow
    private receive?:  ReceiveFlow
    private groups?:   GroupsFlow
    private chanStore?: ChannelKeyStore
    private gsStore?:   GroupSecretStore
    private convCache?: ConvCache
    private stateLock?: StateLock
    private prekey?:   PreKeyManager

    private botUserId?: number
    private running   = false
    /** Set true synchronously when start() enters, before any await, so a second concurrent start() returns
     *  without opening a second WS. Separate from `running` so isConnected stays accurate during boot */
    private starting  = false
    /** Flipped by stop() while start() is mid-flight. start() checks it at every checkpoint,
     *  and throws into its own catch so teardown runs and nothing is left open */
    private stopRequested = false


    private constructor(file: MorokbotFile, config: BotConfig) {
        super()
        this.file     = file
        this.stateDir          = config.stateDir          ?? './bot-state'
        this.apiBaseUrl        = config.apiBaseUrl        ?? 'https://app.morok.me'
        this.wsUrlVal          = deriveWsUrl(this.apiBaseUrl, config.wsUrl)
        // A popular bot's OTPK pool is drained by every new peer's first contact (server-capped at 120/min/target),
        // so a low or infrequent top-up leaves the pool empty and forces peers onto SPK-only X3DH
        // Threshold 100 matches the server's low-water floor (so the reactive `prekeys_low` nudge actually mints),
        // target 200 is the server per-call cap, and the 5-min tick backstops the reactive signal
        this.replenishThreshold = config.replenishThreshold   ?? 100
        this.replenishTarget    = config.replenishTarget      ?? 200
        this.bgIntervalMs       = config.backgroundIntervalMs ?? 5 * 60 * 1000
        this.autoBackfillOnJoin = config.autoBackfillOnJoin   ?? false
        this.serveBackfillRequests = config.serveBackfillRequests ?? false
        if (config.logger !== undefined) this.logger = config.logger

        // Default 'error' listener so an unhandled error doesn't kill the process (Node's EventEmitter throws otherwise)
        // The developer's own listener still fires first
        this.on('error', (err) => {
            this.logger?.warn({ err: (err as Error).message }, '[bot] unhandled error event')
        })
    }


    /** Read + validate the .morokbot file and build the bot. No network IO, call start() to connect */
    static async fromFile(config: BotConfig & { tokenFile: string }): Promise<MorokBot> {
        if (!config.tokenFile) {
            throw new Error('MorokBot.fromFile: tokenFile is required')
        }
        const file = await readMorokbotFile(config.tokenFile, config.logger)
        return new MorokBot(file, config)
    }


    // Lifecycle

    /** Connect. Resolves after WS auth + boot prekey replenish. Throws on fatal init errors. Idempotent */
    async start(): Promise<void> {
        if (this.running || this.starting) return
        this.starting = true
        this.stopRequested = false
        const checkpoint = (where: string): void => {
            if (this.stopRequested) {
                throw new Error(`MorokBot.start: aborted at ${where} - stop() called during boot`)
            }
        }
        try {
            // Cross-process lock. Acquired before touching any other state so a refused acquire leaves disk untouched
            const stateLock = new StateLock(this.stateDir, this.logger)
            await stateLock.acquire()
            this.stateLock = stateLock
            checkpoint('stateLock.acquire')

            // Stores: import key material, fsck the on-disk state
            const store = new FileSignalStore(this.stateDir)
            await store.ensureLayout()
            checkpoint('ensureLayout')
            await store.importInitial({
                botUserId:        this.file.botUserId,
                registrationId:   this.file.registrationId,
                deviceId:         1,
                identityKeyPair:  this.file.identityKey,
                accountSigningKey: this.file.accountSigningKey,
                signedPreKey: {
                    keyId:     this.file.signedPreKey.keyId,
                    pub:       this.file.signedPreKey.pub,
                    priv:      this.file.signedPreKey.priv,
                    signature: this.file.signedPreKey.signature,
                },
                oneTimePreKeys: this.file.oneTimePreKeys.map(o => ({
                    keyId: o.keyId, pub: o.pub, priv: o.priv,
                })),
            })
            checkpoint('importInitial')
            const fsck = await store.fsck()
            checkpoint('fsck')
            if (fsck.quarantinedSessions.length + fsck.quarantinedPreKeys.length > 0) {
                this.logger?.warn(
                    { sessions: fsck.quarantinedSessions, preKeys: fsck.quarantinedPreKeys },
                    '[bot] fsck quarantined corrupted state files',
                )
            }
            this.signal = new SignalEngine(store, this.logger)

            // HTTP: /auth/bot-session
            this.http = new HttpClient({
                apiBaseUrl: this.apiBaseUrl,
                botToken:   this.file.token,
                ...(this.logger !== undefined ? { logger: this.logger } : {}),
            })
            const session = await this.http.initialMint()
            checkpoint('initialMint')
            this.botUserId = session.userId
            // The .morokbot's botUserId must match the resolved userId,
            // a mismatch means a tampered file or a wizard bug
            // We'd encrypt under one identity but call ourselves another, breaking peer TOFU caches
            this.assertResolvedUserId(session.userId)

            // WS: open + handshake
            const ws = new WsClient({
                wsUrl:    this.wsUrlVal,
                deviceId: 1,
                getJwt:   () => this.http!.getJwt(),
                refreshJwt: async () => { await this.http!.refresh() },
                ...(this.logger !== undefined ? { logger: this.logger } : {}),
            })
            ws.on('close', (info) => {
                // 4001 means the session ticket was revoked, other codes are transport-level
                // Surface the distinction so a developer can show different copy
                let reason: 'transport' | 'auth' | 'shutdown'
                if (!info.willReconnect)        reason = 'shutdown'
                else if (info.code === 4001)    reason = 'auth'
                else                            reason = 'transport'
                this.emit('disconnect', {
                    reason,
                    code:          info.code,
                    willReconnect: info.willReconnect,
                })
            })
            ws.on('error', (err) => this.emit('error', err))
            // Assign before await: if ws.start() throws, the socket and listeners already exist,
            // and the catch path needs this.ws to call stop() and close them
            this.ws = ws
            await ws.start()
            checkpoint('ws.start')

            // Flow modules
            this.direct  = new DirectFlow(this.http, ws, this.signal, this.logger)

            // Channel-key + group-secret stores, conv-cache, groups flow
            // Built before ReceiveFlow because the receive ctor wires the group frame handlers
            this.chanStore = new ChannelKeyStore(this.stateDir, this.logger)
            await this.chanStore.init()
            checkpoint('chanStore.init')
            this.gsStore = new GroupSecretStore(this.stateDir, this.logger)
            await this.gsStore.init()
            checkpoint('gsStore.init')
            this.convCache = new ConvCache(session.userId, this.http, this.logger)
            this.groups = new GroupsFlow(
                session.userId, this.http, ws, this.signal,
                this.chanStore, this.gsStore, this.convCache, this.logger,
            )

            this.receive = new ReceiveFlow(
                session.userId, this.http, ws, this.signal,
                this.convCache,
                { emit: (e) => {
                    // Adapter from ReceiveFlow's emitter shape to the public EventEmitter surface
                    switch (e.kind) {
                        case 'message':             this.emit('message',             e.payload); break
                        case 'command':             this.emit('command',             e.payload); break
                        case 'start':               this.emit('start',               e.payload); break
                        case 'stop':                this.emit('stop',                e.payload); break
                        case 'conversation_added':  this.emit('conversation_added',  e.payload); break
                        case 'conversation_kicked': this.emit('conversation_kicked', e.payload); break
                        case 'reaction':            this.emit('reaction',            e.payload); break
                        case 'control':             this.emit('control',             e.payload); break
                        case 'error':               this.emit('error',               e.error);   break
                    }
                }},
                this.groups,
                { autoBackfillOnJoin: this.autoBackfillOnJoin, serveBackfillRequests: this.serveBackfillRequests },
                this.logger,
            )

            // PreKey loop
            this.prekey = new PreKeyManager(
                this.http, this.signal, store,
                {
                    deviceId:             1,
                    replenishThreshold:   this.replenishThreshold,
                    replenishTarget:      this.replenishTarget,
                    backgroundIntervalMs: this.bgIntervalMs,
                    ...(this.logger !== undefined ? { logger: this.logger } : {}),
                },
            )
            await this.prekey.start()
            checkpoint('prekey.start')

            // Reactive OTPK replenish: the server pushes `prekeys_low` when a peer drains this bot's pool
            // below the server floor, so we top up at once. Waiting for the background tick would otherwise
            // leave the pool empty and force peers' first contact onto SPK-only X3DH
            // PreKeyManager single-flights, so a burst of signals collapses to one replenish.
            // The WsClient instance persists across reconnects (only the raw socket reopens) and start() runs once,
            // so this listener is attached exactly once and doesn't accumulate
            ws.on('frame', (frame) => {
                if (frame.type === 'prekeys_low') {
                    this.prekey?.requestReplenish().catch(() => { /* boot/bg tick retries */ })
                }
                // Proactive JWT refresh, piggybacked on inbound traffic. needsProactiveRefresh() is true only
                // inside the skew window before expiry, and refresh() single-flights,
                // so this is cheap and can't storm. An idle bot (no frames) falls back
                // to the reactive 401 / WS-4001 refresh paths
                const http = this.http
                if (http && http.needsProactiveRefresh()) {
                    void http.refresh().catch(() => { /* reactive paths cover it */ })
                }
            })

            // Publish this device's cross-signing certificate so peers see the bot as a certified device
            // with a cross-signed safety number. Fire-and-forget and idempotent
            // The bot works without it (peers fall back to TOFU), so it must never gate readiness or fail start()
            // Captures http/userId internally against teardown
            void this.ensureCrossSigning()

            this.running = true
            this.logger?.info(
                { userId: session.userId, username: session.username },
                '[bot] ready',
            )
        } catch (err) {
            // Partial-failure cleanup: any module created before the failure point is torn down,
            // so we don't leave the WS open or the prekey loop running. Each teardown is wrapped in try/catch,
            // because the module may have never reached a state worth shutting down (e.g. ws never opened)
            try { this.prekey?.stop() } catch { /* ignore */ }
            try { this.direct?.shutdown() } catch { /* ignore */ }
            try { this.groups?.shutdown() } catch { /* ignore */ }
            try { this.ws?.stop() } catch { /* ignore */ }
            this.prekey    = undefined
            this.direct    = undefined
            this.receive   = undefined
            this.groups    = undefined
            this.chanStore = undefined
            this.gsStore   = undefined
            this.convCache = undefined
            // Release the lock so a retry can re-acquire it cleanly
            try { await this.stateLock?.release() } catch { /* ignore */ }
            this.stateLock = undefined
            this.ws        = undefined
            this.http      = undefined
            this.signal    = undefined
            this.botUserId = undefined
            throw err
        } finally {
            this.starting = false
        }
    }


    private assertResolvedUserId(resolvedUserId: number): void {
        if (resolvedUserId !== this.file.botUserId) {
            throw new Error(
                `MorokBot.start: .morokbot says botUserId=${this.file.botUserId} but ` +
                `/auth/bot-session resolved userId=${resolvedUserId} - file tampered or stateDir mismatched`,
            )
        }
    }


    /**
     * One-shot device-certificate publish (D cross-signing). Signs a certificate over this device's identity key
     * under the .morokbot account signing key (XSK) and commits it via POST /crypto/cross-signing,
     * so peers verify the bot's device against its account key and render a cross-signed safety number
     * (routes/developer.ts:556 documents this obligation)
     *
     * Best-effort and idempotent: re-submitting the same (XSK, cert) on every start succeeds server-side
     * Any failure (network, 409 XSK_ALREADY_SET / IDENTITY_ROTATED, missing XSK) is logged and non-fatal,
     * the bot keeps running uncertified while peers fall back to TOFU
     *  One device per bot, so the FE's multi-device XSK propagation races don't apply here
     *
     * Skipped silently when the .morokbot predates cross-signing (no accountSigningKey), matching the FE
     */
    private async ensureCrossSigning(): Promise<void> {
        const xsk       = this.file.accountSigningKey
        const http      = this.http
        const botUserId = this.botUserId
        if (!xsk) {
            this.logger?.debug({}, '[bot] .morokbot has no accountSigningKey - skipping cross-signing (bot stays uncertified / TOFU)')
            return
        }
        if (!http || botUserId === undefined) return

        try {
            const cert = await signDeviceCert(xsk.priv, botUserId, 1, this.file.identityKey.pub)
            // A stop() during the signing await nulls this.http,
            // while the local http still points at the closing client, so bail before the POST
            if (this.stopRequested) return
            await http.post('/crypto/cross-signing', {
                accountSigningKey: xsk.pub,
                deviceCertificate: cert,
            })
            this.logger?.info({ botUserId }, '[bot] device certificate published (cross-signing)')
        } catch (err) {
            this.logger?.warn(
                { err: (err as Error).message },
                '[bot] cross-signing publish failed; bot stays uncertified this run (peers use TOFU)',
            )
        }
    }


    /** Clean shutdown. Stops background loops, closes the socket, rejects pending sends,
     *  releases the state lock. Idempotent. If start() is mid-flight, stopRequested makes it abort
     *  at the next checkpoint into its catch path */
    async stop(): Promise<void> {
        if (!this.running && !this.starting) return
        this.stopRequested = true
        this.running = false
        try { this.prekey?.stop() } catch { /* ignore */ }
        try { this.direct?.shutdown() } catch { /* ignore */ }
        try { this.groups?.shutdown() } catch { /* ignore */ }
        try { this.ws?.stop() } catch { /* ignore */ }
        // Release the lock last so a successor bot can start immediately after stop() resolves
        try { await this.stateLock?.release() } catch { /* ignore */ }
        this.stateLock = undefined
    }

    get isConnected(): boolean {
        return this.running && (this.ws?.isConnected ?? false)
    }

    /** Bot's own userId. Available after start() resolves */
    get userId(): number {
        if (this.botUserId === undefined) {
            throw new Error('MorokBot.userId: call start() first')
        }
        return this.botUserId
    }


    // Public send API

    async send(args: SendArgs): Promise<SendResult> {
        if (!this.running || !this.direct || !this.receive || !this.http) {
            throw new Error('MorokBot.send: not started')
        }
        const hasText       = args.text !== undefined
        const hasAttachment = args.attachment !== undefined
        const hasGallery    = Array.isArray(args.attachments) && args.attachments.length > 0
        if (hasAttachment && hasGallery) {
            throw new Error('MorokBot.send: `attachment` and `attachments` are mutually exclusive')
        }
        if (!hasText && !hasAttachment && !hasGallery) {
            throw new Error('MorokBot.send: must supply at least one of `text`, `attachment`, or `attachments`')
        }
        const hasPeer  = args.peer !== undefined
        const hasGroup = args.conversation !== undefined
        if (hasPeer === hasGroup) {
            throw new Error('MorokBot.send: must supply EXACTLY ONE of `peer` (for DM) or `conversation` (for group chat or channel)')
        }

        if (hasGroup) {
            if (!this.groups) throw new Error('MorokBot.send: groups flow not wired')
            return this.sendGroup(args)
        }
        return this.sendDirect(args)
    }


    private async sendDirect(args: SendArgs): Promise<SendResult> {
        const peerUserId = await this.resolvePeerUserId(args.peer!)
        const sendOpts: {
            replyToId?:         number
            replyToClientMsgId?: string
            threadRootId?:      number
        } = {}
        if (args.replyToId !== undefined)         sendOpts.replyToId         = args.replyToId
        if (args.replyToClientMsgId !== undefined) sendOpts.replyToClientMsgId = args.replyToClientMsgId
        if (args.threadRootId !== undefined)       sendOpts.threadRootId       = args.threadRootId
        const body: { text?: string; attachment?: AttachmentInput; attachments?: AttachmentInput[] } = {}
        if (args.text !== undefined)        body.text        = args.text
        if (args.attachment !== undefined)  body.attachment  = args.attachment
        if (args.attachments !== undefined) body.attachments = args.attachments
        return this.direct!.sendMessage(peerUserId, body, sendOpts)
    }


    private async sendGroup(args: SendArgs): Promise<SendResult> {
        const conversationId = args.conversation!
        if (!Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error(`MorokBot.send: conversationId must be a positive integer, got ${conversationId}`)
        }

        // Group plaintext is UTF-8 text, or the same JSON envelope DMs use for attachments, or a gallery envelope
        const hasText       = typeof args.text === 'string' && args.text.length > 0
        const hasAttachment = args.attachment !== undefined
        const hasGallery    = Array.isArray(args.attachments) && args.attachments.length > 0
        let plaintext: Uint8Array
        let fileId:    number | undefined
        let kind:      'text' | 'file' | 'voice' | 'video_note' | 'gallery' = 'text'
        let additionalFileIds: number[] | undefined

        if (hasGallery) {
            const built = await uploadGalleryAndBuildPayload(
                this.http!, args.attachments!, hasText ? args.text : undefined, this.logger,
            )
            plaintext         = new TextEncoder().encode(built.payload)
            fileId            = built.headFileId
            kind              = 'gallery'
            additionalFileIds = built.additionalFileIds
        } else if (hasAttachment) {
            const built = await uploadAndBuildPayload(
                this.http!, args.attachment!, hasText ? args.text : undefined, this.logger,
            )
            // ref.fileId in the plaintext envelope must match frame.fileId below
            // Both come from the same source so they can't drift today,
            // a future refactor that splits them needs to keep the invariant
            plaintext = new TextEncoder().encode(built.payload)
            fileId    = built.ref.fileId
            kind      = built.kind
            if (kind !== 'file' && hasText) {
                this.logger?.warn(
                    { kind, droppedTextLen: args.text!.length },
                    '[bot] caption ignored: only kind="file" supports caption in groups',
                )
            }
        } else {
            plaintext = new TextEncoder().encode(args.text!)
        }

        const sendOpts: {
            replyToId?:          number
            replyToClientMsgId?: string
            threadRootId?:       number
            fileId?:             number
            kind?:               'text' | 'file' | 'voice' | 'video_note' | 'gallery'
            additionalFileIds?:  number[]
            expiresInSeconds?:   number
        } = { kind }
        if (args.replyToId !== undefined)         sendOpts.replyToId         = args.replyToId
        if (args.replyToClientMsgId !== undefined) sendOpts.replyToClientMsgId = args.replyToClientMsgId
        if (args.threadRootId !== undefined)       sendOpts.threadRootId       = args.threadRootId
        if (fileId !== undefined)                  sendOpts.fileId             = fileId
        if (additionalFileIds !== undefined)       sendOpts.additionalFileIds  = additionalFileIds
        if (args.expiresInSeconds !== undefined)   sendOpts.expiresInSeconds   = args.expiresInSeconds

        const res = await this.groups!.sendMessage(conversationId, plaintext, sendOpts)
        return { messageId: res.messageId, clientMsgId: res.clientMsgId, conversationId: res.conversationId }
    }


    /** Rotate the channel-key. Mints a fresh 32-byte secret, wraps it to every other member device,
     *  POSTs to /channel-key/rotate. The server allows any member,
     *  so the bot's call is functionally identical to a human admin's */
    async rotateChannelKey(conversationId: number): Promise<{ epoch: number }> {
        if (!this.running || !this.groups) {
            throw new Error('MorokBot.rotateChannelKey: not started')
        }
        return this.groups.rotateChannelKey(conversationId)
    }


    /** Share locally-known channel-key epochs with another member's devices
     *  Useful when the bot is the only online member at the moment a new joiner needs history
     *
     *  target.deviceIds optional, absent = fetch via /prekeys/:userId/devices
     *  opts.epochs optional, absent = all local epochs. Server filters pre-join epochs by joined_secret_version */
    async backfillChannelKeys(
        conversationId: number,
        target:         { userId: number; deviceIds?: number[] },
        opts:           { epochs?: number[] } = {},
    ): Promise<{ accepted: number }> {
        if (!this.running || !this.groups) {
            throw new Error('MorokBot.backfillChannelKeys: not started')
        }
        return this.groups.backfillChannelKeys(conversationId, target, opts)
    }


    /**
     * Rotate group_secret and channel-key in one server transaction
     * Run after kicking a leaker so a stale ex-member can't unseal future bundles with the old group_secret
     *
     * Server constraints (POST /groups/:id/group-secret/rotate):
     *   - conv type must be GROUP
     *   - conv must be private or the caller must be owner
     *   - bot must hold the current group_secret (auto-fetched)
     *
     * Error codes (axios error.response.data.code):
     *   SECRET_VERSION_STALE : someone else rotated, retry
     *   NOT_PRIVATE          : bot lacks permission
     *   DIST_MISMATCH        : membership shifted mid-rotate
     *   NO_READY_DEVICES     : no recipient had an SPK
     *
     * Also re-seals every locally-known historical epoch under the new group_secret (server's resealHistorical field)
     * After a rotate, no epoch is unsealable with the old secret
     * If the bot is missing some historical epochs it reseals what it has, the rest can be patched on a later rotate
     */
    async rotateGroupSecret(conversationId: number): Promise<{ epoch: number; version: number }> {
        if (!this.running || !this.groups) {
            throw new Error('MorokBot.rotateGroupSecret: not started')
        }
        return this.groups.rotateGroupSecret(conversationId)
    }


    /**
     * Replace the bot's slash-command catalogue (the /-autocomplete the composer offers users)
     * Call after start(). Defining handlers does not advertise commands, the catalogue is separate
     * Server bounds: up to 32 entries, name /^[a-z][a-z0-9_]{0,31}$/, description trimmed to 256 chars
     * An empty array clears it. Idempotent, safe to call on every start
     */
    async setMyCommands(
        commands: ReadonlyArray<{ command: string; description: string; sortOrder?: number }>,
    ): Promise<{ count: number }> {
        if (!this.running || !this.http) {
            throw new Error('MorokBot.setMyCommands: not started')
        }
        const res = await this.http.post<{ ok: boolean; count: number }>(
            '/developer/bots/self/commands',
            { commands },
        )
        return { count: typeof res.data?.count === 'number' ? res.data.count : 0 }
    }


    async setMyControls(
        controls: ReadonlyArray<BotControl>,
    ): Promise<{ count: number }> {
        if (!this.running || !this.http) {
            throw new Error('MorokBot.setMyControls: not started')
        }
        const res = await this.http.post<{ ok: boolean; count: number }>(
            '/developer/bots/self/controls',
            { controls },
        )
        return { count: typeof res.data?.count === 'number' ? res.data.count : 0 }
    }


    /**
     * Set the control buttons for ONE user's chat without touching the global menu others see
     * Use it to drive a stateful flow, for example search results as buttons or a step-by-step wizard
     * Pass the user id from an incoming message or control event (sender.userId)
     * The override is short-lived on the server and survives that user's reload
     * An empty array shows no buttons, call clearControlsFor to revert to the global menu
     * Bounds match setMyControls, up to 16 top-level and 64 total nodes and depth 4
     */
    async setControlsFor(
        peerUserId: number,
        controls: ReadonlyArray<BotControl>,
    ): Promise<{ count: number }> {
        if (!this.running || !this.http) {
            throw new Error('MorokBot.setControlsFor: not started')
        }
        const res = await this.http.post<{ ok: boolean; count: number }>(
            '/developer/bots/self/controls/conversation',
            { targetUserId: peerUserId, controls },
        )
        return { count: typeof res.data?.count === 'number' ? res.data.count : 0 }
    }


    /**
     * Drop a user's per-chat control override and revert them to the global menu set by setMyControls
     * Call this when the flow ends
     */
    async clearControlsFor(peerUserId: number): Promise<void> {
        if (!this.running || !this.http) {
            throw new Error('MorokBot.clearControlsFor: not started')
        }
        await this.http.post(
            '/developer/bots/self/controls/conversation',
            { targetUserId: peerUserId, controls: null },
        )
    }


    /** Reply to an incoming message. Threads replyToId/clientMsgId,
     *  routes DM vs group/channel by msg.conversationType */
    async reply(msg: IncomingMessage, args: ReplyArgs): Promise<SendResult> {
        if (args.text === undefined && args.attachment === undefined && args.attachments === undefined) {
            throw new Error('MorokBot.reply: must supply at least one of `text`, `attachment`, or `attachments`')
        }
        const sendArgs: SendArgs = {
            replyToId: msg.messageId,
        }
        if (msg.conversationType === 'DIRECT') {
            sendArgs.peer = msg.sender.userId
        } else {
            sendArgs.conversation = msg.conversationId
            // Channel comments thread onto the same root
            // Top-level posts have threadRootId=null and we leave it unset
            if (msg.threadRootId !== null) sendArgs.threadRootId = msg.threadRootId
        }
        if (args.text !== undefined)        sendArgs.text        = args.text
        if (args.attachment !== undefined)  sendArgs.attachment  = args.attachment
        if (args.attachments !== undefined) sendArgs.attachments = args.attachments
        if (args.expiresInSeconds !== undefined) sendArgs.expiresInSeconds = args.expiresInSeconds
        if (msg.clientMsgId !== null)            sendArgs.replyToClientMsgId = msg.clientMsgId
        return this.send(sendArgs)
    }


    /**
     * React to a message with a unicode symbol (any character, emoji included)
     * DM reactions are encrypted per peer device (Signal), group-chat/channel reactions under the shared channel-key
     * The reactor (this bot) is never echoed its own reaction back,
     * so this resolves as soon as the frame is queued, there is no own-echo to await
     * Re-reacting with a different symbol replaces the bot's previous one server-side
     *
     * `msg` is an incoming message or command. It carries messageId, conversationId,
     * conversationType and sender. In a DM the reaction is encrypted to msg.sender (the peer)
     */
    async react(msg: IncomingMessage, unicode: string): Promise<void> {
        if (!this.running || !this.ws || !this.direct || !this.groups) {
            throw new Error('MorokBot.react: not started')
        }
        if (!unicode) {
            throw new Error('MorokBot.react: unicode must be a non-empty string')
        }
        const { messageId, conversationId } = msg
        if (!Number.isInteger(messageId) || messageId < 1
            || !Number.isInteger(conversationId) || conversationId < 1) {
            throw new Error('MorokBot.react: msg must carry a valid messageId and conversationId')
        }
        // The wire key stays `emoji`, the cross-client reaction contract the FE produces and reads (send-reaction.ts)
        // The public param is `unicode` because a reaction can be any character
        const payload = JSON.stringify({ emoji: unicode })
        // Mirror the FE cap (frontend/src/lib/send-reaction.ts) so a huge string can't bloat the wire frame
        if (Buffer.byteLength(payload, 'utf8') > 256) {
            throw new Error('MorokBot.react: unicode payload exceeds 256 bytes')
        }
        const plaintext = new TextEncoder().encode(payload)

        let distributions: unknown[]
        if (msg.conversationType === 'DIRECT') {
            const dists = await this.direct.encryptReaction(msg.sender.userId, plaintext)
            if (dists.length === 0) {
                throw new Error(`MorokBot.react: could not encrypt to any device of peer ${msg.sender.userId}`)
            }
            distributions = dists
        } else {
            // GROUP / CHANNEL: one channel-key envelope shared by every member
            const { ciphertext } = await this.groups.encryptForChannel(conversationId, plaintext)
            distributions = [{ ciphertext, messageType: 8 }]
        }
        this.ws.send({ type: 'reaction_add', messageId, distributions })
    }

    /**
     * Remove this bot's reaction from a message. The server keys deletion off (messageId, reactorUserId),
     * so no ciphertext is needed. One frame clears every distribution shape the bot wrote
     */
    async unreact(msg: IncomingMessage): Promise<void> {
        if (!this.running || !this.ws) {
            throw new Error('MorokBot.unreact: not started')
        }
        const { messageId } = msg
        if (!Number.isInteger(messageId) || messageId < 1) {
            throw new Error('MorokBot.unreact: msg must carry a valid messageId')
        }
        this.ws.send({ type: 'reaction_remove', messageId })
    }


    // Internal helpers

    /** Resolve userId or username to a userId. Usernames hit GET /users/:username every time
     *  (bots usually pass userId from an incoming message, so the miss is rare) */
    private async resolvePeerUserId(ref: number | string): Promise<number> {
        if (typeof ref === 'number') {
            if (!Number.isInteger(ref) || ref < 1) {
                throw new Error(`peer userId must be a positive integer, got ${ref}`)
            }
            return ref
        }
        if (!isUsername(ref)) {
            throw new Error('peer must be a positive integer userId or a non-empty username string')
        }
        const username = ref.toLowerCase()
        const res = await this.http!.get<{
            user: { id: number; username: string; displayName: string | null; isDeleted?: boolean }
        }>(`/users/${encodeURIComponent(username)}`)
        if (res.data.user.isDeleted) {
            throw new Error(`peer ${username} is a deleted account`)
        }
        return res.data.user.id
    }


    // Typed event API

    override on<K extends keyof MorokBotEvents>(event: K, listener: MorokBotEvents[K]): this {
        return super.on(event, listener as (...args: unknown[]) => void)
    }
    override off<K extends keyof MorokBotEvents>(event: K, listener: MorokBotEvents[K]): this {
        return super.off(event, listener as (...args: unknown[]) => void)
    }
    override emit<K extends keyof MorokBotEvents>(event: K, ...args: Parameters<MorokBotEvents[K]>): boolean {
        try {
            return super.emit(event, ...args)
        } catch (err) {
            // A user listener threw synchronously. Node's EventEmitter would propagate it straight out of emit()
            // and, depending on the call site, take the bot down. Route it to the 'error' event
            // the same way async handler rejections already are (a default 'error' listener is installed at startup)
            // Guard recursion: a throwing 'error' handler has nowhere safe to go, so rethrow
            if (event === 'error') throw err
            super.emit('error', err instanceof Error ? err : new Error(String(err)))
            return false
        }
    }
}
