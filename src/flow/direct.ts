/**
 * DM send. Receive lives in flow/receive.ts
 *
 * Send path:
 *   1. resolve peer (number or username to userId)
 *   2. POST /conversations to get-or-create a DIRECT conversation
 *   3. GET /prekeys/:userId/devices for the peer's device list
 *   4. for each device, install a Signal session if missing, encrypt, WS frame with fanoutId
 *   5. wait for the own-echo matched by fanoutId, resolve with messageId
 *
 * Success bar is at least one device acked, a single offline or stale device must not fail the send
 */

import { randomBytes, randomUUID } from 'node:crypto'

import type { HttpClient } from '../transport/http.js'
import type { WsClient, IncomingFrame } from '../transport/ws.js'
import { SignalEngine, type PreKeyBundle } from '../crypto/signal.js'
import {
    uploadAttachment, type EncryptedFileRef,
    buildGalleryPayload,
    GALLERY_MIN_ITEMS, GALLERY_MAX_ITEMS,
} from './attachments.js'
import type { SdkLogger, AttachmentInput, VideoNoteShape } from '../types.js'


// Public input shape

export interface SendTextOptions {
    /** Reply target */
    replyToId?:        number
    /** clientMsgId of the parent so threading survives fan-out */
    replyToClientMsgId?: string
    /** Channel-comment thread root */
    threadRootId?:     number
    /** Own-echo timeout. Default 10s, the echo usually lands sub-100ms since the WS is already connected */
    sendTimeoutMs?:    number
}

export interface SendResult {
    /** Server message id of the own-echo row (the bot's own conversation_members copy)
     *  Peers have their own copies with different ids, that is the fan-out shape */
    messageId:    number
    clientMsgId:  string
    conversationId: number
}


// Plaintext payload builders (byte-exact mirror of FE)

// Voice clamps from frontend/src/lib/send-voice.ts, duration into the [0.1, 600] window
// Waveform capped at 64 ints in [0..100]
const VOICE_DURATION_MIN          = 0.1
const VOICE_DURATION_MAX          = 600
const VOICE_WAVEFORM_MAX_BARS     = 64
// Video note clamps from frontend/src/lib/send-video-note.ts, duration into the [0.5, 300] window
// The shape rides through as an open string and the receiver decides what it renders, unknown names become circle
const VIDEO_NOTE_DURATION_MIN     = 0.5
const VIDEO_NOTE_DURATION_MAX     = 300
const VIDEO_NOTE_SHAPE_RE         = /^[a-zA-Z0-9]{1,32}$/
const VIDEO_NOTE_DEFAULT_SHAPE: VideoNoteShape = 'circle'


function buildFilePayload(ref: EncryptedFileRef, caption?: string): string {
    const body: { type: 'file'; ref: EncryptedFileRef; caption?: string } = {
        type: 'file', ref,
    }
    if (caption && caption.length > 0) body.caption = caption
    return JSON.stringify(body)
}

function buildVoicePayload(
    ref:      EncryptedFileRef,
    duration: number,
    waveform: number[] | undefined,
): string {
    const dur = Math.max(VOICE_DURATION_MIN, Math.min(VOICE_DURATION_MAX, Number(duration) || 0))
    const wf  = Array.isArray(waveform)
        ? waveform.slice(0, VOICE_WAVEFORM_MAX_BARS).map(n => {
            const v = Math.round(Number(n) || 0)
            return v < 0 ? 0 : v > 100 ? 100 : v
        })
        : []
    return JSON.stringify({ type: 'voice', ref, duration: dur, waveform: wf })
}

function buildVideoNotePayload(
    ref:      EncryptedFileRef,
    duration: number,
    shape:    VideoNoteShape | undefined,
): string {
    const dur = Math.max(
        VIDEO_NOTE_DURATION_MIN,
        Math.min(VIDEO_NOTE_DURATION_MAX, Number(duration) || 0),
    )
    const sh = typeof shape === 'string' && VIDEO_NOTE_SHAPE_RE.test(shape) ? shape : VIDEO_NOTE_DEFAULT_SHAPE
    return JSON.stringify({ type: 'video_note', ref, duration: dur, shape: sh })
}


// Defaults match what FE's MediaRecorder emits in Chrome. Callers can override via AttachmentInput.mime
const DEFAULT_VOICE_MIME      = 'audio/ogg'
const DEFAULT_VIDEO_NOTE_MIME = 'video/webm'


function assertNever(x: never): never {
    throw new Error(`unsupported attachment kind: ${(x as { kind?: unknown }).kind}`)
}


/** Upload attachment bytes under a fresh AES key and build the JSON envelope for the Signal plaintext
 *  Voice and video_note upload with noteMedia: true so the bytes don't hit the bot's 10 GB quota */
export async function uploadAndBuildPayload(
    http:       HttpClient,
    attachment: AttachmentInput,
    caption:    string | undefined,
    logger?:    SdkLogger,
): Promise<{ payload: string; ref: EncryptedFileRef; kind: 'file' | 'voice' | 'video_note' }> {
    const data = attachment.data

    switch (attachment.kind) {
        case 'file': {
            const ref = await uploadAttachment(http, data, {
                mime:     attachment.mime ?? 'application/octet-stream',
                filename: attachment.name,
            }, logger)
            return { payload: buildFilePayload(ref, caption), ref, kind: 'file' }
        }
        case 'voice': {
            const ref = await uploadAttachment(http, data, {
                mime:      attachment.mime ?? DEFAULT_VOICE_MIME,
                noteMedia: true,
            }, logger)
            return {
                payload: buildVoicePayload(ref, attachment.duration, attachment.waveform),
                ref,
                kind: 'voice',
            }
        }
        case 'video_note': {
            const ref = await uploadAttachment(http, data, {
                mime:      attachment.mime ?? DEFAULT_VIDEO_NOTE_MIME,
                noteMedia: true,
            }, logger)
            return {
                payload: buildVideoNotePayload(ref, attachment.duration, attachment.shape),
                ref,
                kind: 'video_note',
            }
        }
        default:
            return assertNever(attachment)
    }
}


/**
 * Upload N attachments (file kind only) and build the gallery payload
 * - each item uploaded under its own fresh AES key
 * - 2..10 items, voice and video_note rejected
 * - refs[0] is the head (server's messages.file_id), refs[1..] go into additionalFileIds on the WS frame
 */
export async function uploadGalleryAndBuildPayload(
    http:        HttpClient,
    attachments: AttachmentInput[],
    caption:     string | undefined,
    logger?:     SdkLogger,
): Promise<{
    payload:           string
    refs:              EncryptedFileRef[]
    headFileId:        number
    additionalFileIds: number[]
}> {
    if (!Array.isArray(attachments) || attachments.length < GALLERY_MIN_ITEMS) {
        throw new Error(
            `gallery requires >= ${GALLERY_MIN_ITEMS} attachments, got ${attachments?.length ?? 0}`,
        )
    }
    if (attachments.length > GALLERY_MAX_ITEMS) {
        throw new Error(
            `gallery capped at ${GALLERY_MAX_ITEMS} attachments, got ${attachments.length}`,
        )
    }
    for (const a of attachments) {
        if (!a || typeof a !== 'object') throw new Error('gallery: every item must be an AttachmentInput object')
        if (a.kind !== 'file') {
            throw new Error(
                `gallery items must be kind='file' (got '${a.kind}'); voice / video_note are single-only`,
            )
        }
    }

    // Sequential upload, bounded memory and clean error attribution by index
    // Galleries cap at 10 items, so parallelism would gain nothing
    const refs: EncryptedFileRef[] = []
    for (let i = 0; i < attachments.length; i++) {
        const a = attachments[i] as AttachmentInput & { kind: 'file' }
        const data = a.data
        try {
            const ref = await uploadAttachment(http, data, {
                mime:     a.mime ?? 'application/octet-stream',
                filename: a.name,
            }, logger)
            refs.push(ref)
        } catch (err) {
            throw new Error(
                `gallery upload failed at item ${i + 1}/${attachments.length}: ${(err as Error).message}`,
            )
        }
    }

    const items = refs.map(ref => ({ type: 'file' as const, ref }))
    const payload = buildGalleryPayload(items, caption)
    return {
        payload,
        refs,
        headFileId:        refs[0]!.fileId,
        additionalFileIds: refs.slice(1).map(r => r.fileId),
    }
}


// Internal helpers

interface ConversationResponse {
    conversation: { id: number; type: string }
    existing:     boolean
}

interface DevicesResponse {
    deviceIds: number[]
}


// Server-side regex on fanoutId is /^[A-Za-z0-9_-]{8,32}$/
function mintFanoutId(): string {
    return randomBytes(12).toString('base64url')  // 16 base64url chars
}

// Server-side regex on clientMsgId is /^[A-Za-z0-9_-]{1,64}$/.
// randomUUID without hyphens gives 32 hex chars, well inside bounds
function mintClientMsgId(): string {
    return randomUUID().replace(/-/g, '')
}


/**
 * Per-fanout pending send. Resolves on the matching own-echo frame,
 * rejects on the matching server-error frame or the timeout
 * One entry per per-device fan-out frame, send() waits for the first resolve and cancels the rest,
 * the message is already on the wire and we don't need the messageId from other devices
 */
interface PendingSend {
    resolve: (messageId: number) => void
    reject:  (err: Error) => void
    timer:   NodeJS.Timeout
}


/**
 * Thrown when the server rejects a send with an `error` frame. `code` carries the machine-readable reason
 * ('recipient_storage_full' means the recipient's storage is full and the file was not delivered,
 * plus 'bot_not_started', 'send_blocked') so a bot can branch on it without string-matching the human `message`
 * Undefined `code` means the server sent only a message
 */
export class SendRejectedError extends Error {
    constructor(message: string, readonly code?: string) {
        super(message)
        this.name = 'SendRejectedError'
    }
}


/**
 * Thrown when the socket drops while a send is in flight, before the server confirmed it
 * The message may or may not have been delivered, a retry can double-deliver, so reconcile or accept at-least-once
 */
export class SendUncertainError extends Error {
    constructor(message: string, readonly clientMsgId?: string, readonly conversationId?: number) {
        super(message)
        this.name = 'SendUncertainError'
    }
}


// DirectFlow

export class DirectFlow {
    private pendingSends = new Map<string, PendingSend>()

    constructor(
        private readonly http:   HttpClient,
        private readonly ws:     WsClient,
        private readonly signal: SignalEngine,
        private readonly logger?: SdkLogger,
    ) {
        // Resolve own-echo / error frames by fanoutId
        this.ws.on('frame', (frame) => { this.onFrame(frame) })
        // A transient drop loses the own-echo, so fail in-flight sends with an uncertain result for the caller to retry
        this.ws.on('close', (info) => { if (info.willReconnect) this.failPendingUncertain() })
    }

    /** DM send. Resolves with the messageId from the first device's own-echo
     *  Plaintext is raw UTF-8 for text, or the JSON envelope (file/voice/video_note/gallery) for attachments */
    async sendMessage(
        peerUserId: number,
        body:       { text?: string; attachment?: AttachmentInput; attachments?: AttachmentInput[] },
        opts:       SendTextOptions = {},
    ): Promise<SendResult> {
        if (!Number.isInteger(peerUserId) || peerUserId < 1) {
            throw new Error(`sendMessage: peerUserId must be a positive integer, got ${peerUserId}`)
        }
        const hasText       = typeof body.text === 'string' && body.text.length > 0
        const hasAttachment = body.attachment !== undefined
        const hasGallery    = Array.isArray(body.attachments) && body.attachments.length > 0
        if (hasAttachment && hasGallery) {
            throw new Error('sendMessage: `attachment` and `attachments` are mutually exclusive')
        }
        if (!hasText && !hasAttachment && !hasGallery) {
            throw new Error('sendMessage: must supply at least one of `text`, `attachment`, or `attachments`')
        }

        // Plaintext + optional fileId / kind / additionalFileIds
        let plaintext: Uint8Array
        let fileId:    number | undefined
        let kind:      'text' | 'file' | 'voice' | 'video_note' | 'gallery' = 'text'
        let additionalFileIds: number[] | undefined

        if (hasGallery) {
            const built = await uploadGalleryAndBuildPayload(
                this.http, body.attachments!, hasText ? body.text : undefined,
                this.logger,
            )
            plaintext         = new TextEncoder().encode(built.payload)
            fileId            = built.headFileId
            kind              = 'gallery'
            additionalFileIds = built.additionalFileIds
        } else if (hasAttachment) {
            const built = await uploadAndBuildPayload(
                this.http, body.attachment!, hasText ? body.text : undefined,
                this.logger,
            )
            plaintext = new TextEncoder().encode(built.payload)
            fileId    = built.ref.fileId
            kind      = built.kind
            if (kind !== 'file' && hasText) {
                // Voice / video_note payloads have no caption slot, so the FE ignores it. Warn so the caller knows
                this.logger?.warn(
                    { kind, droppedTextLen: body.text!.length },
                    '[direct] caption ignored: only kind="file" supports caption',
                )
            }
        } else {
            plaintext = new TextEncoder().encode(body.text!)
        }

        const conv = await this.ensureConversation(peerUserId)
        const devices = await this.fetchPeerDevices(peerUserId)
        if (devices.length === 0) {
            throw new Error(`sendMessage: peer ${peerUserId} has no addressable devices`)
        }

        const clientMsgId = mintClientMsgId()
        const timeoutMs   = opts.sendTimeoutMs ?? 10_000

        const perDevice = devices.map((deviceId) =>
            this.sendToDevice({
                peerUserId, peerDeviceId: deviceId,
                conversationId:           conv.id,
                plaintext, clientMsgId, timeoutMs,
                replyToId:                opts.replyToId,
                replyToClientMsgId:       opts.replyToClientMsgId,
                threadRootId:             opts.threadRootId,
                fileId,
                kind,
                additionalFileIds,
            }).catch(err => ({ kind: 'err' as const, err: err as Error })),
        )
        const results = await Promise.all(perDevice)

        const ok = results.find((r): r is number => typeof r === 'number')
        if (ok !== undefined) {
            return { messageId: ok, clientMsgId, conversationId: conv.id }
        }
        const errResults = results
            .filter((r): r is { kind: 'err'; err: Error } => typeof r === 'object' && 'kind' in r)
        const errs = errResults.map(r => r.err.message)
        const aggMsg = `sendMessage: every device send failed - ${errs.join(' ; ')}`
        // A disconnect fails every device's pending at once, surface the uncertain result so the caller decides
        if (errResults.length > 0 && errResults.every(r => r.err instanceof SendUncertainError)) {
            throw new SendUncertainError(aggMsg, clientMsgId, conv.id)
        }
        // Global rejections (recipient_storage_full, bot_not_started, send_blocked) hit every device frame identically
        // Propagate a typed SendRejectedError when the present server codes all agree on one code, even if a sibling
        // device failed for a local reason (prekey-fetch 429, timeout, or a bad cert) that carries no code
        // A genuinely mixed bag of two different server codes stays a plain Error
        const distinctCodes = [...new Set(
            errResults
                .map(r => (r.err instanceof SendRejectedError ? r.err.code : undefined))
                .filter((c): c is string => c !== undefined),
        )]
        const commonCode = distinctCodes.length === 1 ? distinctCodes[0] : undefined
        throw commonCode ? new SendRejectedError(aggMsg, commonCode) : new Error(aggMsg)
    }

    // Internals

    private sendToDevice(args: {
        peerUserId:         number
        peerDeviceId:       number
        conversationId:     number
        plaintext:          Uint8Array
        clientMsgId:        string
        timeoutMs:          number
        replyToId?:         number
        replyToClientMsgId?: string
        threadRootId?:      number
        /** Optional attachment id (server-side messages.file_id). For a gallery this is the head ref's fileId */
        fileId?:            number
        /** Render-hint on the WS frame, mirrors server's ALLOWED_MESSAGE_KINDS */
        kind?:              'text' | 'file' | 'voice' | 'video_note' | 'gallery'
        /** Gallery-only, file ids 2..N (head is `fileId` above). Server validates each against the same ACL */
        additionalFileIds?: number[]
    }): Promise<number> {
        const { peerUserId, peerDeviceId, conversationId, plaintext, clientMsgId } = args

        // bundle-fetch, processPreKey, then encrypt is one critical section per peer-device
        // The same lock covers concurrent decrypt in ReceiveFlow so ratchet writes don't race
        return this.signal.withPeerLock(peerUserId, peerDeviceId, async () => {
            // First contact with this device. Bundle fetch is rate-limited (10/min), no retry here
            // the per-device promise array surfaces the failure to the caller
            if (!(await this.signal.hasOpenSession(peerUserId, peerDeviceId))) {
                const bundle = await this.fetchPreKeyBundle(peerUserId, peerDeviceId)
                await this.signal.processPreKeyBundle(bundle)
            }

            const { type, body } = await this.signal.encrypt(peerUserId, peerDeviceId, plaintext)
            const fanoutId = mintFanoutId()

            return new Promise<number>((resolve, reject) => {
                const timer = setTimeout(() => {
                    if (this.pendingSends.delete(fanoutId)) {
                        reject(new Error(
                            `send timeout after ${args.timeoutMs}ms (peer=${peerUserId}.${peerDeviceId} conv=${conversationId})`,
                        ))
                    }
                }, args.timeoutMs)

                this.pendingSends.set(fanoutId, { resolve, reject, timer })

                const frame: Record<string, unknown> = {
                    type:              'message',
                    conversationId,
                    recipientId:       peerUserId,
                    recipientDeviceId: peerDeviceId,
                    ciphertext:        body,
                    messageType:       type,
                    clientMsgId,
                    fanoutId,
                    kind:              args.kind ?? 'text',
                }
                if (args.replyToId !== undefined)         frame.replyToId          = args.replyToId
                if (args.replyToClientMsgId !== undefined) frame.replyToClientMsgId = args.replyToClientMsgId
                if (args.threadRootId !== undefined)       frame.threadRootId       = args.threadRootId
                if (args.fileId !== undefined)             frame.fileId             = args.fileId
                if (args.additionalFileIds !== undefined && args.additionalFileIds.length > 0) {
                    frame.additionalFileIds = args.additionalFileIds
                }

                this.ws.send(frame)
            })
        })
    }

    private onFrame(frame: IncomingFrame): void {
        // Own-echo / error frames matched by fanoutId. Anything without a fanoutId is somebody else's concern
        const fanoutId = frame.fanoutId
        if (typeof fanoutId !== 'string') return
        const pending = this.pendingSends.get(fanoutId)
        if (!pending) return

        clearTimeout(pending.timer)
        this.pendingSends.delete(fanoutId)

        if (frame.type === 'error') {
            const code = typeof frame.code === 'string' ? frame.code : undefined
            const msg = typeof frame.message === 'string'
                ? frame.message
                : code ?? 'send rejected by server'
            const codeStr = code ? ` (code=${code})` : ''
            pending.reject(new SendRejectedError(`send rejected: ${msg}${codeStr}`, code))
            return
        }

        if (frame.type === 'message') {
            const id = typeof frame.id === 'number' ? frame.id : null
            if (id === null) {
                pending.reject(new Error('own-echo missing message id'))
                return
            }
            pending.resolve(id)
            return
        }

        // Unexpected frame type with our fanoutId, do not orphan the pending entry
        pending.reject(new Error(`unexpected frame type "${frame.type}" for fanoutId ${fanoutId}`))
    }


    /**
     * Encrypt a reaction payload to every device of `peerUserId` and return the per-device distributions
     * for a `reaction_add` frame. Open a Signal session if needed, then encrypt
     * A device the bot can't reach is skipped, the others still get the reaction
     * The bot is single-device, so no sibling or self-AES distributions are produced
     */
    async encryptReaction(
        peerUserId: number, plaintext: Uint8Array,
    ): Promise<Array<{ recipientId: number; recipientDeviceId: number; ciphertext: string; messageType: 1 | 3 }>> {
        const devices = await this.fetchPeerDevices(peerUserId)
        const dists: Array<{ recipientId: number; recipientDeviceId: number; ciphertext: string; messageType: 1 | 3 }> = []
        for (const deviceId of devices) {
            try {
                const env = await this.signal.withPeerLock(peerUserId, deviceId, async () => {
                    if (!(await this.signal.hasOpenSession(peerUserId, deviceId))) {
                        const bundle = await this.fetchPreKeyBundle(peerUserId, deviceId)
                        await this.signal.processPreKeyBundle(bundle)
                    }
                    return this.signal.encrypt(peerUserId, deviceId, plaintext)
                })
                dists.push({
                    recipientId:       peerUserId,
                    recipientDeviceId: deviceId,
                    ciphertext:        env.body,
                    messageType:       env.type,
                })
            } catch (err) {
                this.logger?.warn(
                    { peerUserId, deviceId, err: (err as Error).message },
                    '[direct] reaction encrypt failed for device, skipping',
                )
            }
        }
        return dists
    }


    // HTTP wrappers

    private async ensureConversation(targetUserId: number): Promise<{ id: number }> {
        const res = await this.http.post<ConversationResponse>(
            '/conversations',
            { targetUserId },
        )
        return { id: res.data.conversation.id }
    }

    private async fetchPeerDevices(peerUserId: number): Promise<number[]> {
        const res = await this.http.get<DevicesResponse>(`/prekeys/${peerUserId}/devices`)
        // Empty list on a malformed body, caller throws cleanly
        return Array.isArray(res.data?.deviceIds) ? res.data.deviceIds : []
    }

    private async fetchPreKeyBundle(peerUserId: number, peerDeviceId: number): Promise<PreKeyBundle> {
        const res = await this.http.get<PreKeyBundle>(`/prekeys/${peerUserId}/${peerDeviceId}`)
        return res.data
    }

    /** Reject pending sends and clear timers. Called by MorokBot on stop() */
    shutdown(): void {
        for (const [, p] of this.pendingSends) {
            clearTimeout(p.timer)
            p.reject(new Error('SDK shutdown - send aborted'))
        }
        this.pendingSends.clear()
    }

    /** Fail in-flight sends after a transient disconnect with an uncertain result */
    private failPendingUncertain(): void {
        for (const [, p] of this.pendingSends) {
            clearTimeout(p.timer)
            p.reject(new SendUncertainError('send interrupted by a disconnect before the server confirmed'))
        }
        this.pendingSends.clear()
    }
}
