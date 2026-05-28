/**
 * Inbound WS frame router. Owns:
 *   - message (DM and group-chat/channel)
 *   - bot_started / bot_stopped
 *   - conversation_added / conversation_kicked
 *   - channel_key_rotated, member_count_changed
 *
 * Own-echoes (senderId === botUserId) are skipped here, DirectFlow and GroupsFlow resolve them via fanoutId
 * Plaintext is UTF-8 text or a JSON envelope for attachments, sniff picks between them
 * Dedup is a small LRU keyed by (sender, conv, clientMsgId), needed because the server replays on reconnect
 * (durable queues), 5-minute TTL is plenty since replays land fast
 * Command dispatch: single-line plaintext starting with '/' becomes a CommandInvocation
 * Multi-line bubbles aren't commands
 */

import { TextDecoder } from 'node:util'

import type { HttpClient }                  from '../transport/http.js'
import type { WsClient, IncomingFrame }     from '../transport/ws.js'
import type { SignalEngine }                from '../crypto/signal.js'
import type {
    SdkLogger, Peer,
    IncomingMessage, CommandInvocation,
    BotStartEvent, BotStopEvent,
    ConversationAddedEvent, ConversationKickedEvent,
    ReactionEvent, ControlEvent,
    IncomingAttachment, IncomingGallery, IncomingGalleryItem,
    VideoNoteShape,
    ConversationType,
} from '../types.js'
import {
    downloadAttachment, isEncryptedFileRef,
    type EncryptedFileRef,
    type GalleryItem,
    parseGalleryItem,
    GALLERY_MIN_ITEMS, GALLERY_MAX_ITEMS,
} from './attachments.js'
import type { GroupsFlow }                   from './groups.js'
import type { ConvCache }                    from './conv-cache.js'


// Peer resolution cache

interface CachedPeer {
    peer:    Peer
    fetched: number  // unix ms
}

interface UsersIdResponse {
    user: {
        id:          number
        username:    string
        displayName: string | null
        isDeleted?:  boolean
    }
}

// 5-minute peer cache. displayName/username changes propagate via `user_updated` events,
// this is just a hot-path skip for the common "10 messages from the same peer in a row" pattern
const PEER_CACHE_TTL_MS = 5 * 60 * 1000


// Dedup LRU

const DEDUP_MAX_ENTRIES = 1024
const DEDUP_TTL_MS      = 5 * 60 * 1000

const BACKFILL_REQ_THROTTLE_MS  = 5_000
const BACKFILL_REQ_THROTTLE_MAX = 4096

const PROTOCOL_KINDS: ReadonlySet<string> = new Set([
    'decrypt_share', 'decrypt_share_response',
    'signal_warmup',
    'morok_xsk_propagation', 'morok_xsk_request',
    'morok_peer_session_reset_request', 'morok_dm_backfill',
])

class DedupCache {
    private entries = new Map<string, number>()
    has(key: string): boolean {
        const at = this.entries.get(key)
        if (at === undefined) return false
        if (Date.now() - at > DEDUP_TTL_MS) {
            this.entries.delete(key)
            return false
        }
        return true
    }
    record(key: string): void {
        if (this.entries.size >= DEDUP_MAX_ENTRIES) {
            // Drop the first inserted entry. Map iterates in insertion order,
            // so this is effectively LRU on insertion (we don't touch on read, recent inserts stay on the tail)
            const oldest = this.entries.keys().next().value
            if (oldest !== undefined) this.entries.delete(oldest)
        }
        this.entries.set(key, Date.now())
    }
}


// ReceiveFlow

export type ReceiveEmitter = {
    emit: (event:
        | { kind: 'message',             payload: IncomingMessage }
        | { kind: 'command',             payload: CommandInvocation }
        | { kind: 'start',               payload: BotStartEvent }
        | { kind: 'stop',                payload: BotStopEvent }
        | { kind: 'conversation_added',  payload: ConversationAddedEvent }
        | { kind: 'conversation_kicked', payload: ConversationKickedEvent }
        | { kind: 'reaction',            payload: ReactionEvent }
        | { kind: 'control',             payload: ControlEvent }
        | { kind: 'error',               error:   Error }
    ) => void
}


// Bound on the number of cached peers, evicting the oldest, a miss just refetches
const PEER_CACHE_MAX = 1024

export class ReceiveFlow {
    private peerCache = new Map<number, CachedPeer>()
    private dedup     = new DedupCache()
    private textDec   = new TextDecoder('utf-8', { fatal: false })
    private backfillReqThrottle = new Map<string, number>()

    constructor(
        private readonly botUserId: number,
        private readonly http:      HttpClient,
        private readonly ws:        WsClient,
        private readonly signal:    SignalEngine,
        private readonly convCache: ConvCache | null,
        private readonly emitter:   ReceiveEmitter,
        private readonly groups:    GroupsFlow | null,
        private readonly opts:      { autoBackfillOnJoin: boolean; serveBackfillRequests: boolean },
        private readonly logger?:   SdkLogger,
    ) {
        this.ws.on('frame', (frame) => {
            // Errors in the per-frame handler must never kill the listener
            // Surface them to the bot's `error` event so the handler can decide, the next frame still arrives
            void this.onFrame(frame).catch(err => {
                this.logger?.warn(
                    { err: (err as Error).message, frameType: frame.type },
                    '[receive] frame handler threw',
                )
                this.emitter.emit({ kind: 'error', error: err as Error })
            })
        })
    }


    // Frame router

    private async onFrame(frame: IncomingFrame): Promise<void> {
        switch (frame.type) {
            case 'message':                  return this.onMessageFrame(frame)
            case 'bot_started':              return this.onBotStartedFrame(frame)
            case 'bot_stopped':              return this.onBotStoppedFrame(frame)
            case 'conversation_added':       return this.onConversationAddedFrame(frame)
            case 'conversation_kicked':      return this.onConversationKickedFrame(frame)
            case 'channel_key_rotated':      return this.onChannelKeyRotatedFrame(frame)
            case 'channel_key_backfill_request': return this.onChannelKeyBackfillRequestFrame(frame)
            case 'member_count_changed':     return this.onMemberCountChangedFrame(frame)
            case 'member_updated':           return this.onMemberUpdatedFrame(frame)
            case 'group_updated':            return this.onGroupUpdatedFrame(frame)
            case 'reaction_encrypted':       return this.onReactionEncryptedFrame(frame)
            case 'reaction_removed':         return this.onReactionRemovedFrame(frame)
            default:                         return  // not our concern
        }
    }


    // Inbound message

    private async onMessageFrame(frame: IncomingFrame): Promise<void> {
        const senderId    = frame.senderId
        const messageType = frame.messageType

        // Own-echo: ignore on the receive path
        // DirectFlow/GroupsFlow maps the outbound fanoutId to its own pendingSend entry,
        // we never surface own sends as IncomingMessage
        if (typeof senderId === 'number' && senderId === this.botUserId) {
            return
        }
        // Both DM and group messages come in as type:'message', messageType discriminates:
        // 1/3 = DM, 8 = group, 10 = self-AES (ignored), anything else unknown
        if (messageType === 8) return this.onGroupInbound(frame)
        if (messageType !== 1 && messageType !== 3) {
            this.logger?.debug({ messageType }, '[receive] skipping non-DM message')
            return
        }
        return this.onDirectInbound(frame)
    }


    private async onDirectInbound(frame: IncomingFrame): Promise<void> {
        const senderId    = frame.senderId
        const recipientId = frame.recipientId
        const messageType = frame.messageType
        const ciphertext  = frame.ciphertext
        if (typeof senderId !== 'number'
            || typeof ciphertext !== 'string'
            || typeof frame.senderDeviceId !== 'number'
            || typeof frame.id !== 'number'
            || typeof frame.conversationId !== 'number'
            || (messageType !== 1 && messageType !== 3)) {
            this.logger?.warn({ frame }, '[receive] malformed message frame')
            return
        }
        if (typeof recipientId === 'number' && recipientId !== this.botUserId) {
            this.logger?.debug({ recipientId, botUserId: this.botUserId }, '[receive] message not for us')
            return
        }

        // Dedup key = (sender, conv, clientMsgId)
        // Including sender matters for group messages where one conv has many senders
        const clientMsgId = typeof frame.clientMsgId === 'string' ? frame.clientMsgId : null
        // Prefer the sender's stable clientMsgId, fall back to the server message id
        // (always present and stable across durable-queue replays) when the sender omitted one
        // Without the fallback a clientMsgId-less frame never dedups and re-fires the handler on every reconnect replay
        const dedupKey = clientMsgId !== null
            ? `c:${senderId}.${frame.senderDeviceId}:${frame.conversationId}:${clientMsgId}`
            : `s:${senderId}.${frame.senderDeviceId}:${frame.conversationId}:${frame.id}`
        if (dedupKey && this.dedup.has(dedupKey)) {
            this.logger?.debug({ messageId: frame.id, clientMsgId }, '[receive] deduped replay')
            return
        }

        // Decrypt under the shared per-peer-device lock so an outbound encrypt to the same device
        // can't race the session-on-disk read-modify-write
        //
        // Dedup is recorded after a successful decrypt, so a transient decrypt failure (mid-rotation, ratchet hiccup)
        // leaves the slot empty for the server's next replay
        //
        // Hoist senderDeviceId because TS loses narrowing across an await inside a closure
        const senderDeviceId = frame.senderDeviceId
        let plaintextBytes: Uint8Array
        try {
            plaintextBytes = await this.signal.withPeerLock(
                senderId, senderDeviceId,
                () => this.signal.decrypt(senderId, senderDeviceId, messageType, ciphertext),
            )
        } catch (err) {
            this.logger?.warn(
                { err: (err as Error).message, senderId, deviceId: frame.senderDeviceId, messageType, kind: frame.kind },
                '[receive] decrypt failed',
            )
            if (!(typeof frame.kind === 'string' && PROTOCOL_KINDS.has(frame.kind))) {
                this.emitter.emit({
                    kind:  'error',
                    error: new Error(
                        `decrypt failed for senderId=${senderId}.${frame.senderDeviceId} type=${messageType}: ${(err as Error).message}`,
                    ),
                })
            }
            return
        }
        if (dedupKey) this.dedup.record(dedupKey)

        if (typeof frame.kind === 'string' && PROTOCOL_KINDS.has(frame.kind)) {
            this.logger?.debug({ kind: frame.kind, senderId }, '[receive] dropped protocol envelope (not user input)')
            return
        }

        // Sniff a JSON payload (attachment or future kinds) vs plain UTF-8 text
        // If the decoded text starts with `{` and the outer JSON has a recognised `type`,
        // treat it as a structured payload, otherwise plain text. Real text rarely starts with `{`,
        // and a literal "{... not json" just fails JSON.parse and falls through as text
        const decoded = this.textDec.decode(plaintextBytes)
        const action  = parseBotAction(decoded)
        if (action) {
            const actionPeer = await this.resolvePeer(senderId).catch(() => null)
            this.emitter.emit({
                kind: 'control',
                payload: {
                    controlId:        action.controlId,
                    sender:           actionPeer ?? { userId: senderId, username: `user_${senderId}`, displayName: null },
                    conversationId:   frame.conversationId,
                    conversationType: 'DIRECT',
                },
            })
            return
        }
        if (isProtocolPayload(decoded)) {
            this.logger?.debug({ senderId }, '[receive] dropped protocol payload by type (not user input)')
            return
        }
        const sniffed = sniffStructuredPayload(decoded)
        const text       = sniffed?.caption ?? (sniffed === null ? decoded : '')
        const attachment = sniffed?.attachment

        const peer = await this.resolvePeer(senderId).catch(() => null)
        if (!peer) {
            // Couldn't resolve the peer profile, fall back to a stub so the handler still fires with a partial peer,
            // the message isn't dropped silently
            this.logger?.warn({ senderId }, '[receive] peer resolution failed; emitting with stub')
        }

        const createdAt = typeof frame.createdAt === 'string'
            ? new Date(frame.createdAt)
            : new Date()

        // Build the IncomingAttachment/IncomingGallery if one was parsed
        // The download() closures bind to the SDK's http client, bytes hit the network only when the handler calls them
        let attachmentObj: IncomingAttachment | undefined
        let galleryObj:    IncomingGallery    | undefined
        if (attachment) {
            attachmentObj = buildIncomingAttachment(attachment, () => downloadAttachment(this.http, attachment.ref, this.logger))
        } else if (sniffed?.gallery) {
            galleryObj = buildIncomingGallery(
                sniffed.gallery,
                (ref) => () => downloadAttachment(this.http, ref, this.logger),
            )
        }

        const baseMsg: IncomingMessage = {
            messageId:        frame.id,
            conversationId:   frame.conversationId,
            conversationType: 'DIRECT',
            sender:           peer ?? { userId: senderId, username: `user_${senderId}`, displayName: null },
            senderDeviceId:   frame.senderDeviceId,
            text,
            ...(attachmentObj ? { attachment: attachmentObj } : {}),
            ...(galleryObj    ? { gallery:    galleryObj }    : {}),
            clientMsgId,
            replyToId:      typeof frame.replyToId    === 'number' ? frame.replyToId    : null,
            threadRootId:   typeof frame.threadRootId === 'number' ? frame.threadRootId : null,
            createdAt,
        }

        // Command-vs-message dispatch. Single-line, leading '/', a-z|0-9|_ name
        // (matches the server-side /^[a-z][a-z0-9_]{0,31}$/ from routes/developer.ts:commands)
        const parsed = parseCommand(text)
        if (parsed) {
            const cmd: CommandInvocation = {
                ...baseMsg,
                command: parsed.command,
                args:    parsed.args,
                argv:    parsed.argv,
            }
            this.emitter.emit({ kind: 'command', payload: cmd })
            return
        }
        this.emitter.emit({ kind: 'message', payload: baseMsg })
    }


    // Lifecycle frames

    private async onBotStartedFrame(frame: IncomingFrame): Promise<void> {
        const userId    = frame.userId
        const botUserId = frame.botUserId
        const startedAt = frame.startedAt
        if (typeof userId !== 'number' || (typeof botUserId === 'number' && botUserId !== this.botUserId)) {
            this.logger?.warn({ frame }, '[receive] malformed bot_started')
            return
        }
        const peer = await this.resolvePeer(userId).catch(() => null)
        const startedAtDate = typeof startedAt === 'string' ? new Date(startedAt) : new Date()
        this.emitter.emit({
            kind:    'start',
            payload: {
                peer: peer ?? { userId, username: `user_${userId}`, displayName: null },
                startedAt: startedAtDate,
            },
        })
    }

    private async onBotStoppedFrame(frame: IncomingFrame): Promise<void> {
        const userId    = frame.userId
        const botUserId = frame.botUserId
        const stoppedAt = frame.stoppedAt
        if (typeof userId !== 'number' || (typeof botUserId === 'number' && botUserId !== this.botUserId)) {
            this.logger?.warn({ frame }, '[receive] malformed bot_stopped')
            return
        }
        // Drop the peer cache entry, the user just revoked consent, their profile may also have changed (e.g. blocked us)
        this.peerCache.delete(userId)
        const peer = await this.resolvePeer(userId).catch(() => null)
        const stoppedAtDate = typeof stoppedAt === 'string' ? new Date(stoppedAt) : new Date()
        this.emitter.emit({
            kind:    'stop',
            payload: {
                peer: peer ?? { userId, username: `user_${userId}`, displayName: null },
                stoppedAt: stoppedAtDate,
            },
        })
    }


    // Reactions

    // reaction_encrypted: a member reacted to a message. DM reactions arrive as a peer-Signal envelope
    // addressed to the bot's device (messageType 1/3), group reactions as a channel-key envelope
    // (messageType 8) shared by every member. Either way the bot is a recipient and decrypts the reaction
    // like a message. Inner plaintext is JSON `{ emoji }`, the wire key stays emoji though it holds any unicode (a legacy thing)
    private async onReactionEncryptedFrame(frame: IncomingFrame): Promise<void> {
        const reactorId      = frame.reactorUserId
        const reactorDevice  = frame.reactorDeviceId
        const messageId      = frame.messageId
        const messageType    = frame.messageType
        const ciphertext     = frame.ciphertext
        const conversationId = frame.conversationId
        const clientMsgId    = typeof frame.clientMsgId === 'string' ? frame.clientMsgId : null
        if (typeof reactorId !== 'number'
            || typeof reactorDevice !== 'number'
            || typeof messageId !== 'number'
            || typeof messageType !== 'number'
            || typeof ciphertext !== 'string') {
            this.logger?.warn({ frame }, '[receive] malformed reaction_encrypted')
            return
        }
        // Own reaction echo, the bot already knows what it sent
        if (reactorId === this.botUserId) return

        // Decrypt the reaction. A failure (missing channel-key epoch, ratchet hiccup) is non-fatal,
        // surface the reaction anyway with unicode=null so the handler knows someone reacted
        let unicode: string | null = null
        try {
            let plaintext: Uint8Array
            if (messageType === 8) {
                if (!this.groups || typeof conversationId !== 'number') {
                    this.logger?.debug({ messageId }, '[receive] group reaction dropped: no GroupsFlow / convId')
                    return
                }
                plaintext = await this.groups.decryptGroupMessage(conversationId, ciphertext)
            } else if (messageType === 1 || messageType === 3) {
                plaintext = await this.signal.withPeerLock(
                    reactorId, reactorDevice,
                    () => this.signal.decrypt(reactorId, reactorDevice, messageType, ciphertext),
                )
            } else {
                // messageType 10 (self-AES) is never broadcast, anything else is unknown
                return
            }
            unicode = parseReactionUnicode(this.textDec.decode(plaintext))
        } catch (err) {
            this.logger?.warn(
                { messageId, reactorId, messageType, err: (err as Error).message },
                '[receive] reaction decrypt failed; emitting with unicode=null',
            )
        }

        const peer = await this.resolvePeer(reactorId).catch(() => null)
        this.emitter.emit({
            kind: 'reaction',
            payload: {
                messageId,
                clientMsgId,
                reactor: peer ?? { userId: reactorId, username: `user_${reactorId}`, displayName: null },
                unicode,
                added: true,
            },
        })
    }

    // reaction_removed: a member peeled their reaction off
    // No ciphertext rides along, so unicode is null and added is false
    private async onReactionRemovedFrame(frame: IncomingFrame): Promise<void> {
        const reactorId   = frame.reactorUserId
        const messageId   = frame.messageId
        const clientMsgId = typeof frame.clientMsgId === 'string' ? frame.clientMsgId : null
        if (typeof reactorId !== 'number' || typeof messageId !== 'number') {
            this.logger?.warn({ frame }, '[receive] malformed reaction_removed')
            return
        }
        if (reactorId === this.botUserId) return
        const peer = await this.resolvePeer(reactorId).catch(() => null)
        this.emitter.emit({
            kind: 'reaction',
            payload: {
                messageId,
                clientMsgId,
                reactor: peer ?? { userId: reactorId, username: `user_${reactorId}`, displayName: null },
                unicode: null,
                added: false,
            },
        })
    }


    // Group-chat / channel frames (v0.3)

    private async onGroupInbound(frame: IncomingFrame): Promise<void> {
        if (!this.groups) {
            this.logger?.debug({ messageType: frame.messageType }, '[receive] group-message dropped: GroupsFlow not wired')
            return
        }
        const senderId       = frame.senderId
        const senderDeviceId = frame.senderDeviceId
        const conversationId = frame.conversationId
        const ciphertext     = frame.ciphertext
        const messageId      = frame.id
        const clientMsgId    = typeof frame.clientMsgId === 'string' ? frame.clientMsgId : null

        if (typeof senderId !== 'number'
            || typeof senderDeviceId !== 'number'
            || typeof conversationId !== 'number'
            || typeof ciphertext !== 'string'
            || typeof messageId !== 'number') {
            this.logger?.warn({ frame }, '[receive] malformed group-chat/channel frame')
            return
        }

        // Own-echo guard already enforced by the parent onMessageFrame

        // Same dedup as the DM path: check before, record after success
        // A failed decrypt (missing epoch) is not recorded, so a server replay can recover once the key share lands
        // The fallback to the server message id covers a frame the sender sent without clientMsgId
        const dedupKey = clientMsgId !== null
            ? `c:${senderId}.${senderDeviceId}:${conversationId}:${clientMsgId}`
            : `s:${senderId}.${senderDeviceId}:${conversationId}:${messageId}`
        if (dedupKey && this.dedup.has(dedupKey)) {
            this.logger?.debug({ messageId, clientMsgId }, '[receive] deduped group replay')
            return
        }

        let plaintextBytes: Uint8Array
        try {
            plaintextBytes = await this.groups.decryptGroupMessage(conversationId, ciphertext)
        } catch (err) {
            // Usually means the channel-key for this epoch hasn't reached us yet
            // Lazy-fetch already ran inside decryptGroupMessage. Server replay on reconnect retries
            this.logger?.warn(
                {
                    conversationId, senderId, senderDeviceId,
                    err: (err as Error).message,
                },
                '[receive] group_message decrypt failed',
            )
            this.emitter.emit({
                kind:  'error',
                error: new Error(
                    `group decrypt failed for conv=${conversationId} msg=${messageId}: ${(err as Error).message}`,
                ),
            })
            return
        }
        if (dedupKey) this.dedup.record(dedupKey)

        if (typeof frame.kind === 'string' && PROTOCOL_KINDS.has(frame.kind)) {
            this.logger?.debug({ kind: frame.kind, senderId }, '[receive] dropped protocol envelope (group path, not user input)')
            return
        }

        // CHANNEL vs GROUP from the cached isChannel flag
        // Default GROUP when metadata isn't ready yet, it's only a hint
        // Post vs comment is signalled by threadRootId
        let conversationType: ConversationType = 'GROUP'
        if (this.convCache) {
            const info = this.convCache.peek(conversationId)
                ?? await this.convCache.load(conversationId).catch(() => null)
            if (info && info.isChannel) conversationType = 'CHANNEL'
        }

        const decoded = this.textDec.decode(plaintextBytes)
        if (isProtocolPayload(decoded)) {
            this.logger?.debug({ senderId }, '[receive] dropped protocol payload by type (group path, not user input)')
            return
        }
        const sniffed = sniffStructuredPayload(decoded)
        const text       = sniffed?.caption ?? (sniffed === null ? decoded : '')
        const attachment = sniffed?.attachment

        const peer = await this.resolvePeer(senderId).catch(() => null)
        if (!peer) {
            this.logger?.warn({ senderId }, '[receive] peer resolution failed; emitting with stub')
        }

        const createdAt = typeof frame.createdAt === 'string'
            ? new Date(frame.createdAt)
            : new Date()

        let attachmentObj: IncomingAttachment | undefined
        let galleryObj:    IncomingGallery    | undefined
        if (attachment) {
            attachmentObj = buildIncomingAttachment(attachment, () => downloadAttachment(this.http, attachment.ref, this.logger))
        } else if (sniffed?.gallery) {
            galleryObj = buildIncomingGallery(
                sniffed.gallery,
                (ref) => () => downloadAttachment(this.http, ref, this.logger),
            )
        }

        const baseMsg: IncomingMessage = {
            messageId:        messageId,
            conversationId:   conversationId,
            conversationType,
            sender:           peer ?? { userId: senderId, username: `user_${senderId}`, displayName: null },
            senderDeviceId:   senderDeviceId,
            text,
            ...(attachmentObj ? { attachment: attachmentObj } : {}),
            ...(galleryObj    ? { gallery:    galleryObj }    : {}),
            clientMsgId,
            replyToId:      typeof frame.replyToId    === 'number' ? frame.replyToId    : null,
            threadRootId:   typeof frame.threadRootId === 'number' ? frame.threadRootId : null,
            createdAt,
        }

        // Group commands work identically to DM commands: same regex, same dispatch
        // The developer's handler distinguishes by `conversationType` if they want different behaviour
        const parsed = parseCommand(text)
        if (parsed) {
            const cmd: CommandInvocation = {
                ...baseMsg,
                command: parsed.command,
                args:    parsed.args,
                argv:    parsed.argv,
            }
            this.emitter.emit({ kind: 'command', payload: cmd })
            return
        }
        this.emitter.emit({ kind: 'message', payload: baseMsg })
    }


    private async onConversationAddedFrame(frame: IncomingFrame): Promise<void> {
        if (!this.groups) return
        const conversationId = frame.conversationId
        const conv           = (frame as { conversation?: {
            id: unknown
            isChannel?: boolean
            isGroup?: boolean
            title?: string | null
        } }).conversation
        if (typeof conversationId !== 'number' || !conv || typeof conv.id !== 'number') {
            this.logger?.warn({ frame }, '[receive] malformed conversation_added')
            return
        }
        // The server publishes conversation_added for DM-creation too (peer just hit /start)
        // The bot already handles those via bot_started, for v0.3 we only react to GROUP/CHANNEL adds
        const isChannel = conv.isChannel === true
        const isGroup   = conv.isGroup   === true || isChannel
        if (!isGroup) return

        // Prime three caches in parallel:
        //  - channel-key epochs (per-device wraps and sealed bundles)
        //  - conv-cache (isChannel + canPost metadata)
        //  - group_secret (sealedBundle fallback for epochs where the per-device wrap didn't reach us)
        //
        // group_secret install runs first so the channel-key install can use sealed bundles in the same call
        await this.groups.installGroupSecret(conversationId).catch(err => {
            this.logger?.warn(
                { conversationId, err: (err as Error).message },
                '[receive] group_secret install on conversation_added failed',
            )
        })
        await Promise.all([
            this.groups.installFromServer(conversationId, { sinceEpoch: -1 }).catch(err => {
                this.logger?.warn(
                    { conversationId, err: (err as Error).message },
                    '[receive] channel-key install on conversation_added failed',
                )
            }),
            this.convCache?.load(conversationId).catch(err => {
                this.logger?.warn(
                    { conversationId, err: (err as Error).message },
                    '[receive] conv-cache load on conversation_added failed',
                )
            }) ?? Promise.resolve(),
        ])

        const addedAtStr  = (frame as { addedAt?: unknown }).addedAt
        const addedAtDate = typeof addedAtStr === 'string' ? new Date(addedAtStr) : new Date()
        this.emitter.emit({
            kind: 'conversation_added',
            payload: {
                conversationId,
                conversationType: isChannel ? 'CHANNEL' : 'GROUP',
                title:            typeof conv.title === 'string' ? conv.title : null,
                addedAt:          addedAtDate,
            },
        })
    }


    private async onConversationKickedFrame(frame: IncomingFrame): Promise<void> {
        const conversationId = frame.conversationId
        const reasonStr      = (frame as { reason?: string }).reason
        const actor          = (frame as { actorUserId?: unknown }).actorUserId
        if (typeof conversationId !== 'number') {
            this.logger?.warn({ frame }, '[receive] malformed conversation_kicked')
            return
        }
        const reason = reasonStr === 'left' ? 'left' : 'kicked'
        // Drop channel-key state and conv-cache so a re-add under a fresh joined_secret_version starts clean
        // Stores tolerate missing files, a double-kick is safe
        if (this.groups) {
            try {
                await this.groups.forgetConversation(conversationId)
            } catch (err) {
                this.logger?.warn(
                    { conversationId, err: (err as Error).message },
                    '[receive] forgetConversation failed',
                )
            }
        }
        this.convCache?.drop(conversationId)
        this.emitter.emit({
            kind: 'conversation_kicked',
            payload: {
                conversationId,
                reason,
                actorUserId: typeof actor === 'number' ? actor : null,
                removedAt:   new Date(),
            },
        })
    }


    private onMemberUpdatedFrame(frame: IncomingFrame): void {
        // A member's role/permissions changed. We only care when the target is the bot
        // ConvCache's cached myRole/canPost would otherwise stay stale until the next membership change
        // The server re-checks role authoritatively on every send, so this is purely a freshness fix
        // Drop the cache entry so the next send re-fetches our role
        const conversationId = frame.conversationId
        if (typeof conversationId !== 'number') return
        const memberUserId = frame.memberUserId
        if (typeof memberUserId !== 'number' || memberUserId !== this.botUserId) return
        this.convCache?.invalidate(conversationId)
    }

    private onGroupUpdatedFrame(frame: IncomingFrame): void {
        // A conversation-level setting changed (e.g. defaultCanPost, commentsEnabled)
        // ConvCache derives a member-role bot's canPost from the conv's defaultCanPost, which member_updated
        // doesn't cover, so a flip would otherwise leave a stale-high canPost and the bot keeps attempting posts
        // the server now rejects. Invalidate unconditionally (group_updated is rare, the next send re-fetches once)
        // The server re-checks authoritatively, so this is purely a freshness fix
        const conversationId = frame.conversationId
        if (typeof conversationId !== 'number') return
        this.convCache?.invalidate(conversationId)
    }


    private async onMemberCountChangedFrame(frame: IncomingFrame): Promise<void> {
        // Roles/canPost can shift on membership changes, invalidate the conv-cache so the next send re-fetches
        const conversationId = frame.conversationId
        if (typeof conversationId !== 'number') return
        this.convCache?.invalidate(conversationId)

        // Opt-in auto-backfill on join. Fire-and-forget, errors go to the bot's error event
        // Server's joined_secret_version filter prevents pre-join leakage
        if (!this.opts.autoBackfillOnJoin) return
        if (!this.groups) return
        const change = (frame as { change?: { kind?: string; userId?: number } }).change
        if (!change || change.kind !== 'added') return
        if (typeof change.userId !== 'number' || change.userId === this.botUserId) return

        const newUserId = change.userId
        const groups    = this.groups
        const p = groups.backfillChannelKeys(conversationId, { userId: newUserId })
            .then(({ accepted }) => {
                this.logger?.info(
                    { conversationId, newUserId, accepted },
                    '[receive] auto-backfill on join complete',
                )
            })
            .catch((err: unknown) => {
                this.logger?.warn(
                    {
                        conversationId, newUserId,
                        err: (err as Error).message,
                    },
                    '[receive] auto-backfill on join failed',
                )
                this.emitter.emit({
                    kind:  'error',
                    error: new Error(`auto-backfill failed for conv=${conversationId} user=${newUserId}: ${(err as Error).message}`),
                })
            })
        // Register with GroupsFlow so shutdown() can drop the reference
        groups.trackBackfill(p)
    }


    private async onChannelKeyBackfillRequestFrame(frame: IncomingFrame): Promise<void> {
        if (!this.opts.serveBackfillRequests) return
        if (!this.groups) return
        const conversationId    = frame.conversationId
        const recipientUserId   = frame.recipientUserId
        const recipientDeviceId = frame.recipientDeviceId
        if (typeof conversationId    !== 'number'
            || typeof recipientUserId   !== 'number'
            || typeof recipientDeviceId !== 'number') {
            this.logger?.warn({ frame }, '[receive] malformed channel_key_backfill_request')
            return
        }
        if (recipientUserId === this.botUserId) return

        const key  = `${conversationId}:${recipientUserId}:${recipientDeviceId}`
        const now  = Date.now()
        const last = this.backfillReqThrottle.get(key)
        if (last !== undefined && now - last < BACKFILL_REQ_THROTTLE_MS) {
            this.logger?.debug(
                { conversationId, recipientUserId, recipientDeviceId },
                '[receive] channel_key_backfill_request throttled',
            )
            return
        }
        this.pruneBackfillThrottle(now)
        this.backfillReqThrottle.set(key, now)

        const groups = this.groups
        const p = groups.backfillChannelKeys(
            conversationId,
            { userId: recipientUserId, deviceIds: [recipientDeviceId] },
        )
            .then(({ accepted }) => {
                this.logger?.info(
                    { conversationId, recipientUserId, recipientDeviceId, accepted },
                    '[receive] served channel_key_backfill_request',
                )
            })
            .catch((err: unknown) => {
                this.logger?.warn(
                    {
                        conversationId, recipientUserId, recipientDeviceId,
                        err: (err as Error).message,
                    },
                    '[receive] channel_key_backfill_request: backfill failed',
                )
                this.emitter.emit({
                    kind:  'error',
                    error: new Error(
                        `backfill_request failed for conv=${conversationId} ` +
                        `user=${recipientUserId}.${recipientDeviceId}: ${(err as Error).message}`,
                    ),
                })
            })
        groups.trackBackfill(p)
    }

    private pruneBackfillThrottle(now: number): void {
        if (this.backfillReqThrottle.size < BACKFILL_REQ_THROTTLE_MAX) return
        for (const [k, t] of this.backfillReqThrottle) {
            if (now - t >= BACKFILL_REQ_THROTTLE_MS) this.backfillReqThrottle.delete(k)
        }
        while (this.backfillReqThrottle.size >= BACKFILL_REQ_THROTTLE_MAX) {
            const oldest = this.backfillReqThrottle.keys().next().value
            if (oldest === undefined) break
            this.backfillReqThrottle.delete(oldest)
        }
    }


    private async onChannelKeyRotatedFrame(frame: IncomingFrame): Promise<void> {
        if (!this.groups) return
        const conversationId = frame.conversationId
        const epoch          = (frame as { epoch?: unknown }).epoch
        if (typeof conversationId !== 'number' || typeof epoch !== 'number') {
            this.logger?.warn({ frame }, '[receive] malformed channel_key_rotated')
            return
        }
        // since=epoch-1 ensures the server includes this new epoch (default sinceEpoch=local_max could skip it)
        // decryptGroupMessage's lazy fetch covers misses too, this is a latency optimisation
        try {
            await this.groups.installFromServer(conversationId, {
                sinceEpoch: Math.max(-1, epoch - 1),
            })
        } catch (err) {
            this.logger?.warn(
                { conversationId, epoch, err: (err as Error).message },
                '[receive] channel-key install on rotation failed',
            )
        }
    }


    // Peer resolution + caching

    async resolvePeer(userId: number): Promise<Peer> {
        const cached = this.peerCache.get(userId)
        if (cached && Date.now() - cached.fetched < PEER_CACHE_TTL_MS) {
            return cached.peer
        }
        const res = await this.http.get<UsersIdResponse>(`/users/id/${userId}`)
        const u   = res.data.user
        const peer: Peer = {
            userId:      u.id,
            username:    u.username,
            displayName: u.displayName,
        }
        this.peerCache.set(userId, { peer, fetched: Date.now() })
        while (this.peerCache.size > PEER_CACHE_MAX) {
            const oldest = this.peerCache.keys().next().value
            if (oldest === undefined) break
            this.peerCache.delete(oldest)
        }
        return peer
    }

}


// Reaction payload

// Reaction plaintext is JSON `{ emoji }`. The wire key stays `emoji` (cross-client contract),
// though a reaction is any unicode string (a legacy thing)
// Returns that string, or null on a malformed/oversized/empty payload
function parseReactionUnicode(plaintext: string): string | null {
    if (plaintext.length === 0 || plaintext.length > 512) return null
    let parsed: unknown
    try { parsed = JSON.parse(plaintext) }
    catch { return null }
    if (!parsed || typeof parsed !== 'object') return null
    const e = (parsed as { emoji?: unknown }).emoji
    return typeof e === 'string' && e.length > 0 && e.length <= 64 ? e : null
}


// Command parser

// Mirrors the server's command-name regex, SDK never emits a CommandInvocation the server wouldn't accept
const COMMAND_LINE_RE = /^\/([a-z][a-z0-9_]{0,31})(?:\s+([\s\S]*))?$/

interface ParsedCommand {
    command: string
    args:    string
    argv:    string[]
}

/** Parsed command if the text is a single line matching the grammar, null otherwise
 * Multi-line messages aren't commands */
function parseCommand(text: string): ParsedCommand | null {
    // Multi-line bails out before regex work
    if (text.includes('\n')) return null
    const m = COMMAND_LINE_RE.exec(text.trim())
    if (!m) return null
    const args = (m[2] ?? '').trim()
    const argv = args.length === 0 ? [] : args.split(/\s+/)
    return { command: m[1] as string, args, argv }
}


// Internal exports for unit tests, not in index.ts
export const _parseCommand = parseCommand
export const _parseReactionUnicode = parseReactionUnicode


// Structured-payload sniff (file / voice / video_note)

interface ParsedAttachment {
    kind:     'file' | 'voice' | 'video_note'
    ref:      EncryptedFileRef
    duration?: number
    waveform?: number[]
    shape?:   VideoNoteShape
}

interface ParsedGallery {
    items:    GalleryItem[]
}

interface SniffResult {
    /** Caption / text from 'file' / 'gallery' payload, empty for voice/video_note */
    caption?:   string
    /** Single-attachment payload. Mutually exclusive with `gallery` */
    attachment?: ParsedAttachment
    /** Multi-attachment gallery (2..10 items). Mutually exclusive with `attachment` */
    gallery?:    ParsedGallery
}

/** Decide whether plaintext is a known structured payload or just text. null = text
 * Never throws, a malformed JSON envelope falls through as text */
function sniffStructuredPayload(plaintext: string): SniffResult | null {
    // Anything not starting with { is text
    if (plaintext.length === 0 || plaintext.charCodeAt(0) !== 0x7b /* `{` */) {
        return null
    }
    let parsed: unknown
    try { parsed = JSON.parse(plaintext) }
    catch { return null }
    if (!parsed || typeof parsed !== 'object') return null
    const p = parsed as Record<string, unknown>
    const type = p.type
    if (type === 'file') {
        if (!isEncryptedFileRef(p.ref)) return null
        const caption = typeof p.caption === 'string' ? p.caption : ''
        return {
            caption,
            attachment: { kind: 'file', ref: p.ref },
        }
    }
    if (type === 'voice') {
        if (!isEncryptedFileRef(p.ref)) return null
        const duration = typeof p.duration === 'number' && isFinite(p.duration) && p.duration > 0
            ? Math.min(p.duration, 600) : 0
        const waveform: number[] = Array.isArray(p.waveform)
            ? (p.waveform as unknown[])
                .filter((n): n is number => typeof n === 'number' && isFinite(n))
                .slice(0, 64)
                .map(n => {
                    const v = Math.round(n)
                    return v < 0 ? 0 : v > 100 ? 100 : v
                })
            : []
        return {
            attachment: { kind: 'voice', ref: p.ref, duration, waveform },
        }
    }
    if (type === 'video_note') {
        if (!isEncryptedFileRef(p.ref)) return null
        const duration = typeof p.duration === 'number' && isFinite(p.duration) && p.duration > 0
            ? Math.min(p.duration, 300) : 0
        // The shape is an open string, the receiver decides what it renders and unknown names become circle
        // Bound it to a short alphanumeric token so a sender cannot inject arbitrary content
        const shape: VideoNoteShape =
            (typeof p.shape === 'string' && /^[a-zA-Z0-9]{1,32}$/.test(p.shape))
                ? (p.shape as VideoNoteShape)
                : 'circle'
        return {
            attachment: { kind: 'video_note', ref: p.ref, duration, shape },
        }
    }
    if (type === 'gallery') {
        if (!Array.isArray(p.items)) return null
        // Drop malformed items but keep the gallery. If too few valid items remain, fall through as text
        const items: GalleryItem[] = []
        for (const raw of p.items) {
            const it = parseGalleryItem(raw)
            if (it) items.push(it)
        }
        if (items.length < GALLERY_MIN_ITEMS) return null
        // Truncate hostile-sized galleries, sniffer is pure so no logger handy
        if (items.length > GALLERY_MAX_ITEMS) {
            items.length = GALLERY_MAX_ITEMS
        }
        const caption = typeof p.caption === 'string' ? p.caption : ''
        return {
            caption,
            gallery: { items },
        }
    }
    // Unknown structured type, fall through as text
    return null
}


/** ParsedAttachment + download closure -> IncomingAttachment */
function buildIncomingAttachment(
    parsed:   ParsedAttachment,
    download: () => Promise<Buffer>,
): IncomingAttachment {
    const base: IncomingAttachment = {
        kind:     parsed.kind,
        fileId:   parsed.ref.fileId,
        sha256:   parsed.ref.sha256,
        mime:     parsed.ref.mime,
        size:     parsed.ref.size,
        name:     parsed.ref.name ?? null,
        virusTotalVerdict: null,
        download,
    }
    if (parsed.duration !== undefined) base.duration = parsed.duration
    if (parsed.waveform !== undefined) base.waveform = parsed.waveform
    if (parsed.shape !== undefined)    base.shape    = parsed.shape
    return base
}


/** Build an IncomingGallery from a parsed payload */
function buildIncomingGallery(
    parsed: ParsedGallery,
    makeDownload: (ref: EncryptedFileRef) => () => Promise<Buffer>,
): IncomingGallery {
    const items: IncomingGalleryItem[] = parsed.items.map(it => {
        if (it.type === 'file') {
            const fileAtt: ParsedAttachment = { kind: 'file', ref: it.ref }
            return { kind: 'file', attachment: buildIncomingAttachment(fileAtt, makeDownload(it.ref)) }
        }
        if (it.type === 'contact') {
            const out: IncomingGalleryItem = { kind: 'contact', userId: it.userId }
            if (it.username    !== undefined) out.username    = it.username
            if (it.displayName !== undefined) out.displayName = it.displayName
            if (it.avatarUrl   !== undefined) out.avatarUrl   = it.avatarUrl
            if (it.avatarEmoji !== undefined) out.avatarUnicode = it.avatarEmoji
            return out
        }
        return { kind: 'location', lat: it.lat, lng: it.lng }
    })
    return { items }
}


function isProtocolPayload(plaintext: string): boolean {
    if (plaintext.length === 0 || plaintext.charCodeAt(0) !== 0x7b) return false
    let parsed: unknown
    try { parsed = JSON.parse(plaintext) } catch { return false }
    if (!parsed || typeof parsed !== 'object') return false
    const t = (parsed as { type?: unknown }).type
    return typeof t === 'string' && t.startsWith('morok_') && t !== 'morok_bot_action'
}

// Internal exports for unit tests
function parseBotAction(plaintext: string): { controlId: string } | null {
    if (plaintext.length === 0 || plaintext.charCodeAt(0) !== 0x7b) return null
    let parsed: unknown
    try { parsed = JSON.parse(plaintext) } catch { return null }
    if (!parsed || typeof parsed !== 'object') return null
    const p = parsed as Record<string, unknown>
    if (p.type !== 'morok_bot_action') return null
    if (typeof p.controlId !== 'string' || p.controlId.length === 0) return null
    return { controlId: p.controlId }
}

export const _sniffStructuredPayload = sniffStructuredPayload
export const _buildIncomingAttachment = buildIncomingAttachment
