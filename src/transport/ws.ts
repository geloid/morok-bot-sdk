/**
 * Single long-lived WebSocket with exponential-backoff reconnect, an auth frame on every connect,
 * and a send queue while disconnected
 *
 * Server contract:
 *   - client opens GET /ws and sends { type: 'auth', token, deviceId, locale } within 5s, server replies
 *     { type: 'ready' } or { type: 'error' } + close
 *   - after ready, either side sends arbitrary frames
 *   - server pings every 30s, client pongs, idle timeout 90s
 *   - on JWT revoke the server closes with 4001, SDK refreshes the JWT before reconnecting
 *
 * Send queue holds at most 1000 frames while disconnected and drains on the next ready, oldest dropped on overflow
 */

import { EventEmitter } from 'node:events'
import WebSocket        from 'ws'
import type { SdkLogger } from '../types.js'


export interface WsClientConfig {
    wsUrl:    string
    deviceId: number
    getJwt:   () => string | null
    /** Force a JWT refresh, called on code 4001 / auth errors */
    refreshJwt: () => Promise<void>
    logger?:  SdkLogger
}


export interface IncomingFrame {
    type: string
    [key: string]: unknown
}

interface WsEvents {
    frame:      (frame: IncomingFrame) => void
    open:       () => void
    close:      (info: { code: number; reason: string; willReconnect: boolean }) => void
    error:      (err: Error) => void
    /** Fires once the server's `ready` lands. open alone isn't enough, the server can reject the auth frame */
    ready:      () => void
}


const MAX_QUEUE        = 1000
const RECONNECT_MIN_MS = 500
const RECONNECT_MAX_MS = 30_000
const AUTH_TIMEOUT_MS  = 10_000


export class WsClient extends EventEmitter {
    private socket?:        WebSocket
    private sendQueue:      string[] = []
    private connected      = false
    private authed         = false
    private shuttingDown   = false
    private reconnectAttempts = 0
    private reconnectTimer?: NodeJS.Timeout
    private authTimer?:      NodeJS.Timeout

    constructor(private readonly config: WsClientConfig) { super() }

    get isConnected(): boolean { return this.authed }

    /** Open the socket. Resolves on the first ready */
    async start(): Promise<void> {
        // Bail if already connected, shutting down, or mid-handshake
        // A second parallel start() just resolves, the first caller's promise drives the handshake
        if (this.connected || this.shuttingDown || this.socket) return
        return new Promise<void>((resolve, reject) => {
            const onReady = () => {
                this.off('ready', onReady)
                this.off('error', onError)
                resolve()
            }
            const onError = (err: Error) => {
                this.off('ready', onReady)
                this.off('error', onError)
                reject(err)
            }
            this.on('ready', onReady)
            this.on('error', onError)
            this.openSocket()
        })
    }

    /** Clean close. Won't reconnect */
    stop(): void {
        this.shuttingDown = true
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer)
            this.reconnectTimer = undefined
        }
        if (this.authTimer) {
            clearTimeout(this.authTimer)
            this.authTimer = undefined
        }
        if (this.socket && this.socket.readyState <= WebSocket.OPEN) {
            try { this.socket.close(1000, 'sdk shutdown') } catch { /* ignore */ }
        }
        this.socket = undefined
        this.connected = false
        this.authed = false
        // Drop unsent frames so a future restart doesn't flush stale frames onto a new session
        this.sendQueue = []
    }

    /** Send a frame. If authed, dispatched directly, otherwise queued. Best-effort, no application-level ack */
    send(frame: object): void {
        let payload: string
        try {
            payload = JSON.stringify(frame)
        } catch (err) {
            // send() is best-effort, so a non-serializable frame (BigInt or circular ref) is logged and dropped,
            // the caller gets no synchronous throw
            this.config.logger?.warn(
                { err: (err as Error).message },
                '[ws] send: frame not JSON-serializable, dropping',
            )
            return
        }
        if (this.authed && this.socket?.readyState === WebSocket.OPEN) {
            this.socket.send(payload)
            return
        }
        if (this.sendQueue.length >= MAX_QUEUE) {
            const dropped = this.sendQueue.shift()
            this.config.logger?.warn(
                { dropped: dropped?.slice(0, 80), queue: this.sendQueue.length },
                '[ws] send queue overflow, dropping oldest frame',
            )
        }
        this.sendQueue.push(payload)
    }


    // Open + auth lifecycle

    private openSocket(): void {
        const url = this.config.wsUrl
        this.config.logger?.debug({ url }, '[ws] opening socket')

        const socket = new WebSocket(url)
        this.socket  = socket

        socket.on('open', () => {
            this.connected = true
            this.reconnectAttempts = 0
            this.config.logger?.debug({}, '[ws] socket open, sending auth frame')

            const jwt = this.config.getJwt()
            if (!jwt) {
                socket.close(4001, 'no-jwt')
                return
            }

            // socket.send can throw if the socket closed between 'open' and now (server kicks right after upgrade)
            // An unhandled throw kills the process, so close and reconnect instead
            try {
                socket.send(JSON.stringify({
                    type:     'auth',
                    token:    jwt,
                    deviceId: this.config.deviceId,
                    locale:   'en',
                }))
            } catch (err) {
                this.config.logger?.warn(
                    { err: (err as Error).message },
                    '[ws] auth-frame send threw; falling through to reconnect',
                )
                try { socket.close(4003, 'auth-send-failed') } catch { /* ignore */ }
                return
            }

            this.authTimer = setTimeout(() => {
                this.config.logger?.warn({}, '[ws] auth timeout, closing socket')
                try { socket.close(4002, 'auth-timeout') } catch { /* ignore */ }
            }, AUTH_TIMEOUT_MS)
            this.emit('open')
        })

        socket.on('message', (data) => {
            let parsed: unknown
            try {
                parsed = JSON.parse(data.toString('utf8'))
            } catch (err) {
                this.config.logger?.warn({ err: (err as Error).message }, '[ws] non-JSON frame, dropping')
                return
            }
            if (!parsed || typeof parsed !== 'object' || typeof (parsed as { type?: unknown }).type !== 'string') {
                this.config.logger?.warn({ frame: parsed }, '[ws] frame missing type')
                return
            }
            const frame = parsed as IncomingFrame

            // Server pings every 30s and drops idle sockets at 90s, pong or the socket closes each cycle
            if (frame.type === 'ping') {
                if (this.socket?.readyState === WebSocket.OPEN) {
                    try { this.socket.send(JSON.stringify({ type: 'pong' })) }
                    catch (err) {
                        this.config.logger?.warn(
                            { err: (err as Error).message },
                            '[ws] pong send failed; close handler will reconnect',
                        )
                    }
                }
                // Don't surface ping to flow modules
                return
            }

            // First post-auth frame: drain queued sends, signal ready
            if (!this.authed && frame.type === 'ready') {
                if (this.authTimer) { clearTimeout(this.authTimer); this.authTimer = undefined }
                this.authed = true
                this.config.logger?.info({}, '[ws] auth complete, draining send queue')
                while (this.sendQueue.length > 0 && this.socket?.readyState === WebSocket.OPEN) {
                    const payload = this.sendQueue.shift()!
                    this.socket.send(payload)
                }
                this.emit('ready')
                return
            }

            if (!this.authed && frame.type === 'error') {
                this.config.logger?.warn({ frame }, '[ws] auth-frame error from server')
                // Reconnect via the close handler below
            }

            this.emit('frame', frame)
        })

        socket.on('close', (code, reasonBuf) => {
            const reason = reasonBuf?.toString('utf8') ?? ''
            const wasAuthed = this.authed
            this.connected = false
            this.authed    = false
            this.socket    = undefined
            if (this.authTimer) { clearTimeout(this.authTimer); this.authTimer = undefined }

            const willReconnect = !this.shuttingDown
            this.config.logger?.info(
                { code, reason, willReconnect, wasAuthed },
                '[ws] socket closed',
            )
            this.emit('close', { code, reason, willReconnect })

            if (!willReconnect) return

            // Code 4001 = session ticket revoked. Refresh the JWT before reconnecting,
            // otherwise we reconnect with the same dead token, get 4001 again, and tight-loop
            if (code === 4001) {
                this.config.logger?.info({}, '[ws] code 4001 - refreshing JWT before reconnect')
                this.config.refreshJwt()
                    .catch(err => {
                        this.config.logger?.warn(
                            { err: (err as Error).message },
                            '[ws] JWT refresh failed; will retry via reconnect',
                        )
                    })
                    .finally(() => {
                        // Reconnect regardless, the next attempt refreshes again after backoff
                        this.scheduleReconnect()
                    })
                return
            }
            this.scheduleReconnect()
        })

        socket.on('error', (err) => {
            this.config.logger?.warn({ err: err.message }, '[ws] socket error')
            this.emit('error', err)
            // 'close' fires after 'error', reconnect logic is there
        })
    }

    private scheduleReconnect(): void {
        if (this.shuttingDown || this.reconnectTimer) return
        const base = Math.min(
            RECONNECT_MAX_MS,
            RECONNECT_MIN_MS * Math.pow(2, this.reconnectAttempts),
        )
        // Equal jitter ([base/2, base]) so a fleet of bots bounced by one backend does not reconnect in lockstep
        // on the identical 500/1000/.../30000 schedule
        const delay = Math.floor(base / 2 + Math.random() * (base / 2))
        this.reconnectAttempts++
        this.config.logger?.debug(
            { delayMs: delay, attempt: this.reconnectAttempts },
            '[ws] scheduling reconnect',
        )
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = undefined
            this.openSocket()
        }, delay)
    }


    // Typed event API

    override on<K extends keyof WsEvents>(event: K, listener: WsEvents[K]): this {
        return super.on(event, listener as (...args: unknown[]) => void)
    }
    override off<K extends keyof WsEvents>(event: K, listener: WsEvents[K]): this {
        return super.off(event, listener as (...args: unknown[]) => void)
    }
    override emit<K extends keyof WsEvents>(event: K, ...args: Parameters<WsEvents[K]>): boolean {
        return super.emit(event, ...args)
    }
}
