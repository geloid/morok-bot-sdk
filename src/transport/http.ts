/**
 * Axios wrapper. Mints a JWT via /auth/bot-session at construction and again on 401 (one retry per request),
 * dedupes concurrent refreshes so a flood of 401s collapses to one round-trip, and does not retry non-401s
 * Flow modules call .get/.post directly, the shared axios instance adds the Bearer token via an interceptor
 */

import axios, {
    AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse,
} from 'axios'
import type { SdkLogger } from '../types.js'


export interface HttpClientConfig {
    apiBaseUrl: string
    /** Raw bot token: `bot:<id>:<secret>`. Used to mint JWTs */
    botToken:   string
    logger?:    SdkLogger
    /** Fires on every successful mint, the SDK uses it for the WS auth frame and proactive-refresh bookkeeping */
    onJwtRefreshed?: (jwt: string, expiresAt: number) => void
}

export interface BotSessionResult {
    token:    string
    userId:   number
    username: string
    deviceId: number
}


export class HttpClient {
    readonly axios: AxiosInstance
    private jwt:            string | null = null
    private jwtExpiresAt:   number        = 0   // unix ms
    private refreshInFlight: Promise<void> | null = null

    constructor(private readonly config: HttpClientConfig) {
        this.axios = axios.create({
            baseURL: config.apiBaseUrl,
            // Flow modules override per-request for long uploads
            timeout: 30_000,
            // 4xx/5xx -> error so the catch arm can pattern-match on status
            validateStatus: (s) => s >= 200 && s < 300,
            // Cap how much a hostile server can buffer off the socket
            // Axios' Node default is unlimited (-1), so a malicious server could stream a multi-GB body and OOM the bot
            // 64 MB is far above any legitimate JSON response
            // The attachment path overrides this per-request with a tight bound from the ref's declared size
            // (flow/attachments.ts fetchCiphertextBytes)
            maxContentLength: 64 * 1024 * 1024,
            maxBodyLength:    64 * 1024 * 1024,
        })

        // Inject the current JWT on every request
        this.axios.interceptors.request.use((cfg) => {
            if (this.jwt) {
                cfg.headers = cfg.headers ?? {}
                cfg.headers.Authorization = `Bearer ${this.jwt}`
            }
            return cfg
        })

        // On 401, mint a fresh JWT and retry the original request once. A second 401 bubbles up unchanged
        this.axios.interceptors.response.use(
            (r) => r,
            async (err: AxiosError) => {
                if (!err.config) throw err
                const status = err.response?.status
                const cfg = err.config as AxiosRequestConfig & { _retried?: boolean }
                if (status === 401 && !cfg._retried) {
                    cfg._retried = true
                    try {
                        await this.refresh()
                    } catch (refreshErr) {
                        this.logger?.warn(
                            { err: (refreshErr as Error).message },
                            '[http] JWT refresh failed during 401 retry',
                        )
                        throw err
                    }
                    return this.axios.request(cfg)
                }
                throw err
            },
        )
    }

    private get logger(): SdkLogger | undefined { return this.config.logger }

    /** Force a fresh /auth/bot-session
     * Concurrent callers share one in-flight promise, so parallel mints don't pile up */
    async refresh(): Promise<void> {
        if (this.refreshInFlight) return this.refreshInFlight
        this.refreshInFlight = this.doRefresh()
            .finally(() => { this.refreshInFlight = null })
        return this.refreshInFlight
    }

    /** Parse JWT exp into a unix-ms expiry
     * Malformed JWT -> 0, which disables proactive refresh, the 401 retry path still works */
    private updateExpiryFromJwt(jwt: string): void {
        try {
            const body = jwt.split('.')[1] ?? ''
            // Buffer accepts 'base64url' natively on Node 16+.
            const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as { exp?: number }
            this.jwtExpiresAt = typeof claims.exp === 'number' ? claims.exp * 1000 : 0
        } catch {
            this.jwtExpiresAt = 0
        }
    }

    /** Validate the /auth/bot-session response shape,
     *  so a malformed 200 doesn't leave us with an undefined JWT and NPEs downstream */
    private extractSession(data: unknown): BotSessionResult {
        if (!data || typeof data !== 'object') {
            throw new Error('/auth/bot-session: response body is not an object')
        }
        const d = data as Record<string, unknown>
        if (typeof d.token !== 'string' || d.token.length === 0) {
            throw new Error('/auth/bot-session: missing or empty `token`')
        }
        if (typeof d.userId !== 'number' || !Number.isInteger(d.userId) || d.userId < 1) {
            throw new Error('/auth/bot-session: missing or invalid `userId`')
        }
        if (typeof d.username !== 'string' || d.username.length === 0) {
            throw new Error('/auth/bot-session: missing or empty `username`')
        }
        if (typeof d.deviceId !== 'number' || !Number.isInteger(d.deviceId)) {
            throw new Error('/auth/bot-session: missing or invalid `deviceId`')
        }
        return { token: d.token, userId: d.userId, username: d.username, deviceId: d.deviceId }
    }

    private async doRefresh(): Promise<void> {
        // Use raw axios to bypass our request interceptor, /auth/bot-session takes the token in the body
        const res = await axios.post(
            `${this.config.apiBaseUrl}/auth/bot-session`,
            { token: this.config.botToken, deviceName: 'bot-sdk', platform: 'bot' },
            { timeout: 30_000 },
        )
        const session = this.extractSession(res.data)
        this.jwt = session.token
        this.updateExpiryFromJwt(this.jwt)

        this.config.onJwtRefreshed?.(this.jwt, this.jwtExpiresAt)
        this.logger?.debug(
            { userId: session.userId, expiresAt: new Date(this.jwtExpiresAt).toISOString() },
            '[http] minted bot-session JWT',
        )
    }

    /** First mint. Returns the session payload so the caller can cache userId / username / deviceId */
    async initialMint(): Promise<BotSessionResult> {
        const res = await axios.post(
            `${this.config.apiBaseUrl}/auth/bot-session`,
            { token: this.config.botToken, deviceName: 'bot-sdk', platform: 'bot' },
            { timeout: 30_000 },
        )
        const session = this.extractSession(res.data)
        this.jwt = session.token
        this.updateExpiryFromJwt(this.jwt)

        this.config.onJwtRefreshed?.(this.jwt, this.jwtExpiresAt)
        this.logger?.info(
            { userId: session.userId, username: session.username },
            '[http] bot-session established',
        )
        return session
    }

    getJwt(): string | null {
        return this.jwt
    }

    /** True when the current JWT is within skewMs of expiry, called from the background loop */
    needsProactiveRefresh(skewMs: number = 5 * 60 * 1000): boolean {
        if (!this.jwt || this.jwtExpiresAt === 0) return false
        return Date.now() + skewMs >= this.jwtExpiresAt
    }


    // Endpoint helpers

    async get<T>(url: string, cfg?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
        return this.axios.get<T>(url, cfg)
    }
    async post<T>(url: string, body?: unknown, cfg?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
        return this.axios.post<T>(url, body, cfg)
    }
}
