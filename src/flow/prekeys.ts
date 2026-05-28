/**
 * Prekey pool maintenance. Three triggers:
 *   - boot: once after MorokBot.start() lands, tops up the OTPK pool and rotates SPK if the server says so
 *   - background tick: every backgroundIntervalMs (default 5 min)
 *   - on-demand: from a flow module that hit a peer-side prekey error
 *
 * Server:
 *   GET  /prekeys/count?deviceId=1  -> { count, shouldRotateSignedPreKey }
 *   POST /prekeys/replenish         body { deviceId, signedPreKey?, oneTimePreKeys? }
 *
 * OTPK ids are monotonic in state.json. The server caps at 200 per call and we keep target below that,
 * so one request fits one batch, and a UNIQUE(user_id, device_id, key_id) bounces a stray duplicate
 * SPK rotation bumps nextSignedPreKeyId and the rotation ts
 * The old SPK row stays on disk, libsignal needs it to decrypt in-flight type-3 frames addressed to the old keyId
 */

import type { HttpClient }   from '../transport/http.js'
import type { SignalEngine } from '../crypto/signal.js'
import type { FileSignalStore } from '../crypto/stores.js'
import type { SdkLogger }    from '../types.js'


const HARD_TARGET_CAP = 200
// 24-bit OTPK id space, rollover at 1k/day takes ~46 years
const OTPK_ID_MAX = 0x00FFFFFF


export interface PreKeyManagerConfig {
    deviceId:              number  // always 1 for bots
    replenishThreshold:    number
    replenishTarget:       number
    backgroundIntervalMs:  number
    logger?:               SdkLogger
}


interface PrekeyCountResponse {
    count:                    number
    shouldRotateSignedPreKey: boolean
}


export class PreKeyManager {
    private timer?:         NodeJS.Timeout
    private running        = false
    private inFlightCheck?: Promise<void>

    constructor(
        private readonly http:   HttpClient,
        private readonly signal: SignalEngine,
        private readonly store:  FileSignalStore,
        private readonly config: PreKeyManagerConfig,
    ) {}


    /** Boot check inline (fresh bot needs OTPKs before peers reach it), then start the background loop. Idempotent */
    async start(): Promise<void> {
        if (this.running) return
        this.running = true

        try {
            await this.checkAndReplenish('boot')
        } catch (err) {
            this.config.logger?.warn(
                { err: (err as Error).message },
                '[prekeys] boot replenish failed; background loop will retry',
            )
        }

        if (this.config.backgroundIntervalMs > 0) {
            this.timer = setInterval(() => {
                this.checkAndReplenish('background').catch(err => {
                    this.config.logger?.warn(
                        { err: (err as Error).message },
                        '[prekeys] background replenish failed; will retry next tick',
                    )
                })
            }, this.config.backgroundIntervalMs)
            // unref so a bot running only this timer can exit cleanly
            if (typeof this.timer.unref === 'function') this.timer.unref()
        }
    }

    stop(): void {
        this.running = false
        if (this.timer) {
            clearInterval(this.timer)
            this.timer = undefined
        }
    }

    /** Caller-triggered replenish */
    async requestReplenish(): Promise<void> {
        return this.checkAndReplenish('on-demand')
    }


    /** Single-flight: a check already in progress is shared */
    private async checkAndReplenish(reason: string): Promise<void> {
        if (this.inFlightCheck) return this.inFlightCheck
        this.inFlightCheck = this.doCheckAndReplenish(reason)
            .finally(() => { this.inFlightCheck = undefined })
        return this.inFlightCheck
    }

    private async doCheckAndReplenish(reason: string): Promise<void> {
        const { deviceId, replenishThreshold, replenishTarget, logger } = this.config
        const target = Math.min(replenishTarget, HARD_TARGET_CAP)

        const res = await this.http.get<PrekeyCountResponse>(
            `/prekeys/count?deviceId=${deviceId}`,
        )
        const { count, shouldRotateSignedPreKey } = res.data

        const needOtpks = count < replenishThreshold ? target - count : 0
        if (needOtpks <= 0 && !shouldRotateSignedPreKey) {
            logger?.debug({ reason, count, threshold: replenishThreshold }, '[prekeys] pool healthy')
            return
        }
        logger?.info(
            { reason, count, threshold: replenishThreshold, willMintOtpks: needOtpks, willRotateSpk: shouldRotateSignedPreKey },
            '[prekeys] running replenish',
        )

        const body: {
            deviceId:        number
            signedPreKey?:   { keyId: number; publicKey: string; signature: string }
            oneTimePreKeys?: Array<{ keyId: number; publicKey: string }>
        } = { deviceId }

        if (shouldRotateSignedPreKey) {
            const st = await this.store.loadState()
            const nextSpkId = st.nextSignedPreKeyId
            const spk = await this.signal.mintSignedPreKey(nextSpkId)
            body.signedPreKey = {
                keyId:     spk.keyId,
                publicKey: spk.publicKey,
                signature: spk.signature,
            }
            await this.store.patchState({
                nextSignedPreKeyId:         nextSpkId + 1,
                lastSignedPreKeyRotationMs: Date.now(),
            })
        }

        // OTPK top-up. Persist locally as we mint and bump the counter before POST
        // If POST fails the counter still advanced, which is fine, burning a few ids beats colliding on retry
        if (needOtpks > 0) {
            const st = await this.store.loadState()
            let nextId = st.nextOneTimePreKeyId
            const minted: Array<{ keyId: number; publicKey: string }> = []
            try {
                for (let i = 0; i < needOtpks; i++) {
                    if (nextId > OTPK_ID_MAX) {
                        logger?.error(
                            { nextId, max: OTPK_ID_MAX },
                            '[prekeys] OTPK id space exhausted',
                        )
                        break
                    }
                    const otpk = await this.signal.mintOneTimePreKey(nextId)
                    nextId++
                    minted.push(otpk)
                }
            } finally {
                // Record consumed ids even if a mint threw mid-loop. Each minted OTPK's privkey is already persisted,
                // so re-minting its id next run would clobber that privkey and a peer could fetch
                // a pubkey whose privkey is gone, making X3DH undecryptable. The finally bumps the counter
                // past every id actually consumed (nextId++ runs after each successful mint)
                await this.store.patchState({ nextOneTimePreKeyId: nextId })
            }
            body.oneTimePreKeys = minted
        }

        if (!body.signedPreKey && (!body.oneTimePreKeys || body.oneTimePreKeys.length === 0)) {
            logger?.debug({}, '[prekeys] nothing to upload')
            return
        }

        await this.http.post<{ success: boolean }>('/prekeys/replenish', body)
        logger?.info(
            {
                spk:   body.signedPreKey?.keyId,
                otpks: body.oneTimePreKeys?.length ?? 0,
            },
            '[prekeys] replenish committed',
        )
    }
}
