/**
 * libsignal wrapper. Exposes only what the SDK uses: encrypt/decrypt, processPreKeyBundle for first
 * contact with a new peer device, and mintOneTimePreKey/mintSignedPreKey for replenish
 * libsignal-protocol-typescript picks up node:crypto via globalThis.crypto on Node 22+, no setWebCrypto
 */

import {
    KeyHelper,
    SessionBuilder,
    SessionCipher,
    SignalProtocolAddress,
    type KeyPairType,
    type DeviceType,
} from '@privacyresearch/libsignal-protocol-typescript'

import type { FileSignalStore } from './stores.js'
import type { SdkLogger }       from '../types.js'
import { verifyPeerCert }       from './cross-signing.js'


function toArrayBuffer(b64: string): ArrayBuffer {
    const buf = Buffer.from(b64, 'base64')
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
}

function fromArrayBuffer(buf: ArrayBuffer): string {
    return Buffer.from(buf).toString('base64')
}


/** Prekey bundle from GET /prekeys/:userId/:deviceId */
export interface PreKeyBundle {
    userId:         number
    deviceId:       number
    registrationId: number
    identityKey:    string            // base64
    signedPreKey: {
        keyId:     number
        publicKey: string             // base64
        signature: string             // base64
    }
    oneTimePreKey: null | {
        keyId:     number
        publicKey: string
    }
    accountSigningKey?: string | null
    deviceCertificate?: string | null
}


export class SignalEngine {
    /**
     * Per-(peerUserId.peerDeviceId) serialisation around every session-mutating libsignal call
     * (encrypt, decrypt, processPreKeyBundle)
     * Without it, concurrent calls to the same device race the on-disk ratchet record and corrupt the session
     * One shared lock map so encrypt blocks decrypt and the reverse for the same address
     */
    private peerChains = new Map<string, Promise<unknown>>()

    constructor(
        private readonly store:  FileSignalStore,
        private readonly logger?: SdkLogger,
    ) {}

    /** Run `fn` chained after any in-flight task for the same peer-device
     * The get-and-set of the chain tail is synchronous so two callers in the same tick can't both see an empty prev */
    withPeerLock<T>(peerUserId: number, peerDeviceId: number, fn: () => Promise<T>): Promise<T> {
        const key  = `${peerUserId}.${peerDeviceId}`
        const prev = this.peerChains.get(key) ?? Promise.resolve()
        const next = prev.then(fn, fn)
        // catch-wrap so a rejection doesn't poison the chain tail
        const tail = next.catch(() => {})
        this.peerChains.set(key, tail)
        // When this op settles, drop the entry if no newer op chained onto it, so the map holds only active addresses
        void tail.then(() => { if (this.peerChains.get(key) === tail) this.peerChains.delete(key) })
        return next
    }

    /**
     * Encrypt bytes for a peer device. Returns a Signal envelope:
     *   { type: 1, body }  WhisperMessage (continuing ratchet)
     *   { type: 3, body }  PreKeySignalMessage (first frame, peer installs the session on receive)
     *
     * libsignal's MessageType.body is a binary string (charCodes 0-255 per byte),
     * the wire format is base64 so we re-encode
     * The caller must processPreKeyBundle the address first for a fresh session
     */
    async encrypt(
        peerUserId: number, peerDeviceId: number, plaintext: Uint8Array,
    ): Promise<{ type: 1 | 3; body: string }> {
        const cipher = new SessionCipher(this.store, addr(peerUserId, peerDeviceId))
        const msg = await cipher.encrypt(plaintext.buffer.slice(
            plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength,
        ) as ArrayBuffer)
        const t = msg.type === 3 ? 3 : 1
        const body = msg.body
            ? Buffer.from(msg.body, 'binary').toString('base64')
            : ''
        return { type: t, body }
    }

    /**
     * Decrypt an incoming envelope. Type-3 frames install the session on first receive (X3DH receiver path)
     * ciphertextBody is base64 from the wire, decode to ArrayBuffer before handing to libsignal
     * Passing it with 'binary' encoding makes libsignal read the base64 chars as bytes and corrupt everything
     */
    async decrypt(
        peerUserId: number, peerDeviceId: number,
        messageType: number, ciphertextBody: string,
    ): Promise<Uint8Array> {
        const cipher = new SessionCipher(this.store, addr(peerUserId, peerDeviceId))
        const buf = Buffer.from(ciphertextBody, 'base64')
        const ab  = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
        let plaintext: ArrayBuffer
        if (messageType === 3) {
            // The vendored libsignal type-3 path (session-builder processV3) calls isTrustedIdentity
            // without awaiting it, so its "changed identity, reject" TOFU check is a no-op on receive
            // (the encrypt path is intact). We deliberately don't hard-reject here, identity is per-device,
            // so a peer reinstalling legitimately presents a new identity, and a bot must never become un-writable-to.
            // The right behavior is to accept and rebuild history, libsignal re-pins and we only surface it loudly.
            // Telling a legit rotation from a malicious-server impersonation  needs an account-membership check
            // (cross-signing), a pending design
            const peerAddr = `${peerUserId}.${peerDeviceId}`
            const before   = await this.store.peekPeerIdentity(peerAddr)
            plaintext = await cipher.decryptPreKeyWhisperMessage(ab)
            if (before !== undefined) {
                const after = await this.store.peekPeerIdentity(peerAddr)
                if (after === undefined || !Buffer.from(before).equals(Buffer.from(after))) {
                    this.logger?.warn(
                        { peerUserId, peerDeviceId },
                        '[signal] PEER IDENTITY CHANGED on a type-3 frame: a KNOWN peer presented a ' +
                        'new identity key and the session was silently re-pinned. This is a legit ' +
                        'reinstall/rotation OR a malicious-server impersonation attempt, verify before ' +
                        'trusting subsequent messages from this peer.',
                    )
                }
            }
        } else if (messageType === 1) {
            plaintext = await cipher.decryptWhisperMessage(ab)
        } else {
            throw new Error(`unsupported DM message type ${messageType} (expected 1 or 3)`)
        }
        return new Uint8Array(plaintext)
    }

    /** Install a Signal session from a fresh prekey bundle. Don't call this with an open session,
     *  it overwrites the ratchet state, check hasOpenSession first
     *
     *  Encrypt-side cross-signing gate: if the bundle carries both an account signing key and a per-device cert,
     *  the cert is verified over the canonical (userId,deviceId,identityKey) message before any session state is written
     *  A present-but-invalid cert is refused (tampered bundle or server identity injection)
     *  NULL on either side falls through to TOFU, and a curve-wrapper fault also returns 'uncertified',
     *  so a crypto-init failure never cuts the bot off */
    async processPreKeyBundle(bundle: PreKeyBundle): Promise<void> {
        const certStatus = await verifyPeerCert({
            userId:            bundle.userId,
            deviceId:          bundle.deviceId,
            identityKeyB64:    bundle.identityKey,
            accountSigningKey: bundle.accountSigningKey,
            deviceCertificate: bundle.deviceCertificate,
        }, this.logger)
        if (certStatus === 'invalid') {
            throw new Error(
                `processPreKeyBundle: peer ${bundle.userId}.${bundle.deviceId} presented an INVALID ` +
                `cross-signing certificate - refusing to open a session (tampered bundle or server ` +
                `identity injection)`,
            )
        }

        const builder = new SessionBuilder(this.store, addr(bundle.userId, bundle.deviceId))
        const device: DeviceType<ArrayBuffer> = {
            identityKey:    toArrayBuffer(bundle.identityKey),
            registrationId: bundle.registrationId,
            signedPreKey: {
                keyId:     bundle.signedPreKey.keyId,
                publicKey: toArrayBuffer(bundle.signedPreKey.publicKey),
                signature: toArrayBuffer(bundle.signedPreKey.signature),
            },
            preKey: bundle.oneTimePreKey ? {
                keyId:     bundle.oneTimePreKey.keyId,
                publicKey: toArrayBuffer(bundle.oneTimePreKey.publicKey),
            } : undefined,
        }
        await builder.processPreKey(device)
    }

    async hasOpenSession(peerUserId: number, peerDeviceId: number): Promise<boolean> {
        const cipher = new SessionCipher(this.store, addr(peerUserId, peerDeviceId))
        return cipher.hasOpenSession()
    }


    // Replenish helpers (called from flow/prekeys.ts)

    /** Generate a one-time prekey, persist locally, return the public half + keyId for upload */
    async mintOneTimePreKey(keyId: number): Promise<{ keyId: number; publicKey: string }> {
        const kp = await KeyHelper.generatePreKey(keyId)
        await this.store.storePreKey(kp.keyId, kp.keyPair)
        return {
            keyId:     kp.keyId,
            publicKey: fromArrayBuffer(kp.keyPair.pubKey),
        }
    }

    /** Generate a signed prekey, sign with the bot's identity key, persist, return the public + signature for upload */
    async mintSignedPreKey(
        keyId: number,
    ): Promise<{ keyId: number; publicKey: string; signature: string }> {
        const idPair = await this.store.getIdentityKeyPair()
        if (!idPair) throw new Error('identity key pair missing - bot state not imported')
        const spk = await KeyHelper.generateSignedPreKey(idPair as KeyPairType, keyId)
        await this.store.storeSignedPreKeyFull({
            keyId:     spk.keyId,
            keyPair:   spk.keyPair,
            signature: spk.signature,
        })
        return {
            keyId:     spk.keyId,
            publicKey: fromArrayBuffer(spk.keyPair.pubKey),
            signature: fromArrayBuffer(spk.signature),
        }
    }
}


function addr(userId: number, deviceId: number): SignalProtocolAddress {
    return new SignalProtocolAddress(String(userId), deviceId)
}
