/**
 * D cross-signing primitives: canonical-message server-compat,
 * sign/verify round-trip, and the NULL-tolerant + hard-reject policy
 * of the encrypt-side gate, pure crypto, no IO
 *
 * The canonical-message test is the load-bearing one: if the SDK's
 * byte encoding drifts from the server's (src/routes/prekeys.ts) or
 * the FE's (frontend/src/signal/cross-signing.ts), every cert the bot
 * mints 400s server-side and every peer gate reports 'invalid'
 */

import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { KeyHelper } from '@privacyresearch/libsignal-protocol-typescript'
import {
    signDeviceCert, verifyPeerCert, canonicalCrossSignMessage,
} from '../../src/crypto/cross-signing.js'


// Independent reimplementation of the SERVER's canonicalCrossSignMessage
// (src/routes/prekeys.ts), must stay byte-identical to the SDK's
function serverCanonical(userId: number, deviceId: number, identityB64: string): Buffer {
    const identity = Buffer.from(identityB64, 'base64')
    const buf = Buffer.alloc(8 + 4 + identity.length)
    buf.writeBigUInt64BE(BigInt(userId), 0)
    buf.writeUInt32BE(deviceId, 8)
    identity.copy(buf, 12)
    return createHash('sha256').update(buf).digest()
}

async function freshXsk(): Promise<{ pubB64: string; privB64: string }> {
    const kp = await KeyHelper.generateIdentityKeyPair()
    return {
        pubB64:  Buffer.from(new Uint8Array(kp.pubKey)).toString('base64'),
        privB64: Buffer.from(new Uint8Array(kp.privKey)).toString('base64'),
    }
}

async function freshIdentityB64(): Promise<string> {
    const kp = await KeyHelper.generateIdentityKeyPair()
    return Buffer.from(new Uint8Array(kp.pubKey)).toString('base64')
}


describe('canonicalCrossSignMessage', () => {
    it('matches the server byte-for-byte', async () => {
        const id = await freshIdentityB64()
        const sdk = canonicalCrossSignMessage(4242, 1, id)
        const srv = serverCanonical(4242, 1, id)
        expect(Buffer.compare(Buffer.from(sdk), srv)).toBe(0)
        expect(sdk.length).toBe(32) // SHA-256 digest
    })

    it('binds userId and deviceId (different inputs -> different digests)', async () => {
        const id = await freshIdentityB64()
        const base = Buffer.from(canonicalCrossSignMessage(10, 1, id)).toString('hex')
        expect(Buffer.from(canonicalCrossSignMessage(11, 1, id)).toString('hex')).not.toBe(base)
        expect(Buffer.from(canonicalCrossSignMessage(10, 2, id)).toString('hex')).not.toBe(base)
    })

    it('rejects bad inputs', () => {
        expect(() => canonicalCrossSignMessage(0, 1, 'AAAA')).toThrow()
        expect(() => canonicalCrossSignMessage(1, 0, 'AAAA')).toThrow()
        expect(() => canonicalCrossSignMessage(1, 1, '')).toThrow()
    })
})


describe('signDeviceCert + verifyPeerCert round-trip', () => {
    it('a freshly-signed cert verifies, with server-compatible lengths', async () => {
        const xsk = await freshXsk()
        const id  = await freshIdentityB64()
        const cert = await signDeviceCert(xsk.privB64, 4242, 1, id)

        // Server brackets: cert 80..100 b64 chars, XSK pub 40..64
        expect(cert.length).toBeGreaterThanOrEqual(80)
        expect(cert.length).toBeLessThanOrEqual(100)
        expect(xsk.pubB64.length).toBeGreaterThanOrEqual(40)
        expect(xsk.pubB64.length).toBeLessThanOrEqual(64)

        const status = await verifyPeerCert({
            userId: 4242, deviceId: 1, identityKeyB64: id,
            accountSigningKey: xsk.pubB64, deviceCertificate: cert,
        })
        expect(status).toBe('verified')
    })

    it('rejects an XSK private of the wrong length', async () => {
        await expect(signDeviceCert('AAAA', 4242, 1, await freshIdentityB64())).rejects.toThrow()
    })
})


describe('verifyPeerCert policy', () => {
    it("returns 'uncertified' when XSK or cert is missing (NULL-tolerant / TOFU)", async () => {
        const xsk = await freshXsk()
        const id  = await freshIdentityB64()
        const cert = await signDeviceCert(xsk.privB64, 4242, 1, id)
        const base = { userId: 4242, deviceId: 1, identityKeyB64: id }
        expect(await verifyPeerCert({ ...base, accountSigningKey: null,       deviceCertificate: cert })).toBe('uncertified')
        expect(await verifyPeerCert({ ...base, accountSigningKey: xsk.pubB64,  deviceCertificate: null })).toBe('uncertified')
        expect(await verifyPeerCert({ ...base, accountSigningKey: undefined,   deviceCertificate: undefined })).toBe('uncertified')
    })

    it("returns 'invalid' for a tampered cert (hard reject)", async () => {
        const xsk = await freshXsk()
        const id  = await freshIdentityB64()
        const cert = Buffer.from(await signDeviceCert(xsk.privB64, 4242, 1, id), 'base64')
        cert[0] ^= 0x01
        expect(await verifyPeerCert({
            userId: 4242, deviceId: 1, identityKeyB64: id,
            accountSigningKey: xsk.pubB64, deviceCertificate: cert.toString('base64'),
        })).toBe('invalid')
    })

    it("returns 'invalid' when the cert is replayed under a different (userId, deviceId)", async () => {
        const xsk = await freshXsk()
        const id  = await freshIdentityB64()
        const cert = await signDeviceCert(xsk.privB64, 4242, 1, id)
        expect(await verifyPeerCert({
            userId: 9999, deviceId: 1, identityKeyB64: id,
            accountSigningKey: xsk.pubB64, deviceCertificate: cert,
        })).toBe('invalid')
        expect(await verifyPeerCert({
            userId: 4242, deviceId: 2, identityKeyB64: id,
            accountSigningKey: xsk.pubB64, deviceCertificate: cert,
        })).toBe('invalid')
    })

    it("returns 'invalid' for a cert that doesn't match the XSK", async () => {
        const xskA = await freshXsk()
        const xskB = await freshXsk()
        const id   = await freshIdentityB64()
        const cert = await signDeviceCert(xskA.privB64, 4242, 1, id)
        expect(await verifyPeerCert({
            userId: 4242, deviceId: 1, identityKeyB64: id,
            accountSigningKey: xskB.pubB64, deviceCertificate: cert,
        })).toBe('invalid')
    })
})
