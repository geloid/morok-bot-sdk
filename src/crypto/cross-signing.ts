/**
 * D cross-signing primitives for the bot SDK, the headless counterpart to frontend/src/signal/cross-signing.ts
 * with the server mirror in src/routes/prekeys.ts. All three must produce byte-identical canonical messages
 * and use the same XEdDSA (Curve25519), or certificates won't verify across ends
 *
 * signDeviceCert signs a cert over the bot's own device identity key under the account signing key (XSK)
 * from the .morokbot file, then POSTs it to /crypto/cross-signing (see bot.ts:ensureCrossSigning)
 * Without the cert the bot stays an uncertified legacy device and users can't derive a cross-signed safety number
 *
 * verifyPeerCert is the encrypt-side gate wired into signal.ts:processPreKeyBundle
 * When a peer bundle carries both an XSK and a device cert, the cert is verified before opening a session
 * Present-but-invalid is the one hard-reject case (tampered bundle, server identity injection)
 * NULL on either side falls back to TOFU, since most peers may legitimately be uncertified
 * and rejecting NULL is a lock-out trap
 *
 * Canonical message (mirror, a change here means changing the other two):
 *   SHA-256( userId u64-BE || deviceId u32-BE || identity_key raw bytes )
 * identity_key is the libsignal-serialised public key (33-byte, 0x05-prefixed)
 * exactly as the server stored it in devices.identity_key
 * The 32-byte digest is the message that is signed and verified directly, with no second hashing
 *
 * Primitive: Curve25519Wrapper, the same WASM library libsignal, the server, and the FE use
 * Sign with the 32-byte XSK private, verify with signatureIsValid, NEVER verify (it returns true on invalid signatures)
 *
 * A one-time self-test at wrapper init, a valid round-trip + tamper-reject + wrong-key-reject
 * over a full canonicalCrossSignMessage cycle, tripwires an encoding regression or a broken wrapper
 * before it can silently reject every valid peer cert or mint a cert that fails server-side
 * On failure getWrapper throws and verifyPeerCert maps it to 'uncertified' (TOFU)
 * so a crypto fault degrades the bot and never cuts it off from every peer
 */

import { createHash }            from 'node:crypto'
import { Curve25519Wrapper }     from '@privacyresearch/curve25519-typescript'
import { KeyHelper }             from '@privacyresearch/libsignal-protocol-typescript'
import type { SdkLogger }        from '../types.js'


const DJB_PREFIX_BYTE = 0x05
const PUBKEY_RAW_BYTES = 32
const PUBKEY_PREFIXED  = 33
const PRIVKEY_BYTES    = 32
const SIGNATURE_BYTES  = 64


function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
    const out = new ArrayBuffer(u8.byteLength)
    new Uint8Array(out).set(u8)
    return out
}

// Normalises a 32-byte raw or 33-byte DJB-prefixed Curve25519 pubkey to the 32-byte raw form the wrapper accepts
// Returns null on any other length
function stripDjbPrefix(bytes: Uint8Array): Uint8Array | null {
    if (bytes.length === PUBKEY_RAW_BYTES) return bytes
    if (bytes.length === PUBKEY_PREFIXED && bytes[0] === DJB_PREFIX_BYTE) return bytes.subarray(1)
    return null
}


/**
 * Canonical bytes the device cert is signed over, byte-identical to the server's and the FE's
 * The 32-byte SHA-256 digest is the message that is signed and verified directly, no second hashing
 */
export function canonicalCrossSignMessage(
    userId: number, deviceId: number, identityKeyB64: string,
): Uint8Array {
    if (!Number.isInteger(userId) || userId < 1) {
        throw new Error('canonicalCrossSignMessage: bad userId')
    }
    if (!Number.isInteger(deviceId) || deviceId < 1) {
        throw new Error('canonicalCrossSignMessage: bad deviceId')
    }
    const identity = Buffer.from(identityKeyB64, 'base64')
    if (identity.length === 0) {
        throw new Error('canonicalCrossSignMessage: empty identity')
    }
    const buf = Buffer.alloc(8 + 4 + identity.length)
    buf.writeBigUInt64BE(BigInt(userId), 0)
    buf.writeUInt32BE(deviceId, 8)
    identity.copy(buf, 12)
    return new Uint8Array(createHash('sha256').update(buf).digest())
}


let wrapperPromise: Promise<Curve25519Wrapper> | null = null

function getWrapper(): Promise<Curve25519Wrapper> {
    if (!wrapperPromise) {
        wrapperPromise = (async () => {
            const w = await Curve25519Wrapper.create()
            await selfTest(w)
            return w
        })().catch(err => {
            // Reset so a transient WASM-init failure doesn't poison subsequent calls,
            // the next sign / verify retries init
            wrapperPromise = null
            throw err
        })
    }
    return wrapperPromise
}

// Sign, verify, tamper-reject, and wrong-key-reject over a full canonicalCrossSignMessage cycle
// Uses libsignal KeyHelper keypairs (the clamped shape the real XSK and identity keys use),
// so there are no clamping assumptions. Catches a broken wrapper, a regression from signatureIsValid
// back to the always-true `verify`, and any drift in the canonical-message encoding
async function selfTest(w: Curve25519Wrapper): Promise<void> {
    const kp        = await KeyHelper.generateIdentityKeyPair()
    const wrongKp   = await KeyHelper.generateIdentityKeyPair()
    const pubRaw    = new Uint8Array(kp.pubKey).slice(1)        // 33-byte DJB -> 32 raw
    const wrongRaw  = new Uint8Array(wrongKp.pubKey).slice(1)
    const identityB64 = Buffer.from(new Uint8Array(kp.pubKey)).toString('base64')
    const msg       = canonicalCrossSignMessage(424242, 7, identityB64)
    const sig       = w.sign(kp.privKey, toArrayBuffer(msg))

    if (!w.signatureIsValid(toArrayBuffer(pubRaw), toArrayBuffer(msg), sig)) {
        throw new Error('cross-signing self-test FAIL: valid signature verifies false (wrapper broken or encoding regression)')
    }
    const tampered = new Uint8Array(sig)
    tampered[0] ^= 0x01
    if (w.signatureIsValid(toArrayBuffer(pubRaw), toArrayBuffer(msg), toArrayBuffer(tampered))) {
        throw new Error('cross-signing self-test FAIL: tampered signature verifies true (signatureIsValid replaced with legacy verify?)')
    }
    if (w.signatureIsValid(toArrayBuffer(wrongRaw), toArrayBuffer(msg), sig)) {
        throw new Error('cross-signing self-test FAIL: signature verifies under the wrong public key (wrapper broken)')
    }
}


/**
 * Signs the canonical message for (userId, deviceId, identityKeyB64) under the 32-byte XSK private key
 * Returns base64 of the 64-byte XEdDSA signature, passed as `deviceCertificate` to POST /crypto/cross-signing
 */
export async function signDeviceCert(
    xskPrivB64: string, userId: number, deviceId: number, identityKeyB64: string,
): Promise<string> {
    const priv = Buffer.from(xskPrivB64, 'base64')
    if (priv.length !== PRIVKEY_BYTES) {
        throw new Error(`signDeviceCert: bad XSK private length ${priv.length} (expected ${PRIVKEY_BYTES})`)
    }
    const w   = await getWrapper()
    const msg = canonicalCrossSignMessage(userId, deviceId, identityKeyB64)
    const sig = new Uint8Array(w.sign(toArrayBuffer(new Uint8Array(priv)), toArrayBuffer(msg)))
    if (sig.length !== SIGNATURE_BYTES) {
        throw new Error(`signDeviceCert: unexpected signature length ${sig.length}`)
    }
    return Buffer.from(sig).toString('base64')
}


/** verifyPeerCert result. Mirrors the FE's PeerDeviceCertStatus */
export type PeerCertStatus = 'verified' | 'uncertified' | 'invalid'


/**
 * Encrypt-side gate. Verifies a peer device's cert over the canonical message
 * NULL-tolerant, a missing XSK or cert means 'uncertified' (caller proceeds with TOFU)
 * Present-but-unverifiable returns 'invalid' and the caller hard-rejects the session
 * Never throws. If the curve wrapper is unavailable it returns 'uncertified' and logs, degrading the bot to TOFU
 */
export async function verifyPeerCert(args: {
    userId:             number
    deviceId:           number
    identityKeyB64:     string
    accountSigningKey?: string | null
    deviceCertificate?: string | null
}, logger?: SdkLogger): Promise<PeerCertStatus> {
    if (!args.accountSigningKey || !args.deviceCertificate) return 'uncertified'

    let w: Curve25519Wrapper
    try {
        w = await getWrapper()
    } catch (err) {
        logger?.warn(
            { err: (err as Error).message, peer: `${args.userId}.${args.deviceId}` },
            '[cross-signing] curve unavailable; treating peer cert as uncertified (TOFU)',
        )
        return 'uncertified'
    }

    try {
        const pubRaw = stripDjbPrefix(new Uint8Array(Buffer.from(args.accountSigningKey, 'base64')))
        if (!pubRaw) return 'invalid'
        const sig = new Uint8Array(Buffer.from(args.deviceCertificate, 'base64'))
        if (sig.length !== SIGNATURE_BYTES) return 'invalid'
        const msg = canonicalCrossSignMessage(args.userId, args.deviceId, args.identityKeyB64)
        // signatureIsValid, NEVER verify (legacy thing: verify returns true on invalid signatures)
        const ok = w.signatureIsValid(toArrayBuffer(pubRaw), toArrayBuffer(msg), toArrayBuffer(sig))
        return ok ? 'verified' : 'invalid'
    } catch {
        return 'invalid'
    }
}
