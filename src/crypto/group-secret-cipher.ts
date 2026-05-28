/**
 * AES-256-GCM seal/unseal for the "sealed-to-group-secret" bundles served alongside per-device
 * channel-key wraps in GET /channel-key
 * A member holding the group_secret of a version can unwrap any epoch sealed under it
 * Byte-identical to frontend/src/signal/group-secret.ts
 *
 * Wire:
 *   aad       = "morok-group-secret-${conv}-v${version}" (utf-8)
 *   iv        = 12 random bytes
 *   plaintext = 32 bytes (legacy) OR [uint32 BE epoch (4) || key (32)]
 *   ct        = AES-256-GCM(plaintext, key=group_secret(version), iv, aad)
 *
 * The version goes into the AAD, so a bundle sealed under v=5 can't be relabelled as v=6 on the wire
 */

import { webcrypto } from 'node:crypto'

const subtle = webcrypto.subtle
type CryptoKey = webcrypto.CryptoKey
type KeyUsage  = webcrypto.KeyUsage

export const GROUP_SECRET_BYTES        = 32
export const GROUP_SECRET_IV_BYTES     = 12
export const GROUP_SECRET_EPOCH_HEADER = 4  // uint32 BE


export function groupSecretAad(conversationId: number, version: number): Uint8Array {
    if (!Number.isInteger(conversationId) || conversationId < 1) {
        throw new Error(`group-secret-cipher: bad conversationId ${conversationId}`)
    }
    if (!Number.isInteger(version) || version < 0) {
        throw new Error(`group-secret-cipher: bad version ${version}`)
    }
    return new TextEncoder().encode(`morok-group-secret-${conversationId}-v${version}`)
}


async function importKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
    if (raw.byteLength !== GROUP_SECRET_BYTES) {
        throw new Error(`group-secret-cipher: secret must be ${GROUP_SECRET_BYTES} bytes; got ${raw.byteLength}`)
    }
    return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages)
}


/**
 * Seal a 32-byte epoch key under group_secret(version). Plaintext is [uint32 BE predictedEpoch || epochKey] (36 bytes)
 * The inner epoch claim binds the bundle to one epoch, a relabel on the wire fails the inner check on unseal
 *
 * predictedEpoch is the bot's guess at what the server will assign (usually localMax + 1)
 * If it's wrong the receiver's inner check throws and ignores the bundle, the per-device wraps still land
 */
export async function sealEpochKey(args: {
    epochKey:       Uint8Array
    groupSecret:    Uint8Array
    conversationId: number
    version:        number
    predictedEpoch: number
}): Promise<{ ciphertext: string; iv: string }> {
    if (args.epochKey.byteLength !== GROUP_SECRET_BYTES) {
        throw new Error(`group-secret-cipher: epoch key must be ${GROUP_SECRET_BYTES} bytes; got ${args.epochKey.byteLength}`)
    }
    if (!Number.isInteger(args.predictedEpoch) || args.predictedEpoch < 0 || args.predictedEpoch > 0xffffffff) {
        throw new Error(`group-secret-cipher: predictedEpoch out of range: ${args.predictedEpoch}`)
    }
    const plaintext = new Uint8Array(GROUP_SECRET_EPOCH_HEADER + GROUP_SECRET_BYTES)
    new DataView(plaintext.buffer).setUint32(0, args.predictedEpoch >>> 0, false)
    plaintext.set(args.epochKey, GROUP_SECRET_EPOCH_HEADER)

    const aad = groupSecretAad(args.conversationId, args.version)
    const key = await importKey(args.groupSecret, ['encrypt'])
    const iv  = webcrypto.getRandomValues(new Uint8Array(GROUP_SECRET_IV_BYTES))
    const ct  = await subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        plaintext,
    )
    // Wipe our local copy of the plaintext. The caller's epochKey input is theirs to manage
    plaintext.fill(0)
    return {
        ciphertext: Buffer.from(ct).toString('base64'),
        iv:         Buffer.from(iv).toString('base64'),
    }
}


/**
 * Unseal an epoch bundle. AAD binds conversationId + version. With expectedEpoch and a new-format bundle
 * (36 bytes) the inner epoch is verified, legacy 32-byte bundles skip that check
 * Throws on wrong secret size, wrong iv size, AES-GCM tag fail, unknown plaintext length, inner-epoch mismatch
 */
export async function unsealEpochKey(args: {
    ciphertextBase64: string
    ivBase64:         string
    groupSecret:      Uint8Array
    conversationId:   number
    version:          number
    expectedEpoch?:   number
}): Promise<Uint8Array> {
    const iv = Buffer.from(args.ivBase64, 'base64')
    if (iv.byteLength !== GROUP_SECRET_IV_BYTES) {
        throw new Error(`group-secret-cipher: sealed iv must be ${GROUP_SECRET_IV_BYTES} bytes; got ${iv.byteLength}`)
    }
    const ct  = Buffer.from(args.ciphertextBase64, 'base64')
    const aad = groupSecretAad(args.conversationId, args.version)
    const key = await importKey(args.groupSecret, ['decrypt'])

    let pt: ArrayBuffer
    try {
        pt = await subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: aad },
            key,
            ct,
        )
    } catch (err) {
        throw new Error(
            `group-secret-cipher: unseal v${args.version} for conv ${args.conversationId} failed (tag mismatch or wrong secret): ${(err as Error).message}`,
        )
    }

    const raw = new Uint8Array(pt)
    if (raw.byteLength === GROUP_SECRET_BYTES) {
        // Legacy: bare 32-byte key, no inner check
        return raw
    }
    if (raw.byteLength !== GROUP_SECRET_BYTES + GROUP_SECRET_EPOCH_HEADER) {
        throw new Error(
            `group-secret-cipher: unwrapped epoch key has unexpected length ${raw.byteLength}`,
        )
    }
    const innerEpoch = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint32(0, false)
    if (args.expectedEpoch !== undefined && innerEpoch !== args.expectedEpoch) {
        throw new Error(
            `group-secret-cipher: inner epoch ${innerEpoch} does not match expected ${args.expectedEpoch}`,
        )
    }
    return raw.subarray(GROUP_SECRET_EPOCH_HEADER)
}
