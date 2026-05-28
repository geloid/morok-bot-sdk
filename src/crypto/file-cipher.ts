/**
 * Per-file AES-256-GCM, byte-identical to frontend/src/lib/crypto-utils.ts
 * Any drift on this layout breaks decryption on the peer with an AES-GCM tag error
 *
 * Single-shot wire (packSealed): [ iv (12) || ct+tag (plaintext + 16) ], total plaintext + 28
 * Chunked: each chunk packed with its own IV and AAD "morok-chunk-${index}-of-${total}", same layout
 */

import { randomBytes, webcrypto } from 'node:crypto'

const subtle = webcrypto.subtle
type CryptoKey = webcrypto.CryptoKey
type BufferSource = ArrayBufferView | ArrayBuffer


export interface SealedData {
    iv: Uint8Array  // 12 bytes
    ct: Uint8Array  // ct + 16-byte GCM tag at the tail
}

export const AES_IV_BYTES  = 12
export const AES_TAG_BYTES = 16


/** Fresh AES-256-GCM key, extractable so callers can serialise the raw 32 bytes into the message envelope */
export async function generateAesKey(): Promise<CryptoKey> {
    return subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
    )
}

/** Returns the raw 32 bytes. Throws on a non-extractable key */
export async function exportKeyRaw(key: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await subtle.exportKey('raw', key))
}

/** Re-import a raw 32-byte key for decrypt. Non-extractable */
export async function importKeyForDecrypt(rawKey: Uint8Array): Promise<CryptoKey> {
    if (rawKey.byteLength !== 32) {
        throw new Error(`AES key must be 32 bytes, got ${rawKey.byteLength}`)
    }
    return subtle.importKey(
        'raw',
        rawKey as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
    )
}


/**
 * Encrypt under `key` with a random IV. Optional `aad` binds extra bytes into the tag,
 * the chunked path uses it to make chunks non-reorderable
 */
export async function aesGcmEncrypt(
    key:       CryptoKey,
    plaintext: Uint8Array,
    aad?:      Uint8Array,
): Promise<SealedData> {
    const iv = randomBytes(AES_IV_BYTES)
    const ct = await subtle.encrypt(
        {
            name: 'AES-GCM',
            iv:   iv as BufferSource,
            ...(aad ? { additionalData: aad as BufferSource } : {}),
        },
        key,
        plaintext as BufferSource,
    )
    return { iv: new Uint8Array(iv), ct: new Uint8Array(ct) }
}

/** Decrypt. Throws "decryption failed" on tag mismatch (same wording as the FE so log greps line up) */
export async function aesGcmDecrypt(
    key:    CryptoKey,
    sealed: SealedData,
    aad?:   Uint8Array,
): Promise<Uint8Array> {
    try {
        const pt = await subtle.decrypt(
            {
                name: 'AES-GCM',
                iv:   sealed.iv as BufferSource,
                ...(aad ? { additionalData: aad as BufferSource } : {}),
            },
            key,
            sealed.ct as BufferSource,
        )
        return new Uint8Array(pt)
    } catch {
        throw new Error('decryption failed')
    }
}


/** [ iv(12) || ct+tag ] */
export function packSealed(s: SealedData): Uint8Array {
    if (s.iv.byteLength !== AES_IV_BYTES) {
        throw new Error(`packSealed: iv must be ${AES_IV_BYTES} bytes, got ${s.iv.byteLength}`)
    }
    const out = new Uint8Array(s.iv.byteLength + s.ct.byteLength)
    out.set(s.iv, 0)
    out.set(s.ct, s.iv.byteLength)
    return out
}

/** Reverse of packSealed. Returns subarrays (views, no copy) */
export function unpackSealed(packed: Uint8Array): SealedData {
    const min = AES_IV_BYTES + AES_TAG_BYTES
    if (packed.byteLength < min) {
        throw new Error(`unpackSealed: too short (need >= ${min} bytes, got ${packed.byteLength})`)
    }
    return {
        iv: packed.subarray(0, AES_IV_BYTES),
        ct: packed.subarray(AES_IV_BYTES),
    }
}


/** AAD for chunked uploads. Matches FE chunkAad */
export function chunkAad(index: number, total: number): Uint8Array {
    return new TextEncoder().encode(`morok-chunk-${index}-of-${total}`)
}
