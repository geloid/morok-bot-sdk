/**
 * AES-256-GCM wire format for group/channel messages (Signal type 8), byte-identical to frontend/src/signal/channel.ts
 * Any drift here breaks decryption end-to-end
 *
 * Wire: [ "MOK1" (4) || epoch (uint32 BE, 4) || iv (12) || ct+tag ]
 *
 * AAD is "morok-channel-${conversationId}", conv-scoped and not epoch-scoped
 * The epoch sits in the wire header, the receiver reads it to pick the key, then runs AES-GCM with the conv-scoped AAD
 *
 * Legacy wires have no MOK1 prefix and decode as epoch=0
 * The chance a random IV's first 4 bytes spell "MOK1" is 1 / 2^32 per message
 */

import { webcrypto } from 'node:crypto'

const subtle = webcrypto.subtle
type CryptoKey = webcrypto.CryptoKey
type KeyUsage  = webcrypto.KeyUsage

export const CHANNEL_KEY_BYTES   = 32
export const CHANNEL_IV_BYTES    = 12
export const CHANNEL_TAG_BYTES   = 16
export const CHANNEL_MAGIC       = new TextEncoder().encode('MOK1')   // 4 bytes
export const CHANNEL_MAGIC_BYTES = CHANNEL_MAGIC.length
export const CHANNEL_EPOCH_BYTES = 4
export const CHANNEL_HEADER_BYTES = CHANNEL_MAGIC_BYTES + CHANNEL_EPOCH_BYTES + CHANNEL_IV_BYTES   // 20


async function importChannelKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
    if (raw.byteLength !== CHANNEL_KEY_BYTES) {
        throw new Error(`channel-cipher: key must be ${CHANNEL_KEY_BYTES} bytes; got ${raw.byteLength}`)
    }
    return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages)
}


export function channelAad(conversationId: number): Uint8Array {
    if (!Number.isInteger(conversationId) || conversationId < 1) {
        throw new Error(`channel-cipher: bad conversationId ${conversationId}`)
    }
    return new TextEncoder().encode(`morok-channel-${conversationId}`)
}


function writeUint32BE(out: Uint8Array, offset: number, value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new Error(`channel-cipher: epoch ${value} out of uint32 range`)
    }
    new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(offset, value, false)
}


function readUint32BE(buf: Uint8Array, offset: number): number {
    if (offset + 4 > buf.byteLength) {
        throw new Error(`channel-cipher: readUint32BE past end (offset=${offset}, len=${buf.byteLength})`)
    }
    return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(offset, false)
}


function hasChannelMagic(buf: Uint8Array): boolean {
    // Need full header + at least one byte of tag. Empty plaintext still produces a 16-byte tag
    if (buf.byteLength < CHANNEL_HEADER_BYTES + CHANNEL_TAG_BYTES) return false
    for (let i = 0; i < CHANNEL_MAGIC_BYTES; i++) {
        if (buf[i] !== CHANNEL_MAGIC[i]) return false
    }
    return true
}


export interface ParsedChannelWire {
    epoch: number
    iv:    Uint8Array
    ct:    Uint8Array   // ct + GCM tag, ready for subtle.decrypt
}


/** Splits a wire into (epoch, iv, ct). Handles the multi-epoch layout and the legacy [iv || ct+tag] as epoch=0 */
export function parseChannelWire(wire: Uint8Array): ParsedChannelWire {
    if (hasChannelMagic(wire)) {
        const epoch = readUint32BE(wire, CHANNEL_MAGIC_BYTES)
        const iv    = wire.subarray(CHANNEL_MAGIC_BYTES + CHANNEL_EPOCH_BYTES, CHANNEL_HEADER_BYTES)
        const ct    = wire.subarray(CHANNEL_HEADER_BYTES)
        return { epoch, iv, ct }
    }
    if (wire.byteLength < CHANNEL_IV_BYTES + CHANNEL_TAG_BYTES) {
        throw new Error(
            `channel-cipher: legacy wire too short (${wire.byteLength} < ${CHANNEL_IV_BYTES + CHANNEL_TAG_BYTES})`,
        )
    }
    const iv = wire.subarray(0, CHANNEL_IV_BYTES)
    const ct = wire.subarray(CHANNEL_IV_BYTES)
    return { epoch: 0, iv, ct }
}


/** Encrypt under the per-epoch 32-byte secret and return the full wire envelope. IV is random per call */
export async function encryptChannelWire(
    secret:         Uint8Array,
    conversationId: number,
    epoch:          number,
    plaintext:      Uint8Array,
): Promise<Uint8Array> {
    if (!Number.isInteger(epoch) || epoch < 0 || epoch > 0xffffffff) {
        throw new Error(`channel-cipher: epoch ${epoch} out of uint32 range`)
    }
    const key = await importChannelKey(secret, ['encrypt'])
    const iv  = webcrypto.getRandomValues(new Uint8Array(CHANNEL_IV_BYTES))
    const aad = channelAad(conversationId)
    const ct  = new Uint8Array(await subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        plaintext,
    ))

    const wire = new Uint8Array(CHANNEL_HEADER_BYTES + ct.byteLength)
    wire.set(CHANNEL_MAGIC, 0)
    writeUint32BE(wire, CHANNEL_MAGIC_BYTES, epoch)
    wire.set(iv, CHANNEL_MAGIC_BYTES + CHANNEL_EPOCH_BYTES)
    wire.set(ct, CHANNEL_HEADER_BYTES)
    return wire
}


/** Decrypt a parsed wire under the given secret. Caller picks the secret based on parsed.epoch */
export async function decryptChannelWire(
    secret:         Uint8Array,
    conversationId: number,
    parsed:         ParsedChannelWire,
): Promise<Uint8Array> {
    const key = await importChannelKey(secret, ['decrypt'])
    const aad = channelAad(conversationId)
    return new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: parsed.iv, additionalData: aad },
        key,
        parsed.ct,
    ))
}
