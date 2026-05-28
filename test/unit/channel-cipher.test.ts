/** Channel cipher unit tests cover the byte-exact wire format of group-chat and channel messages (channel-key flow) */

import { describe, it, expect } from 'vitest'
import { webcrypto } from 'node:crypto'

import {
    parseChannelWire,
    encryptChannelWire, decryptChannelWire,
    channelAad,
    CHANNEL_KEY_BYTES, CHANNEL_IV_BYTES, CHANNEL_TAG_BYTES,
    CHANNEL_MAGIC, CHANNEL_MAGIC_BYTES, CHANNEL_EPOCH_BYTES,
    CHANNEL_HEADER_BYTES,
} from '../../src/crypto/channel-cipher.js'

function randSecret(): Uint8Array {
    return webcrypto.getRandomValues(new Uint8Array(CHANNEL_KEY_BYTES))
}


describe('channelAad', () => {
    it('encodes the conversation-scoped string in UTF-8', () => {
        const aad = channelAad(42)
        const decoded = new TextDecoder().decode(aad)
        expect(decoded).toBe('morok-channel-42')
    })

    it('rejects non-integer conversationId', () => {
        expect(() => channelAad(1.5)).toThrow()
        expect(() => channelAad(0)).toThrow()
        expect(() => channelAad(-1)).toThrow()
    })
})


describe('parseChannelWire', () => {
    it('decodes a fresh MAGIC-prefixed wire', () => {
        const wire = new Uint8Array(CHANNEL_HEADER_BYTES + CHANNEL_TAG_BYTES)
        wire.set(CHANNEL_MAGIC, 0)
        // epoch = 42
        new DataView(wire.buffer).setUint32(CHANNEL_MAGIC_BYTES, 42, false)
        // IV = bytes 4..16
        for (let i = 0; i < CHANNEL_IV_BYTES; i++) {
            wire[CHANNEL_MAGIC_BYTES + CHANNEL_EPOCH_BYTES + i] = i + 1
        }
        const p = parseChannelWire(wire)
        expect(p.epoch).toBe(42)
        expect(p.iv.byteLength).toBe(CHANNEL_IV_BYTES)
        expect(p.iv[0]).toBe(1)
        expect(p.iv[11]).toBe(12)
        expect(p.ct.byteLength).toBe(CHANNEL_TAG_BYTES)
    })

    it('decodes a legacy (no-magic) wire as epoch=0', () => {
        const wire = new Uint8Array(CHANNEL_IV_BYTES + CHANNEL_TAG_BYTES + 5)
        // Force first 4 bytes to NOT match MAGIC
        wire[0] = 0xff; wire[1] = 0xff; wire[2] = 0xff; wire[3] = 0xff
        const p = parseChannelWire(wire)
        expect(p.epoch).toBe(0)
        expect(p.iv.byteLength).toBe(CHANNEL_IV_BYTES)
        expect(p.ct.byteLength).toBe(wire.byteLength - CHANNEL_IV_BYTES)
    })

    it('rejects a wire that is too short to be legacy', () => {
        const wire = new Uint8Array(CHANNEL_IV_BYTES + CHANNEL_TAG_BYTES - 1)
        expect(() => parseChannelWire(wire)).toThrow(/too short/i)
    })

    it('encodes the largest representable epoch (uint32 max)', () => {
        const wire = new Uint8Array(CHANNEL_HEADER_BYTES + CHANNEL_TAG_BYTES)
        wire.set(CHANNEL_MAGIC, 0)
        new DataView(wire.buffer).setUint32(CHANNEL_MAGIC_BYTES, 0xffffffff, false)
        const p = parseChannelWire(wire)
        expect(p.epoch).toBe(0xffffffff)
    })
})


describe('encrypt/decrypt round-trip', () => {
    it('text round-trips under a fresh key', async () => {
        const secret = randSecret()
        const conv = 7
        const epoch = 3
        const plaintext = new TextEncoder().encode('Привет, группа!')
        const wire = await encryptChannelWire(secret, conv, epoch, plaintext)
        const parsed = parseChannelWire(wire)
        expect(parsed.epoch).toBe(epoch)
        const pt = await decryptChannelWire(secret, conv, parsed)
        expect(new TextDecoder().decode(pt)).toBe('Привет, группа!')
    })

    it('empty plaintext round-trips (just the tag)', async () => {
        const secret = randSecret()
        const wire = await encryptChannelWire(secret, 1, 0, new Uint8Array(0))
        const parsed = parseChannelWire(wire)
        expect(parsed.ct.byteLength).toBe(CHANNEL_TAG_BYTES)
        const pt = await decryptChannelWire(secret, 1, parsed)
        expect(pt.byteLength).toBe(0)
    })

    it('produces fresh IV per call (probability of collision negligible)', async () => {
        const secret = randSecret()
        const pt = new TextEncoder().encode('same plaintext')
        const a = parseChannelWire(await encryptChannelWire(secret, 1, 0, pt))
        const b = parseChannelWire(await encryptChannelWire(secret, 1, 0, pt))
        // 12-byte random IV, compared as Buffers
        expect(Buffer.compare(Buffer.from(a.iv), Buffer.from(b.iv))).not.toBe(0)
    })

    it('rejects decrypt with the wrong key', async () => {
        const a = randSecret(), b = randSecret()
        const wire = await encryptChannelWire(a, 5, 1, new TextEncoder().encode('hi'))
        const parsed = parseChannelWire(wire)
        await expect(decryptChannelWire(b, 5, parsed)).rejects.toThrow()
    })

    it('rejects decrypt with the wrong conversationId (AAD mismatch)', async () => {
        const secret = randSecret()
        const wire = await encryptChannelWire(secret, 5, 1, new TextEncoder().encode('hi'))
        const parsed = parseChannelWire(wire)
        await expect(decryptChannelWire(secret, 6, parsed)).rejects.toThrow()
    })

    it('rejects a flipped bit in the ciphertext body', async () => {
        const secret = randSecret()
        const wire = await encryptChannelWire(secret, 5, 1, new TextEncoder().encode('hi'))
        // Flip a bit in the ciphertext (offset HEADER+1 is past the IV)
        wire[CHANNEL_HEADER_BYTES + 1] ^= 0x01
        const parsed = parseChannelWire(wire)
        await expect(decryptChannelWire(secret, 5, parsed)).rejects.toThrow()
    })

    it('rejects a flipped bit in the auth tag', async () => {
        const secret = randSecret()
        const wire = await encryptChannelWire(secret, 5, 1, new TextEncoder().encode('hi'))
        // Last byte is the last byte of the GCM tag
        wire[wire.byteLength - 1] ^= 0x01
        const parsed = parseChannelWire(wire)
        await expect(decryptChannelWire(secret, 5, parsed)).rejects.toThrow()
    })
})


describe('key length / epoch range guards', () => {
    it('rejects encrypt with a non-32-byte key', async () => {
        const bad = new Uint8Array(16)
        await expect(encryptChannelWire(bad, 1, 0, new Uint8Array(0)))
            .rejects.toThrow(/key must be 32/i)
    })

    it('rejects decrypt with a non-32-byte key', async () => {
        const goodSecret = randSecret()
        const w = await encryptChannelWire(goodSecret, 1, 0, new Uint8Array(0))
        const parsed = parseChannelWire(w)
        await expect(decryptChannelWire(new Uint8Array(31), 1, parsed))
            .rejects.toThrow(/key must be 32/i)
    })

    it('rejects encrypt with an out-of-range epoch', async () => {
        const secret = randSecret()
        await expect(encryptChannelWire(secret, 1, -1, new Uint8Array(0)))
            .rejects.toThrow(/epoch/i)
        await expect(encryptChannelWire(secret, 1, 0x1_0000_0000, new Uint8Array(0)))
            .rejects.toThrow(/epoch/i)
    })
})
