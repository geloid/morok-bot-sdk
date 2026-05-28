import { describe, it, expect } from 'vitest'

import {
    generateAesKey, exportKeyRaw, importKeyForDecrypt,
    aesGcmEncrypt, aesGcmDecrypt,
    packSealed, unpackSealed, chunkAad,
    AES_IV_BYTES, AES_TAG_BYTES,
} from '../../src/crypto/file-cipher.js'


describe('file-cipher: AES-GCM round-trip', () => {
    it('encrypts and decrypts arbitrary bytes', async () => {
        const key = await generateAesKey()
        const pt  = new TextEncoder().encode('hello world, this is a test')
        const sealed = await aesGcmEncrypt(key, pt)

        expect(sealed.iv.byteLength).toBe(AES_IV_BYTES)
        expect(sealed.ct.byteLength).toBe(pt.byteLength + AES_TAG_BYTES)

        const out = await aesGcmDecrypt(key, sealed)
        expect(new TextDecoder().decode(out)).toBe('hello world, this is a test')
    })

    it('handles an empty plaintext (only the GCM tag in ct)', async () => {
        const key   = await generateAesKey()
        const sealed = await aesGcmEncrypt(key, new Uint8Array(0))
        expect(sealed.ct.byteLength).toBe(AES_TAG_BYTES)
        const out = await aesGcmDecrypt(key, sealed)
        expect(out.byteLength).toBe(0)
    })

    it('handles large plaintext (~1 MB)', async () => {
        const key = await generateAesKey()
        const pt  = new Uint8Array(1024 * 1024).fill(0x42)
        const sealed = await aesGcmEncrypt(key, pt)
        const out = await aesGcmDecrypt(key, sealed)
        expect(out.byteLength).toBe(pt.byteLength)
        expect(out[0]).toBe(0x42)
        expect(out[pt.byteLength - 1]).toBe(0x42)
    })

    it('decrypt with wrong key throws "decryption failed"', async () => {
        const a = await generateAesKey()
        const b = await generateAesKey()
        const sealed = await aesGcmEncrypt(a, new TextEncoder().encode('secret'))
        await expect(aesGcmDecrypt(b, sealed)).rejects.toThrow(/decryption failed/)
    })

    it('decrypt with flipped ciphertext byte throws "decryption failed"', async () => {
        const key = await generateAesKey()
        const sealed = await aesGcmEncrypt(key, new TextEncoder().encode('integrity'))
        // Flip one ciphertext bit
        const flipped = new Uint8Array(sealed.ct)
        flipped[0] = (flipped[0]! ^ 0xff) >>> 0 & 0xff
        await expect(
            aesGcmDecrypt(key, { iv: sealed.iv, ct: flipped }),
        ).rejects.toThrow(/decryption failed/)
    })

    it('AAD mismatch fails — chunked-path invariant', async () => {
        const key = await generateAesKey()
        const sealed = await aesGcmEncrypt(key, new TextEncoder().encode('chunk0'), chunkAad(0, 3))
        // Decrypt under a different aad, same plaintext, same chunk count, but pretend it's chunk #1
        await expect(
            aesGcmDecrypt(key, sealed, chunkAad(1, 3)),
        ).rejects.toThrow(/decryption failed/)
    })
})


describe('file-cipher: pack/unpack wire layout (byte-exact FE mirror)', () => {
    it('packed length == iv + ct', async () => {
        const key = await generateAesKey()
        const pt  = new TextEncoder().encode('wire')
        const sealed = await aesGcmEncrypt(key, pt)
        const packed = packSealed(sealed)
        expect(packed.byteLength).toBe(sealed.iv.byteLength + sealed.ct.byteLength)
        // First 12 bytes match IV byte-for-byte
        for (let i = 0; i < AES_IV_BYTES; i++) {
            expect(packed[i]).toBe(sealed.iv[i])
        }
    })

    it('unpack(pack(x)) === x (round-trip)', async () => {
        const key = await generateAesKey()
        const pt  = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
        const sealed = await aesGcmEncrypt(key, pt)
        const repacked = unpackSealed(packSealed(sealed))
        expect(Array.from(repacked.iv)).toEqual(Array.from(sealed.iv))
        expect(Array.from(repacked.ct)).toEqual(Array.from(sealed.ct))
    })

    it('packed bytes successfully decrypt after a network-style roundtrip', async () => {
        // Simulates wire → server-storage → wire by serialising
        // pack(...) into a fresh Uint8Array, then unpack and decrypt
        const key = await generateAesKey()
        const original = new TextEncoder().encode('wire roundtrip')
        const packed = packSealed(await aesGcmEncrypt(key, original))
        // Mimic server storing the bytes, copy into a new typed array
        const onWire = new Uint8Array(packed)
        const recovered = await aesGcmDecrypt(key, unpackSealed(onWire))
        expect(new TextDecoder().decode(recovered)).toBe('wire roundtrip')
    })

    it('unpack rejects too-short input', () => {
        expect(() => unpackSealed(new Uint8Array(27))).toThrow(/too short/)
    })

    it('unpack accepts exactly IV + TAG (empty plaintext case)', async () => {
        const key = await generateAesKey()
        const sealed = await aesGcmEncrypt(key, new Uint8Array(0))
        const packed = packSealed(sealed)
        expect(packed.byteLength).toBe(AES_IV_BYTES + AES_TAG_BYTES)
        const recovered = await aesGcmDecrypt(key, unpackSealed(packed))
        expect(recovered.byteLength).toBe(0)
    })

    it('packSealed rejects an iv of wrong length', () => {
        expect(() => packSealed({ iv: new Uint8Array(8), ct: new Uint8Array(20) }))
            .toThrow(/iv must be 12 bytes/)
    })
})


describe('file-cipher: key export / import', () => {
    it('exportKeyRaw returns exactly 32 bytes', async () => {
        const key = await generateAesKey()
        const raw = await exportKeyRaw(key)
        expect(raw.byteLength).toBe(32)
    })

    it('importKeyForDecrypt round-trip', async () => {
        const original  = await generateAesKey()
        const raw       = await exportKeyRaw(original)
        const reimport  = await importKeyForDecrypt(raw)
        const sealed    = await aesGcmEncrypt(original, new TextEncoder().encode('cross-key'))
        const decoded   = await aesGcmDecrypt(reimport, sealed)
        expect(new TextDecoder().decode(decoded)).toBe('cross-key')
    })

    it('importKeyForDecrypt rejects wrong-length raw key', async () => {
        await expect(importKeyForDecrypt(new Uint8Array(31)))
            .rejects.toThrow(/must be 32 bytes/)
        await expect(importKeyForDecrypt(new Uint8Array(33)))
            .rejects.toThrow(/must be 32 bytes/)
    })
})


describe('file-cipher: chunkAad shape', () => {
    it('produces UTF-8 of "morok-chunk-${i}-of-${total}"', () => {
        const aad = chunkAad(0, 5)
        expect(new TextDecoder().decode(aad)).toBe('morok-chunk-0-of-5')
    })

    it('different indices produce different bytes', () => {
        const a = chunkAad(0, 10)
        const b = chunkAad(1, 10)
        expect(a.byteLength).toBe(b.byteLength)
        expect(Buffer.compare(Buffer.from(a), Buffer.from(b))).not.toBe(0)
    })
})
