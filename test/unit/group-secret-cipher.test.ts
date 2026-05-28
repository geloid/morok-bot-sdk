/**
 * Group-secret unseal helpers, wire-format round-trip + tamper /
 * label-swap defence checks, pure crypto unit tests, no IO
 */

import { describe, it, expect } from 'vitest'
import { webcrypto } from 'node:crypto'
import {
    unsealEpochKey, sealEpochKey, groupSecretAad,
    GROUP_SECRET_BYTES, GROUP_SECRET_IV_BYTES,
} from '../../src/crypto/group-secret-cipher.js'


/**
 * Re-implementation of the FE seal (`frontend/src/signal/group-
 * secret.ts:sealEpochKey`) so the tests can hand the SDK
 * SDK-unseal-compatible bundles, keep this in lockstep with the
 * production server / FE seal logic
 */
async function seal(args: {
    epochKey:       Uint8Array
    groupSecret:    Uint8Array
    conversationId: number
    version:        number
    predictedEpoch?: number
}): Promise<{ ciphertext: string; iv: string }> {
    const aad = groupSecretAad(args.conversationId, args.version)
    let plaintext: Uint8Array
    if (args.predictedEpoch !== undefined) {
        plaintext = new Uint8Array(4 + 32)
        new DataView(plaintext.buffer).setUint32(0, args.predictedEpoch >>> 0, false)
        plaintext.set(args.epochKey, 4)
    } else {
        plaintext = args.epochKey
    }
    const key = await webcrypto.subtle.importKey('raw', args.groupSecret, { name: 'AES-GCM' }, false, ['encrypt'])
    const iv  = webcrypto.getRandomValues(new Uint8Array(GROUP_SECRET_IV_BYTES))
    const ct  = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext)
    return {
        ciphertext: Buffer.from(ct).toString('base64'),
        iv:         Buffer.from(iv).toString('base64'),
    }
}


function rand(bytes: number): Uint8Array {
    return webcrypto.getRandomValues(new Uint8Array(bytes))
}


describe('groupSecretAad', () => {
    it('produces stable scoped string', () => {
        expect(new TextDecoder().decode(groupSecretAad(7, 1))).toBe('morok-group-secret-7-v1')
        expect(new TextDecoder().decode(groupSecretAad(42, 100))).toBe('morok-group-secret-42-v100')
    })
    it('rejects bad inputs', () => {
        expect(() => groupSecretAad(0, 1)).toThrow()
        expect(() => groupSecretAad(-1, 1)).toThrow()
        expect(() => groupSecretAad(7, -1)).toThrow()
    })
})


describe('unsealEpochKey — new-format bundle (36 bytes inner)', () => {
    it('round-trips a sealed epoch key with matching expectedEpoch', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await seal({
            epochKey, groupSecret, conversationId: 7, version: 1, predictedEpoch: 5,
        })
        const out = await unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret,
            conversationId: 7, version: 1, expectedEpoch: 5,
        })
        expect(out.byteLength).toBe(GROUP_SECRET_BYTES)
        expect(Buffer.compare(Buffer.from(out), Buffer.from(epochKey))).toBe(0)
    })

    it('rejects when expectedEpoch disagrees with the inner claim', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await seal({
            epochKey, groupSecret, conversationId: 7, version: 1, predictedEpoch: 5,
        })
        await expect(unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret,
            conversationId: 7, version: 1, expectedEpoch: 6,    // wrong
        })).rejects.toThrow(/inner epoch.*does not match expected/i)
    })

    it('rejects when conversationId in AAD changes', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await seal({
            epochKey, groupSecret, conversationId: 7, version: 1, predictedEpoch: 5,
        })
        await expect(unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret,
            conversationId: 8, version: 1, expectedEpoch: 5,
        })).rejects.toThrow(/unseal/i)
    })

    it('rejects when version in AAD changes', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await seal({
            epochKey, groupSecret, conversationId: 7, version: 1, predictedEpoch: 5,
        })
        await expect(unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret,
            conversationId: 7, version: 2, expectedEpoch: 5,
        })).rejects.toThrow(/unseal/i)
    })

    it('rejects under a wrong group_secret', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const wrongSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await seal({
            epochKey, groupSecret, conversationId: 7, version: 1, predictedEpoch: 5,
        })
        await expect(unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret:      wrongSecret,
            conversationId:   7, version: 1, expectedEpoch: 5,
        })).rejects.toThrow(/unseal/i)
    })
})


describe('unsealEpochKey — legacy 32-byte inner', () => {
    it('round-trips and bypasses inner-epoch check', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await seal({
            epochKey, groupSecret, conversationId: 9, version: 0,
            // no predictedEpoch -> legacy 32-byte plaintext
        })
        // Even with a wrong expectedEpoch a legacy bundle unseals,
        // the 32-byte format carries no inner-epoch binding
        const out = await unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret,
            conversationId: 9, version: 0, expectedEpoch: 999,
        })
        expect(Buffer.compare(Buffer.from(out), Buffer.from(epochKey))).toBe(0)
    })
})


describe('sealEpochKey ↔ unsealEpochKey full round-trip', () => {
    it('round-trips via the SDK\'s own seal helper', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const sealed = await sealEpochKey({
            epochKey, groupSecret,
            conversationId: 11, version: 3, predictedEpoch: 7,
        })
        const out = await unsealEpochKey({
            ciphertextBase64: sealed.ciphertext,
            ivBase64:         sealed.iv,
            groupSecret,
            conversationId: 11, version: 3, expectedEpoch: 7,
        })
        expect(Buffer.compare(Buffer.from(out), Buffer.from(epochKey))).toBe(0)
    })

    it('rejects sealEpochKey with non-32-byte epoch key', async () => {
        const gs = rand(GROUP_SECRET_BYTES)
        await expect(sealEpochKey({
            epochKey: new Uint8Array(16),
            groupSecret: gs,
            conversationId: 1, version: 0, predictedEpoch: 0,
        })).rejects.toThrow(/32 bytes/i)
    })

    it('rejects sealEpochKey with out-of-range predictedEpoch', async () => {
        const ek = rand(GROUP_SECRET_BYTES)
        const gs = rand(GROUP_SECRET_BYTES)
        await expect(sealEpochKey({
            epochKey: ek, groupSecret: gs,
            conversationId: 1, version: 0, predictedEpoch: -1,
        })).rejects.toThrow(/out of range/i)
        await expect(sealEpochKey({
            epochKey: ek, groupSecret: gs,
            conversationId: 1, version: 0, predictedEpoch: 0x1_0000_0000,
        })).rejects.toThrow(/out of range/i)
    })

    it('produces fresh IV per call', async () => {
        const epochKey    = rand(GROUP_SECRET_BYTES)
        const groupSecret = rand(GROUP_SECRET_BYTES)
        const a = await sealEpochKey({ epochKey, groupSecret, conversationId: 1, version: 0, predictedEpoch: 0 })
        const b = await sealEpochKey({ epochKey, groupSecret, conversationId: 1, version: 0, predictedEpoch: 0 })
        expect(a.iv).not.toBe(b.iv)
    })
})


describe('unsealEpochKey — input validation', () => {
    it('rejects iv not 12 bytes', async () => {
        const groupSecret = rand(GROUP_SECRET_BYTES)
        await expect(unsealEpochKey({
            ciphertextBase64: Buffer.from('xxxxxxxxxxxxxxxx').toString('base64'),
            ivBase64:         Buffer.from('short').toString('base64'),
            groupSecret,
            conversationId: 1, version: 0,
        })).rejects.toThrow(/iv must be 12/i)
    })

    it('rejects secret not 32 bytes', async () => {
        await expect(unsealEpochKey({
            ciphertextBase64: 'AAAA',
            ivBase64:         Buffer.alloc(12, 0).toString('base64'),
            groupSecret:      new Uint8Array(16),
            conversationId: 1, version: 0,
        })).rejects.toThrow(/must be 32/i)
    })
})
