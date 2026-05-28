import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { promises as fs } from 'node:fs'
import { tmpdir }         from 'node:os'
import path               from 'node:path'

import { FileSignalStore } from '../../src/crypto/stores.js'

let dir: string
let store: FileSignalStore

const KP = () => ({
    pub:  Buffer.from('A'.repeat(33)).toString('base64'),
    priv: Buffer.from('B'.repeat(32)).toString('base64'),
})

const ARR = (s: string) => {
    const buf = Buffer.from(s)
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
}


beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(tmpdir(), 'morokbot-store-'))
    store = new FileSignalStore(dir)
})

afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true })
})


describe('FileSignalStore.importInitial', () => {
    it('writes identity / state / signed prekey / OTPKs on first import', async () => {
        await store.importInitial({
            botUserId:      42,
            registrationId: 12345,
            deviceId:       1,
            identityKeyPair: KP(),
            signedPreKey: { keyId: 1, pub: KP().pub, priv: KP().priv, signature: 'sig==' },
            oneTimePreKeys: [
                { keyId: 1, pub: KP().pub, priv: KP().priv },
                { keyId: 2, pub: KP().pub, priv: KP().priv },
            ],
        })

        expect(await store.getLocalRegistrationId()).toBe(12345)
        expect(await store.listOneTimePreKeyIds()).toEqual([1, 2].sort())

        const spk = await store.getSignedPreKeyRecord(1)
        expect(spk?.signature).toBe('sig==')

        const idPair = await store.getIdentityKeyPair()
        expect(idPair).toBeDefined()
    })

    it('is idempotent — second import of the same bot is a no-op', async () => {
        const args = {
            botUserId:      7,
            registrationId: 999,
            deviceId:       1,
            identityKeyPair: KP(),
            signedPreKey: { keyId: 5, pub: KP().pub, priv: KP().priv, signature: 'X' },
            oneTimePreKeys: [{ keyId: 5, pub: KP().pub, priv: KP().priv }],
        }
        await store.importInitial(args)
        await store.importInitial(args)
        // No throw → success
        expect(await store.getLocalRegistrationId()).toBe(999)
    })

    it('refuses when stateDir holds a different bot', async () => {
        await store.importInitial({
            botUserId:      7,
            registrationId: 100,
            deviceId:       1,
            identityKeyPair: KP(),
            signedPreKey: { keyId: 1, pub: KP().pub, priv: KP().priv, signature: 'X' },
            oneTimePreKeys: [{ keyId: 1, pub: KP().pub, priv: KP().priv }],
        })
        await expect(store.importInitial({
            botUserId:      8,  // different bot
            registrationId: 100,
            deviceId:       1,
            identityKeyPair: KP(),
            signedPreKey: { keyId: 1, pub: KP().pub, priv: KP().priv, signature: 'X' },
            oneTimePreKeys: [{ keyId: 1, pub: KP().pub, priv: KP().priv }],
        })).rejects.toThrow(/refusing to overwrite/)
    })

    it('refuses when registrationId mismatches an existing import', async () => {
        await store.importInitial({
            botUserId:      7,
            registrationId: 100,
            deviceId:       1,
            identityKeyPair: KP(),
            signedPreKey: { keyId: 1, pub: KP().pub, priv: KP().priv, signature: 'X' },
            oneTimePreKeys: [{ keyId: 1, pub: KP().pub, priv: KP().priv }],
        })
        await expect(store.importInitial({
            botUserId:      7,
            registrationId: 200,  // different
            deviceId:       1,
            identityKeyPair: KP(),
            signedPreKey: { keyId: 1, pub: KP().pub, priv: KP().priv, signature: 'X' },
            oneTimePreKeys: [{ keyId: 1, pub: KP().pub, priv: KP().priv }],
        })).rejects.toThrow(/registrationId/)
    })
})


describe('FileSignalStore.session', () => {
    it('stores and reloads sessions keyed by encoded address', async () => {
        await store.ensureLayout()
        await store.storeSession('42.1', 'serialized-session-blob')
        const got = await store.loadSession('42.1')
        expect(got).toBe('serialized-session-blob')
    })

    it('returns undefined for unknown sessions', async () => {
        await store.ensureLayout()
        const got = await store.loadSession('99.1')
        expect(got).toBeUndefined()
    })

    it('refuses path-traversal addresses', async () => {
        await store.ensureLayout()
        await expect(store.storeSession('../etc/passwd', 'x'))
            .rejects.toThrow(/refusing unsafe session address/)
    })
})


describe('FileSignalStore.identity (TOFU)', () => {
    it('isTrustedIdentity returns true on first sight (TOFU)', async () => {
        await store.ensureLayout()
        const trusted = await store.isTrustedIdentity('42.1', ARR('peer-key'), 1)
        expect(trusted).toBe(true)
    })

    it('saveIdentity returns false on first save (no prior identity to change from)', async () => {
        await store.ensureLayout()
        const changed = await store.saveIdentity('42.1', ARR('peer-key'))
        expect(changed).toBe(false)
    })

    it('saveIdentity returns true when peer rotates identity', async () => {
        await store.ensureLayout()
        await store.saveIdentity('42.1', ARR('old-key'))
        const changed = await store.saveIdentity('42.1', ARR('new-key'))
        expect(changed).toBe(true)
    })

    it('isTrustedIdentity rejects byte-mismatched peer key', async () => {
        await store.ensureLayout()
        await store.saveIdentity('42.1', ARR('the-key'))
        const trusted = await store.isTrustedIdentity('42.1', ARR('different'), 1)
        expect(trusted).toBe(false)
    })
})


describe('FileSignalStore.prekeys', () => {
    it('OTPK lifecycle: store → load → remove', async () => {
        await store.ensureLayout()
        await store.storePreKey(7, { pubKey: ARR('p'), privKey: ARR('q') })
        const got = await store.loadPreKey(7)
        expect(got).toBeDefined()
        await store.removePreKey(7)
        const after = await store.loadPreKey(7)
        expect(after).toBeUndefined()
    })

    it('removePreKey on missing id is a no-op', async () => {
        await store.ensureLayout()
        await expect(store.removePreKey(123)).resolves.toBeUndefined()
    })

    it('storeSignedPreKey preserves the signature from a prior full-write', async () => {
        await store.ensureLayout()
        await store.storeSignedPreKeyFull({
            keyId: 5,
            keyPair: { pubKey: ARR('p'), privKey: ARR('q') },
            signature: ARR('SIG'),
        })
        // libsignal's storeSignedPreKey only ships keyPair, no signature
        await store.storeSignedPreKey(5, { pubKey: ARR('p2'), privKey: ARR('q2') })

        const rec = await store.getSignedPreKeyRecord(5)
        expect(rec?.signature).toBe(Buffer.from('SIG').toString('base64'))
    })
})


describe('FileSignalStore.fsck', () => {
    it('quarantines a corrupted session file', async () => {
        await store.ensureLayout()
        const badPath = path.join(dir, 'sessions', '99.1.json')
        await fs.writeFile(badPath, '{ not json}')

        const res = await store.fsck()
        expect(res.quarantinedSessions).toContain(badPath)
        // Original file moved away
        await expect(fs.access(badPath)).rejects.toThrow()
    })

    it('leaves valid sessions intact', async () => {
        await store.ensureLayout()
        await store.storeSession('42.1', 'ok-record')
        const res = await store.fsck()
        expect(res.quarantinedSessions).toHaveLength(0)
        expect(await store.loadSession('42.1')).toBe('ok-record')
    })
})


describe('FileSignalStore.state', () => {
    it('initializes state.json on first read', async () => {
        await store.ensureLayout()
        const s = await store.loadState()
        expect(s.lastSignedPreKeyRotationMs).toBe(0)
        expect(s.nextOneTimePreKeyId).toBe(1)
    })

    it('patchState merges and persists', async () => {
        await store.ensureLayout()
        await store.loadState()
        await store.patchState({ nextOneTimePreKeyId: 50 })
        const s2 = await store.loadState()
        expect(s2.nextOneTimePreKeyId).toBe(50)
        expect(s2.nextSignedPreKeyId).toBe(1)  // untouched
    })
})
