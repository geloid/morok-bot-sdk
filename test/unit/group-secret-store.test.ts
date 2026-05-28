/**
 * GroupSecretStore unit tests parallel channel-key-store.test.ts
 * (same atomic-write + per-conv lock + fsck pattern, different field
 * names: `version` vs `epoch`)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, readdir, writeFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { GroupSecretStore } from '../../src/crypto/group-secret-store.js'


let scratch: string
let store:   GroupSecretStore


function b64key(byte: number): string {
    return Buffer.alloc(32, byte).toString('base64')
}


beforeEach(async () => {
    scratch = await mkdtemp(join(tmpdir(), 'morok-sdk-gskey-'))
    store = new GroupSecretStore(scratch)
    await store.init()
})

afterEach(async () => {
    try { await rm(scratch, { recursive: true, force: true }) } catch { /* ignore */ }
})


describe('GroupSecretStore.init', () => {
    it('creates the group-secrets/ subdir', async () => {
        const d = await stat(join(scratch, 'group-secrets'))
        expect(d.isDirectory()).toBe(true)
    })

    it('sweeps stale .tmp files', async () => {
        const dir = join(scratch, 'group-secrets')
        await writeFile(join(dir, '5.json.tmp.abcd'), '{}')
        const fresh = new GroupSecretStore(scratch)
        await fresh.init()
        const entries = await readdir(dir)
        expect(entries.includes('5.json.tmp.abcd')).toBe(false)
    })
})


describe('load / mergeVersions / getSecret', () => {
    it('load returns null for an unknown conversation', async () => {
        expect(await store.load(123)).toBeNull()
    })

    it('mergeVersions writes a fresh state file', async () => {
        const state = await store.mergeVersions(7, [
            { version: 0, secretBase64: b64key(0xaa) },
            { version: 1, secretBase64: b64key(0xbb) },
        ])
        expect(state.currentVersion).toBe(1)
        expect(state.secrets['0']).toBe(b64key(0xaa))
        expect(state.secrets['1']).toBe(b64key(0xbb))

        const round = await store.load(7)
        expect(round!.currentVersion).toBe(1)
    })

    it('tracks max(version) on out-of-order merges', async () => {
        await store.mergeVersions(7, [{ version: 5, secretBase64: b64key(0x05) }])
        const r = await store.mergeVersions(7, [{ version: 2, secretBase64: b64key(0x02) }])
        expect(r.currentVersion).toBe(5)
    })

    it('overwrites the same version idempotently', async () => {
        await store.mergeVersions(7, [{ version: 0, secretBase64: b64key(0xaa) }])
        const r = await store.mergeVersions(7, [{ version: 0, secretBase64: b64key(0xcc) }])
        expect(r.secrets['0']).toBe(b64key(0xcc))
    })

    it('getSecret returns raw 32-byte secret', async () => {
        await store.mergeVersions(9, [{ version: 3, secretBase64: b64key(0x42) }])
        const sec = await store.getSecret(9, 3)
        expect(sec).not.toBeNull()
        expect(sec!.byteLength).toBe(32)
        expect(sec![0]).toBe(0x42)
    })

    it('getSecret returns null for missing version', async () => {
        await store.mergeVersions(9, [{ version: 3, secretBase64: b64key(0x42) }])
        expect(await store.getSecret(9, 4)).toBeNull()
    })

    it('rejects merge of a non-32-byte secret', async () => {
        const shortKey = Buffer.alloc(16, 1).toString('base64')
        await expect(store.mergeVersions(7, [{ version: 0, secretBase64: shortKey }]))
            .rejects.toThrow(/expected 32/i)
    })

    it('rejects merge of an out-of-range version', async () => {
        await expect(store.mergeVersions(7, [{ version: -1, secretBase64: b64key(0) }]))
            .rejects.toThrow(/bad version/i)
        await expect(store.mergeVersions(7, [{ version: 0x1_0000_0000, secretBase64: b64key(0) }]))
            .rejects.toThrow(/bad version/i)
    })

    it('atomic write — no .tmp file remains after merge', async () => {
        await store.mergeVersions(7, [{ version: 0, secretBase64: b64key(1) }])
        const entries = await readdir(join(scratch, 'group-secrets'))
        const tmps = entries.filter(e => e.includes('.tmp.'))
        expect(tmps).toEqual([])
    })
})


describe('drop', () => {
    it('removes the state file', async () => {
        await store.mergeVersions(7, [{ version: 0, secretBase64: b64key(1) }])
        await store.drop(7)
        expect(await store.load(7)).toBeNull()
    })

    it('is a no-op on missing state', async () => {
        await expect(store.drop(404)).resolves.toBeUndefined()
    })
})


describe('quarantine on corrupt state', () => {
    it('quarantines malformed JSON and returns null', async () => {
        const dir = join(scratch, 'group-secrets')
        await writeFile(join(dir, '99.json'), '{not json')
        expect(await store.load(99)).toBeNull()
        const entries = await readdir(dir)
        expect(entries.some(e => e.startsWith('99.json.corrupt-'))).toBe(true)
        expect(entries.includes('99.json')).toBe(false)
    })
})


describe('concurrency', () => {
    it('serialises parallel merges on the same conv', async () => {
        const ops: Promise<unknown>[] = []
        for (let i = 0; i < 10; i++) {
            ops.push(store.mergeVersions(11, [{ version: i, secretBase64: b64key(i) }]))
        }
        await Promise.all(ops)
        const final = await store.load(11)
        expect(final!.currentVersion).toBe(9)
        for (let i = 0; i < 10; i++) {
            expect(final!.secrets[String(i)]).toBe(b64key(i))
        }
    })
})


describe('file permissions', () => {
    it('writes state files with mode 0o600', async () => {
        await store.mergeVersions(7, [{ version: 0, secretBase64: b64key(1) }])
        const st = await stat(join(scratch, 'group-secrets', '7.json'))
        // eslint-disable-next-line no-bitwise
        expect((st.mode & 0o077)).toBe(0)
    })
})
