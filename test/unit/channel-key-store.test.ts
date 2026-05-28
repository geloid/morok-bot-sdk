/**
 * ChannelKeyStore unit tests
 * Touches the real fs, uses os.tmpdir() under a per-test scratch
 * dir and wipes it in afterEach
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, readdir, writeFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { ChannelKeyStore } from '../../src/crypto/channel-key-store.js'


let scratch: string
let store:   ChannelKeyStore


function b64key(byte: number): string {
    const k = Buffer.alloc(32, byte)
    return k.toString('base64')
}


beforeEach(async () => {
    scratch = await mkdtemp(join(tmpdir(), 'morok-sdk-chankey-'))
    store = new ChannelKeyStore(scratch)
    await store.init()
})

afterEach(async () => {
    try { await rm(scratch, { recursive: true, force: true }) } catch { /* ignore */ }
})


describe('init', () => {
    it('creates the channel-keys directory under stateDir', async () => {
        const d = await stat(join(scratch, 'channel-keys'))
        expect(d.isDirectory()).toBe(true)
    })

    it('sweeps stale .tmp files', async () => {
        const dir = join(scratch, 'channel-keys')
        await writeFile(join(dir, '5.json.tmp.abcd'), '{}')
        // Reset store and init() again so fsck runs
        const fresh = new ChannelKeyStore(scratch)
        await fresh.init()
        const entries = await readdir(dir)
        expect(entries.includes('5.json.tmp.abcd')).toBe(false)
    })
})


describe('load / mergeEpochs / getSecret', () => {
    it('load returns null for an unknown conversation', async () => {
        expect(await store.load(123)).toBeNull()
    })

    it('mergeEpochs writes a fresh state file', async () => {
        const state = await store.mergeEpochs(7, [
            { epoch: 0, secretBase64: b64key(0xaa) },
            { epoch: 1, secretBase64: b64key(0xbb) },
        ])
        expect(state.currentEpoch).toBe(1)
        expect(state.keys['0']).toBe(b64key(0xaa))
        expect(state.keys['1']).toBe(b64key(0xbb))

        const round = await store.load(7)
        expect(round).not.toBeNull()
        expect(round!.currentEpoch).toBe(1)
    })

    it('mergeEpochs is idempotent for the same epoch', async () => {
        await store.mergeEpochs(7, [{ epoch: 0, secretBase64: b64key(0xaa) }])
        const round = await store.mergeEpochs(7, [{ epoch: 0, secretBase64: b64key(0xcc) }])
        // Second write overwrites, same FE behaviour
        expect(round.keys['0']).toBe(b64key(0xcc))
        expect(round.currentEpoch).toBe(0)
    })

    it('mergeEpochs tracks max(epoch) when out-of-order', async () => {
        await store.mergeEpochs(7, [{ epoch: 5, secretBase64: b64key(0x05) }])
        const r = await store.mergeEpochs(7, [{ epoch: 2, secretBase64: b64key(0x02) }])
        // 5 stays as the highest known
        expect(r.currentEpoch).toBe(5)
    })

    it('getSecret returns raw 32-byte secret for an installed epoch', async () => {
        await store.mergeEpochs(9, [{ epoch: 3, secretBase64: b64key(0x42) }])
        const sec = await store.getSecret(9, 3)
        expect(sec).not.toBeNull()
        expect(sec!.byteLength).toBe(32)
        expect(sec![0]).toBe(0x42)
    })

    it('getSecret returns null for an unknown epoch', async () => {
        await store.mergeEpochs(9, [{ epoch: 3, secretBase64: b64key(0x42) }])
        expect(await store.getSecret(9, 4)).toBeNull()
    })

    it('rejects merge of a non-32-byte secret', async () => {
        const shortKey = Buffer.alloc(16, 1).toString('base64')
        await expect(store.mergeEpochs(7, [{ epoch: 0, secretBase64: shortKey }]))
            .rejects.toThrow(/expected 32/i)
    })

    it('rejects merge of an out-of-range epoch', async () => {
        await expect(store.mergeEpochs(7, [{ epoch: -1, secretBase64: b64key(0) }]))
            .rejects.toThrow(/bad epoch/i)
        await expect(store.mergeEpochs(7, [{ epoch: 0x1_0000_0000, secretBase64: b64key(0) }]))
            .rejects.toThrow(/bad epoch/i)
    })

    it('atomic write — no .tmp file remains after a successful merge', async () => {
        await store.mergeEpochs(7, [{ epoch: 0, secretBase64: b64key(1) }])
        const entries = await readdir(join(scratch, 'channel-keys'))
        const tmps = entries.filter(e => e.includes('.tmp.'))
        expect(tmps).toEqual([])
    })
})


describe('drop', () => {
    it('removes the state file', async () => {
        await store.mergeEpochs(7, [{ epoch: 0, secretBase64: b64key(1) }])
        await store.drop(7)
        expect(await store.load(7)).toBeNull()
    })

    it('is a no-op if the state file is missing', async () => {
        await expect(store.drop(404)).resolves.toBeUndefined()
    })
})


describe('quarantine on corrupt state', () => {
    it('moves a malformed JSON file to a .corrupt-<ts> sibling and returns null', async () => {
        const dir = join(scratch, 'channel-keys')
        await writeFile(join(dir, '99.json'), '{not json')
        const loaded = await store.load(99)
        expect(loaded).toBeNull()
        const entries = await readdir(dir)
        expect(entries.some(e => e.startsWith('99.json.corrupt-'))).toBe(true)
        expect(entries.includes('99.json')).toBe(false)
    })

    it('quarantines a JSON file with a missing currentEpoch field', async () => {
        const dir = join(scratch, 'channel-keys')
        await writeFile(join(dir, '100.json'), JSON.stringify({ keys: {} }))
        const loaded = await store.load(100)
        expect(loaded).toBeNull()
    })

    it('quarantines a JSON file with non-string epoch entries', async () => {
        const dir = join(scratch, 'channel-keys')
        await writeFile(join(dir, '101.json'), JSON.stringify({ currentEpoch: 0, keys: { 0: 12345 } }))
        const loaded = await store.load(101)
        expect(loaded).toBeNull()
    })
})


describe('concurrency — per-conversation lock', () => {
    it('serialises parallel merges on the same conv', async () => {
        // 10 parallel merges, each introducing a different epoch
        const ops: Promise<unknown>[] = []
        for (let i = 0; i < 10; i++) {
            ops.push(store.mergeEpochs(11, [{ epoch: i, secretBase64: b64key(i) }]))
        }
        await Promise.all(ops)
        const final = await store.load(11)
        expect(final).not.toBeNull()
        expect(final!.currentEpoch).toBe(9)
        for (let i = 0; i < 10; i++) {
            expect(final!.keys[String(i)]).toBe(b64key(i))
        }
    })

    it('parallel writes to different convs do not block each other', async () => {
        // Smoke: both should resolve, the lock map is per-conv and there's
        // no way to assert "didn't wait" cleanly from tests, so we just confirm correctness
        const [a, b] = await Promise.all([
            store.mergeEpochs(21, [{ epoch: 0, secretBase64: b64key(0x21) }]),
            store.mergeEpochs(22, [{ epoch: 0, secretBase64: b64key(0x22) }]),
        ])
        expect(a.currentEpoch).toBe(0)
        expect(b.currentEpoch).toBe(0)
    })
})


describe('file permissions', () => {
    it('writes state files with mode 0o600', async () => {
        await store.mergeEpochs(7, [{ epoch: 0, secretBase64: b64key(1) }])
        const st = await stat(join(scratch, 'channel-keys', '7.json'))
        // mask off the file-type bits, just look at perm bits eslint-disable-next-line no-bitwise
        const perms = st.mode & 0o777
        // umask may strip group/other bits, what we care about is that group/other don't get any access
        expect(perms & 0o077).toBe(0)
    })
})
