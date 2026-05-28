import { describe, it, expect } from 'vitest'

import {
    _sniffStructuredPayload as sniff,
    _buildIncomingAttachment as buildIncoming,
} from '../../src/flow/receive.js'
import { isEncryptedFileRef } from '../../src/flow/attachments.js'


// Minimal valid EncryptedFileRef, the only field shapes the SDK actually validates
// are exact-form (sha256 hex, key/iv length floors)
function makeRef(overrides: Partial<{
    fileId: number; sha256: string; key: string; iv: string;
    size: number; mime: string; name: string
}> = {}) {
    return {
        fileId: 42,
        sha256: 'a'.repeat(64),
        key:    'A'.repeat(44),  // base64 of 32 bytes
        iv:     'B'.repeat(16),
        size:   1024,
        mime:   'image/jpeg',
        ...overrides,
    }
}


describe('sniffStructuredPayload', () => {
    it('returns null for plain UTF-8 text', () => {
        expect(sniff('hello world')).toBeNull()
    })

    it('returns null for text starting with "{" but not valid JSON', () => {
        expect(sniff('{not json}')).toBeNull()
    })

    it('returns null for empty string', () => {
        expect(sniff('')).toBeNull()
    })

    it('returns null for valid JSON without a recognised type', () => {
        expect(sniff('{"type":"sticker","stickerId":1}')).toBeNull()
        expect(sniff('{"hello":"world"}')).toBeNull()
    })

    it('parses a "file" payload with caption', () => {
        const json = JSON.stringify({
            type:    'file',
            ref:     makeRef(),
            caption: 'photo of my cat',
        })
        const res = sniff(json)
        expect(res?.attachment?.kind).toBe('file')
        expect(res?.caption).toBe('photo of my cat')
        expect(res?.attachment?.ref.fileId).toBe(42)
    })

    it('parses a "file" payload without caption (caption defaults to empty string)', () => {
        const res = sniff(JSON.stringify({ type: 'file', ref: makeRef() }))
        expect(res?.caption).toBe('')
        expect(res?.attachment?.kind).toBe('file')
    })

    it('parses a "voice" payload with duration and waveform', () => {
        const res = sniff(JSON.stringify({
            type:     'voice',
            ref:      makeRef({ mime: 'audio/ogg' }),
            duration: 5.3,
            waveform: [10, 50, 99, 200, -5, 0],
        }))
        expect(res?.attachment?.kind).toBe('voice')
        expect(res?.attachment?.duration).toBe(5.3)
        // Clamps 200 → 100, -5 → 0, preserves valid samples
        expect(res?.attachment?.waveform).toEqual([10, 50, 99, 100, 0, 0])
    })

    it('voice: waveform capped at 64 entries', () => {
        const big = new Array(200).fill(50)
        const res = sniff(JSON.stringify({
            type:     'voice',
            ref:      makeRef(),
            duration: 3,
            waveform: big,
        }))
        expect(res?.attachment?.waveform?.length).toBe(64)
    })

    it('voice: caps duration at 600 seconds', () => {
        const res = sniff(JSON.stringify({
            type:     'voice',
            ref:      makeRef(),
            duration: 99999,
            waveform: [],
        }))
        expect(res?.attachment?.duration).toBe(600)
    })

    it('parses a "video_note" payload with shape', () => {
        const res = sniff(JSON.stringify({
            type:     'video_note',
            ref:      makeRef({ mime: 'video/webm' }),
            duration: 12.5,
            shape:    'star',
        }))
        expect(res?.attachment?.kind).toBe('video_note')
        expect(res?.attachment?.shape).toBe('star')
    })

    it('video_note: shape passes through to the receiver', () => {
        const res = sniff(JSON.stringify({
            type:     'video_note',
            ref:      makeRef(),
            duration: 5,
            shape:    'rhombus',
        }))
        expect(res?.attachment?.shape).toBe('rhombus')
    })

    it('rejects payload with malformed ref (missing sha256)', () => {
        const ref = makeRef() as Record<string, unknown>
        delete ref.sha256
        expect(sniff(JSON.stringify({ type: 'file', ref }))).toBeNull()
    })

    it('rejects payload with key too short', () => {
        expect(sniff(JSON.stringify({
            type: 'file',
            ref:  makeRef({ key: 'A'.repeat(10) }),
        }))).toBeNull()
    })

    it('handles a payload preceded by leading whitespace as text (no sniff)', () => {
        // Strict: payload must START with '{' or it's text. Leading
        // whitespace is unusual for a structured payload and we err
        // on the side of "show the developer the raw text"
        const raw = ' ' + JSON.stringify({ type: 'file', ref: makeRef() })
        expect(sniff(raw)).toBeNull()
    })
})


describe('isEncryptedFileRef', () => {
    it('accepts a well-formed ref', () => {
        expect(isEncryptedFileRef(makeRef())).toBe(true)
    })

    it('rejects bad sha256 (uppercase)', () => {
        expect(isEncryptedFileRef(makeRef({ sha256: 'A'.repeat(64) }))).toBe(false)
    })

    it('rejects bad sha256 (wrong length)', () => {
        expect(isEncryptedFileRef(makeRef({ sha256: 'a'.repeat(63) }))).toBe(false)
    })

    it('rejects non-object', () => {
        expect(isEncryptedFileRef(null)).toBe(false)
        expect(isEncryptedFileRef('foo')).toBe(false)
        expect(isEncryptedFileRef(42)).toBe(false)
    })

    it('rejects negative or zero fileId', () => {
        expect(isEncryptedFileRef(makeRef({ fileId: 0 }))).toBe(false)
        expect(isEncryptedFileRef(makeRef({ fileId: -1 }))).toBe(false)
    })

    it('accepts optional name + non-chunked ref', () => {
        expect(isEncryptedFileRef({
            ...makeRef(),
            name: 'doc.pdf',
        })).toBe(true)
    })

    it('accepts chunked ref with iv="" and totalChunks present', () => {
        // FE wire shape for chunked: iv is intentionally empty since
        // each chunk carries its own IV in the packed bytes
        expect(isEncryptedFileRef({
            ...makeRef(),
            iv: '',
            chunked: true,
            totalChunks: 5,
        })).toBe(true)
    })

    it('rejects chunked ref with non-empty iv (FE never emits that shape)', () => {
        expect(isEncryptedFileRef({
            ...makeRef(),
            iv: 'B'.repeat(16),
            chunked: true,
            totalChunks: 5,
        })).toBe(false)
    })

    it('rejects chunked ref missing totalChunks', () => {
        expect(isEncryptedFileRef({
            ...makeRef(),
            iv: '',
            chunked: true,
        })).toBe(false)
    })

    it('rejects single-shot ref with iv length != 16 (base64 of 12 bytes)', () => {
        expect(isEncryptedFileRef({ ...makeRef(), iv: 'AAA' })).toBe(false)
        expect(isEncryptedFileRef({ ...makeRef(), iv: 'A'.repeat(12) })).toBe(false)
        expect(isEncryptedFileRef({ ...makeRef(), iv: 'A'.repeat(15) })).toBe(false)
        expect(isEncryptedFileRef({ ...makeRef(), iv: 'A'.repeat(17) })).toBe(false)
        expect(isEncryptedFileRef({ ...makeRef(), iv: 'A'.repeat(24) })).toBe(false)
    })

    it('accepts single-shot ref with iv length === 16 (base64 of 12 bytes)', () => {
        expect(isEncryptedFileRef({ ...makeRef(), iv: 'A'.repeat(16) })).toBe(true)
    })

    it('rejects totalChunks < 2', () => {
        expect(isEncryptedFileRef({
            ...makeRef(),
            iv: '',
            chunked: true,
            totalChunks: 1,
        })).toBe(false)
    })
})


describe('buildIncomingAttachment', () => {
    it('exposes a lazy download() closure', async () => {
        let called = 0
        const out = buildIncoming(
            { kind: 'file', ref: makeRef({ name: 'foo.txt' }) },
            async () => { called++; return Buffer.from('hello') },
        )
        expect(out.kind).toBe('file')
        expect(out.name).toBe('foo.txt')
        expect(out.size).toBe(1024)
        expect(called).toBe(0)
        const bytes = await out.download()
        expect(called).toBe(1)
        expect(bytes.toString('utf8')).toBe('hello')
    })

    it('voice: name is null (anonymous), duration/waveform present', () => {
        const out = buildIncoming(
            { kind: 'voice', ref: makeRef({ mime: 'audio/ogg' }), duration: 3, waveform: [10, 20, 30] },
            async () => Buffer.from('audio-bytes'),
        )
        expect(out.kind).toBe('voice')
        expect(out.name).toBeNull()
        expect(out.duration).toBe(3)
        expect(out.waveform).toEqual([10, 20, 30])
        expect(out.shape).toBeUndefined()
    })

    it('video_note: shape present, no waveform', () => {
        const out = buildIncoming(
            { kind: 'video_note', ref: makeRef({ mime: 'video/webm' }), duration: 7, shape: 'heart' },
            async () => Buffer.from('vid'),
        )
        expect(out.kind).toBe('video_note')
        expect(out.shape).toBe('heart')
        expect(out.waveform).toBeUndefined()
    })
})
