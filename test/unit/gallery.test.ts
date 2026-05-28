/**
 * Gallery wire-format unit tests:
 *   • buildGalleryPayload emits the JSON envelope the receiver
 *     can parse back into items
 *   • parseGalleryItem accepts well-formed file / contact /
 *     location items, rejects malformed shapes
 *   • _sniffStructuredPayload recognises `type:'gallery'` payloads
 *     and surfaces them as `gallery: ParsedGallery`
 */

import { describe, it, expect } from 'vitest'
import {
    buildGalleryPayload, parseGalleryItem,
    GALLERY_MIN_ITEMS, GALLERY_MAX_ITEMS,
    type EncryptedFileRef,
} from '../../src/flow/attachments.js'
import { _sniffStructuredPayload as sniff } from '../../src/flow/receive.js'


function ref(fileId: number, name = `f${fileId}.bin`): EncryptedFileRef {
    return {
        fileId,
        sha256: 'a'.repeat(64),
        key:    'A'.repeat(44),
        iv:     'B'.repeat(16),
        size:   1024,
        mime:   'image/jpeg',
        name,
    }
}


describe('buildGalleryPayload', () => {
    it('emits the {type:"gallery", items:[...]} envelope', () => {
        const json = buildGalleryPayload([
            { type: 'file', ref: ref(10) },
            { type: 'file', ref: ref(11) },
        ])
        const parsed = JSON.parse(json)
        expect(parsed.type).toBe('gallery')
        expect(Array.isArray(parsed.items)).toBe(true)
        expect(parsed.items.length).toBe(2)
        expect(parsed.items[0].type).toBe('file')
        expect(parsed.items[0].ref.fileId).toBe(10)
        expect(parsed.caption).toBeUndefined()
    })

    it('preserves caption when provided', () => {
        const json = buildGalleryPayload(
            [{ type: 'file', ref: ref(1) }, { type: 'file', ref: ref(2) }],
            'cat photos',
        )
        const parsed = JSON.parse(json)
        expect(parsed.caption).toBe('cat photos')
    })

    it('drops empty caption', () => {
        const json = buildGalleryPayload(
            [{ type: 'file', ref: ref(1) }, { type: 'file', ref: ref(2) }],
            '',
        )
        const parsed = JSON.parse(json)
        expect(parsed.caption).toBeUndefined()
    })

    it('round-trips contact + location items', () => {
        const json = buildGalleryPayload([
            { type: 'contact', userId: 42, username: 'alice', displayName: 'Alice' },
            { type: 'location', lat: 55.7558, lng: 37.6173 },
        ])
        const parsed = JSON.parse(json)
        expect(parsed.items[0]).toEqual({ type: 'contact', userId: 42, username: 'alice', displayName: 'Alice' })
        expect(parsed.items[1]).toEqual({ type: 'location', lat: 55.7558, lng: 37.6173 })
    })

    it('exposes correct min/max constants', () => {
        expect(GALLERY_MIN_ITEMS).toBe(2)
        expect(GALLERY_MAX_ITEMS).toBe(10)
    })
})


describe('parseGalleryItem', () => {
    it('accepts a valid file item', () => {
        const item = parseGalleryItem({ type: 'file', ref: ref(7) })
        expect(item).not.toBeNull()
        expect(item!.type).toBe('file')
    })

    it('rejects file item with malformed ref', () => {
        expect(parseGalleryItem({ type: 'file', ref: { fileId: 'nope' } })).toBeNull()
        expect(parseGalleryItem({ type: 'file', ref: null })).toBeNull()
    })

    it('accepts contact item with required userId', () => {
        const item = parseGalleryItem({ type: 'contact', userId: 100 })
        expect(item).toEqual({ type: 'contact', userId: 100 })
    })

    it('rejects contact item with invalid userId', () => {
        expect(parseGalleryItem({ type: 'contact', userId: 0 })).toBeNull()
        expect(parseGalleryItem({ type: 'contact', userId: -1 })).toBeNull()
        expect(parseGalleryItem({ type: 'contact' })).toBeNull()
    })

    it('accepts location with valid lat/lng', () => {
        expect(parseGalleryItem({ type: 'location', lat: 0, lng: 0 })).toEqual({ type: 'location', lat: 0, lng: 0 })
        expect(parseGalleryItem({ type: 'location', lat: 90, lng: 180 })).toEqual({ type: 'location', lat: 90, lng: 180 })
        expect(parseGalleryItem({ type: 'location', lat: -90, lng: -180 })).toEqual({ type: 'location', lat: -90, lng: -180 })
    })

    it('rejects location with out-of-range coordinates', () => {
        expect(parseGalleryItem({ type: 'location', lat: 91, lng: 0 })).toBeNull()
        expect(parseGalleryItem({ type: 'location', lat: 0, lng: 181 })).toBeNull()
        expect(parseGalleryItem({ type: 'location', lat: -91, lng: 0 })).toBeNull()
        expect(parseGalleryItem({ type: 'location', lat: NaN, lng: 0 })).toBeNull()
        expect(parseGalleryItem({ type: 'location', lat: 0, lng: Infinity })).toBeNull()
    })

    it('rejects unknown item types', () => {
        expect(parseGalleryItem({ type: 'sticker' })).toBeNull()
        expect(parseGalleryItem({})).toBeNull()
        expect(parseGalleryItem(null)).toBeNull()
        expect(parseGalleryItem(42)).toBeNull()
    })
})


describe('_sniffStructuredPayload — gallery', () => {
    it('parses a 2-item gallery envelope', () => {
        const json = buildGalleryPayload([
            { type: 'file', ref: ref(1) },
            { type: 'file', ref: ref(2) },
        ])
        const res = sniff(json)
        expect(res).not.toBeNull()
        expect(res?.gallery?.items.length).toBe(2)
        expect(res?.attachment).toBeUndefined()
        expect(res?.caption).toBe('')
    })

    it('parses a 3-item mixed gallery (file + contact + location)', () => {
        const json = buildGalleryPayload([
            { type: 'file', ref: ref(1) },
            { type: 'contact', userId: 50, username: 'bob' },
            { type: 'location', lat: 10, lng: 20 },
        ], 'mixed bag')
        const res = sniff(json)
        expect(res?.gallery?.items.length).toBe(3)
        expect(res?.gallery?.items[1]).toMatchObject({ type: 'contact', userId: 50 })
        expect(res?.gallery?.items[2]).toEqual({ type: 'location', lat: 10, lng: 20 })
        expect(res?.caption).toBe('mixed bag')
    })

    it('drops malformed items but keeps the rest', () => {
        const json = JSON.stringify({
            type: 'gallery',
            items: [
                { type: 'file', ref: ref(1) },
                { type: 'file', ref: { fileId: 'broken' } },  // dropped
                { type: 'file', ref: ref(3) },
            ],
        })
        const res = sniff(json)
        expect(res?.gallery?.items.length).toBe(2)
    })

    it('falls back to plain text when fewer than min items remain', () => {
        const json = JSON.stringify({
            type: 'gallery',
            items: [{ type: 'file', ref: ref(1) }],
        })
        // 1 item < GALLERY_MIN_ITEMS (2). Falls through as text
        expect(sniff(json)).toBeNull()
    })

    it('truncates an over-large gallery to GALLERY_MAX_ITEMS', () => {
        const items: { type: 'file'; ref: EncryptedFileRef }[] = []
        for (let i = 1; i <= 15; i++) items.push({ type: 'file', ref: ref(i) })
        const json = buildGalleryPayload(items)
        const res = sniff(json)
        expect(res?.gallery?.items.length).toBe(GALLERY_MAX_ITEMS)
    })

    it('returns null on non-array items', () => {
        expect(sniff(JSON.stringify({ type: 'gallery', items: 'oops' }))).toBeNull()
    })
})
