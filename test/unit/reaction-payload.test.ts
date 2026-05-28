/** Reaction is any unicode symbol, the JSON wire field is just named `emoji` (a legacy thing) */

import { describe, it, expect } from 'vitest'
import { _parseReactionUnicode as parse } from '../../src/flow/receive.js'


describe('parseReactionUnicode', () => {
    it('extracts the unicode from the canonical { emoji } JSON', () => {
        expect(parse(JSON.stringify({ emoji: '👍' }))).toBe('👍')
        expect(parse(JSON.stringify({ emoji: '🔥' }))).toBe('🔥')
        // multi-codepoint grapheme
        expect(parse(JSON.stringify({ emoji: '👩‍👩‍👧' }))).toBe('👩‍👩‍👧')
    })

    it('ignores extra fields, returns the unicode', () => {
        expect(parse(JSON.stringify({ emoji: '🎉', foo: 1, bar: 'x' }))).toBe('🎉')
    })

    it('returns null on non-JSON / empty / non-object', () => {
        expect(parse('')).toBeNull()
        expect(parse('not json')).toBeNull()
        expect(parse('👍')).toBeNull()            // bare unicode without the JSON envelope
        expect(parse('null')).toBeNull()
        expect(parse('"just a string"')).toBeNull()
        expect(parse('[1,2,3]')).toBeNull()
    })

    it('returns null when the emoji key is missing or not a non-empty string', () => {
        expect(parse(JSON.stringify({}))).toBeNull()
        expect(parse(JSON.stringify({ emoji: '' }))).toBeNull()
        expect(parse(JSON.stringify({ emoji: 42 }))).toBeNull()
        expect(parse(JSON.stringify({ emoji: null }))).toBeNull()
    })

    it('rejects oversized payloads and oversized unicode', () => {
        expect(parse('{' + 'x'.repeat(600))).toBeNull()                  // >512 bytes, malformed
        expect(parse(JSON.stringify({ emoji: 'x'.repeat(100) }))).toBeNull() // unicode >64 chars
    })
})
