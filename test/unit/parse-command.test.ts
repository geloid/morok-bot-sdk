import { describe, it, expect } from 'vitest'
import { _parseCommand as parseCommand } from '../../src/flow/receive.js'


describe('parseCommand', () => {
    it('extracts a bare command', () => {
        expect(parseCommand('/help')).toEqual({
            command: 'help', args: '', argv: [],
        })
    })

    it('extracts command + single-word arg', () => {
        expect(parseCommand('/echo hello')).toEqual({
            command: 'echo', args: 'hello', argv: ['hello'],
        })
    })

    it('extracts command + multiple-word args', () => {
        expect(parseCommand('/say one two three')).toEqual({
            command: 'say', args: 'one two three', argv: ['one', 'two', 'three'],
        })
    })

    it('collapses runs of whitespace in argv', () => {
        expect(parseCommand('/cmd   a   b   c')?.argv).toEqual(['a', 'b', 'c'])
    })

    it('trims leading/trailing whitespace', () => {
        expect(parseCommand('  /help  ')?.command).toBe('help')
    })

    it('returns null for non-slash text', () => {
        expect(parseCommand('just a message')).toBeNull()
    })

    it('returns null for multi-line text (even if first line is a command)', () => {
        expect(parseCommand('/help\nplease')).toBeNull()
    })

    it('returns null for slash followed by capital letter (server forbids)', () => {
        expect(parseCommand('/Help')).toBeNull()
    })

    it('returns null for slash followed by digit', () => {
        expect(parseCommand('/1cmd')).toBeNull()
    })

    it('rejects command names over 32 chars', () => {
        const longName = '/' + 'a'.repeat(33)
        expect(parseCommand(longName)).toBeNull()
    })

    it('accepts command name at the 32-char boundary', () => {
        const exact = '/' + 'a'.repeat(32)
        expect(parseCommand(exact)?.command).toBe('a'.repeat(32))
    })

    it('allows underscores and digits inside command names', () => {
        expect(parseCommand('/say_hi_42')?.command).toBe('say_hi_42')
    })

    it('treats /command followed by tab + arg as a command', () => {
        expect(parseCommand('/echo\thello')).toEqual({
            command: 'echo', args: 'hello', argv: ['hello'],
        })
    })

    it('preserves the raw arg string in `args` (single-space-joined)', () => {
        // args is the raw, post-command portion, argv is the tokenised view
        expect(parseCommand('/say   keep   spaces')?.args).toBe('keep   spaces')
    })
})
