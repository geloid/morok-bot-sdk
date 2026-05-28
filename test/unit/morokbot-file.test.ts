import { describe, it, expect } from 'vitest'
import { parseMorokbotJson, MorokbotParseError } from '../../src/morokbot-file.js'

// Minimal valid fixture, real keys would be libsignal-shaped base64,
// but the parser only checks shape + character class, wire-level
// byte validation lives in the crypto layer, not in the parser
const validFixture = {
    version: 1,
    botUserId: 42,
    username: 'echo-bot',
    token: 'bot:42:' + 'A'.repeat(43),
    registrationId: 12345,
    identityKey: {
        pub:  'A'.repeat(44),
        priv: 'B'.repeat(44),
    },
    accountSigningKey: {
        pub:  'C'.repeat(44),
        priv: 'D'.repeat(44),
    },
    signedPreKey: {
        keyId:     1,
        pub:       'E'.repeat(44),
        priv:      'F'.repeat(44),
        signature: 'G'.repeat(88),
    },
    oneTimePreKeys: [
        { keyId: 1, pub: 'H'.repeat(44), priv: 'I'.repeat(44) },
        { keyId: 2, pub: 'J'.repeat(44), priv: 'K'.repeat(44) },
    ],
}


describe('parseMorokbotJson', () => {
    it('accepts a valid fixture', () => {
        const out = parseMorokbotJson(JSON.stringify(validFixture))
        expect(out.botUserId).toBe(42)
        expect(out.username).toBe('echo-bot')
        expect(out.oneTimePreKeys).toHaveLength(2)
    })

    it('rejects non-JSON', () => {
        expect(() => parseMorokbotJson('not json'))
            .toThrowError(MorokbotParseError)
    })

    it('rejects token whose embedded id mismatches botUserId', () => {
        const bad = { ...validFixture, token: 'bot:999:' + 'X'.repeat(43) }
        expect(() => parseMorokbotJson(JSON.stringify(bad)))
            .toThrowError(/token's bot id.*does not match/)
    })

    it('rejects missing oneTimePreKeys', () => {
        const bad = { ...validFixture, oneTimePreKeys: [] as unknown[] }
        expect(() => parseMorokbotJson(JSON.stringify(bad)))
            .toThrowError(/no one-time prekeys/)
    })

    it('rejects wrong version', () => {
        const bad = { ...validFixture, version: 2 }
        expect(() => parseMorokbotJson(JSON.stringify(bad)))
            .toThrowError(MorokbotParseError)
    })

    it('rejects malformed token shape', () => {
        const bad = { ...validFixture, token: 'banana' }
        expect(() => parseMorokbotJson(JSON.stringify(bad)))
            .toThrowError(/is not of shape bot:/)
    })

    it('rejects unknown top-level fields (strict mode)', () => {
        const bad = { ...validFixture, mysteryField: 'lol' }
        expect(() => parseMorokbotJson(JSON.stringify(bad)))
            .toThrowError(MorokbotParseError)
    })

    it('accepts file without optional accountSigningKey', () => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { accountSigningKey, ...rest } = validFixture
        const out = parseMorokbotJson(JSON.stringify(rest))
        expect(out.accountSigningKey).toBeUndefined()
    })

    it('caps oneTimePreKeys at 200', () => {
        const tooMany = Array.from({ length: 201 }, (_, i) => ({
            keyId: i + 1,
            pub:   'A'.repeat(44),
            priv:  'B'.repeat(44),
        }))
        const bad = { ...validFixture, oneTimePreKeys: tooMany }
        expect(() => parseMorokbotJson(JSON.stringify(bad)))
            .toThrowError(MorokbotParseError)
    })
})
