/**
 * Parser for the .morokbot file. The zod schema turns a malformed file into a clear field-level error
 * Key material fields are named pub and priv
 */

import { promises as fs }                from 'node:fs'
import { z, type ZodError } from 'zod'
import type { MorokbotFile, SdkLogger }  from './types.js'


// Base64, canonical or url-safe. 40-char floor leaves slack below the smallest libsignal key (44 chars)
const Base64 = z.string()
    .min(40,  'base64 string too short')
    .max(256, 'base64 string too long')
    .regex(/^[A-Za-z0-9+/_-]+=*$/, 'string is not valid base64')

const KeyPair = z.object({
    pub:  Base64,
    priv: Base64,
}).strict()

const SignedPreKey = z.object({
    keyId:     z.number().int().min(1).max(0x7FFFFFFF),
    pub:       Base64,
    priv:      Base64,
    signature: Base64,
}).strict()

const OneTimePreKey = z.object({
    keyId: z.number().int().min(1).max(0x00FFFFFF),
    pub:   Base64,
    priv:  Base64,
}).strict()

// bot:<id>:<43-char base64url secret>
const TokenRegex = /^bot:(\d+):([A-Za-z0-9_-]{43})$/

const MorokbotFileSchema = z.object({
    version:           z.literal(1),
    botUserId:         z.number().int().positive(),
    username:          z.string().min(1).max(32).regex(
        /^[a-z0-9-]+$/,
        'username must be lower-case alphanumerics + hyphens',
    ),
    token:             z.string().regex(TokenRegex, '`token` is not of shape bot:<id>:<43chars>'),
    registrationId:    z.number().int().min(1).max(16380),
    identityKey:       KeyPair,
    // Optional. SDK skips the cross-signing POST when it is missing
    accountSigningKey: KeyPair.optional(),
    signedPreKey:      SignedPreKey,
    oneTimePreKeys:    z.array(OneTimePreKey).min(1, 'no one-time prekeys in file').max(200),
}).strict()


export class MorokbotParseError extends Error {
    constructor(message: string, readonly path: string, readonly cause?: unknown) {
        super(message)
        this.name = 'MorokbotParseError'
    }
}

/** Read + validate. Throws MorokbotParseError on any failure */
export async function readMorokbotFile(path: string, logger?: SdkLogger): Promise<MorokbotFile> {
    let raw: string
    try {
        raw = await fs.readFile(path, 'utf8')
    } catch (err) {
        throw new MorokbotParseError(
            `cannot read .morokbot file at ${path}: ${(err as Error).message}`,
            path,
            err,
        )
    }
    // The file holds the bot's private keys, warn if group or other can read it
    if (process.platform !== 'win32') {
        try {
            const st = await fs.stat(path)
            if (st.mode & 0o077) {
                logger?.warn(
                    { path, mode: (st.mode & 0o777).toString(8) },
                    '[morokbot] file is readable by group or other and holds private keys, tighten it with chmod 600',
                )
            }
        } catch { /* a stat failure should not fail the read */ }
    }
    return parseMorokbotJson(raw, path)
}

export function parseMorokbotJson(raw: string, path = '<inline>'): MorokbotFile {
    let json: unknown
    try {
        json = JSON.parse(raw)
    } catch (err) {
        throw new MorokbotParseError(
            `${path} is not valid JSON: ${(err as Error).message}`,
            path,
            err,
        )
    }

    let parsed: z.infer<typeof MorokbotFileSchema>
    try {
        parsed = MorokbotFileSchema.parse(json)
    } catch (err) {
        const zErr = err as ZodError
        const issue = zErr.issues?.[0]
        const where = issue?.path?.length ? issue.path.join('.') : '<root>'
        throw new MorokbotParseError(
            `${path} schema mismatch at ${where}: ${issue?.message ?? 'invalid'}`,
            path,
            err,
        )
    }

    // Token's embedded id must equal botUserId. /auth/bot-session keys on the token id,
    // a mismatch otherwise surfaces as BOT_NOT_FOUND
    const m = TokenRegex.exec(parsed.token)!
    const tokenBotId = Number(m[1])
    if (tokenBotId !== parsed.botUserId) {
        throw new MorokbotParseError(
            `${path}: token's bot id (${tokenBotId}) does not match top-level botUserId (${parsed.botUserId})`,
            path,
        )
    }

    return parsed
}
