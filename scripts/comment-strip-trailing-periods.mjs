#!/usr/bin/env node
/**
 * Remove a single trailing '.' at the end of a comment line. Keeps:
 *   - URLs ('https://...' has a '.' but it's not at line-end)
 *   - decimal numbers (the '.' isn't followed by EOL on its own)
 *   - abbreviations mid-sentence (same)
 *   - ellipses ('...' is left alone, only solitary '.' is removed)
 *
 * Rule: strip '.' iff
 *   - inside a // or /* *\/ comment, AND
 *   - immediately followed (after optional trailing spaces / tabs) by
 *     end-of-line or end-of-comment, AND
 *   - immediately preceded by a word char (letter, digit, ')', ']'),
 *     NOT by another '.' (that would be an ellipsis), NOT by '/'
 *     (URL guard).
 *
 * Usage:
 *   node scripts/comment-strip-trailing-periods.mjs           rewrites in place
 *   node scripts/comment-strip-trailing-periods.mjs --dry     preview, no write
 *   node scripts/comment-strip-trailing-periods.mjs <file>    process one file
 */

import { readFileSync, writeFileSync, statSync, readdirSync } from 'node:fs'
import { join, extname }                                       from 'node:path'
import { fileURLToPath }                                       from 'node:url'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const SDK_ROOT = join(HERE, '..')

const args   = process.argv.slice(2)
const dryRun = args.includes('--dry')
const explicit = args.filter(a => !a.startsWith('--'))

const targets = explicit.length > 0
    ? explicit
    : [join(SDK_ROOT, 'src'), join(SDK_ROOT, 'test'), join(SDK_ROOT, 'examples')]


/**
 * Decide whether the period at `src[i]` is a strip candidate. We are
 * inside a comment when this is called; the caller handles state.
 * `commentEnd` is the index past the last comment char (newline for
 * line comments, `*` index for block comments).
 */
function isStripCandidate(src, i, commentEnd) {
    // Must be '.'.
    if (src[i] !== '.') return false

    // What's BEFORE the period? Reject '/' (url), '.' (ellipsis),
    // whitespace (already empty-looking sentence). Accept word
    // chars + a few sane closers like ')', ']'.
    const prev = src[i - 1]
    if (!prev) return false
    if (prev === '/') return false
    if (prev === '.') return false
    if (/\s/.test(prev)) return false
    if (!/[\w)\]'"`]/.test(prev)) return false

    // What's AFTER the period? Skip optional spaces and tabs, then
    // require either:
    //   - end-of-line, OR
    //   - end-of-comment (for block comments: '*' followed by '/').
    let j = i + 1
    while (j < commentEnd && (src[j] === ' ' || src[j] === '\t')) j++
    if (j >= src.length) return true
    if (src[j] === '\n' || src[j] === '\r') return true
    if (j >= commentEnd) return true
    return false
}


function rewrite(src) {
    let out = ''
    let i = 0
    let changes = 0
    let state = 'code'

    while (i < src.length) {
        const ch  = src[i]
        const nx  = src[i + 1]

        if (state === 'code') {
            if (ch === '/' && nx === '/') {
                // Find the end of this line comment (newline or EOF).
                let end = src.indexOf('\n', i)
                if (end < 0) end = src.length
                state = { kind: 'line', end }
                out += '//'
                i += 2
                continue
            }
            if (ch === '/' && nx === '*') {
                let end = src.indexOf('*/', i + 2)
                if (end < 0) end = src.length  // unterminated; treat rest as comment
                state = { kind: 'block', end }
                out += '/*'
                i += 2
                continue
            }
            if (ch === "'")  { state = 'single-string'; out += ch; i += 1; continue }
            if (ch === '"')  { state = 'double-string'; out += ch; i += 1; continue }
            if (ch === '`')  { state = 'template-string'; out += ch; i += 1; continue }
            out += ch; i += 1; continue
        }

        if (typeof state === 'object' && (state.kind === 'line' || state.kind === 'block')) {
            // End-of-comment handling.
            if (state.kind === 'line' && ch === '\n') {
                state = 'code'; out += ch; i += 1; continue
            }
            if (state.kind === 'block' && ch === '*' && nx === '/') {
                state = 'code'; out += '*/'; i += 2; continue
            }

            if (ch === '.' && isStripCandidate(src, i, state.end)) {
                // Drop the period.
                changes++
                i += 1
                continue
            }

            out += ch; i += 1; continue
        }

        if (state === 'single-string' || state === 'double-string') {
            const quote = state === 'single-string' ? "'" : '"'
            if (ch === '\\') { out += ch + (nx ?? ''); i += 2; continue }
            if (ch === quote) { state = 'code'; out += ch; i += 1; continue }
            out += ch; i += 1; continue
        }

        if (state === 'template-string') {
            if (ch === '\\') { out += ch + (nx ?? ''); i += 2; continue }
            if (ch === '`')  { state = 'code'; out += ch; i += 1; continue }
            out += ch; i += 1; continue
        }

        out += ch; i += 1
    }

    return { out, changes }
}


function walk(path) {
    const st = statSync(path)
    if (st.isDirectory()) {
        for (const entry of readdirSync(path)) {
            if (entry === 'node_modules' || entry === 'dist') continue
            walk(join(path, entry))
        }
        return
    }
    if (!st.isFile()) return
    if (extname(path) !== '.ts') return

    const src = readFileSync(path, 'utf8')
    const { out, changes } = rewrite(src)
    if (changes === 0) return

    if (dryRun) {
        console.log(`would strip ${changes.toString().padStart(4)} trailing . in ${path}`)
    } else {
        writeFileSync(path, out)
        console.log(`stripped ${changes.toString().padStart(4)} trailing . in ${path}`)
    }
}


for (const t of targets) {
    try { walk(t) }
    catch (err) { console.error(`failed on ${t}: ${err.message}`) }
}

if (dryRun) console.log('--dry: no files were written')
