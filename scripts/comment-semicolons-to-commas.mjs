#!/usr/bin/env node
/**
 * Replace ';' with ',' inside comments only. Code is left alone.
 *
 * Walks every .ts file under src/ and test/, runs a tiny state
 * machine that tracks whether we're in code, a string, a template
 * literal, a // comment, or a /* *\/ block, and only rewrites
 * semicolons when state == comment.
 *
 * Usage:
 *   node scripts/comment-semicolons-to-commas.mjs           rewrites in place
 *   node scripts/comment-semicolons-to-commas.mjs --dry     print which files would change, no write
 *   node scripts/comment-semicolons-to-commas.mjs <file>    process one file
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


// State machine. Returns the rewritten file contents and a count of
// replacements. State is local; nothing leaks between files.
function rewrite(src) {
    let out = ''
    let i = 0
    let changes = 0

    // States: 'code' | 'line-comment' | 'block-comment'
    //         | 'single-string' | 'double-string' | 'template-string'
    // Plus regex literals are tricky to distinguish from division; we
    // err on the side of NOT entering regex mode, which means inside
    // a regex literal a ';' would still get rewritten. Comments
    // inside regex literals don't exist, so this is harmless.
    let state = 'code'

    while (i < src.length) {
        const ch  = src[i]
        const nx  = src[i + 1]

        if (state === 'code') {
            if (ch === '/' && nx === '/') { state = 'line-comment'; out += '//'; i += 2; continue }
            if (ch === '/' && nx === '*') { state = 'block-comment'; out += '/*'; i += 2; continue }
            if (ch === "'")               { state = 'single-string'; out += ch;  i += 1; continue }
            if (ch === '"')               { state = 'double-string'; out += ch;  i += 1; continue }
            if (ch === '`')               { state = 'template-string'; out += ch; i += 1; continue }
            out += ch; i += 1; continue
        }

        if (state === 'line-comment') {
            if (ch === '\n') { state = 'code'; out += ch; i += 1; continue }
            if (ch === ';')  { out += ','; changes++; i += 1; continue }
            out += ch; i += 1; continue
        }

        if (state === 'block-comment') {
            if (ch === '*' && nx === '/') { state = 'code'; out += '*/'; i += 2; continue }
            if (ch === ';')               { out += ','; changes++; i += 1; continue }
            out += ch; i += 1; continue
        }

        if (state === 'single-string' || state === 'double-string') {
            const quote = state === 'single-string' ? "'" : '"'
            if (ch === '\\')              { out += ch + (nx ?? ''); i += 2; continue }
            if (ch === quote)             { state = 'code'; out += ch; i += 1; continue }
            out += ch; i += 1; continue
        }

        if (state === 'template-string') {
            // We don't recurse into ${...} expressions; semicolons
            // inside a template substitution are part of the
            // template-string state. That's fine because we only
            // touch comments anyway.
            if (ch === '\\')              { out += ch + (nx ?? ''); i += 2; continue }
            if (ch === '`')               { state = 'code'; out += ch; i += 1; continue }
            out += ch; i += 1; continue
        }

        // Unreachable.
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
        console.log(`would rewrite ${changes.toString().padStart(4)} ; -> , in ${path}`)
    } else {
        writeFileSync(path, out)
        console.log(`rewrote ${changes.toString().padStart(4)} ; -> , in ${path}`)
    }
}


let total = 0
for (const t of targets) {
    try { walk(t) }
    catch (err) { console.error(`failed on ${t}: ${err.message}`) }
}

if (dryRun) console.log('--dry: no files were written')
