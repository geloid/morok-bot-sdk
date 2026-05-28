/**
 * Attachment upload and download. uploadAttachment picks single-shot or chunked by plaintext size:
 *   <= 50 MB:  POST /files/upload
 *   > 50 MB:   POST /files/upload/init + chunk x N + complete
 *
 * Each chunk gets its own random IV and AAD chunkAad(i, total) so the server can't reorder or drop chunks
 * Byte-exact mirror of frontend/src/api/files.ts
 *
 * Upload mints a fresh AES-256-GCM key, encrypts, SHA-256s the ciphertext (server dedup), POSTs
 * The server returns { fileId, sha256, ... }. The caller embeds an EncryptedFileRef in the message plaintext
 * Download is lazy via IncomingAttachment.download(): GET ciphertext, decrypt, length-check
 *
 * The plaintext never reaches the server. The 32-byte AES key is exported once into the ref
 */

import { createHash, webcrypto }            from 'node:crypto'
import type { HttpClient }                  from '../transport/http.js'
import {
    generateAesKey, exportKeyRaw, importKeyForDecrypt,
    aesGcmEncrypt, aesGcmDecrypt,
    packSealed, unpackSealed, chunkAad,
    AES_IV_BYTES, AES_TAG_BYTES,
} from '../crypto/file-cipher.js'
import type { SdkLogger } from '../types.js'

// CryptoKey lives on webcrypto in Node, alias for readable signatures without pulling DOM into tsconfig
type CryptoKey = webcrypto.CryptoKey


// Single-shot cap, above this we go chunked
export const SINGLE_UPLOAD_PLAINTEXT_LIMIT = 50 * 1024 * 1024
// Hard ceiling. Server's MAX_TOTAL_SIZE_BYTES, over 5 GB throws
export const MAX_PLAINTEXT_BYTES           = 5 * 1024 * 1024 * 1024

// Chunk wire size matches FE WIRE_CHUNK_BUDGET
// The server's per-chunk body cap is CHUNK_SIZE + 4096 (default 5 MB)
// Receivers walk the blob in these strides, every non-last chunk must be exactly this size
const WIRE_CHUNK_BUDGET                    = 5 * 1024 * 1024 - 4096
const CHUNK_PLAINTEXT_SIZE                 = WIRE_CHUNK_BUDGET - AES_IV_BYTES - AES_TAG_BYTES
// Server caps at MAX_TOTAL_CHUNKS=10_000, we never reach that at the 5 GB / 5 MB ratio (~1024 chunks)
const MAX_CHUNK_COUNT                      = 10_000
// Matches FE. 4 saturates home broadband without exceeding the server's per-minute chunk rate limit (300)
const CHUNK_UPLOAD_CONCURRENCY             = 4


// Wire shapes

/**
 * `EncryptedFileRef` is the JSON handle the SDK embeds into the message plaintext,
 * byte-for-byte compatible with the FE's `EncryptedFileRef` (frontend/src/api/files.ts)
 */
export interface EncryptedFileRef {
    fileId:       number
    sha256:       string
    /** Base64 of the raw 32-byte AES key */
    key:          string
    /** Base64 of the 12-byte IV (single-shot only) */
    iv:           string
    /** Plaintext size in bytes */
    size:         number
    /** Plaintext mime */
    mime:         string
    /** Optional filename hint */
    name?:        string
    /** Set on chunked uploads */
    chunked?:     boolean
    totalChunks?: number
}


interface UploadResponse {
    fileId:            number
    sha256:            string
    deduplicated:      boolean
    virusTotalVerdict: string | null
}


// Upload

export interface UploadOptions {
    /** Plaintext mime. Default application/octet-stream */
    mime?:     string
    /** Filename, server records via x-file-extension */
    filename?: string
    /** true for voice and video_note. The server keeps bytes on local disk and skips the per-user quota */
    noteMedia?: boolean
}


/**
 * Thrown when the server rejects a file upload with a typed code,
 * e.g. BOT_STAGING_FULL when the bot's unsent staging is full
 */
export class UploadRejectedError extends Error {
    constructor(message: string, readonly code?: string, readonly status?: number) {
        super(message)
        this.name = 'UploadRejectedError'
    }
}

// A server error response with a code becomes a typed UploadRejectedError, everything else passes through untouched
function asUploadError(err: unknown): unknown {
    const e = err as { response?: { status?: number; data?: { code?: unknown; error?: unknown } } }
    const code = typeof e?.response?.data?.code === 'string' ? e.response.data.code : undefined
    if (code) {
        const msg = typeof e.response?.data?.error === 'string'
            ? e.response.data.error
            : err instanceof Error ? err.message : code
        return new UploadRejectedError(`upload rejected: ${msg} (${code})`, code, e.response?.status)
    }
    return err
}


/**
 * Encrypt and upload, single-shot for <=50 MB and chunked for >50 MB up to 5 GB, throwing above 5 GB
 * Note media (voice and video_note) rides either path and the server keeps it on the asset disk, off the quota
 */
export async function uploadAttachment(
    http:       HttpClient,
    plaintext:  Uint8Array,
    opts:       UploadOptions = {},
    logger?:    SdkLogger,
): Promise<EncryptedFileRef> {
    if (plaintext.byteLength === 0) {
        throw new Error('uploadAttachment: empty attachment')
    }
    if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
        throw new Error(
            `uploadAttachment: plaintext is ${plaintext.byteLength} bytes; max for direct upload is ` +
            `${MAX_PLAINTEXT_BYTES} (Quickshare / P2P is not in v0.2 scope)`,
        )
    }
    // Map a server-coded rejection such as BOT_STAGING_FULL onto a typed UploadRejectedError
    // Network and malformed-response errors pass through
    try {
        if (plaintext.byteLength <= SINGLE_UPLOAD_PLAINTEXT_LIMIT) {
            return await uploadSingle(http, plaintext, opts, logger)
        }
        return await uploadChunked(http, plaintext, opts, logger)
    } catch (err) {
        throw asUploadError(err)
    }
}


// Single-shot upload

async function uploadSingle(
    http:       HttpClient,
    plaintext:  Uint8Array,
    opts:       UploadOptions,
    logger?:    SdkLogger,
): Promise<EncryptedFileRef> {
    const key       = await generateAesKey()
    const sealed    = await aesGcmEncrypt(key, plaintext)
    const keyRaw    = await exportKeyRaw(key)
    const packed    = packSealed(sealed)

    // Ciphertext hash for the x-file-sha256 header (server dedup)
    const ciphertextSha256 = createHash('sha256').update(packed).digest('hex')
    // Plaintext hash for VirusTotal lookup
    const plaintextSha256  = createHash('sha256').update(plaintext).digest('hex')

    const mime     = opts.mime ?? 'application/octet-stream'
    const filename = opts.filename
    const dotIdx   = filename ? filename.lastIndexOf('.') : -1
    const fileExt  = filename && dotIdx > 0 && dotIdx < filename.length - 1
        ? filename.slice(dotIdx + 1).toLowerCase().slice(0, 16)
        : ''

    // Header order doesn't matter for HTTP, we match the FE's order so audit log-grep diffs stay clean
    const headers: Record<string, string> = {
        'Content-Type':       'application/octet-stream',
        'x-file-sha256':      ciphertextSha256,
        'x-plaintext-sha256': plaintextSha256,
        'x-file-mime':        mime,
    }
    if (fileExt)        headers['x-file-extension'] = fileExt
    if (opts.noteMedia) headers['x-note-media']     = '1'

    logger?.debug(
        { size: plaintext.byteLength, mime, noteMedia: opts.noteMedia ?? false },
        '[attachments] uploading',
    )

    const res = await http.post<UploadResponse>(
        '/files/upload',
        Buffer.from(packed.buffer, packed.byteOffset, packed.byteLength),
        {
            headers,
            // 5 min covers a 50 MB upload at around 1.4 Mbps
            timeout: 5 * 60 * 1000,
        },
    )

    if (typeof res.data?.fileId !== 'number' || typeof res.data?.sha256 !== 'string') {
        throw new Error(
            `uploadAttachment: malformed server response (status=${res.status})`,
        )
    }
    if (res.data.sha256 !== ciphertextSha256) {
        // Server hashes the stream independently, a mismatch means a wire error, don't embed an unfetchable ref
        throw new Error(
            `uploadAttachment: server returned sha256 mismatch (expected ${ciphertextSha256}, got ${res.data.sha256})`,
        )
    }

    return {
        fileId: res.data.fileId,
        sha256: res.data.sha256,
        key:    Buffer.from(keyRaw).toString('base64'),
        iv:     Buffer.from(sealed.iv).toString('base64'),
        size:   plaintext.byteLength,
        mime,
        ...(filename ? { name: filename } : {}),
    }
}


// Chunked upload

interface UploadInitResponse  { uploadId: string }
interface ChunkResponse       { received: number; totalChunks: number; done: boolean }
interface CompleteResponse    {
    fileId:            number
    sha256:            string
    deduplicated:      boolean
    virusTotalVerdict: string | null
}


/** Best-effort abort. The server's 24h Redis TTL is the backstop, an explicit abort frees staged chunks now */
async function abortChunkedUpload(http: HttpClient, uploadId: string): Promise<void> {
    if (uploadId.length < 8) return
    try {
        await http.post<{ aborted: boolean }>('/files/upload/abort', { uploadId })
    } catch { /* TTL is the backstop */ }
}


/** Three-step init / chunk * N / complete. Each chunk is AES-GCM-sealed with chunkAad(index, total)
 * so the server can't reorder or drop chunks, tamper surfaces as a tag mismatch at decrypt
 * CHUNK_UPLOAD_CONCURRENCY chunks in flight, the first failure aborts the rest and POSTs /upload/abort */
async function uploadChunked(
    http:      HttpClient,
    plaintext: Uint8Array,
    opts:      UploadOptions,
    logger?:   SdkLogger,
): Promise<EncryptedFileRef> {
    const totalSize   = plaintext.byteLength
    const totalChunks = Math.ceil(totalSize / CHUNK_PLAINTEXT_SIZE)
    if (totalChunks < 2) {
        throw new Error('uploadChunked: requires > 1 chunk; use uploadSingle instead')
    }
    if (totalChunks > MAX_CHUNK_COUNT) {
        throw new Error(
            `uploadChunked: ${totalChunks} chunks exceeds server cap of ${MAX_CHUNK_COUNT}`,
        )
    }

    const mime    = opts.mime ?? 'application/octet-stream'
    const filename = opts.filename
    const dotIdx  = filename ? filename.lastIndexOf('.') : -1
    const fileExt = filename && dotIdx > 0 && dotIdx < filename.length - 1
        ? filename.slice(dotIdx + 1).toLowerCase().slice(0, 16)
        : null

    // Plaintext SHA for the server's VirusTotal lookup
    // Capped at 200 MB (mirrors the FE) to avoid hashing huge files in memory,
    // beyond the cap we send null and the server skips VT
    const VT_HASH_MAX = 200 * 1024 * 1024
    const plaintextSha256: string | null = totalSize <= VT_HASH_MAX
        ? createHash('sha256').update(plaintext).digest('hex')
        : null

    // INIT
    const initRes = await http.post<UploadInitResponse>('/files/upload/init', {
        totalSize,                  // server reads as plaintext size
        totalChunks,
        mimeType:      mime,
        fileExtension: fileExt,
        plaintextSha256,
        // Note media on the chunked path (a video note can exceed 50 MB),
        // the server routes it to the asset disk and skips quota, same as the single-shot x-note-media header
        ...(opts.noteMedia ? { noteMedia: true } : {}),
    })
    const uploadId = initRes.data?.uploadId
    if (typeof uploadId !== 'string' || uploadId.length < 8) {
        throw new Error('uploadChunked: malformed /files/upload/init response')
    }

    // One AES key for the whole file
    const key    = await generateAesKey()
    const keyRaw = await exportKeyRaw(key)

    logger?.debug(
        { uploadId, totalSize, totalChunks, chunkConcurrency: CHUNK_UPLOAD_CONCURRENCY },
        '[attachments] chunked upload begin',
    )

    // Bounded worker pool. Per chunk: slice, encrypt with chunkAad, pack [iv | ct+tag], sha256, POST
    // The axios signal lets the first failure cancel siblings mid-flight
    const abort = new AbortController()
    let nextIndex = 0
    let firstError: Error | null = null
    const inflight: Promise<void>[] = []

    const runChunk = async (i: number): Promise<void> => {
        const start = i * CHUNK_PLAINTEXT_SIZE
        const end   = Math.min(start + CHUNK_PLAINTEXT_SIZE, totalSize)
        // subarray to avoid a copy
        const slice = plaintext.subarray(start, end)
        const sealed   = await aesGcmEncrypt(key, slice, chunkAad(i, totalChunks))
        const packed   = packSealed(sealed)
        const chunkSha = createHash('sha256').update(packed).digest('hex')
        await http.post<ChunkResponse>(
            '/files/upload/chunk',
            Buffer.from(packed.buffer, packed.byteOffset, packed.byteLength),
            {
                headers: {
                    'Content-Type':   'application/octet-stream',
                    'x-upload-id':    uploadId,
                    'x-chunk-index':  String(i),
                    'x-chunk-sha256': chunkSha,
                },
                timeout: 10 * 60 * 1000, // 10 min per chunk
                signal:  abort.signal,
            },
        )
    }

    const worker = async (): Promise<void> => {
        while (!firstError) {
            const myIndex = nextIndex++
            if (myIndex >= totalChunks) return
            try {
                await runChunk(myIndex)
            } catch (err) {
                // First failure wins and abort cancels siblings
                // The resulting CanceledError lands in this catch but firstError is already set
                if (!firstError) {
                    firstError = err as Error
                    abort.abort()
                }
                return
            }
        }
    }

    for (let w = 0; w < Math.min(CHUNK_UPLOAD_CONCURRENCY, totalChunks); w++) {
        inflight.push(worker())
    }
    await Promise.all(inflight)

    if (firstError) {
        // Don't await, surface the original error now, the abort is best-effort
        void abortChunkedUpload(http, uploadId)
        throw firstError
    }

    let completeRes
    try {
        completeRes = await http.post<CompleteResponse>(
            '/files/upload/complete',
            { uploadId },
            { timeout: 5 * 60 * 1000 },
        )
    } catch (err) {
        void abortChunkedUpload(http, uploadId)
        throw err
    }
    const c = completeRes.data
    if (typeof c?.fileId !== 'number' || typeof c?.sha256 !== 'string') {
        // 200 with a broken body. Abort in case the server didn't actually persist
        void abortChunkedUpload(http, uploadId)
        throw new Error('uploadChunked: malformed /files/upload/complete response')
    }

    logger?.info(
        { fileId: c.fileId, sha256: c.sha256, totalSize, totalChunks },
        '[attachments] chunked upload complete',
    )

    return {
        fileId:      c.fileId,
        sha256:      c.sha256,
        key:         Buffer.from(keyRaw).toString('base64'),
        // No top-level IV for chunked, each chunk carries its own inside the packed bytes
        iv:          '',
        size:        totalSize,
        mime,
        chunked:     true,
        totalChunks,
        ...(filename ? { name: filename } : {}),
    }
}


// Download

/** Fetch and decrypt under the ref's key. Lazy getter behind IncomingAttachment.download()
 *  The server can return 404 (file row gone), 410 (sender hard-deleted), or 503 (P2P-only),
 *  all surface as a plain Error */
export async function downloadAttachment(
    http:    HttpClient,
    ref:     EncryptedFileRef,
    logger?: SdkLogger,
): Promise<Buffer> {
    if (!/^[a-f0-9]{64}$/.test(ref.sha256)) {
        throw new Error(`downloadAttachment: invalid sha256 ${ref.sha256}`)
    }
    if (ref.size <= 0) {
        throw new Error(`downloadAttachment: ref.size must be > 0 (got ${ref.size})`)
    }
    if (ref.size > MAX_PLAINTEXT_BYTES) {
        // Refuse oversized claims so a hostile sender cannot trick us into multi-GB allocations
        throw new Error(`downloadAttachment: ref.size ${ref.size} exceeds 5 GB ceiling`)
    }
    const keyRaw = Buffer.from(ref.key, 'base64')
    if (keyRaw.byteLength !== 32) {
        throw new Error(`downloadAttachment: ref.key decodes to ${keyRaw.byteLength} bytes; expected 32`)
    }

    // Tight upper bound on a valid ciphertext blob for this ref: plaintext + per-chunk (IV+TAG) overhead +
    // one chunk of slack (covers single-shot and rounding). This caps the socket read (passed as axios maxContentLength)
    // so a hostile server can't stream more than the ref could produce.
    // The downstream ref.size/allocUnsafe guards don't cover the unbounded-buffer OOM,
    // they run only after the whole body is in memory
    const maxChunks     = Math.ceil(ref.size / CHUNK_PLAINTEXT_SIZE) + 1
    const ciphertextCap = ref.size + maxChunks * (AES_IV_BYTES + AES_TAG_BYTES) + WIRE_CHUNK_BUDGET
    const ciphertextBytes = await fetchCiphertextBytes(http, ref.sha256, ciphertextCap)
    const key             = await importKeyForDecrypt(keyRaw)

    if (ref.chunked === true) {
        return downloadChunked(ref, ciphertextBytes, key, logger)
    }
    return downloadSingle(ref, ciphertextBytes, key, logger)
}


/** Single-shot decrypt. One AES-GCM seal, no AAD. Cross-checks the blob's IV against ref.iv */
async function downloadSingle(
    ref:             EncryptedFileRef,
    ciphertextBytes: Buffer,
    key:             CryptoKey,
    logger?:         SdkLogger,
): Promise<Buffer> {
    const ivBytes = Buffer.from(ref.iv, 'base64')
    if (ivBytes.byteLength !== 12) {
        throw new Error(`downloadAttachment: ref.iv decodes to ${ivBytes.byteLength} bytes; expected 12`)
    }
    const sealed = unpackSealed(ciphertextBytes)
    // The blob's IV and ref.iv must match, a mismatch means tamper
    if (Buffer.compare(Buffer.from(sealed.iv), ivBytes) !== 0) {
        throw new Error(
            'downloadAttachment: IV in the encrypted blob does not match the IV recorded in the message payload',
        )
    }
    const plaintext = await aesGcmDecrypt(key, sealed)
    if (plaintext.byteLength !== ref.size) {
        throw new Error(
            `downloadAttachment: decrypted size ${plaintext.byteLength} doesn't match ref.size ${ref.size}`,
        )
    }
    logger?.debug({ sha256: ref.sha256, size: plaintext.byteLength }, '[attachments] downloaded + decrypted')
    return Buffer.from(plaintext)
}


/** Chunked decrypt. Walk the blob in WIRE_CHUNK_BUDGET strides, decrypt each chunk under chunkAad(i, total)
 *  so a reorder, drop, or swap fails the GCM tag. The last chunk may be shorter */
async function downloadChunked(
    ref:             EncryptedFileRef,
    ciphertextBytes: Buffer,
    key:             CryptoKey,
    logger?:         SdkLogger,
): Promise<Buffer> {
    const totalChunks = ref.totalChunks
    if (typeof totalChunks !== 'number' || !Number.isInteger(totalChunks) || totalChunks < 2) {
        throw new Error(
            `downloadAttachment: chunked ref missing valid totalChunks (got ${ref.totalChunks})`,
        )
    }
    if (totalChunks > MAX_CHUNK_COUNT) {
        throw new Error(
            `downloadAttachment: ${totalChunks} chunks exceeds cap of ${MAX_CHUNK_COUNT}`,
        )
    }

    // Min ciphertext size: (n-1) full chunks + at least 1 plaintext byte in the last. Max: n full chunks
    // Anything outside this is a malformed blob, reject it before decrypting and hitting a confusing GCM error
    const lastChunkMinCt = AES_IV_BYTES + AES_TAG_BYTES + 1
    const lastChunkMaxCt = WIRE_CHUNK_BUDGET
    const minWire = (totalChunks - 1) * WIRE_CHUNK_BUDGET + lastChunkMinCt
    const maxWire = (totalChunks - 1) * WIRE_CHUNK_BUDGET + lastChunkMaxCt
    if (ciphertextBytes.byteLength < minWire || ciphertextBytes.byteLength > maxWire) {
        throw new Error(
            `downloadAttachment: chunked ciphertext is ${ciphertextBytes.byteLength} bytes; expected [${minWire}, ${maxWire}] for ${totalChunks} chunks`,
        )
    }

    // Bind ref.size to totalChunks before allocating n chunks decrypt to at most n*CHUNK_PLAINTEXT_SIZE
    // and at least (n-1)*CHUNK_PLAINTEXT_SIZE + 1 bytes
    // Without this a hostile sender could pair totalChunks=2 (a few MB of ciphertext) with ref.size=5 GB,
    // forcing a 5 GB allocUnsafe off a tiny payload as a DoS
    // Rejecting the mismatch keeps the allocation proportional to the length-bounded ciphertext
    const minPlaintext = (totalChunks - 1) * CHUNK_PLAINTEXT_SIZE + 1
    const maxPlaintext = totalChunks * CHUNK_PLAINTEXT_SIZE
    if (ref.size < minPlaintext || ref.size > maxPlaintext) {
        throw new Error(
            `downloadAttachment: ref.size ${ref.size} is inconsistent with ${totalChunks} chunks ` +
            `(expected [${minPlaintext}, ${maxPlaintext}])`,
        )
    }

    const out = Buffer.allocUnsafe(ref.size)
    let writeOff = 0
    let readOff  = 0
    for (let i = 0; i < totalChunks; i++) {
        const isLast = i === totalChunks - 1
        // Non-last chunks are exactly WIRE_CHUNK_BUDGET, last chunk consumes whatever's left
        const ctEnd  = isLast ? ciphertextBytes.byteLength : readOff + WIRE_CHUNK_BUDGET
        if (ctEnd > ciphertextBytes.byteLength) {
            throw new Error(
                `downloadAttachment: chunk ${i} expects ciphertext past end of blob`,
            )
        }
        const chunkCt = ciphertextBytes.subarray(readOff, ctEnd)
        const sealed  = unpackSealed(chunkCt)
        const aad     = chunkAad(i, totalChunks)
        let pt: Uint8Array
        try {
            pt = await aesGcmDecrypt(key, sealed, aad)
        } catch (err) {
            throw new Error(
                `downloadAttachment: AES-GCM auth-tag mismatch on chunk ${i}/${totalChunks} (${(err as Error).message})`,
            )
        }
        if (writeOff + pt.byteLength > out.byteLength) {
            // Sender lied about ref.size, bail before truncating
            throw new Error(
                `downloadAttachment: decrypted chunk ${i} would overflow declared ref.size ${ref.size}`,
            )
        }
        Buffer.from(pt.buffer, pt.byteOffset, pt.byteLength).copy(out, writeOff)
        writeOff += pt.byteLength
        readOff  = ctEnd
    }

    if (writeOff !== ref.size) {
        throw new Error(
            `downloadAttachment: chunked decrypt yielded ${writeOff} bytes; ref.size was ${ref.size}`,
        )
    }
    if (readOff !== ciphertextBytes.byteLength) {
        // Trailing bytes after the final chunk, refuse
        throw new Error(
            `downloadAttachment: ${ciphertextBytes.byteLength - readOff} trailing bytes after final chunk`,
        )
    }

    logger?.debug(
        { sha256: ref.sha256, size: ref.size, totalChunks },
        '[attachments] chunked download + decrypt complete',
    )
    return out
}


/** GET /files/:sha256 returns raw ciphertext. Re-throws axios errors as plain Errors
 *  so the caller doesn't pattern-match on axios status codes */
async function fetchCiphertextBytes(http: HttpClient, sha256: string, maxBytes: number): Promise<Buffer> {
    let buf: Buffer
    try {
        const res = await http.get<ArrayBuffer>(`/files/${sha256}`, {
            responseType: 'arraybuffer',
            // 1h covers a 5 GB download at about 10 Mbps, TCP/proxy keepalive is the real stall detector
            timeout:      60 * 60 * 1000,
            // Hard-cap the buffered body to what this ref can legitimately produce
            // axios aborts a read past this, so a lying or hostile server can't OOM us (its Node default is unlimited)
            maxContentLength: maxBytes,
            maxBodyLength:    maxBytes,
        })
        buf = Buffer.from(res.data)
    } catch (err) {
        const status = (err as { response?: { status?: number } })?.response?.status
        if (status === 404 || status === 410) {
            throw new Error(`attachment ${sha256} no longer available on server (status=${status})`)
        }
        if (status === 503) {
            throw new Error(`attachment ${sha256} is P2P-only - v0.2 does not implement Quickshare`)
        }
        throw err
    }
    // Content-address integrity: the server is semi-trusted, so confirm it returned the blob we addressed
    // GCM under the per-file key already guards the plaintext,
    // this rejects a wrong, substituted, or over-long blob early, before a downstream auth-tag mismatch
    const got = createHash('sha256').update(buf).digest('hex')
    if (got !== sha256) {
        throw new Error(`attachment ${sha256} integrity check failed (server returned sha256 ${got})`)
    }
    return buf
}


// Ref validator used by the receive sniff path

/** Narrows an unknown to EncryptedFileRef. A malformed ref is a misbehaving sender,
 * the receiver drops it with a warn-log */
export function isEncryptedFileRef(x: unknown): x is EncryptedFileRef {
    if (!x || typeof x !== 'object') return false
    const r = x as Record<string, unknown>
    if (typeof r.fileId !== 'number' || !Number.isInteger(r.fileId) || r.fileId < 1) return false
    if (typeof r.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.sha256)) return false
    if (typeof r.key    !== 'string' || r.key.length < 40) return false
    if (typeof r.iv     !== 'string') return false
    if (typeof r.size   !== 'number' || !Number.isInteger(r.size) || r.size <= 0) return false
    if (typeof r.mime   !== 'string' || r.mime.length === 0) return false
    if (r.name !== undefined && typeof r.name !== 'string') return false
    if (r.chunked !== undefined && typeof r.chunked !== 'boolean') return false
    if (r.totalChunks !== undefined && (typeof r.totalChunks !== 'number' || !Number.isInteger(r.totalChunks) || r.totalChunks < 2)) return false
    // Single-shot refs carry iv = base64(12 bytes) = 16 chars
    // Chunked refs carry a per-chunk IV inside the packed bytes, so the top-level ref.iv is empty
    // Single is a 16-char iv, chunked is an empty iv
    if (r.chunked === true) {
        if (r.iv !== '') return false
        if (r.totalChunks === undefined) return false
    } else {
        // Single-shot iv = base64(12 bytes) = exactly 16 chars, reject early at parse time
        if (r.iv.length !== 16) return false
    }
    return true
}


// Gallery (multi-attachment)

// 10 items total (1 head + 9 extras). Matches FE
export const GALLERY_MIN_ITEMS = 2
export const GALLERY_MAX_ITEMS = 10


export type GalleryFileItem = { type: 'file';     ref: EncryptedFileRef }
export type GalleryContactItem = {
    type: 'contact'
    userId: number
    username?: string
    displayName?: string
    avatarUrl?: string
    avatarEmoji?: string
}
export type GalleryLocationItem = { type: 'location'; lat: number; lng: number }
export type GalleryItem = GalleryFileItem | GalleryContactItem | GalleryLocationItem


export interface GalleryPayload {
    type:     'gallery'
    items:    GalleryItem[]
    caption?: string
}


/** Build the JSON envelope for an outbound gallery. Pure, the caller passes already-uploaded refs */
export function buildGalleryPayload(
    items:   GalleryItem[],
    caption?: string,
): string {
    const body: GalleryPayload = { type: 'gallery', items }
    if (caption && caption.length > 0) body.caption = caption
    return JSON.stringify(body)
}


/** Narrow an unknown to GalleryItem, null if malformed. The caller decides whether to keep a half-valid gallery */
export function parseGalleryItem(raw: unknown): GalleryItem | null {
    if (!raw || typeof raw !== 'object') return null
    const it = raw as Record<string, unknown>
    if (it.type === 'file') {
        if (!isEncryptedFileRef(it.ref)) return null
        return { type: 'file', ref: it.ref }
    }
    if (it.type === 'contact') {
        if (typeof it.userId !== 'number' || !Number.isInteger(it.userId) || it.userId < 1) return null
        const out: GalleryContactItem = { type: 'contact', userId: it.userId }
        if (typeof it.username    === 'string' && it.username.length    > 0) out.username    = it.username
        if (typeof it.displayName === 'string' && it.displayName.length > 0) out.displayName = it.displayName
        if (typeof it.avatarUrl   === 'string' && it.avatarUrl.length   > 0) out.avatarUrl   = it.avatarUrl
        if (typeof it.avatarEmoji === 'string' && it.avatarEmoji.length > 0) out.avatarEmoji = it.avatarEmoji
        return out
    }
    if (it.type === 'location') {
        if (typeof it.lat !== 'number' || !isFinite(it.lat) || it.lat < -90  || it.lat > 90)  return null
        if (typeof it.lng !== 'number' || !isFinite(it.lng) || it.lng < -180 || it.lng > 180) return null
        return { type: 'location', lat: it.lat, lng: it.lng }
    }
    return null
}


// Test-only exports. Not part of the public surface
export const _internals = {
    downloadChunked,
    WIRE_CHUNK_BUDGET,
    CHUNK_PLAINTEXT_SIZE,
    MAX_CHUNK_COUNT,
}
