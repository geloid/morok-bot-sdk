/**
 * file-bot - attachment round-trip example
 *
 * Saves every incoming attachment to ./inbox/, then echoes the bytes back as a 'file' attachment
 * /png ships a 1x1 PNG to prove the outbound path
 * voice / video_note are acknowledged with metadata since the FE has no caption slot for those kinds
 *
 * Run from the sdk directory:
 *
 *   node --experimental-strip-types examples/file-bot/index.ts ./bot.morokbot ./inbox/
 */

import { promises as fs }   from 'node:fs'
import path                 from 'node:path'

import { MorokBot }         from '../../src/index.js'


async function main(): Promise<void> {
    const tokenFile = process.argv[2]
    const inboxDir  = process.argv[3] ?? './inbox'
    if (!tokenFile) {
        console.error('usage: file-bot ./bot.morokbot [inbox-dir]')
        process.exit(1)
    }
    await fs.mkdir(inboxDir, { recursive: true })

    const bot = await MorokBot.fromFile({
        tokenFile,
        logger: {
            info:  (o, m) => console.log ('info ', m ?? '', o),
            warn:  (o, m) => console.warn('warn ', m ?? '', o),
            error: (o, m) => console.error('error', m ?? '', o),
            debug: (o, m) => console.debug('debug', m ?? '', o),
        },
    })

    bot.on('start', (e) => console.log(`👋 new user: @${e.peer.username}`))

    bot.on('command', async (c) => {
        if (c.command === 'png') {
            // 1x1 transparent PNG - 67 bytes, fits in a single packed envelope (95 bytes on the wire)
            // Replies with this file as a 'file' attachment to prove the send-attachment path end-to-end
            const oneByOnePng = Buffer.from(
                '89504e470d0a1a0a0000000d4948445200000001000000010806000000' +
                '1f15c4890000000d49444154789c63000100000005000148f15dfa00000000' +
                '49454e44ae426082',
                'hex',
            )
            await bot.reply(c, {
                text: 'here is a 1x1 png',
                attachment: { kind: 'file', data: oneByOnePng, name: '1x1.png', mime: 'image/png' },
            })
            return
        }
        await bot.reply(c, { text: `unknown command: /${c.command}` })
    })

    bot.on('message', async (m) => {
        const a = m.attachment
        if (!a) {
            await bot.reply(m, { text: `echo: ${m.text}` })
            return
        }

        // Download + save locally so we can verify the round-trip
        try {
            const bytes = await a.download()
            const baseName = a.name ?? `attachment-${a.fileId}`
            const outPath  = path.join(inboxDir, `${Date.now()}-${baseName}`)
            await fs.writeFile(outPath, bytes)
            console.log(`📥 saved ${a.kind} ${bytes.byteLength}B to ${outPath}`)
        } catch (err) {
            console.error('download failed:', (err as Error).message)
            await bot.reply(m, { text: `couldn't download your ${a.kind}` })
            return
        }

        // Echo: send the same bytes back as a file (regardless of incoming kind,
        // voice/video_note can't carry plaintext captions but a 'file' attachment can)
        const bytes = await a.download()
        const fileName = a.name ?? `${a.kind}.bin`
        await bot.reply(m, {
            text: `received your ${a.kind} (${a.size} bytes${a.duration ? `, ${a.duration.toFixed(1)}s` : ''})`,
            attachment: {
                kind: 'file',
                data: bytes,
                name: fileName,
                mime: a.mime,
            },
        })
    })

    bot.on('disconnect', (d) => console.log('socket dropped, reconnecting:', d.willReconnect))
    bot.on('error',      (e) => console.error('bot error:', e.message))

    const teardown = async () => { await bot.stop(); process.exit(0) }
    process.on('SIGINT',  () => { void teardown() })
    process.on('SIGTERM', () => { void teardown() })

    await bot.start()
    console.log(`file-bot ${bot.userId} online; saving inbox to ${inboxDir}`)
}


main().catch((err) => { console.error('fatal:', err); process.exit(1) })
