/**
 * Echo bot - replies to every text DM and answers /help
 *
 * Run from the sdk directory (after `npm install`):
 *
 *   node --experimental-strip-types examples/echo-bot/index.ts ./bot.morokbot
 *
 * To use this file in your own project: swap the relative import below
 * for `'morok-bot-sdk'`, install the SDK from npm, then run with tsx:
 *
 *   npm install morok-bot-sdk
 *   node --import=tsx index.ts ./bot.morokbot
 */

import { MorokBot } from '../../src/index.js'


async function main(): Promise<void> {
    const tokenFile = process.argv[2]
    if (!tokenFile) {
        console.error('usage: echo-bot ./bot.morokbot')
        process.exit(1)
    }

    const bot = await MorokBot.fromFile({
        tokenFile,
        // Optional: a console-shaped logger so we can see the SDK's own info / warn lines
        // Drop this for silent operation
        logger: {
            info:  (o, m) => console.log('info ', m ?? '', o),
            warn:  (o, m) => console.warn('warn ', m ?? '', o),
            error: (o, m) => console.error('error', m ?? '', o),
            debug: (o, m) => console.debug('debug', m ?? '', o),
        },
    })

    bot.on('start', (e) => {
        console.log(`👋 new user: @${e.peer.username} (${e.peer.userId})`)
    })

    bot.on('stop', (e) => {
        console.log(`👋 user left: @${e.peer.username}`)
    })

    bot.on('command', async (c) => {
        if (c.command === 'help') {
            await bot.reply(c, { text: 'I\'m an echo bot. Just type something, and I\'ll echo it back' })
            return
        }
        await bot.reply(c, { text: `Unknown command: /${c.command}` })
    })

    bot.on('message', async (m) => {
        await bot.reply(m, { text: `Echo: ${m.text}` })
    })

    bot.on('disconnect', (d) => {
        console.log(`socket dropped (${d.reason}, code=${d.code}); ` +
                    `reconnecting=${d.willReconnect}`)
    })

    bot.on('error', (err) => {
        console.error('bot error:', err.message)
    })

    // Graceful shutdown on Ctrl-C / SIGTERM
    const teardown = async () => {
        console.log('shutting down...')
        await bot.stop()
        process.exit(0)
    }
    process.on('SIGINT',  () => { void teardown() })
    process.on('SIGTERM', () => { void teardown() })

    await bot.start()
    console.log(`bot ${bot.userId} online`)
}


main().catch((err) => {
    console.error('fatal:', err)
    process.exit(1)
})
