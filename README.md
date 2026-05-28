# morok-bot-sdk

Node.js / TypeScript SDK for building bots on the [Morok](https://morok.me) end-to-end encrypted messaging platform.

The SDK handles Signal Protocol session bootstrap, channel-key fan-out for group chats and channels, prekey replenish, JWT refresh, WebSocket reconnect, and attachment crypto. You write event handlers.

- Русская версия: [README.ru.md](./README.ru.md).
- First-time setup walkthrough with dev-panel screenshots: [docs/getting-started.md](./docs/getting-started.md).
- Full HTTP / WebSocket / wire-format reference: [api.md](https://morok.me/api).
- Production deployment recipes (systemd, Docker, backups, monitoring): [docs/deployment.md](./docs/deployment.md).

## Install

```bash
npm install morok-bot-sdk
```

Requirements:

- Node **22 or later** (the SDK uses `globalThis.crypto`, native `Buffer.from(..., 'base64url')`, and `fs.rename` semantics older versions do not guarantee)
- A `.morokbot` token file generated when you create a bot in the Morok app

Bot private keys must stay on a server you control.

## Quickstart

1. In the Morok app: **Settings -> About Morok**, flip the **Developer mode** toggle. A section of the same name appears in Settings.
2. **Settings -> Developer mode -> Create bot**. Fill in the three steps (description, appearance, management) and press **Create**. A **Download .morokbot** button then appears under the token. It saves a JSON file with the bot's token and Signal key material.
3. Place the file next to your bot code as `bot.morokbot` (or pass an absolute path to `tokenFile`).
4. Write the handler:

> **Do not commit `.morokbot` or `bot-state/` to git.** The `.morokbot` file contains the bot's signing key, anyone with it can impersonate the bot. `bot-state/` holds the Signal identity and prekey pool after first start. A `.gitignore` with both entries ships in the SDK (`sdk/.gitignore`), copy it into your project before the first commit. On first import: `chmod 0600 bot.morokbot && chmod 0700 bot-state/`.


```ts
import { MorokBot } from 'morok-bot-sdk'

const bot = await MorokBot.fromFile({ tokenFile: './bot.morokbot' })

bot.on('start',   (e) => console.log(`new user: @${e.peer.username}`))
bot.on('stop',    (e) => console.log(`user left: @${e.peer.username}`))

bot.on('command', async (c) => {
    if (c.command === 'help') await bot.reply(c, { text: 'I am an echo bot.' })
})

bot.on('message', async (m) => {
    if (m.text) await bot.reply(m, { text: `echo: ${m.text}` })
})

bot.on('disconnect', (d) => console.log('socket dropped, willReconnect:', d.willReconnect))
bot.on('error',      (e) => console.error('bot error:', e.message))

await bot.start()
```

The SDK handles:

- `/auth/bot-session` mint + JWT refresh on WS code 4001 / HTTP 401
- WebSocket connect with exponential backoff
- X3DH bootstrap on first contact + Double Ratchet via libsignal
- One-time prekey replenish (boot top-up, a reactive `prekeys_low` server push, plus a 5-minute background backstop)
- Signed prekey rotation on the server's 7-day mark
- Multi-device fan-out so an outbound DM lands on every peer device
- Own-echo matching by `fanoutId` so `bot.send()` resolves to the real `messageId`

## Configuration

`MorokBot.fromFile` accepts `BotConfig & { tokenFile }`:

| Field                  | Default                  | Notes                                                          |
|------------------------|--------------------------|----------------------------------------------------------------|
| `tokenFile`            | (required)               | Path to the `.morokbot` file                                   |
| `stateDir`             | `./bot-state/`           | Per-bot, exclusive. Holds private keys after import. chmod 0700 |
| `apiBaseUrl`           | `https://app.morok.me`   | Override for self-host / dev                                   |
| `wsUrl`                | derived                  | http -> ws, https -> wss, append `/ws`                         |
| `replenishThreshold`   | `100`                    | Top up OTPKs when the pool drops below this. Matches the server's low-water mark, so this threshold and the reactive `prekeys_low` signal agree |
| `replenishTarget`      | `200`                    | OTPK count after replenish (equals the server's per-call cap)  |
| `backgroundIntervalMs` | `300_000` (5 min)        | Backstop tick behind the reactive `prekeys_low` server signal that tops up on demand. Set to 0 to disable the loop (tests only) |
| `autoBackfillOnJoin`   | `false`                  | Auto-share local epoch keys when a member joins                |
| `logger`               | silent                   | Pino-shaped: `info` / `warn` / `error` / `debug`               |

## Storage

Bot data lives in two places:

- `stateDir` on your machine: identity key, prekeys, Double Ratchet sessions, local copies of channel-keys and group-secrets. Tens of MB at most. Morok does not quota this, it's your disk.
- The Morok server keeps the in-flight ciphertext and every file a bot sends, including while an offline recipient has not fetched them yet. The only difference is whose quota they count against. A **regular file** immediately takes up the quota of whoever it went to: in a DM the recipient (who must have started the bot), in a group chat or channel the conversation owner (who added the bot). The bot can fill that party's free space, and once it runs out the send rejects with `SendRejectedError`, code `recipient_storage_full`. **Voice and video messages are different: they do not count against anyone's quota.** The server still keeps them, on a local media disk, and auto-deletes them **30 days after sending** (and sooner if that disk runs low, oldest first across all users). Recipients keep whatever they downloaded or saved to their Notes earlier.

The rest of this section is the layout inside `stateDir` (default `./bot-state/`).

```
bot-state/
  identity.json              key pair + accountSigningKey + registrationId
  state.json                 counters (next OTPK id, last SPK rotation)
  state.lock                 pid-based lock, one process per stateDir
  sessions/<peer>.<dev>.json per-peer-device Double Ratchet record
  prekeys/signed-<id>.json   signed prekeys (signature preserved across rounds)
  prekeys/onetime-<id>.json  one-time prekeys
  identity-cache/<addr>.json peer identity_key for TOFU
  channel-keys/<conv>.json   per-conversation channel-key history
  group-secrets/<conv>.json  per-conversation group-secret history
  quarantine/                fsck moves corrupted files here on start
```

After the first start `stateDir` holds the bot's private key material. Don't sync it to S3, don't email it, don't commit it. Back it up the way you back up an SSH key.

Two processes on one `stateDir` corrupt the Signal sessions. The pid-lock catches it, but give each bot its own directory anyway.

## API surface

### Construction

```ts
MorokBot.fromFile(config: BotConfig & { tokenFile: string }): Promise<MorokBot>
```

Reads and validates the token file, builds the bot. No network IO until `start()`.

### Lifecycle

| Call                | Effect                                                                                       |
|---------------------|----------------------------------------------------------------------------------------------|
| `await bot.start()` | Imports keys (idempotent), fscks state, mints session, opens WS, runs boot prekey replenish. |
| `await bot.stop()`  | Stops background loops, closes WS, rejects pending sends, releases state lock. Idempotent.    |
| `bot.isConnected`   | `true` once WS auth is complete.                                                              |
| `bot.userId`        | Numeric userId. Throws before `start()` resolves.                                             |

`start()` is safe to call concurrently: the second caller returns immediately, the bot ends up in one state. Calling `stop()` while `start()` is mid-flight aborts the boot cleanly at the next internal checkpoint.

### Events

```ts
bot.on('message',             (m: IncomingMessage)         => …)
bot.on('command',             (c: CommandInvocation)       => …)
bot.on('start',               (e: BotStartEvent)           => …)  // user pressed "Start"
bot.on('stop',                (e: BotStopEvent)            => …)  // user pressed "Stop"
bot.on('reaction',            (e: ReactionEvent)           => …)
bot.on('conversation_added',  (e: ConversationAddedEvent)  => …)
bot.on('conversation_kicked', (e: ConversationKickedEvent) => …)
bot.on('disconnect',          (d: DisconnectInfo)          => …)
bot.on('error',               (err: Error)                 => …)
```

`IncomingMessage`:

```ts
{
    messageId:        number
    conversationId:   number
    conversationType: 'DIRECT' | 'GROUP' | 'CHANNEL'
    sender:           Peer            // { userId, username, displayName }
    senderDeviceId:   number
    text:             string          // body or caption ('' if neither)
    attachment?:      IncomingAttachment
    gallery?:         IncomingGallery  // 2-10 items
    clientMsgId:      string | null
    replyToId:        number | null
    threadRootId:     number | null
    createdAt:        Date
}
```

`CommandInvocation` extends it with `{ command, args, argv }` for messages that start with `/cmd`.

`DisconnectInfo.reason`:
- `'transport'`: network drop, the SDK is reconnecting
- `'auth'`: WS code 4001, session ticket revoked, the SDK refreshes the JWT and reconnects
- `'shutdown'`: your code called `stop()`, no further reconnect

### Sending

```ts
// text DM
await bot.send({ peer: 12345,   text: 'hi' })
await bot.send({ peer: 'alice', text: 'hi' })  // pseudonym resolved via REST

// file (caption optional)
await bot.send({
    peer,
    text: 'photo of my cat',
    attachment: {
        kind: 'file',
        data: fs.readFileSync('./cat.jpg'),
        name: 'cat.jpg',
        mime: 'image/jpeg',
    },
})

// voice note (voice notes carry no caption)
await bot.send({
    peer,
    attachment: {
        kind: 'voice',
        data: oggBytes,
        duration: 4.2,
        waveform: [10, 30, 80, 100, 70, 30, 10],
    },
})

// video note
await bot.send({
    peer,
    attachment: {
        kind: 'video_note',
        data: webmBytes,
        duration: 6,
        shape: 'circle',     // see "Video-note shapes" note below
    },
})

// gallery: 2-10 file attachments in one bubble
await bot.send({
    peer,
    text: 'cat photos',
    attachments: [
        { kind: 'file', data: a, name: '1.jpg', mime: 'image/jpeg' },
        { kind: 'file', data: b, name: '2.jpg', mime: 'image/jpeg' },
    ],
})

// group-chat / channel post
await bot.send({ conversation: 42, text: 'announcement' })

// reply to an incoming message (threads correctly in DMs and group chats)
await bot.reply(msg, { text: 'thanks' })

// react with any unicode symbol (not just emoji), or remove the reaction
await bot.react(msg, '𔙃')
await bot.unreact(msg)
```

`bot.send()` resolves to `{ messageId, clientMsgId, conversationId }`. Exactly one of `peer` or `conversation` is required.

`bot.react(msg, unicode)` / `bot.unreact(msg)` take an incoming message or command. A reaction can be any unicode string, not just an emoji. It is encrypted to the conversation: per peer-device in DMs, under the channel-key in group chats and channels. A bot has only one reaction per message, and a new one replaces the previous. The bot is never echoed its own reaction, so `react` resolves once the frame is sent. Other users' reactions arrive via `bot.on('reaction', ...)`.

`peer` accepts a numeric `userId` (preferred when replying to an incoming message, the value is already in hand) or a pseudonym string (the SDK resolves it via `GET /users/:username` once per call, no caching).

`expiresInSeconds` on `send` or `reply` makes a disappearing message, the server removes it for everyone that many seconds after it is delivered

Server caps:

- File attachments up to **5 GB** plaintext. Single-shot path for files <= 50 MB, chunked path above it, the SDK picks transparently.
- Voice notes: duration `[0.1, 600]` seconds, up to 64 waveform peaks.
- Video notes: duration `[0.5, 300]` seconds. Shape is an opaque string, see the callout below for the canonical list.
- Galleries: 2-10 items, all `kind: 'file'`. Voice and video notes are not allowed inside a gallery (FE renderer does not support them there).
- A bot's **regular files** are billed to whoever gets them (a DM recipient, or a group-chat/channel owner), up to that party's quota, see [Storage](#storage). **Voice and video messages are quota-free**. A long video message can still exceed 50 MB (a 5-minute circle is about 58 MB), and the SDK uploads it via the chunked path transparently.

> **Video-note shapes**: `shape` is a string the SDK passes through, the receiver renders the names it knows and shows `circle` for anything else
>
> Names the receiver renders: `circle`, `square`, `slanted`, `pill`, `oval`, `arch`, `diamond`, `pentagon`, `gem`, `clamShell`, `sunny`, `cookie1`, `cookie2`, `cookie3`, `cookie4`, `clover1`, `clover2`, `burst`, `softBurst`, `puffyDiamond`, `pixelCircle`, `heart`

### Commands and controls

`bot.setMyCommands([{ command, description, sortOrder? }])` publishes the slash-command catalogue the composer offers when a user types `/`. `bot.setMyControls([...])` publishes a tree of buttons in the composer's bot-menu, where a control is `{ id, label, icon?, command?, children? }`. A button with `children` opens a submenu in place. A button with `command` drops `/command ` into the input. A button with neither is a callback, the bot gets a `control` event and can answer or rebuild the menu with another `setMyControls`. Handle taps with `bot.on('control', e => ...)`, where `e.controlId` is the button and `e.sender` is who tapped. Call these after `start()`, each call replaces the whole tree. A bot may declare up to 32 commands and a control tree of up to 64 nodes, 4 levels deep. A control `icon` is a Material Symbols name.

`setMyControls` is global, the same menu in every chat. For an individual flow, where each user has their own buttons, use `bot.setControlsFor(userId, [...])` to set the buttons for ONE user's chat without touching the others. This is how you render per-user search results as buttons, or walk one user through a wizard. The user id is `e.sender.userId` from a control event or `msg.sender.userId` from a message. The override is short-lived and survives that user's reload. `bot.clearControlsFor(userId)` drops it and reverts the user to the global menu. The same bounds apply (64 nodes, 4 levels). Keep `setMyControls` for the durable root menu and drive the dynamic parts with `setControlsFor`.

### Receiving attachments

`m.attachment` is present on single-attachment messages, `m.gallery` on multi-attachment bubbles. Bytes are not fetched until `.download()` is called:

```ts
bot.on('message', async (m) => {
    if (m.attachment) {
        const a = m.attachment
        console.log(`got ${a.kind} ${a.size}B (${a.mime})`)
        if (a.kind === 'voice')      console.log(`duration: ${a.duration}s`)
        if (a.kind === 'video_note') console.log(`shape:    ${a.shape}`)
        const bytes = await a.download()
        fs.writeFileSync(`./inbox/${a.name ?? a.fileId}`, bytes)
        return
    }
    if (m.gallery) {
        for (const item of m.gallery.items) {
            if (item.kind === 'file') {
                const bytes = await item.attachment.download()
                fs.writeFileSync(`./inbox/${item.attachment.name ?? item.attachment.fileId}`, bytes)
            }
            if (item.kind === 'contact')  console.log(`contact: @${item.username ?? item.userId}`)
            if (item.kind === 'location') console.log(`location: ${item.lat},${item.lng}`)
        }
        return
    }
    console.log('text:', m.text)
})
```

`download()` returns a `Buffer` of decrypted plaintext. It rejects on 404 / 410 (file removed or quota-evicted) and on decryption failure (wire tamper or wrong key). The SDK does not enforce a mime allow-list, the consumer is a Node process, treat `mime` as a sender-supplied hint.

`attachment.virusTotalVerdict` carries the VirusTotal result (`'clean'`, `'suspicious'`, `'malware'`) as of when the SDK received the file. Safe types (images, media) aren't scanned and come through as `'clean'` right away. Potentially dangerous ones (executables, archives) go to VirusTotal, and until it answers the verdict is `null`. The SDK reads the verdict once and doesn't watch for updates, so `null` means the scan hadn't finished at that point.

### Group chats and channels

Once the bot is added to a group chat or channel (`conversation_added` event), it can post with `bot.send({ conversation, ... })` and reply to incoming messages with `bot.reply(msg, ...)`. The SDK keeps per-conversation channel-keys under `stateDir/channel-keys/` and group-secrets under `stateDir/group-secrets/`.

**What a bot can and cannot do:**

- Only the conversation owner adds a bot and assigns its role (the "Боты" / Bots tab in the profile, no bot-side accept step).
- A bot has the same permissions as a human with the same role.
- A **channel** has posts and comments, only an admin or owner bot writes a top-level post, a moderator or member bot can only comment.
- A **group chat** has plain messages, any member bot can send, the role only changes moderation power such as removing other people's messages or muting, which needs moderator or higher.
- It **cannot**: change members' roles, add another bot, become owner, create group chats or channels, or `/start` another bot.
- A disallowed action is rejected server-side with HTTP 403 or `SendRejectedError`.

Group-chat / channel administration:

```ts
// Mint a fresh channel-key, distribute to every other member device
await bot.rotateChannelKey(conversationId)

// Re-key the group_secret (used to seal channel-key bundles) and
// channel-key in one server transaction. Run after kicking a leaker
// so old members cannot unseal future bundles
await bot.rotateGroupSecret(conversationId)

// Share local channel-key history with another member's devices
// Useful when the bot is the only online member and a new joiner needs to catch up
await bot.backfillChannelKeys(conversationId, { userId: 7777 })
```

`autoBackfillOnJoin: true` in `BotConfig` runs `backfillChannelKeys` for every new joiner without you wiring it up. The server still filters by `joined_secret_version`, so pre-join history doesn't leak.

### Error model

- **Decryption failure** -> `error` event, the message is dropped, the peer's next type-3 frame rebuilds the session
- **Send rejected by the server** -> `send()` rejects with the exported `SendRejectedError`, the `.code` carries the reason: `bot_not_started` (the user has not pressed Start), `recipient_storage_full`, `send_blocked`, `too_many_messages`
- **Upload rejected** -> the upload throws the exported `UploadRejectedError` with the server `.code` such as `BOT_STAGING_FULL`, this happens before any send frame leaves
- **Network drop** -> `disconnect` event with `willReconnect: true`, a send still in the WS queue flushes on reconnect, a send already on the wire and waiting for its echo rejects with the exported `SendUncertainError` so you retry or reconcile (it may or may not have landed)
- **JWT revoked** (the developer panel rotated the token, or the bot was deleted) -> WS closes with code 4001, the SDK calls `/auth/bot-session` again and reconnects if the bot is still alive, a token re-issue (panel: "Regenerate token") is destructive so restart the SDK with the new `.morokbot`
- **Send to a kicked group chat or channel** -> `send()` rejects with HTTP 403, the SDK already dropped local channel-key state on the `conversation_kicked` event

## Helpers

Small standalone utilities shipped alongside `MorokBot`. None of them are required, they exist to keep typical bot patterns out of your event handlers.

### RateLimiter

Token-bucket per key. Use it to throttle floods from one peer without dropping legitimate traffic from others.

```ts
import { MorokBot, RateLimiter } from 'morok-bot-sdk'

const limiter = new RateLimiter({
    capacity:     5,    // burst tolerance
    refillPerSec: 1,    // sustained rate
})

bot.on('message', async (m) => {
    if (!limiter.tryAcquire(m.sender.userId)) {
        await bot.reply(m, { text: 'Too many messages, give me a moment.' })
        return
    }
    // ... your handler
})
```

`tryAcquire(key, cost = 1)` returns `true` if `cost` tokens were available and deducted, `false` otherwise. `available(key)` peeks the count without consuming. `reset(key)` clears one bucket, `clear()` wipes all.

Buckets are O(1) on access and prune themselves once idle and full. In-memory only. If you run multiple bot processes against one logical bot, use a shared Redis-backed limiter instead (not shipped).

To pace top-level channel posts to the server cadence (a burst of 5 then one per 30 seconds) configure the bucket as `new RateLimiter({ capacity: 5, refillPerSec: 1 / 30 })` and call `tryAcquire` before each post. The SDK never retries a `too_many_messages` rejection for you, catch the `SendRejectedError`, read `.code`, and back off, the same goes for a `SendUncertainError` after a drop where you decide to retry or reconcile

### BotSessions

Per-user state store for multi-step flows ("ask name", "ask email", "confirm"). Plain `Map<userId, State>` with optional TTL and a shallow `update()` for partial mutations.

```ts
import { MorokBot, BotSessions } from 'morok-bot-sdk'

interface RegisterFlow {
    step:   'name' | 'email'
    name?:  string
    email?: string
}

const flows = new BotSessions<RegisterFlow>({ ttlMs: 5 * 60_000 })  // 5 min idle = abandon

bot.on('command', async (c) => {
    if (c.command === 'register') {
        flows.set(c.sender.userId, { step: 'name' })
        await bot.reply(c, { text: 'What is your name?' })
    }
})

bot.on('message', async (m) => {
    const state = flows.get(m.sender.userId)
    if (!state) return                              // not in a flow

    if (state.step === 'name' && m.text) {
        flows.update(m.sender.userId, { step: 'email', name: m.text })
        await bot.reply(m, { text: 'And your email?' })
        return
    }
    if (state.step === 'email' && m.text) {
        const final = flows.update(m.sender.userId, { email: m.text })
        flows.delete(m.sender.userId)              // flow complete
        await bot.reply(m, { text: `Got it, ${final.name}. We will email ${final.email}.` })
    }
})
```

In-memory only. Process restart wipes everything. If you need durable flows across restarts, persist the state to disk or Redis from your handler.

## Token rotation and recovery

If you lose the `.morokbot` file:

1. Developer mode -> your bot -> **Edit** -> the **Management** step -> **Regenerate**.
2. The server revokes the old token AND closes any live sessions.
3. The wizard shows the fresh token once. Replace the `token` field in your `.morokbot` (everything else stays put, identity / SPK / OTPKs are unchanged).
4. Restart the SDK.

If you also lose the key material, you have to delete and recreate the bot. Deleting a bot removes its account entirely: to peers it turns into a deleted account and drops out of search. The recreated bot is a separate account even under the same pseudonym, and consent does not carry over, so each peer has to find the bot again and press "Start".

## Security

- The Morok server never decrypts message payloads. The SDK uses Signal Protocol session keys for DMs and a per-conversation channel-key (AES-256-GCM) for group chats and channels.
- A full database leak surfaces ciphertext, public Signal keys, HMAC'd phone numbers, who talked to whom and when, and file sizes. Message contents and private keys aren't in the DB. Raw IPs aren't logged.
- The `.morokbot` file and `stateDir` are private keys on disk. If they leak, the bot is gone.
- On connect the bot cross-signs its device by publishing a device certificate, and it verifies peer certificates on first contact, so a renamed contact or a contact on a new device still derives a consistent safety number. A device certificate is **set once**. The server rejects a silent re-key (posting a different certificate to an already-certified device returns HTTP 409), so neither a hostile server nor a hijacked session can quietly swap the bot's verification material.

> **Vulnerability reports**: email `security@morok.me`. Please, **do not file public GitHub issues for security reports**, this will expose the bug to everyone who comes across before the fix is released. The machine-readable disclosure policy is at [`/.well-known/security.txt`](https://morok.me/.well-known/security.txt) (RFC 9116).

## Troubleshooting

Common symptoms and the fix. For lower-level details on the underlying error codes see the [API reference](https://morok.me/api).

### Connection / auth

| Symptom                                                         | What it means                                                                                                                                  | Fix                                                                                                                              |
|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `disconnect` events every few seconds, `reason: 'transport'`    | Network or NAT is flapping, server restarting, or load balancer killing idle connections.                                                       | Check `curl https://app.morok.me/health`. If the server is healthy, the SDK will reconnect on its own. Enable `logger` for detail. |
| WS keeps closing with code 4001 (`reason: 'auth'`)              | Session ticket was revoked, either the developer panel rotated the token, or `/auth/bot-session` rejected your token.                          | The SDK refreshes the JWT automatically. If it loops, your token is dead, run **Regenerate token** in the dev panel and patch the `token` field in your `.morokbot`. |
| `MorokBot.start: ... 401 INVALID_CREDENTIALS`                    | `.morokbot` file has a stale `token`.                                                                                                          | Replace the `token` field in your `.morokbot` with a fresh one from the dev panel. The rest of the file (identity, prekeys) stays put. |
| `MorokBot.start: refused state-dir lock, another process ...`   | Two SDK processes pointed at the same `stateDir`. The pid-based lock caught it.                                                                | Kill the other process or give each instance its own `stateDir`. Stale `state.lock` is auto-cleared when the holding pid is gone. |

### Sending

Send rejections throw the exported `SendRejectedError`, which carries a machine-readable `.code` (`bot_not_started`, `recipient_storage_full`, `send_blocked`, `too_many_messages`). A bot may send **5 messages in a row** in one conversation (DM, group chat, channel comments), the run resets as soon as a non-bot posts there. Top-level channel posts use a different limit: a burst of 5, then no faster than one per 30 seconds. A gallery counts as one message (up to 10 items), and reactions, edits and deletes don't count. A refused upload (over the 5 GB per-file cap, or the bot over its 10 GB unsent staging) throws the exported `UploadRejectedError` with `.code` like `BOT_STAGING_FULL`, and a drop while a send waits for its echo throws the exported `SendUncertainError` where the message may or may not have landed, so you retry or reconcile

| Symptom                                                         | What it means                                                                                                                                  | Fix                                                                                                                                                                                                                                                                                                              |
|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `send()` rejects with `bot_not_started`                          | The peer has not pressed "Start" on your bot's profile. Server-side guard, bots can't cold-DM users.                                       | Wait for the `start` event, then it's safe to message them. To prompt users, ship a profile description that asks them to press the button.                                                                                                                                                                      |
| `send()` rejects with HTTP 403 on a group chat / channel              | The bot was kicked or the conversation was destroyed. The `conversation_kicked` event already fired and the SDK dropped local channel-key state. | Don't retry. Wait for `conversation_added` if you expect to be re-added.                                                                                                                                                                                                                                         |
| `send()` throws `UploadRejectedError`                           | The file is over the 5 GB per-file cap, or the bot holds over 10 GB of uploaded-but-unsent files (`.code` `BOT_STAGING_FULL`)                                              | Trim the file, or send what is already uploaded (a sent file no longer counts against the staging limit) |
| `send()` rejects with `SendRejectedError` (`code: 'recipient_storage_full'`) | A regular file was billed to the party who bears it: the DM recipient who started the bot, or the group-chat/channel owner who added it. Their storage is full.                          | That party frees space or moves to a personal cloud with more room, or you send less.                                                                                                                                                                           |
| `send()` rejects with `SendRejectedError` (`code: 'too_many_messages'`) | The bot hit its send-rate limit: 5 in a row in a DM/group-chat/comments (a non-bot post resets it), or, for top-level channel posts, faster than one per 30 seconds after the first 5.                          | In a DM/group-chat/comments, wait for a non-bot post (opens a fresh 5). In a channel, slow to one post per 30 seconds. Or pack more into fewer messages: a gallery is one message of up to 10 items. Reactions, edits and deletes don't count.                                                                                                                                                                           |
| `send()` rejects with `SendUncertainError` after a `disconnect`  | The socket dropped while the send was waiting for its server echo, the message may or may not have been delivered                              | Catch `SendUncertainError`, then retry or reconcile against history (it carries `clientMsgId` and `conversationId`), a blind retry can double-deliver if the first one landed |
| `bot.send({ peer: 'alice' })` resolves pseudonyms slowly         | Pseudonym -> userId resolution hits `GET /users/:username` on every call (no SDK cache).                                                       | If you DM the same peer repeatedly, cache `userId` on your side. The numeric value never changes.                                                                                                                                                                                                                |

### Receiving

| Symptom                                                         | What it means                                                                                                                                  | Fix                                                                                                                              |
|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `error` event with "decrypt failed" / "no matching session"      | The peer's Double Ratchet state diverged from the bot's. Often happens after the peer reinstalls the app.                                       | The SDK drops the message and waits for the next type-3 frame from the peer, which re-bootstraps the session. No action needed.   |
| `warn` log `[signal] PEER IDENTITY CHANGED` on a type-3 frame    | A known peer presented a new identity key and the SDK re-pinned it, usually because the peer reinstalled. The SDK accepts it and keeps going, it does not block.   | No action for a normal reinstall. If you track peer identities out of band, treat it as a prompt to re-verify that peer.          |
| `attachment.download()` rejects with HTTP 404 / 410              | File was deleted, expired, or evicted by quota cron.                                                                                           | Treat as gone. The sender can re-upload.                                                                                          |
| Peer's app shows the "Safety number changed" warning             | The same account's identity key changed (a different `.morokbot` with new key material was imported). This does not happen in the normal flow: regenerating the token leaves identity alone, wiping `stateDir` re-imports the same key from `.morokbot`, and re-creating the bot yields a separate account (a new bot — peers just find it again and press Start).                                           | Peers' clients re-pin the new key automatically (TOFU); the warning shows once and nothing is blocked, and re-verifying the safety number by hand is optional.                               |

### State directory

| Symptom                                                         | What it means                                                                                                                                  | Fix                                                                                                                              |
|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Boot log: `[bot] fsck quarantined N session files`               | One or more files under `stateDir/sessions/` failed to parse. They've been moved to `stateDir/quarantine/` so the rest of the state still works. | Affected peer sessions will rebuild on the next message. Inspect `quarantine/` once to see what corrupted them (disk failure, kill -9 during write, etc.). |
| `stateDir` size growing slowly over months                       | Per-peer session records accumulate. One file per `(peer, device)` pair.                                                                       | This is normal: even with thousands of peers the directory is tens of MB. Don't clean it by hand, deleting session files breaks Signal sessions. |
| Stale `state.lock` after process kill -9                         | Pid file mentions a dead PID. SDK refuses to start.                                                                                            | The SDK actually checks if the recorded PID is still alive and clears the lock if not. If you still see "refused", the recorded PID was recycled, delete `state.lock` manually. |

### Bot creation / management

| Symptom                                                         | What it means                                                                                                                                  | Fix                                                                                                                              |
|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `BOT_USERNAME_TAKEN` on bot creation                              | The pseudonym with the `-bot` suffix is already used.                                                                                          | Pick a different pseudonym.                                                                                                       |
| `BOT_LIMIT_REACHED` (409)                                         | You already own 10 bots.                                                                                                                       | Delete one you don't need from the Developer mode tab, or via `DELETE /developer/bots/:id`.                                                                       |
| `.morokbot` file from "Regenerate token" doesn't import         | If you only kept the new `token` and pasted it on top of an old file, that's the correct procedure. If you re-downloaded the whole `.morokbot` and the identity changed, peers will see "Safety number changed". | The dev panel "Regenerate" rotates only the token by default. If the identity changed too, peers get a one-time "Safety number changed" warning and their clients re-pin the new key automatically (TOFU); the old identity can't be restored. |

### Debugging

Pass a logger to see what the SDK is doing. Pino works directly, `console`-shaped also fine:

```ts
const bot = await MorokBot.fromFile({
    tokenFile: './bot.morokbot',
    logger: {
        info:  (o, m) => console.log  (m, o),
        warn:  (o, m) => console.warn (m, o),
        error: (o, m) => console.error(m, o),
        debug: (o, m) => console.debug(m, o),
    },
})
```

The `debug` level logs every WebSocket frame and every prekey-replenish tick, which floods the log fast. `info` keeps the boot trace and rare events. In production, route `warn` and `error` to a file via systemd or journald.

If you suspect a server issue, capture:
- `curl https://app.morok.me/health` and `/version`
- The exact `error.message` from the `error` event
- Surrounding log lines at `debug` level

and open a [GitHub issue](https://github.com/geloid/morok-bot-sdk/issues) with that.

## Development

```bash
git clone https://github.com/geloid/morok-bot-sdk.git
cd morok-bot-sdk
npm install
npm run build       # tsc -> dist/
npm run typecheck
npm test            # vitest unit tests
```

Unit tests cover the `.morokbot` parser, file-backed Signal stores (with fsck and path-traversal guards), the channel / group-secret wire formats, the file cipher (single-shot and chunked AAD), and the gallery payload envelope. There is no integration suite, run the example bot under `examples/echo-bot/` against your own staging instance.

There is no `npm run lint` script, the project leans on `tsc --strict` and the test suite.

### Generated API reference

```bash
npm run docs:api      # typedoc -> docs-api/
```

`docs-api/` is a static HTML site of the SDK's public surface (everything exported from `src/index.ts`), generated by [TypeDoc](https://typedoc.org/) from the TypeScript types and JSDoc. The published live copy is at [morok.me/sdk-api/](https://morok.me/sdk-api/). The directory is gitignored, it's a build artifact, regenerated on each release.

## Glossary

Cryptographic terms used throughout the SDK and the [API reference](https://morok.me/api).

| Term                          | Meaning                                                                                                                                                                          |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Signal Protocol**           | The set of cryptographic primitives Morok inherits from [Open Whisper Systems](https://signal.org/docs/). E2E ratcheted DMs + channel-key group chats and channels + asynchronous handshake.    |
| **X3DH**                      | Extended Triple Diffie-Hellman: the asynchronous handshake that lets a sender start an encrypted session with a recipient who is offline. Mixes identity + signed + one-time keys. |
| **Double Ratchet**            | The per-session key-evolution algorithm that follows X3DH. Every message advances the key, so a single key compromise leaks at most one message in each direction.              |
| **prekey**                    | A public Curve25519 key the recipient publishes ahead of time, consumed by an X3DH initiator. Two flavours below.                                                                |
| **signed prekey (SPK)**       | Long-lived prekey signed by the identity key. Rotated by the server every 7 days. Used when no OTPK is available.                                                                |
| **one-time prekey (OTPK)**    | Short-lived prekey consumed on first use. Pool maintained at `replenishTarget` items. SDK refills automatically.                                                                  |
| **identity key**              | The bot's long-lived Curve25519 keypair. Defines the bot's cryptographic identity to peers. Lives in `stateDir/identity.json`.                                                  |
| **TOFU**                      | "Trust On First Use": the peer accepts the identity key shown on first contact and verifies it stays the same afterwards. A changed identity key triggers a warning in the FE.   |
| **sender_id scrubbing**       | Retroactive metadata minimisation. On DMs the server keeps sender_id only during a hot window (7 days by default) so delivery and read receipts can route back, then nulls it. At routing time the server does see the sender, so this is not sealed sender (that stricter model is not active in the service). Group-chat and channel content is encrypted under the channel-key. |
| **channel-key**               | Per-conversation AES-256 symmetric key used to encrypt messages in a group chat or channel. Rotated by `rotateChannelKey()`.                                            |
| **group-secret**              | Per-conversation symmetric key used to wrap channel-key bundles when distributing them to new members. Rotated by `rotateGroupSecret()` (also rotates the channel-key).         |
| **epoch**                     | A monotonic counter on the channel-key. Each rotation bumps it. The SDK keeps history so older messages stay readable after a rotation.                                          |
| **wire format**               | The exact byte layout of a ciphertext envelope. The channel cipher uses `"MOK1" \| epoch_BE32 \| iv12 \| ct+tag` (see `src/crypto/channel-cipher.ts`).                            |
| **fanoutId**                  | Per-recipient-copy id the server stamps on each device's copy of an outbound message. The SDK matches own-echo by it so `bot.send()` resolves to the real `messageId`.           |
| **clientMsgId**               | Sender-stable id shared by every fan-out copy of one logical send. `bot.reply()` threads through it so replies hit the logical message, not a per-device copy.                  |
| **AAD**                       | Additional Authenticated Data: bytes passed to AES-GCM that aren't encrypted but must match on decrypt. Morok uses scoped strings like `morok-channel-<convId>` to bind ciphertext to context. |

Further reading: [Signal Protocol whitepaper](https://signal.org/docs/), [X3DH spec](https://signal.org/docs/specifications/x3dh/), [Double Ratchet spec](https://signal.org/docs/specifications/doubleratchet/).

## Performance and scaling

One SDK process serves one bot. Per-bot footprint:

| Aspect                          | Value                                                                              |
|---------------------------------|------------------------------------------------------------------------------------|
| RAM (resident)                  | 80-150 MB. libsignal accounts for most of it.                                    |
| CPU                             | < 5% of one core when idle, spikes during X3DH handshakes and AES-GCM on uploads.  |
| Throughput                      | A single process handles hundreds of messages per second. The bottleneck is almost always your handler code or the network. |
| `stateDir` growth               | ~ 1 KB per active peer-device pair. Tens of MB even for bots with thousands of peers. |

Sharing one `stateDir` between processes corrupts the Signal sessions, the pid-lock prevents it from happening accidentally. To run multiple bots on one host, give each its own process and its own `stateDir`. Memory scales roughly linearly.

Outbound fan-out to a multi-device peer happens server-side: one `bot.send()` produces one envelope on your side, the server replicates it to each peer device.

When a single bot exceeds the throughput of one process, the handler is almost always the cause: DB lookups, external API calls, image processing. The WebSocket and libsignal layers keep up with much more than typical handler code.

The shipped `RateLimiter` and `BotSessions` helpers live in memory and don't cross process boundaries. If multiple processes serve one logical bot, write a thin Redis-backed equivalent.

## Migrating from Telegram Bot API

If you've built a Telegram bot before, the rough equivalents are:

| Concept                  | Telegram Bot API                            | Morok                                                                            |
|--------------------------|---------------------------------------------|-----------------------------------------------------------------------------------|
| Transport                | HTTPS long-poll or webhook                  | Persistent WebSocket (the SDK handles reconnect)                                  |
| Token format             | `<int>:<base64>`                             | `bot:<int>:<base64url>`                                                            |
| Server -> bot delivery   | `getUpdates` long-poll or HTTP POST to URL  | WS frame -> `bot.on('message')`                                                   |
| Bot identity             | Single bot per token, no key material        | Signal identity key + signed prekey + one-time prekeys, generated client-side    |
| Multi-device             | Not applicable, bot is a singleton          | Built-in: one outbound DM fans out to every peer device on the server side       |
| Group-chat support            | Native (`message.chat.id`)                   | Same shape (`bot.send({ conversation })`). Admin adds the bot, SDK consumes channel-keys |
| Channel support          | Native (broadcast)                           | Same. Comments thread via `threadRootId`                                          |
| Encryption               | Plaintext on Telegram servers                | E2E (Signal Protocol DMs, channel-key group chats and channels). Server stores ciphertext only.  |
| Slash commands           | Set via `setMyCommands`                      | Set in the bot's Edit screen or `POST /developer/bots/:id/commands`            |
| Buttons (controls)       | Reply / inline keyboards                     | Set via `setMyControls` as a tree, taps fire `bot.on('control')`                |
| Webhooks                 | First-class                                  | Not supported                                                                     |
| Inline mode              | First-class                                  | Not supported                                                                     |
| Payments                 | First-class                                  | Not supported                                                                     |
| Sticker pack creation    | `createNewStickerSet` etc.                   | Not supported                                                                     |
| File upload caps         | Tier-dependent (20 MB to 2 GB)                | 5 GB per file; charged to the recipient (DM) or conversation owner (group chat / channel) |
| Rate limits              | ~ 30 msg/sec global                          | A bot: 5 in a row in a DM/group-chat/comments (a non-bot post resets it); top-level channel posts: 5, then no faster than one per 30 s. Plus a 300 msg/min per-user cap |
| Consent model            | User starts a chat by message                | User presses **Start** first, the bot cannot cold-DM. `bot.on('start')` fires.              |
| Identity changes         | Token regen doesn't change identity          | Identity key change triggers a TOFU warning on the peer side                     |

If you're porting a Telegram bot mechanically, most of the message-handling code translates directly. The consent model is the same as Telegram: you can't message a user until they press the button. The one thing to rethink is attachment encryption: the SDK encrypts each file under its own AES key, but the client-side mime allow-list does **not** apply to a Node bot, so treat `mime` from peers as a hint, not a guarantee.

## Versioning

The package follows [semver](https://semver.org/). Anything exported from `morok-bot-sdk` (the `MorokBot` class, `BotConfig`, `IncomingMessage`, the event payloads, the attachment types) is part of the public API. Wire-format changes follow the Morok server's own compatibility policy described in [api.md](https://morok.me/api).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
