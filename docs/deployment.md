# Production deployment

A Morok bot is a long-running Node process that holds an outbound WebSocket to `app.morok.me`, keeps state on local disk, and never accepts inbound connections of its own. Anywhere you can run `node` and persist a directory you can host a bot. This document covers two concrete recipes, **systemd on a VPS** and **Docker**, plus the cross-cutting concerns (state, logging, backups, monitoring, security, upgrades).

Русская версия: [deployment.ru.md](./deployment.ru.md).

## Sizing

For one bot:

| Resource | Footprint                                                                  |
|----------|---------------------------------------------------------------------------|
| CPU      | < 5% of one core on a quiet bot, spikes during X3DH handshakes and uploads |
| RAM      | ~ 80-150 MB resident, libsignal accounts for most of it                   |
| Disk     | tens of MB for `stateDir`, grows ~ 1 KB per active peer-device pair        |
| Network  | one persistent outbound WebSocket + REST bursts for file uploads          |

A single VPS with 1 vCPU + 1 GB RAM holds dozens of bots happily. Don't run multiple bots in one process, give each its own `stateDir` and its own process.

## Pre-deploy checklist

- Node 22 or newer on the target host (`node --version`)
- `.morokbot` from the dev panel saved locally
- DNS / network egress to `app.morok.me:443` open
- A persistent directory on the host that will outlive process restarts (for `bot-state/`)
- Logger sink decided (journald, file, stdout-to-aggregator)

## Recipe A: systemd on a VPS

One unit file, journald for logs, restart-on-crash via `Restart=on-failure`.

### 1. Dedicated user

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin morokbot
sudo mkdir -p /opt/morokbot
sudo chown morokbot:morokbot /opt/morokbot
```

### 2. Code and dependencies

```bash
# Drop the bot project into /opt/morokbot/app
sudo -u morokbot bash -c '
    cd /opt/morokbot &&
    git clone <your-bot-repo>.git app &&
    cd app &&
    npm ci &&
    npm run build
'
```

### 3. Token and state directory

```bash
# .morokbot lives in /opt/morokbot/secrets, never in the code tree
sudo install -d -o morokbot -g morokbot -m 0700 /opt/morokbot/secrets
sudo install -m 0600 /path/to/downloaded/bot.morokbot /opt/morokbot/secrets/bot.morokbot
sudo chown morokbot:morokbot /opt/morokbot/secrets/bot.morokbot

# stateDir lives in /opt/morokbot/state. The SDK creates it on first start,
# but we pre-create it so permissions are right from the start
sudo install -d -o morokbot -g morokbot -m 0700 /opt/morokbot/state
```

### 4. systemd unit

`/etc/systemd/system/morokbot.service`:

```ini
[Unit]
Description=Morok bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=morokbot
Group=morokbot
WorkingDirectory=/opt/morokbot/app
ExecStart=/usr/bin/node dist/index.js
Environment=NODE_ENV=production
Environment=BOT_TOKEN_FILE=/opt/morokbot/secrets/bot.morokbot
Environment=BOT_STATE_DIR=/opt/morokbot/state

# Restart policy: process crash -> restart in 5 s, with backoff on rapid failures
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=120

# systemd sandboxing: restrict privileges, filesystem, devices, kernel access
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ReadWritePaths=/opt/morokbot/state

# stdout / stderr -> journald (queryable via journalctl)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=morokbot

# RAM ceiling. The bot should never use this much, the limit catches a
# memory leak before OOM hits the rest of the host
MemoryMax=512M
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

In your bot's `dist/index.js`, read the env vars:

```ts
const tokenFile = process.env.BOT_TOKEN_FILE ?? './bot.morokbot'
const stateDir  = process.env.BOT_STATE_DIR  ?? './bot-state'
const bot = await MorokBot.fromFile({ tokenFile, stateDir })
```

### 5. Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now morokbot
sudo systemctl status morokbot
sudo journalctl -u morokbot -f                # tail logs
```

### 6. Multiple bots on one host

Replicate the user / paths / unit per bot:

```
/opt/morokbot/<botname>/app
/opt/morokbot/<botname>/secrets/bot.morokbot
/opt/morokbot/<botname>/state
/etc/systemd/system/morokbot-<botname>.service
```

Use `systemctl <verb> 'morokbot-*'` to manage them as a group.

## Recipe B: Docker

Containerization is fine if you remember the **stateDir must be a persistent volume**, otherwise the container loses its Signal identity on every restart and every peer sees a fresh-bot TOFU warning.

### Dockerfile

Multi-stage build to keep the runtime image small:

```dockerfile
# build stage
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

# runtime stage
FROM node:22-alpine
RUN addgroup -S morokbot && adduser -S morokbot -G morokbot
WORKDIR /app

COPY --from=build --chown=morokbot:morokbot /app/dist          ./dist
COPY --from=build --chown=morokbot:morokbot /app/node_modules  ./node_modules
COPY --from=build --chown=morokbot:morokbot /app/package*.json ./

USER morokbot
ENV NODE_ENV=production
ENV BOT_TOKEN_FILE=/secrets/bot.morokbot
ENV BOT_STATE_DIR=/state

CMD ["node", "dist/index.js"]
```

### docker-compose.yml

```yaml
services:
  morokbot:
    build: .
    container_name: morokbot
    restart: unless-stopped
    mem_limit: 512m
    pids_limit: 256
    read_only: true
    cap_drop: [ ALL ]
    security_opt: [ no-new-privileges:true ]
    volumes:
      # The .morokbot is read-only inside the container
      - ./secrets/bot.morokbot:/secrets/bot.morokbot:ro
      # State must persist across restarts. Named volume OR a host bind-mount
      - botstate:/state
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 5

volumes:
  botstate:
```

`read_only: true` forces the container fs read-only, the bot only ever writes to `/state` (the volume) and `/tmp` (provide via `tmpfs:` if you need it).

### Run

```bash
docker compose build
docker compose up -d
docker compose logs -f morokbot
```

### Volume backups

```bash
# Snapshot the named volume into a tarball
docker run --rm -v morokbot_botstate:/source -v "$(pwd)":/backup alpine \
    tar czf /backup/botstate-$(date +%F).tgz -C /source .
```

Restoration is the same in reverse, untar into the volume **before** the bot starts. Restoring while the bot is running corrupts ratchet state.

## Logging

The SDK emits four levels via the optional `logger` argument. Pick the verbosity by environment:

```ts
import { MorokBot } from 'morok-bot-sdk'

const level = process.env.LOG_LEVEL ?? 'info'   // 'debug' | 'info' | 'warn' | 'error'
const emit = (lvl: 'log' | 'warn' | 'error' | 'debug') => (o: object, m?: string) => {
    console[lvl](`[${lvl}] ${m ?? ''} ${JSON.stringify(o)}`)
}
const enabled = (want: string) => ['debug', 'info', 'warn', 'error'].indexOf(level) <= ['debug', 'info', 'warn', 'error'].indexOf(want)

const bot = await MorokBot.fromFile({
    tokenFile, stateDir,
    logger: {
        info:  enabled('info')  ? emit('log')   : () => {},
        warn:  enabled('warn')  ? emit('warn')  : () => {},
        error: enabled('error') ? emit('error') : () => {},
        debug: enabled('debug') ? emit('debug') : () => {},
    },
})
```

In production: `LOG_LEVEL=info`. Bump to `debug` only when chasing an incident, the volume is significant (every WS frame, every replenish tick).

journald handles rotation automatically. For Docker, `json-file` with the `max-size` / `max-file` knobs above gives you bounded retention. If you ship to an external aggregator (Datadog, Loki, ELK), have it parse the JSON lines from `stdout`.

## Backups

What to back up:

| What                  | Why                                                                                            |
|-----------------------|------------------------------------------------------------------------------------------------|
| `stateDir/` (whole)   | The bot's Signal identity, prekey pool, and per-peer ratchets. Losing it = new identity to every peer: peers get a one-time safety-number warning and their clients re-pin automatically. |
| `bot.morokbot`        | Convenience copy. If lost you can use **Перевыпустить токен** in the dev panel to get a fresh one, but identity / prekeys in the new file may not match what your `stateDir` already has. Easier to keep the file. |

What **NOT** to back up live:

- `stateDir/state.lock`: re-created on every start, snapshot copies cause "refused state-dir lock" on restore.

Cadence: a daily snapshot is enough for a low-traffic bot. Understand the risk window: the ratchet state on disk advances with every message, while a snapshot is a single point in time. If the primary disk dies and you restore yesterday's snapshot, the ratchet rewinds, and messages from the gap between the snapshot and the failure may fail to decrypt. Some sessions recover on their own from the peer's next type-3 frame (the same recovery as a decrypt failure), but some messages can be lost. The shorter the interval between snapshots, the smaller this gap, so a high-traffic bot may want hourly snapshots.

Restore procedure:

1. Stop the bot service.
2. Replace `stateDir/` from the backup. Make sure `state.lock` is **not** in the restored contents.
3. Restore `bot.morokbot`.
4. `chown` / `chmod` to the service user (`0700` dir, `0600` files).
5. Start the bot.

Test restoration on a staging environment at least once.

## Monitoring

The SDK is a client, not a server, there's no HTTP healthcheck endpoint to probe. Monitor it from outside:

- **Process liveness**: `systemctl is-active morokbot` or `docker inspect --format='{{.State.Health.Status}}' morokbot`. Alert on `failed` / `unhealthy`.
- **Reconnect storms**: tail logs for `disconnect` events. Many in a short window = either Morok is down (`curl https://app.morok.me/health`) or your network egress is failing.
- **Quiet timer**: if your bot is expected to receive at least one message per N hours, alert when it's been silent longer than that.
- **Disk usage on `stateDir`**: alert at 80% disk full. Even with thousands of peers, real growth is slow, sudden jumps point to a bug.
- **External probe**: send a test message to your bot from a separate account on a schedule and assert the reply lands.

Optional but recommended: hook the `error` event into a real error tracker (Sentry, GlitchTip):

```ts
import * as Sentry from '@sentry/node'
Sentry.init({ dsn: process.env.SENTRY_DSN })
bot.on('error', (err) => Sentry.captureException(err))
```

## Security hygiene

- Run as a **non-root user**. `User=morokbot` in systemd, `USER morokbot` in Docker.
- `stateDir` is `chmod 0700` and owned by the service user. `.morokbot` is `chmod 0600`.
- `.morokbot` does **not** go into the bot's source code repo. Keep it in `/opt/<bot>/secrets/` or pulled at deploy time from a secret manager (HashiCorp Vault, AWS SSM, etc.).
- The bot only needs **outbound** access to `app.morok.me:443` and no inbound ports. If your VPS firewall is permissive, tighten:
  - UFW: `ufw default deny incoming; ufw allow ssh`.
  - Cloud firewall: same posture.
- Update Node and OS packages on the host monthly. Out-of-date Node is the main attack surface for a bot host.
- Use full-disk encryption on the host (LUKS) or at least encrypt the partition holding `/opt/morokbot/`. If the disk leaves the datacenter unencrypted, every `.morokbot` and every ratchet key leaves with it.

## SDK upgrades

When a new minor or patch ships:

```bash
sudo -u morokbot bash -c '
    cd /opt/morokbot/app &&
    npm install morok-bot-sdk@<version> &&
    npm run build
'
sudo systemctl restart morokbot
```

Major versions follow the policy in [api.md §Versioning](https://morok.me/api): check the release notes for wire-format changes. If a major changes the on-disk format of `stateDir`, the SDK will run a one-way migration on first boot, **back up `stateDir` before the upgrade**.

## Troubleshooting deployment

| Symptom                                                            | Likely cause                                                                                    | Fix                                                                                          |
|--------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `EACCES: permission denied, open '.../identity.json'`              | systemd user can't write `stateDir`.                                                            | `chown -R morokbot:morokbot /opt/morokbot/state && chmod 700 /opt/morokbot/state`.           |
| Container restarts in a loop, logs say "refused state-dir lock"    | Container restarted before the previous process released the lock.                              | Ensure only one replica is mounted at the same volume. `restart: unless-stopped` + `mem_limit` are fine. Scale horizontally by multiplying bots, not replicas. |
| Bot starts but `start()` hangs                                     | Egress to `app.morok.me:443` blocked.                                                           | `curl -v https://app.morok.me/health` from the host. Open egress or fix DNS.                |
| State directory grows fast                                         | Many corrupted files moving to `quarantine/`, or a misconfigured logger writing into `stateDir`. | Inspect `quarantine/` and `du -sh stateDir/*`. Logger output must go to stdout / journald, NOT into `stateDir`. |
| Logs say "[bot] unhandled error event"                              | Your code didn't register a `bot.on('error', ...)` handler and the SDK's default fallback fired. | Add an explicit `error` handler. The SDK's default just prevents process kill, it doesn't surface the cause to your alerting. |

See the [SDK README §Troubleshooting](../README.md#troubleshooting) for runtime issues that aren't deployment-specific.
