# Examples

Two reference bots. Each is a single `.ts` file using the public SDK API.

Русская версия: [README.ru.md](./README.ru.md).

- [`echo-bot/`](./echo-bot): text DM echo + `/help`, console logger, graceful SIGINT.
- [`file-bot/`](./file-bot): receives any attachment, saves it, echoes it back as a `file`. `/png` ships a 1×1 PNG.

## Running

Both take the `.morokbot` path as `argv[2]`:

```bash
# from sdk/
npm install
npm run build

node --experimental-strip-types examples/echo-bot/index.ts ./bot.morokbot
node --experimental-strip-types examples/file-bot/index.ts ./bot.morokbot ./inbox/
```

If your Node doesn't have `--experimental-strip-types`:

```bash
npm run build
node dist/examples/echo-bot/index.js ./bot.morokbot
```

`.morokbot`, `bot-state/`, `inbox/` are in [`.gitignore`](./.gitignore). When you copy an example into your own project, copy that gitignore too.

## Copying into your own project

Examples here import the in-tree SDK:

```diff
- import { MorokBot } from '../../src/index.js'
+ import { MorokBot } from 'morok-bot-sdk'
```

Swap the import, `npm install morok-bot-sdk`, run.

## Adding a new example

Single `index.ts` in a folder named after what it does (`reminder-bot/`, `rss-feed-bot/`). Brief docstring at the top. PR against [the SDK repo](https://github.com/geloid/morok-bot-sdk).
