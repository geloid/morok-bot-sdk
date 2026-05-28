# Примеры

Два бота. Каждый это один `.ts` файл с публичным API SDK.

English version: [README.md](./README.md).

- [`echo-bot/`](./echo-bot): эхо текстовых ЛС + `/help`, вывод логов в консоль, корректное завершение на SIGINT.
- [`file-bot/`](./file-bot): принимает любое вложение, сохраняет на диск, шлет обратно как `file`. `/png` отправляет 1×1 PNG.

## Как запустить

Оба принимают путь к `.morokbot` как `argv[2]`:

```bash
# из sdk/
npm install
npm run build

node --experimental-strip-types examples/echo-bot/index.ts ./bot.morokbot
node --experimental-strip-types examples/file-bot/index.ts ./bot.morokbot ./inbox/
```

Если у Node нет `--experimental-strip-types`:

```bash
npm run build
node dist/examples/echo-bot/index.js ./bot.morokbot
```

`.morokbot`, `bot-state/`, `inbox/` лежат в [`.gitignore`](./.gitignore). Если копируете пример в свой проект, заберите и его.

## Перенос в свой проект

Примеры здесь импортируют SDK напрямую из дерева:

```diff
- import { MorokBot } from '../../src/index.js'
+ import { MorokBot } from 'morok-bot-sdk'
```

Поменяйте импорт, `npm install morok-bot-sdk`, запускайте.

## Добавить свой пример

Один `index.ts` в папке с осмысленным именем (`reminder-bot/`, `rss-feed-bot/`). Сверху идет короткий комментарий-описание, что делает пример. Предложите его в [репозиторий SDK](https://github.com/geloid/morok-bot-sdk).
