# Развертывание

Морок-бот это долгоживущий Node-процесс, держащий исходящий WebSocket к `app.morok.me` и хранящий состояние на локальном диске, без собственных входящих соединений. Где можно запустить `node` и иметь постоянную директорию, там его и разворачивайте. Документ покрывает два рецепта, **systemd на VPS** и **Docker**, плюс сквозные вопросы (состояние, логи, бэкапы, мониторинг, безопасность, апгрейды).

English version: [deployment.md](./deployment.md).

## Размер ресурсов

На одного бота:

| Ресурс  | Расход                                                                     |
|---------|----------------------------------------------------------------------------|
| CPU     | < 5% одного ядра у тихого бота, всплески на X3DH handshake и загрузках     |
| RAM     | ~ 80-150 МБ резидентной памяти, libsignal занимает большую часть                      |
| Диск    | десятки МБ для `stateDir`, растет ~ 1 КБ на пару активных собеседник-устройство      |
| Сеть    | один долгоживущий исходящий WebSocket + REST-всплески на загрузках файлов  |

VPS на 1 vCPU + 1 ГБ RAM спокойно держит десятки ботов. Не запускайте несколько ботов в одном процессе, на каждого свой `stateDir` и свой процесс.

## Чек-лист перед развертыванием

- Node 22 или новее на целевом хосте (`node --version`)
- `.morokbot` из панели разработчика сохранен локально
- DNS / исходящий доступ к `app.morok.me:443` открыт
- Постоянная директория на хосте, которая переживет рестарт процесса (для `bot-state/`)
- Решено куда писать логи (journald, файл, stdout в агрегатор)

## Рецепт А: systemd на VPS

Один unit-файл, journald для логов, перезапуск при падении через `Restart=on-failure`.

### 1. Отдельный пользователь

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin morokbot
sudo mkdir -p /opt/morokbot
sudo chown morokbot:morokbot /opt/morokbot
```

### 2. Код и зависимости

```bash
# Положите проект бота в /opt/morokbot/app
sudo -u morokbot bash -c '
    cd /opt/morokbot &&
    git clone <ваш-bot-repo>.git app &&
    cd app &&
    npm ci &&
    npm run build
'
```

### 3. Токен и каталог состояния

```bash
# .morokbot живет в /opt/morokbot/secrets, а не в дереве кода
sudo install -d -o morokbot -g morokbot -m 0700 /opt/morokbot/secrets
sudo install -m 0600 /path/to/downloaded/bot.morokbot /opt/morokbot/secrets/bot.morokbot
sudo chown morokbot:morokbot /opt/morokbot/secrets/bot.morokbot

# stateDir в /opt/morokbot/state. SDK создаст его при первом старте,
# но создаем заранее, чтобы права были правильные сразу
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

# Политика рестарта: процесс упал -> рестарт через 5 с, с нарастающей задержкой на быстрых падениях
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=120

# Песочница systemd: ограничиваем привилегии, доступ к ФС, устройствам и ядру
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ReadWritePaths=/opt/morokbot/state

# stdout / stderr -> journald (запросы через journalctl)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=morokbot

# Потолок RAM. Бот столько никогда не использует, лимит ловит утечку памяти до того,
# как OOM вынесет остальной хост
MemoryMax=512M
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

В коде бота (`dist/index.js`) считайте env-переменные:

```ts
const tokenFile = process.env.BOT_TOKEN_FILE ?? './bot.morokbot'
const stateDir  = process.env.BOT_STATE_DIR  ?? './bot-state'
const bot = await MorokBot.fromFile({ tokenFile, stateDir })
```

### 5. Включить и запустить

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now morokbot
sudo systemctl status morokbot
sudo journalctl -u morokbot -f                # хвост логов
```

### 6. Несколько ботов на одном хосте

Размножьте пользователя / пути / unit на каждого бота:

```
/opt/morokbot/<botname>/app
/opt/morokbot/<botname>/secrets/bot.morokbot
/opt/morokbot/<botname>/state
/etc/systemd/system/morokbot-<botname>.service
```

Управление группой: `systemctl <verb> 'morokbot-*'`.

## Рецепт Б: Docker

Контейнеризация подходит, если помнить, что **stateDir должен быть постоянным томом**, иначе контейнер теряет Signal-идентичность на каждом рестарте, и каждый собеседник видит TOFU-warning от нового бота.

### Dockerfile

Многоэтапная сборка для компактного итогового образа:

```dockerfile
# этап сборки
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

# этап запуска
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
      # .morokbot внутри контейнера read-only
      - ./secrets/bot.morokbot:/secrets/bot.morokbot:ro
      # Состояние обязано переживать рестарты. Именованный том либо bind-mount хоста
      - botstate:/state
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 5

volumes:
  botstate:
```

`read_only: true` делает ФС контейнера read-only, бот пишет только в `/state` (том) и `/tmp` (если нужно, дайте через `tmpfs:`).

### Запуск

```bash
docker compose build
docker compose up -d
docker compose logs -f morokbot
```

### Бэкап тома

```bash
# Снимок именованного тома в архив
docker run --rm -v morokbot_botstate:/source -v "$(pwd)":/backup alpine \
    tar czf /backup/botstate-$(date +%F).tgz -C /source .
```

Восстановление это то же в обратную сторону: распакуйте в том **до** запуска бота. Восстановление на работающем боте ломает состояние ratchet.

## Логирование

SDK выдает четыре уровня через опциональный `logger`. Уровень выбирайте под окружение:

```ts
import { MorokBot } from 'morok-bot-sdk'

const level = process.env.LOG_LEVEL ?? 'info'
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

На рабочем сервере: `LOG_LEVEL=info`. До `debug` поднимайте только при разборе инцидента, объем существенный (каждый WS-фрейм, каждая ротация запаса prekey).

journald ротирует логи сам. В Docker `json-file` с `max-size` / `max-file` выше дает ограниченное хранение. Если пишете во внешний агрегатор (Datadog, Loki, ELK), пусть разбирает JSON-строки из `stdout`.

## Бэкапы

Что включать в резервную копию:

| Что                   | Зачем                                                                                            |
|-----------------------|-------------------------------------------------------------------------------------------------|
| `stateDir/` (целиком) | Signal-идентичность бота, запас prekey, Signal-сессии на каждого собеседника. Потеря = новая идентичность для всех: собеседникам один раз покажется смена номера безопасности, клиент перепиннит ключ сам. |
| `bot.morokbot`        | Удобство. Если потеряли, можно нажать **Перевыпустить токен** в панели и получить свежий, но identity / prekeys в новом файле могут не совпадать с уже сохраненным в `stateDir`. Проще хранить файл. |

Что **НЕ** копировать на лету:

- `stateDir/state.lock`: пересоздается при каждом запуске. Копия этого файла в снимке вызывает "refused state-dir lock" при восстановлении.

Частота: для малонагруженного бота хватает ежедневного снимка. Важно понимать окно риска. Состояние ratchet на диске меняется с каждым сообщением, а снимок это своего рода слепок на один момент. Если основной диск умрет и вы развернетесь из вчерашнего снимка, ratchet откатится назад, и сообщения из промежутка между снимком и сбоем могут не расшифроваться. Часть сессий восстановится сама по первому новому type-3 фрейму собеседника (как при ошибке расшифровки), но что-то можно потерять. Чем короче интервал между снимками, тем меньше этот промежуток, поэтому нагруженному боту имеет смысл делать снимки чаще, вплоть до раза в час.

Процедура восстановления:

1. Остановите сервис.
2. Замените `stateDir/` из бэкапа. Убедитесь, что `state.lock` в восстановленных файлах **нет**.
3. Восстановите `bot.morokbot`.
4. `chown` / `chmod` на пользователя сервиса (`0700` директория, `0600` файлы).
5. Запустите бота.

Протестируйте восстановление на тестовом окружении хотя бы раз.

## Мониторинг

SDK это клиент, а не сервер, то есть своего HTTP-эндпоинта проверки здоровья нет. Следите снаружи:

- **Жив ли процесс**: `systemctl is-active morokbot` или `docker inspect --format='{{.State.Health.Status}}' morokbot`. Оповещение при `failed` / `unhealthy`.
- **Шторм переподключений**: ищите в логах события `disconnect`. Если их много за короткое время, проверьте, доступен ли Морок (`curl https://app.morok.me/health`), и не пропал ли ваш исходящий канал.
- **Таймер тишины**: если бот должен получать хотя бы одно сообщение в N часов, оповещайте при более долгой тишине.
- **Размер `stateDir`**: оповещение при заполнении диска на 80%. На тысячах собеседников он растет медленно, резкий скачок размера означает ошибку.
- **Внешняя проверка**: с отдельного аккаунта по расписанию пишите боту и проверяйте, что ответ приходит.

Опционально, но рекомендую: подключите `error`-событие к системе отслеживания ошибок (Sentry, GlitchTip):

```ts
import * as Sentry from '@sentry/node'
Sentry.init({ dsn: process.env.SENTRY_DSN })
bot.on('error', (err) => Sentry.captureException(err))
```

## Гигиена безопасности

- Запускайте **не от суперпользователя**. `User=morokbot` в systemd, `USER morokbot` в Docker.
- `stateDir` это `chmod 0700`, владелец это пользователь сервиса. `.morokbot` это `chmod 0600`.
- `.morokbot` **не** лежит в git-репозитории кода. Держите в `/opt/<bot>/secrets/` или загружайте при развертывании из менеджера секретов (HashiCorp Vault, AWS SSM и т.п.).
- Боту нужен только **исходящий** доступ к `app.morok.me:443`, входящие порты не нужны. Если брандмауэр на VPS слишком открыт, ужесточите:
  - UFW: `ufw default deny incoming; ufw allow ssh`.
  - Облачный брандмауэр: то же самое.
- Обновляйте Node и пакеты ОС на хосте раз в месяц. Устаревший Node это главная поверхность атаки на машине бота.
- Используйте полнодисковое шифрование на хосте (LUKS) или хотя бы зашифруйте раздел с `/opt/morokbot/`. Если диск покинул дата-центр без шифрования, вместе с ним ушли все `.morokbot` и все ratchet-ключи.

## Обновление SDK

Когда вышла новая минорная или патч-версия:

```bash
sudo -u morokbot bash -c '
    cd /opt/morokbot/app &&
    npm install morok-bot-sdk@<версия> &&
    npm run build
'
sudo systemctl restart morokbot
```

Мажорные версии следуют политике из [api.md §Версионирование](https://morok.me/api): проверьте примечания к релизу на изменения формата обмена. Если мажорная меняет формат хранения `stateDir` на диске, SDK прогонит одностороннюю миграцию при первом запуске, **сделайте бэкап `stateDir` до обновления**.

## Что делать при проблемах развертывания

| Симптом                                                              | Вероятная причина                                                                              | Решение                                                                                                                                                    |
|----------------------------------------------------------------------|------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `EACCES: permission denied, open '.../identity.json'`                | systemd-пользователь не может писать в `stateDir`.                                             | `chown -R morokbot:morokbot /opt/morokbot/state && chmod 700 /opt/morokbot/state`.                                                                         |
| Контейнер рестартует в цикле, в логах "refused state-dir lock"       | Контейнер перезапустился до того, как предыдущий процесс снял блокировку.                       | Убедитесь, что на одном томе работает только одна реплика. `restart: unless-stopped` и `mem_limit` подходят. Масштабируйтесь, умножая ботов, а не реплики. |
| Бот запускается, но `start()` висит                                  | Исходящий доступ к `app.morok.me:443` заблокирован.                                                     | `curl -v https://app.morok.me/health` с хоста. Откройте исходящий доступ или почините DNS.                                                                 |
| `stateDir` растет быстро                                             | Много битых файлов уезжают в `quarantine/`, либо логи по ошибке пишутся в `stateDir`.          | Загляните в `quarantine/` и `du -sh stateDir/*`. Логи должны уходить в stdout / journald, а НЕ в `stateDir`.                                       |
| В логах "[bot] unhandled error event"                                | Вы не зарегистрировали `bot.on('error', ...)`, и сработал запасной обработчик SDK.            | Добавьте явный обработчик `error`. Поведение SDK по умолчанию только защищает от падения процесса, сама причина до вашего оповещения не доходит.              |

Ошибки времени выполнения, не связанные с развертыванием, см. [SDK README §Troubleshooting](../README.ru.md#что-делать-если).
