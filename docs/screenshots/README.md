# Screenshots

PNG-скриншоты для документации (`docs/getting-started.md`). Кладите PNG сюда с указанными именами; разметка их подхватывает автоматически.

PNG screenshots for the docs (`docs/getting-started.md`). Drop PNGs here with the names listed; the markdown references them by name.

## Naming convention

| File                                  | What it should show                                                                                       |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `step-1-developer-mode.png`           | Settings -> "About" tab, after 7 taps on the version - developer mode unlocked                            |
| `step-2-bots-tab.png`                 | Settings -> Developer -> empty Bots list with the "+ Создать бота" / "Create bot" button                  |
| `step-3-wizard-info.png`              | Wizard step 1 - "Информация" / "Info": bare handle, display name, description fields                     |
| `step-4-wizard-appearance.png`        | Wizard step 2 - "Внешний вид" / "Appearance": avatar emoji, private toggle                               |
| `step-5-wizard-token.png`             | Wizard step 3 - "Управление" / "Management": token plate, commands editor, perms toggles                |
| `step-6-download-morokbot.png`        | "Скачать .morokbot" / "Download .morokbot" button highlighted                                            |
| `step-7-bot-row.png`                  | Bots list with one bot present, showing the edit + delete row controls                                   |
| `step-8-regenerate-token.png`         | Confirmation dialog for "Перевыпустить токен" / "Regenerate token"                                       |
| `step-9-edit-bot.png`                 | Edit view: display name, description, avatar, permission toggles, command list                          |

## Capture conventions

- Resolution: 1440×900 desktop screenshots scaled down to roughly 1280px wide for the README.
- Format: PNG, lossless, no annotations baked in (use markdown `> note` blocks outside the image).
- Crop tightly to the relevant UI - no surrounding browser chrome or OS bars unless they are part of the message.
- Anonymize: blur any personal handles, real bot names, or tokens. Tokens shown in screenshots **must be revoked before publishing**.
- Theme: prefer the dark theme since the app's default is dark.
- File size: under 200 KB per image. Use `optipng -o5` or similar to flatten.

## Editing the walkthrough

If you add a step or remove one, update both `docs/getting-started.md` and the list above. Keep them in lockstep so the captions match what's on disk.
