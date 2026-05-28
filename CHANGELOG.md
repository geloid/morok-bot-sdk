# Changelog

Notable changes to morok-bot-sdk. Format based on Keep a Changelog, versioning is semver

## 1.0.2 - 2026-06-07

### Fixed
- Protocol envelopes are no longer surfaced to the bot. A DM carrying a hidden protocol kind (decrypt-share request and response, signal warm-up, peer-session-reset coordination, XSK propagation and request, DM backfill) is decrypted to keep the Signal session in step, then dropped before it reaches `on('message')` or `on('command')`. Previously an unrecognized envelope fell through as plain text, so a bot could parse platform machinery as a user request

## 1.0.1 - 2026-06-06

First version published to npm

### Fixed
- Some startup failures that kept bots from replying to users
