# Production systemd unit

Production installs one user unit, [`assist-ai-bot.service`](ops/systemd/assist-ai-bot.service).
It is server-owned and changes only during explicit cutover or a future reviewed unit
migration.

The unit starts the immutable release selected by `~/.local/lib/assist-ai/current`:

```ini
WorkingDirectory=%h/.local/lib/assist-ai/current
ExecStart=%h/.local/lib/assist-ai/current/.venv/bin/claude-telegram-bot
```

It reads the server-owned `.env`, keeps `UMask=0077` and the production memory limits,
and uses normal systemd restart policy. It does not require an activation, recovery,
launcher, or path unit.

Use `./ops/install-host.sh` for the one-time cutover. Use `./ops/deploy.sh deploy
<sha>` for later exact-SHA releases. Do not edit the unit on the host during a normal
deployment.
