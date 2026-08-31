# systemd deployment

The production service is tracked at
[`ops/systemd/assist-ai-bot.service`](ops/systemd/assist-ai-bot.service).

Do not copy a generic unit or develop in the server checkout. The one-time Linux host
setup, explicit-commit deploy, rollback, permissions, and verification procedure are
documented in [`docs/deployment.md`](docs/deployment.md).
