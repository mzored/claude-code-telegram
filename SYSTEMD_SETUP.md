# systemd deployment

Production uses a stable four-unit control bundle:

- [`assist-ai-bot.service`](ops/systemd/assist-ai-bot.service) starts the stable
  launcher and reads the server-owned environment.
- [`assist-ai-recover.service`](ops/systemd/assist-ai-recover.service) resolves an
  interrupted selection before bot startup.
- [`assist-ai-activation.path`](ops/systemd/assist-ai-activation.path) notices a
  durable request left by a disconnected controller.
- [`assist-ai-activation.service`](ops/systemd/assist-ai-activation.service) performs
  the restart, runtime proof, commit, or rollback.

Application SHA deployments never replace this bundle or call `daemon-reload`. The
prefix-safe one-time install, exact-SHA deploy, rollback, crash recovery, and real
systemd test procedure are in [`docs/deployment.md`](docs/deployment.md).
