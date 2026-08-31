# Fork workflow

Develop in a local macOS checkout. The writable fork is `origin`. The original project
is `upstream`, and it is fetch-only.

## Remotes

```bash
git remote set-url origin https://github.com/mzored/claude-code-telegram.git
git remote get-url upstream >/dev/null 2>&1 || \
  git remote add upstream https://github.com/RichardAtCT/claude-code-telegram.git
git remote set-url upstream https://github.com/RichardAtCT/claude-code-telegram.git
git remote set-url --push upstream DISABLED
git remote -v
```

Push feature branches only to `origin`. Fetch upstream changes locally, review them,
and integrate them through a pull request in the fork. Do not use a production host as
a development workspace.

## Local macOS setup

Install Python 3.11 and Poetry, then install the committed dependency lock:

```bash
git clone https://github.com/mzored/claude-code-telegram.git
cd claude-code-telegram
poetry env use 3.11
poetry sync
cp config/env.local.example .env
chmod 600 .env
make check
```

Fill `.env` with local development credentials. Do not copy production credentials or
runtime data into a local checkout. `make check` is the CI contract on macOS and Linux.
Run `make typecheck` separately while the repository's existing mypy debt remains.
