# Fork workflow

This checkout is one half of the local `assist-ai` workspace. The private parent
repository holds planning and private operations records. This public fork holds bot
code and public deployment automation. Do not copy private issue URLs, secrets, or
runtime data into this repository.

## Remotes

Configure the writable fork as `origin` and the original project as fetch-only
`upstream`:

```bash
git remote set-url origin https://github.com/mzored/claude-code-telegram.git
git remote set-url upstream https://github.com/RichardAtCT/claude-code-telegram.git
git remote set-url --push upstream DISABLED
git remote -v
```

Only push feature branches to `origin`. Fetch upstream changes on the local Mac,
review them, and integrate them through a fork pull request. The production host never
pushes and never carries development branches.

## Local macOS setup

Install Python 3.11 and Poetry, then install exactly the committed lock:

```bash
git clone https://github.com/mzored/claude-code-telegram.git
cd claude-code-telegram
poetry sync
cp config/env.local.example .env
chmod 600 .env
make check
```

Fill `.env` locally with development credentials. Do not copy the production `.env`
or database from `mybots`. `make check` is the required CI contract on both macOS and
Linux. `make typecheck` remains separate until the repository's existing mypy debt is
fixed.
