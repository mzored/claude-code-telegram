# Deploying to `mybots`

`mybots` is a deploy-only Linux host. Development, lock updates, tests, commits, and
pushes happen on the local Mac. Production keeps its own `.env` and `data/`; neither
is copied back into Git.

## One-time host installation

The host must already have Linux, Python 3.11, Poetry, Claude Code authentication, and
a clean clone at `/home/mzored/projects/assist-ai/bot`. Create `.env` from
`config/env.production.example`, insert production values directly on the host, then
run:

```bash
chmod 600 .env
./ops/install-host.sh
```

The installer installs production dependencies from `poetry.lock`, installs the
tracked user unit, sets `.env` to `0600`, `data/` to `0700`, databases to `0600`, and
enables `assist-ai-bot.service`. It refuses non-Linux hosts, dirty checkouts, and
commits that are not on `origin/main`.

## Deploy an exact commit

Run deployments from a clean local checkout after the pull request has merged. Use
the full 40-character commit ID from `origin/main`:

```bash
git fetch origin main
DEPLOY_HOST=mybots ./ops/deploy.sh deploy <full-commit-sha>
```

The local and remote preflight checks both require clean, non-divergent Git state.
The host fetches but never pushes, checks out the commit detached, installs only the
locked production dependencies, installs the tracked unit, restarts the service, and
returns the running commit. A mismatched handshake fails the deployment.

The first deploy from an older mutable checkout can fail because that checkout has a
local-only commit or uncommitted file. Preserve or integrate that work before retrying;
the deploy script will not discard it.

## Roll back

Rollback uses the same safeguards and an earlier full commit ID that remains on
`origin/main`:

```bash
DEPLOY_HOST=mybots ./ops/deploy.sh rollback <full-commit-sha>
```

Check the named destination after either operation:

```bash
ssh mybots 'systemctl --user status assist-ai-bot.service --no-pager'
ssh mybots 'git -C /home/mzored/projects/assist-ai/bot rev-parse HEAD'
```
