# Deploying to `mybots`

`mybots` is a deploy-only Linux host. Development, lock updates, tests, commits, and
pushes happen on the local Mac. Production keeps its own `.env` and `data/`; neither
is copied back into Git.

## One-time host installation

The host must already have Linux, Python 3.11 or 3.12, Claude Code authentication, and
a clean clone from `https://github.com/mzored/claude-code-telegram.git` at
`/home/mzored/projects/assist-ai/bot`. The tracked bootstrap installs Poetry 2.4.1 into
the control-checkout cache, builds a complete environment inside an immutable release,
and atomically points `current` at that release; no global Poetry is needed. On the
first immutable deployment, an existing checkout `.venv` is retained in a complete
rollback release. Create `.env` from
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
./ops/deploy.sh deploy <full-commit-sha>
```

The local and remote preflight checks both require clean, non-divergent Git state.
The deployment target is always the `mybots` host and its canonical checkout; caller
arguments cannot select a different host or repository. The host fetches but never
pushes. It archives the requested reviewed commit into a final immutable release
directory, builds that release's `.venv` before stopping the service, and then
atomically replaces the same-filesystem `current` symlink. The unit always starts
`current/.venv/bin/python`, so it is stable across release directories. The host
rejects a cutover when free disk cannot hold the current release, candidate release,
and reserve, and removes failed candidate and transaction files. A failed release
restores the prior `current` pointer and the separately saved unit directly, then
reloads systemd and restores the prior enabled and active service state. The rollback
code never runs a helper from the failed target or renames a live environment. Targets
older than the automation may not contain a unit; in that case the already-installed
canonical unit remains in place. A mismatched handshake fails the deployment.

The first deploy from an older mutable checkout can fail because that checkout has a
local-only commit or uncommitted file. Preserve or integrate that work before retrying;
the deploy script will not discard it.

## Roll back

Rollback uses the same safeguards and an earlier full commit ID that remains on
`origin/main`:

```bash
./ops/deploy.sh rollback <full-commit-sha>
```

Check the named destination after either operation:

```bash
ssh mybots 'systemctl --user status assist-ai-bot.service --no-pager'
ssh mybots 'readlink -f /home/mzored/projects/assist-ai/bot/current && cat /home/mzored/projects/assist-ai/bot/current/.release-meta'
```
