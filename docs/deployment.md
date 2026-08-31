# Deploying to `mybots`

`mybots` is a production host. It has no Git checkout for normal deploys, creates no
branches or locks, and does not run tests or target-delivered deployment helpers.

## Release layout

```text
~/.local/lib/assist-ai/releases/<40-hex-sha>/
~/.local/lib/assist-ai/current -> releases/<40-hex-sha>
~/projects/assist-ai/bot/.env
~/projects/assist-ai/bot/data/
```

Final release directories are immutable. The deploy process builds a unique temporary
directory, writes and verifies its manifest, then renames it to the final SHA path.
It never rewrites an existing final release. `current` is the only durable selection.

The stable user unit directly starts `current/.venv/bin/claude-telegram-bot`. It keeps
the server-owned environment and the absolute database path outside each release.
There are no activation, recovery, path, launcher, request, receipt, slot, or journal
units or files.

## Deploy an exact commit

Run this only from a clean local checkout. The SHA must be a full lowercase SHA that
is reachable from a freshly fetched `origin/main`:

```bash
./ops/deploy.sh deploy <full-commit-sha>
```

The local controller exports that exact tree and a locked production dependency list.
One foreground receiver on the fixed host takes a nonblocking lock, validates the
archive, builds the release at its final path, and checks disk reserve without deleting
any release. It then atomically replaces `current`, restarts the direct user unit, and
checks the loaded fragment, active state, PID working directory, interpreter, and
restart count for a bounded period.

If the candidate fails while that controller is still running, it replaces `current`
once with the target it held in memory and proves the prior release started. It does
not try a second candidate or delete any evidence.

## Manual recovery

There is no boot-time recovery or automatic rollback after a controller crash or power
loss. Before the selector replacement, `current` still names the old release. After
it, `current` names the candidate. Inspect it and explicitly select a known good ready
release:

```bash
./ops/deploy.sh recover <full-commit-sha>
```

Recovery validates that immutable release, atomically selects it, restarts the unit,
and performs the same bounded health check. It never guesses a rollback target.

## First cutover

After the change is merged and checks pass, run:

```bash
./ops/install-host.sh
```

Cutover requires the existing checkout to be clean, healthy, on the canonical origin,
and at the exact requested SHA. It verifies the existing `.env`, data/database and
disk space before mutation. It first points `current` at the legacy root, converts the
SQLite path to the same absolute data location, and installs the direct unit. The
legacy root stays in place. The same SHA is then built as the first immutable release
and selected through the normal health path.

If a foreground cutover fails after changing state, it restores the exact preflight
`.env`, `current` selector, unit file, and loaded unit before returning the failure.
A controller kill or power loss still leaves the last completed selector/unit change
for an operator to inspect. No background process changes that state. Decommissioning
the legacy checkout is a separate human operation, never a deploy side effect.

## Safety rules

- Never copy `.env`, data, databases, or logs into a release archive.
- Normal deploy does not prune releases. Manual maintenance must never delete the
  resolved `current` target and must check free space before deleting anything.
- Do not run this from `mybots`. Deployment control stays local.
