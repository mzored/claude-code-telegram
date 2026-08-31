# Deploying to `mybots`

`mybots` runs production. It does not host a development checkout, create commits,
update lockfiles, run tests, or execute deployment files from the commit being
deployed. Development and deployment control stay in a clean local macOS or Linux
checkout.

## Production layout

The one-time bootstrap installs a stable control plane and two permanent release
slots:

```text
~/.local/lib/assist-ai/control/v1/ops/control/  launcher and activation worker
~/.local/lib/assist-ai/releases/slot-a/         final release path
~/.local/lib/assist-ai/releases/slot-b/         final release path
~/.local/state/assist-ai/active.json            durable release selection
~/.local/state/assist-ai/activation-request.json
~/projects/assist-ai/bot/.env                    server-owned credentials
~/projects/assist-ai/bot/data/                   server-owned data
```

The two release directory names never change. Poetry creates each virtual environment
inside its final slot, so its absolute interpreter paths remain valid. At most the
running release and one other release occupy the server. Building a new candidate
retires the older rollback slot first; a failed build never changes the running slot.

The stable systemd unit starts the stable launcher. The launcher reads `active.json`,
accepts only `legacy`, `slot-a`, or `slot-b`, verifies the selected ready manifest,
then executes that release. An application deploy never replaces or reloads the unit.

## First cutover from the legacy checkout

Run the bootstrap from a clean local checkout after the change has merged and all
required checks are green:

```bash
./ops/install-host.sh
```

Before this command, the existing host must still have:

- A clean checkout at `/home/mzored/projects/assist-ai/bot` whose `origin` is this
  fork and whose current commit is on its existing `origin/main` ref.
- Its working `.venv`, `.env`, and `data/` directory.
- An active user systemd manager.

The local bootstrap streams only the reviewed stable controller and unit bundle to a
temporary directory. The host performs all preflight checks before changing its unit.
It installs the launcher and recovery units first, writes a durable `legacy` selection,
and atomically installs the bot unit last. Every on-disk prefix remains bootable: a
reboot sees either the old unit, or a complete new unit with a valid legacy selection.

The bootstrap changes the relative SQLite URL to the absolute stable data path,
restricts `.env` and data permissions, and preserves the bot unit's prior enabled and
active state. It then deploys the live SHA fresh into `slot-a`. After the same-SHA
release passes runtime stabilization, it removes tracked application files, `.git`,
the legacy `.venv`, and old deployment caches. `.env`, `data/`, and any unrelated
untracked server configuration remain in place. Interrupted cleanup is idempotent.

Do not run the bootstrap against a partially repaired release layout. It refuses an
existing state that does not match the inspected legacy commit.

## Deploy an exact commit

The commit must be a full lowercase SHA already reachable from `origin/main`:

```bash
./ops/deploy.sh deploy <full-commit-sha>
```

The controller:

1. Captures the caller checkout's HEAD, index, tracked diff, and untracked status.
2. Fetches `origin/main` into a temporary bare repository, not the caller checkout.
3. Verifies the exact commit and exports its Git tree as a tar archive.
4. Streams the archive to the installed worker on the fixed `mybots` host.
5. Requires a matching `DEPLOYED_SHA=<sha>` receipt and the unchanged checkout
   identity.

The worker extracts only regular files, directories, and safe relative symlinks. It
rejects credentials, persistent data, path traversal, hard links, and special files.
It installs locked production dependencies with stable Poetry 2.4.1 and `--no-root`.
It does not run a target helper, import `src.main`, or read a target unit.

The worker records file contents, modes, symlink targets, archive digest, exact SHA,
Git tree, Python identity, builder identity, and allocated bytes. It writes the ready
marker last and makes the release read-only. It measures free space after the real
build and refuses activation if the 512 MiB reserve is not present.

## Activation and recovery

An activation request is a new immutable JSON file. The activation worker atomically
changes the complete selection record to `pending`, asks systemd for one bot restart,
and verifies the real `MainPID` for ten seconds. Verification includes:

- Expected unit `FragmentPath` and `NeedDaemonReload=no`.
- Active and running service state.
- `/proc/<MainPID>/cwd` matching the selected slot.
- `/proc/<MainPID>/cmdline` naming that slot's interpreter.
- No increase in systemd's automatic restart count.

Only then does the worker commit the candidate and keep the old current release as the
rollback slot. A failed candidate writes `rollback-pending`, restarts the old release,
verifies it, and commits the restored selection. If rollback cannot stabilize, the
request and state remain for diagnosis.

The worker uses file `fsync`, atomic same-directory replacement, and parent-directory
`fsync` for every durable state change. SIGKILL restarts the activation service. On
reboot, `assist-ai-recover.service` runs before the bot and conservatively restores the
previous release for an uncommitted activation. A committed selection with a leftover
request is finalized instead of rolled back.

## Roll back

Immediate rollback and historical rollback use the same exact-SHA path:

```bash
./ops/deploy.sh rollback <full-commit-sha>
```

The requested commit may predate all deployment automation. It only needs a compatible
locked Python project on `origin/main`; no helper or unit from that commit runs.

## Inspect production without changing it

```bash
ssh mybots 'systemctl --user show assist-ai-bot.service -p ActiveState -p SubState -p MainPID -p NRestarts -p FragmentPath -p NeedDaemonReload'
ssh mybots 'python3 -m json.tool ~/.local/state/assist-ai/active.json'
ssh mybots 'ls -l ~/.local/state/assist-ai/receipts/'
```

Never copy `.env`, the database, media, or logs into a deployment archive or Git.
Ordinary deploy and rollback leave the credential and data bytes, inode, owner, and
mode unchanged.

## Verification contract

`make check` runs the state-machine, SIGKILL, manifest tamper, fixed-slot, measured
disk, credential/data invariance, and checkout identity tests on macOS and Ubuntu. CI
also runs `tests/deploy/test_systemd_integration.sh` as root on a disposable Ubuntu
24.04 runner. That lane requires real systemd 255 and proves the loaded fragment,
`MainPID` working directory and interpreter, failed-candidate restart, and rollback.
A fake `systemctl` is not runtime acceptance evidence.
