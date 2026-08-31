#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ssh_bin=${SSH_BIN:-ssh}
host=mybots
origin=https://github.com/mzored/claude-code-telegram.git

if [[ -n $(git -C "$repo" status --porcelain --untracked-files=normal) ]]; then
    echo "error: host bootstrap requires a clean local checkout" >&2
    exit 1
fi
if [[ $(git -C "$repo" remote get-url origin) != "$origin" ]]; then
    echo "error: bootstrap origin must be $origin" >&2
    exit 1
fi
local_head=$(git -C "$repo" rev-parse HEAD)
remote_main=$(git -C "$repo" ls-remote origin refs/heads/main | awk '{print $1}')
if [[ $local_head != "$remote_main" ]]; then
    echo "error: bootstrap must run from the exact current origin/main commit" >&2
    exit 1
fi

bootstrap_output=$(
    tar -C "$repo" -cf - \
        ops/__init__.py \
        ops/control/__init__.py \
        ops/control/bootstrap.py \
        ops/control/integrity.py \
        ops/control/launcher.py \
        ops/control/manifest.py \
        ops/control/state.py \
        ops/control/worker.py \
        ops/systemd/assist-ai-bot.service \
        ops/systemd/assist-ai-recover.service \
        ops/systemd/assist-ai-activation.service \
        ops/systemd/assist-ai-activation.path |
        "$ssh_bin" "$host" 'set -e; stage=$(mktemp -d); trap '\''rm -rf "$stage"'\'' EXIT; tar -xf - -C "$stage"; /usr/bin/python3 "$stage/ops/control/bootstrap.py" prepare-legacy'
)
printf '%s\n' "$bootstrap_output"
legacy_sha=$(sed -n 's/^LEGACY_SHA=//p' <<<"$bootstrap_output")
cutover_action=$(sed -n 's/^CUTOVER_ACTION=//p' <<<"$bootstrap_output")
if [[ ! $legacy_sha =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: mybots did not report the inspected legacy commit" >&2
    exit 1
fi
if [[ $cutover_action != deploy && $cutover_action != retire && $cutover_action != complete ]]; then
    echo "error: mybots did not report a valid durable cutover action" >&2
    exit 1
fi

if [[ $cutover_action == deploy ]]; then
    "$repo/ops/deploy.sh" deploy "$legacy_sha"
fi
if [[ $cutover_action != complete ]]; then
    retire_output=$(
        "$ssh_bin" "$host" /usr/bin/python3 \
            /home/mzored/.local/lib/assist-ai/control/v1/ops/control/worker.py \
            retire-legacy "$legacy_sha"
    )
    printf '%s\n' "$retire_output"
    grep -Fxq "RETIRED_LEGACY_SHA=$legacy_sha" <<<"$retire_output"
fi
echo "INSTALLED_SHA=$legacy_sha"
