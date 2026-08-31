#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]] || ! command -v systemd-analyze >/dev/null; then
    echo "error: this unit verification requires systemd-analyze on Linux" >&2
    exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixture=$(mktemp -d /tmp/assist-ai-unit.XXXXXX)
home="$fixture/home"
unit="$fixture/assist-ai-bot.service"

cleanup() {
    rm -rf "$fixture"
}
trap cleanup EXIT

mkdir -p "$home/projects/assist-ai/bot" "$home/.local/lib/assist-ai/current/.venv/bin"
touch "$home/projects/assist-ai/bot/.env"
printf '#!/bin/sh\nexit 0\n' >"$home/.local/lib/assist-ai/current/.venv/bin/claude-telegram-bot"
chmod 0755 "$home/.local/lib/assist-ai/current/.venv/bin/claude-telegram-bot"
sed "s|%h|$home|g" "$root/ops/systemd/assist-ai-bot.service" >"$unit"

systemd-analyze verify "$unit"

for property in \
    'Type=exec' \
    "EnvironmentFile=$home/projects/assist-ai/bot/.env" \
    "WorkingDirectory=$home/.local/lib/assist-ai/current" \
    "ExecStart=$home/.local/lib/assist-ai/current/.venv/bin/claude-telegram-bot" \
    'Restart=on-failure' \
    'UMask=0077' \
    'WantedBy=default.target'; do
    grep -Fxq "$property" "$unit"
done

if grep -Eq 'assist-ai-(recover|activation)|launcher|^ExecStart=.*ops/' "$unit"; then
    echo "error: the direct unit references a retired control-plane dependency" >&2
    exit 1
fi

echo "systemd-analyze direct-unit property verification passed"
