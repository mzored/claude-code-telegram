#!/usr/bin/env bash
set -euo pipefail

if [[ ${CI:-} != true && ${ASSIST_AI_SYSTEMD_INTEGRATION:-} != 1 ]]; then
    echo "error: run only in an isolated Ubuntu 24.04 test host" >&2
    exit 2
fi
if [[ $(id -u) != 0 ]]; then
    echo "error: real systemd integration requires root on its disposable test host" >&2
    exit 2
fi
if [[ $(uname -s) != Linux ]]; then
    echo "error: real systemd integration requires Linux" >&2
    exit 2
fi
systemd_version=$(systemctl --version)
grep -Eq '^systemd 255 ' <<<"${systemd_version%%$'\n'*}"

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d /tmp/assist-ai-systemd.XXXXXX)
test_home="$test_root/home"
units=(
    assist-ai-recover.service
    assist-ai-activation.service
    assist-ai-activation.path
    assist-ai-bot.service
)

report_failure() {
    local line=$1
    echo "error: systemd integration failed at line $line" >&2
    systemctl status "${units[@]}" --no-pager -l >&2 || true
    journalctl -b -u assist-ai-recover.service -u assist-ai-activation.service \
        -u assist-ai-bot.service --no-pager -n 200 >&2 || true
}

cleanup() {
    systemctl stop assist-ai-activation.path assist-ai-activation.service assist-ai-bot.service assist-ai-recover.service >/dev/null 2>&1 || true
    for unit in "${units[@]}"; do
        rm -f "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    rm -rf "$test_root"
}
trap 'report_failure "$LINENO"' ERR
trap cleanup EXIT

mkdir -p "$test_home/.local/lib/assist-ai/control/v1"
cp -a "$root/ops" "$test_home/.local/lib/assist-ai/control/v1/"

for unit in "${units[@]}"; do
    sed "s|%h|$test_home|g" "$root/ops/systemd/$unit" >"/etc/systemd/system/$unit"
    if [[ $unit == *.service ]]; then
        sed -i "/^\[Service\]$/a Environment=HOME=$test_home\nEnvironment=ASSIST_AI_SYSTEMD_SCOPE=system\nEnvironment=ASSIST_AI_SYSTEMD_UNIT_ROOT=/etc/systemd/system" "/etc/systemd/system/$unit"
    fi
done
PYTHONPATH="$root" python3 "$root/tests/deploy/systemd_fixture.py" setup "$test_home"
systemd-analyze verify "${units[@]/#//etc/systemd/system/}"
systemctl daemon-reload
systemctl start assist-ai-bot.service

properties=
for _ in {1..20}; do
    properties=$(systemctl show assist-ai-bot.service \
        --property=ActiveState,SubState,MainPID,NRestarts,FragmentPath,NeedDaemonReload)
    main_pid=$(sed -n 's/^MainPID=//p' <<<"$properties")
    if [[ $main_pid =~ ^[1-9][0-9]*$ ]] \
        && [[ $(readlink -f "/proc/$main_pid/cwd") == "$test_home/.local/lib/assist-ai/releases/slot-a" ]] \
        && tr '\0' '\n' <"/proc/$main_pid/cmdline" | grep -Fxq "$test_home/.local/lib/assist-ai/releases/slot-a/.venv/bin/python"; then
        break
    fi
    sleep 0.5
done

grep -Fxq 'ActiveState=active' <<<"$properties"
grep -Fxq 'SubState=running' <<<"$properties"
grep -Fxq 'NeedDaemonReload=no' <<<"$properties"
grep -Fxq 'FragmentPath=/etc/systemd/system/assist-ai-bot.service' <<<"$properties"
[[ $(readlink -f "/proc/$main_pid/cwd") == "$test_home/.local/lib/assist-ai/releases/slot-a" ]]
tr '\0' '\n' <"/proc/$main_pid/cmdline" | grep -Fxq "$test_home/.local/lib/assist-ai/releases/slot-a/.venv/bin/python"

PYTHONPATH="$root" python3 "$root/tests/deploy/systemd_fixture.py" exercise "$test_home"
echo "real systemd 255 launcher, MainPID, activation, and rollback checks passed"
