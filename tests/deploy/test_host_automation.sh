#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_failure() {
    if "$@" >/dev/null 2>&1; then
        fail "command unexpectedly passed: $*"
    fi
}

assert_no_candidates() {
    if find "$repo" -maxdepth 1 -type d -name '.venv.next.*' -print -quit | grep -q .; then
        fail "candidate environment was left behind"
    fi
    if find "$repo/.cache" -maxdepth 1 -type d -name 'deploy-build.*' -print -quit | grep -q .; then
        fail "candidate build directory was left behind"
    fi
}

[[ -x $root/ops/sync-production-env.sh ]] || fail "tracked environment bootstrap is missing"
[[ -x $root/ops/remote-deploy.sh ]] || fail "remote deployment script is missing"

home="$tmp_dir/home"
repo="$home/projects/assist-ai/bot"
bin_dir="$tmp_dir/bin"
state_dir="$tmp_dir/systemd-state"
pre_automation_sha=7149f588d1d8b4d4d6c4bbcaecf2897c7bf65912
mkdir -p "$home/projects/assist-ai" "$bin_dir" "$state_dir"

git clone -q "$root" "$repo"
git -C "$repo" config user.email deploy-test@example.invalid
git -C "$repo" config user.name deploy-test
git -C "$repo" checkout -q --detach HEAD
old_sha=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" cat-file -e "${pre_automation_sha}^{commit}" || fail "pre-automation main is unavailable"
expect_failure git -C "$repo" cat-file -e "${pre_automation_sha}:ops/sync-production-env.sh"
expect_failure git -C "$repo" cat-file -e "${pre_automation_sha}:ops/systemd/assist-ai-bot.service"
git -C "$repo" remote set-url origin https://github.com/mzored/claude-code-telegram.git
rm -rf "$repo/.venv" "$repo/.cache" "$repo/data"
mkdir -p "$repo/data"
printf 'TOKEN=test\n' >"$repo/.env"

sed -i.bak 's/Description=.*/Description=delayed-failure-unit/' "$repo/ops/systemd/assist-ai-bot.service"
rm "$repo/ops/systemd/assist-ai-bot.service.bak"
cat >"$repo/ops/sync-production-env.sh" <<'EOF'
#!/usr/bin/env bash
printf 'target helper ran\n' >>"${TARGET_HELPER_LOG:?}"
mkdir -p .venv
printf 'corrupt-target-environment\n' >.venv/release
exit 1
EOF
chmod +x "$repo/ops/sync-production-env.sh"
git -C "$repo" add ops/systemd/assist-ai-bot.service ops/sync-production-env.sh
git -C "$repo" commit -qm bad-target-bootstrap
target_sha=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" update-ref refs/remotes/origin/main "$target_sha"
git -C "$repo" checkout -q --detach "$old_sha"

cat >"$bin_dir/uname" <<'EOF'
#!/usr/bin/env bash
echo Linux
EOF
cat >"$bin_dir/readlink" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == -f ]]; then
    printf '%s\n' "$2"
else
    /usr/bin/readlink "$@"
fi
EOF
cat >"$bin_dir/flock" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$bin_dir/git" <<'EOF'
#!/usr/bin/env bash
for argument in "$@"; do
    [[ $argument == fetch ]] && exit 0
done
exec /usr/bin/git "$@"
EOF
cat >"$bin_dir/df" <<'EOF'
#!/usr/bin/env bash
if [[ ${LOW_DISK:-0} == 1 ]]; then
    available=1
else
    available=4194304
fi
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf 'fake 4194304 0 %s 0%% /\n' "$available"
EOF
cat >"$bin_dir/python3" <<'EOF'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} == -c ]]; then
    echo 3.12
elif [[ ${1:-} == -m && ${2:-} == venv ]]; then
    mkdir -p "$3/bin"
    cp "$0" "$3/bin/python"
elif [[ ${1:-} == -m && ${2:-} == pip ]]; then
    cat >"$(dirname "$0")/poetry" <<'POETRY'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} == env ]]; then
    exit 0
fi
if [[ ${1:-} == sync ]]; then
    mkdir -p .venv/bin
    cp "${DEPLOY_PYTHON_BIN}" .venv/bin/python
    chmod +x .venv/bin/python
    printf '%s\n' "${DEPLOY_RELEASE_SHA:-$(git -C "${DEPLOY_REPO_DIR:-$PWD}" rev-parse HEAD)}" >.venv/release
    exit 0
fi
exit 1
POETRY
    chmod +x "$(dirname "$0")/poetry"
elif [[ ${1:-} == --version ]]; then
    echo Python 3.12.3
else
    exit 1
fi
EOF
cat >"$bin_dir/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state_dir=${FAKE_SYSTEMD_STATE:?}
unit_file=${HOME}/.config/systemd/user/assist-ai-bot.service
mkdir -p "$state_dir"
printf '%s\n' "$*" >>"$state_dir/calls"
case "${2:-}" in
    daemon-reload) exit 0 ;;
    enable) echo enabled >"$state_dir/enabled" ;;
    disable) echo disabled >"$state_dir/enabled" ;;
    is-enabled) [[ $(cat "$state_dir/enabled" 2>/dev/null || true) == enabled ]] ;;
    restart)
        if grep -q delayed-failure-unit "$unit_file"; then
            echo delayed >"$state_dir/status"
            echo 0 >"$state_dir/active-checks"
        else
            echo active >"$state_dir/status"
        fi
        ;;
    stop) echo inactive >"$state_dir/status" ;;
    is-active)
        status=$(cat "$state_dir/status" 2>/dev/null || echo inactive)
        if [[ $status == delayed ]]; then
            checks=$(cat "$state_dir/active-checks")
            checks=$((checks + 1))
            echo "$checks" >"$state_dir/active-checks"
            if (( checks > 1 )); then
                echo failed >"$state_dir/status"
                exit 3
            fi
            exit 0
        fi
        [[ $status == active ]]
        ;;
    show)
        case "${5:-}" in
            NRestarts) echo 0 ;;
            WorkingDirectory) echo "$HOME/projects/assist-ai/bot" ;;
            ExecStart) echo "path=$HOME/projects/assist-ai/bot/.venv/bin/python" ;;
            *) exit 1 ;;
        esac
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$bin_dir"/*

run_env=(env HOME="$home" PATH="$bin_dir:/usr/bin:/bin" DEPLOY_PYTHON_BIN="$bin_dir/python3" FAKE_SYSTEMD_STATE="$state_dir" TARGET_HELPER_LOG="$state_dir/target-helper.log")
if PATH="$bin_dir:/usr/bin:/bin" command -v poetry >/dev/null; then
    fail "bootstrap test must not have global Poetry"
fi

(
    cd "$repo"
    "${run_env[@]}" ./ops/install-host.sh
)
[[ $(cat "$repo/.venv/release") == "$old_sha" ]] || fail "installer did not create the live environment"
grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "installer did not load the old unit"

expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' TARGET_HELPER_LOG='$state_dir/target-helper.log' '$root/ops/remote-deploy.sh' deploy '$target_sha'"
[[ $(git -C "$repo" rev-parse HEAD) == "$old_sha" ]] || fail "failed target bootstrap did not restore the prior commit"
[[ $(cat "$repo/.venv/release") == "$old_sha" ]] || fail "failed target bootstrap did not restore the live environment"
grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "failed target bootstrap did not restore the prior unit"
tail -n 1 "$state_dir/status" | grep -Fxq active || fail "failed target bootstrap did not restore the active service"
[[ ! -e $state_dir/target-helper.log ]] || fail "target bootstrap helper was executed"
assert_no_candidates

rollback_output=$(bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' TARGET_HELPER_LOG='$state_dir/target-helper.log' '$root/ops/remote-deploy.sh' rollback '$pre_automation_sha'")
grep -Fxq "DEPLOYED_SHA=$pre_automation_sha" <<<"$rollback_output" || fail "pre-automation rollback handshake failed"
[[ $(git -C "$repo" rev-parse HEAD) == "$pre_automation_sha" ]] || fail "rollback did not reach pre-automation main"
[[ $(cat "$repo/.venv/release") == "$pre_automation_sha" ]] || fail "rollback did not install the pre-automation environment"
grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "pre-automation rollback replaced the working unit"
tail -n 1 "$state_dir/status" | grep -Fxq active || fail "pre-automation rollback did not leave the service active"
assert_no_candidates

expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' LOW_DISK=1 DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$target_sha'"
[[ $(git -C "$repo" rev-parse HEAD) == "$pre_automation_sha" ]] || fail "low-disk preflight changed the checkout"
[[ $(cat "$repo/.venv/release") == "$pre_automation_sha" ]] || fail "low-disk preflight changed the live environment"
assert_no_candidates

echo "host bootstrap, trusted candidate rollback, and pre-automation rollback tests passed"
