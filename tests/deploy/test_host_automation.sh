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

[[ -x $root/ops/sync-production-env.sh ]] || fail "tracked environment bootstrap is missing"
[[ -x $root/ops/remote-deploy.sh ]] || fail "remote deployment script is missing"

home="$tmp_dir/home"
repo="$home/projects/assist-ai/bot"
bin_dir="$tmp_dir/bin"
state_dir="$tmp_dir/systemd-state"
mkdir -p "$repo" "$bin_dir" "$state_dir"

cp -R "$root/." "$repo/"
rm -rf "$repo/.git" "$repo/.venv" "$repo/.cache" "$repo/data"
mkdir -p "$repo/data"
printf 'TOKEN=test\n' >"$repo/.env"

git init -q "$repo"
git -C "$repo" config user.email deploy-test@example.invalid
git -C "$repo" config user.name deploy-test
git -C "$repo" add .
git -C "$repo" commit -qm old-release
git -C "$repo" branch -M main
old_sha=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" remote add origin https://github.com/mzored/claude-code-telegram.git
git -C "$repo" update-ref refs/remotes/origin/main "$old_sha"

sed -i.bak 's/Description=.*/Description=old-release-unit/' "$repo/ops/systemd/assist-ai-bot.service"
rm "$repo/ops/systemd/assist-ai-bot.service.bak"
git -C "$repo" add ops/systemd/assist-ai-bot.service
git -C "$repo" commit -qm old-unit
old_sha=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" update-ref refs/remotes/origin/main "$old_sha"

sed -i.bak 's/Description=.*/Description=delayed-failure-unit/' "$repo/ops/systemd/assist-ai-bot.service"
rm "$repo/ops/systemd/assist-ai-bot.service.bak"
git -C "$repo" add ops/systemd/assist-ai-bot.service
git -C "$repo" commit -qm delayed-failure
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
    git rev-parse HEAD >.venv/release
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
    daemon-reload)
        exit 0
        ;;
    enable)
        echo enabled >"$state_dir/enabled"
        exit 0
        ;;
    disable)
        echo disabled >"$state_dir/enabled"
        exit 0
        ;;
    is-enabled)
        [[ $(cat "$state_dir/enabled" 2>/dev/null || true) == enabled ]]
        ;;
    restart)
        if grep -q delayed-failure-unit "$unit_file"; then
            echo delayed >"$state_dir/status"
            echo 0 >"$state_dir/active-checks"
        else
            echo active >"$state_dir/status"
        fi
        exit 0
        ;;
    stop)
        echo inactive >"$state_dir/status"
        exit 0
        ;;
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
    *)
        exit 1
        ;;
esac
EOF
chmod +x "$bin_dir"/*

run_env=(env HOME="$home" PATH="$bin_dir:/usr/bin:/bin" DEPLOY_PYTHON_BIN="$bin_dir/python3" FAKE_SYSTEMD_STATE="$state_dir")

if PATH="$bin_dir:/usr/bin:/bin" command -v poetry >/dev/null; then
    fail "bootstrap test must not have global Poetry"
fi

(
    cd "$repo"
    "${run_env[@]}" ./ops/install-host.sh
)
[[ -x $repo/.venv/bin/python ]] || fail "bootstrap did not create the service environment"
[[ $("$repo/.venv/bin/python" --version) == 'Python 3.12.3' ]] || fail "wrong service interpreter"
grep -Fxq "Description=old-release-unit" "$home/.config/systemd/user/assist-ai-bot.service" || fail "installer did not load the tracked unit"

expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$target_sha'"

[[ $(git -C "$repo" rev-parse HEAD) == "$old_sha" ]] || fail "failed deploy restored $(git -C "$repo" rev-parse HEAD), expected $old_sha"
[[ $(cat "$repo/.venv/release") == "$old_sha" ]] || fail "failed deploy did not restore prior dependencies"
grep -Fxq "Description=old-release-unit" "$home/.config/systemd/user/assist-ai-bot.service" || fail "failed deploy did not restore the prior unit"
grep -q 'daemon-reload' "$state_dir/calls" || fail "failed deploy did not reload systemd"
tail -n 1 "$state_dir/status" | grep -Fxq active || fail "failed deploy did not restore the active service"

wrong_repo="$tmp_dir/wrong-repo"
mkdir -p "$wrong_repo/.git"
expect_failure bash -c "HOME='$home' PATH='$bin_dir:/usr/bin:/bin' '$root/ops/remote-deploy.sh' deploy '$old_sha' '$wrong_repo'"
git -C "$repo" remote set-url origin https://example.invalid/not-the-canonical-origin.git
expect_failure bash -c "HOME='$home' PATH='$bin_dir:/usr/bin:/bin' '$root/ops/remote-deploy.sh' deploy '$old_sha'"
git -C "$repo" remote set-url origin https://github.com/mzored/claude-code-telegram.git

echo "host bootstrap, canonical deployment, rollback, and delayed-failure tests passed"
