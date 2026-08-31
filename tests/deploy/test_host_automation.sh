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
    if find "$repo/releases" -mindepth 1 -maxdepth 1 -type d ! -name "$(basename "$(readlink -f "$repo/current")")" \
        ! -exec test -f '{}/.complete' \; -print -quit | grep -q .; then
        fail "incomplete immutable release was left behind"
    fi
    if find "$repo" -maxdepth 1 \( -name '.current.next.*' -o -name '*.previous.*' -o -name '*.next.*' \) -print -quit | grep -q .; then
        fail "pointer or unit transaction artifact was left behind"
    fi
}

[[ -x $root/ops/sync-production-env.sh ]] || fail "tracked environment bootstrap is missing"
[[ -x $root/ops/remote-deploy.sh ]] || fail "remote deployment script is missing"
grep -Fxq 'WorkingDirectory=%h/projects/assist-ai/bot/current' \
    "$root/ops/systemd/assist-ai-bot.service" || fail "unit must use the current release pointer"
grep -Fxq 'ExecStart=%h/projects/assist-ai/bot/current/.venv/bin/python -m src.main' \
    "$root/ops/systemd/assist-ai-bot.service" || fail "unit must use the current release environment"
if grep -Eq 'git checkout|mv .*\.venv' "$root/ops/remote-deploy.sh"; then
    fail "remote deploy must not mutate the control checkout or move a live venv"
fi

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
if git -C "$repo" cat-file -e "${pre_automation_sha}^{commit}" 2>/dev/null; then
    expect_failure git -C "$repo" cat-file -e "${pre_automation_sha}:ops/sync-production-env.sh"
    expect_failure git -C "$repo" cat-file -e "${pre_automation_sha}:ops/systemd/assist-ai-bot.service"
else
    git -C "$repo" rm -q ops/sync-production-env.sh ops/systemd/assist-ai-bot.service
    git -C "$repo" commit -qm shallow-pre-automation-fixture
    pre_automation_sha=$(git -C "$repo" rev-parse HEAD)
fi
git -C "$repo" remote set-url origin https://github.com/mzored/claude-code-telegram.git
rm -rf "$repo/.venv" "$repo/.cache" "$repo/data"
mkdir -p "$repo/data"
printf 'TOKEN=test\n' >"$repo/.env"

if [[ ! -f $repo/ops/systemd/assist-ai-bot.service ]]; then
    mkdir -p "$repo/ops/systemd"
    git -C "$repo" show "$old_sha:ops/systemd/assist-ai-bot.service" >"$repo/ops/systemd/assist-ai-bot.service"
    git -C "$repo" show "$old_sha:ops/sync-production-env.sh" >"$repo/ops/sync-production-env.sh"
fi
git -C "$repo" commit --allow-empty -qm healthy-immutable-target
healthy_sha=$(git -C "$repo" rev-parse HEAD)
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
    if [[ ${2:-} == */current ]]; then
        target=$(/usr/bin/readlink "$2")
        if [[ $target == /* ]]; then printf '%s\n' "$target"; else printf '%s/%s\n' "$(dirname "$2")" "$target"; fi
    else
        printf '%s\n' "$2"
    fi
else
    /usr/bin/readlink "$@"
fi
EOF
cat >"$bin_dir/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == -Tf ]]; then
    shift
    rm -f -- "$2"
fi
/bin/mv "$@"
EOF
cat >"$bin_dir/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
/usr/bin/shasum -a 256 "$@"
EOF
cat >"$bin_dir/stat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == -c && ${2:-} == %a ]]; then
    /usr/bin/stat -f %Lp "$3"
else
    exec /usr/bin/stat "$@"
fi
EOF
cat >"$bin_dir/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
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
elif [[ ${DF_AVAILABLE:-} == exact ]]; then
    available=$(( $(du -sk "$(readlink -f "$HOME/projects/assist-ai/bot/current")" | awk '{print $1}') * 2 + 524288 ))
elif [[ ${DF_AVAILABLE:-} == one-less ]]; then
    available=$(( $(du -sk "$(readlink -f "$HOME/projects/assist-ai/bot/current")" | awk '{print $1}') * 2 + 524287 ))
elif [[ -n ${DF_AVAILABLE:-} ]]; then
    available=$DF_AVAILABLE
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
    if [[ ${2:-} == *sys.implementation* ]]; then echo cpython-3.12; else echo 3.12; fi
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
            WorkingDirectory) echo "$HOME/projects/assist-ai/bot/current" ;;
            ExecStart) echo "path=$HOME/projects/assist-ai/bot/current/.venv/bin/python" ;;
            *) exit 1 ;;
        esac
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$bin_dir"/*
mkdir -p "$repo/.venv/bin"
cp "$bin_dir/python3" "$repo/.venv/bin/python"
chmod +x "$repo/.venv/bin/python"

run_env=(env HOME="$home" PATH="$bin_dir:/usr/bin:/bin" DEPLOY_PYTHON_BIN="$bin_dir/python3" FAKE_SYSTEMD_STATE="$state_dir" TARGET_HELPER_LOG="$state_dir/target-helper.log")
if PATH="$bin_dir:/usr/bin:/bin" command -v poetry >/dev/null; then
    fail "bootstrap test must not have global Poetry"
fi

# A crashed first migration must leave neither a durable journal nor an
# un-retryable partial legacy release before the normal installer retries it.
expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_FAULT_AT=legacy-assembly DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$old_sha'"
[[ ! -e $repo/.deploy-transaction ]] || fail "migration fault left a deployment journal"
[[ ! -e $repo/releases/${old_sha}-py3.12 ]] || fail "migration fault left an incomplete legacy release"

(
    cd "$repo"
    "${run_env[@]}" ./ops/install-host.sh
)
grep -Fxq "commit=$old_sha" "$(readlink -f "$repo/current")/.release-meta" || fail "installer did not select the initial immutable release"
grep -Fxq 'builder=immutable-release-v2' "$(readlink -f "$repo/current")/.release-meta" || fail "first immutable deployment did not write a durable release manifest"
grep -Fxq 'migration=legacy-copy-v1' "$(readlink -f "$repo/current")/.release-meta" || fail "first immutable deployment did not preserve the live environment as a rollback release"
[[ -x $(readlink -f "$repo/current")/.venv/bin/python ]] || fail "migration rollback release has no usable environment"
grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "installer did not load the old unit"

# Reuse must reject a tampered completed release before it stops the service.
manifest="$(readlink -f "$repo/current")/.release-meta"
initial_release=$(readlink -f "$repo/current")
manifest_saved="$tmp_dir/release-meta.saved"
cp "$manifest" "$manifest_saved"
for field in commit tree lock_sha256 source_sha256 python python_identity python_shebang builder; do
    sed -i.bak "s/^${field}=.*/${field}=tampered/" "$manifest"
    rm "$manifest.bak"
    expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$old_sha'"
    [[ $(readlink -f "$repo/current") == "$initial_release" ]] || fail "tampered $field changed the live pointer"
    cp "$manifest_saved" "$manifest"
done
chmod 755 "$(readlink -f "$repo/current")/.venv"
expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$old_sha'"
chmod 700 "$(readlink -f "$repo/current")/.venv"
printf 'not-a-key\n' >"$(readlink -f "$repo/current")/id_rsa"
expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$old_sha'"
rm "$(readlink -f "$repo/current")/id_rsa" "$manifest_saved"
assert_no_candidates

for fault in release-assembly after-complete before-service-stop before-unit-replace after-unit-replace after-daemon-reload before-pointer-replace after-pointer-replace; do
    expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_FAULT_AT='$fault' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$healthy_sha'"
    [[ $(git -C "$repo" rev-parse HEAD) == "$old_sha" ]] || fail "$fault changed the control checkout"
    grep -Fxq "commit=$old_sha" "$(readlink -f "$repo/current")/.release-meta" || fail "$fault changed the live pointer"
    grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "$fault changed the installed unit"
    tail -n 1 "$state_dir/status" | grep -Fxq active || fail "$fault did not restore the active service"
    assert_no_candidates
done

expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' TARGET_HELPER_LOG='$state_dir/target-helper.log' '$root/ops/remote-deploy.sh' deploy '$target_sha'"
[[ $(git -C "$repo" rev-parse HEAD) == "$old_sha" ]] || fail "failed target bootstrap changed the control checkout"
grep -Fxq "commit=$old_sha" "$(readlink -f "$repo/current")/.release-meta" || fail "failed target bootstrap did not restore the live release"
grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "failed target bootstrap did not restore the prior unit"
tail -n 1 "$state_dir/status" | grep -Fxq active || fail "failed target bootstrap did not restore the active service"
[[ ! -e $state_dir/target-helper.log ]] || fail "target bootstrap helper was executed"
assert_no_candidates

rollback_output=$(bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' TARGET_HELPER_LOG='$state_dir/target-helper.log' '$root/ops/remote-deploy.sh' rollback '$pre_automation_sha'")
grep -Fxq "DEPLOYED_SHA=$pre_automation_sha" <<<"$rollback_output" || fail "pre-automation rollback handshake failed"
[[ $(git -C "$repo" rev-parse HEAD) == "$old_sha" ]] || fail "rollback changed the control checkout"
grep -Fxq "commit=$pre_automation_sha" "$(readlink -f "$repo/current")/.release-meta" || fail "rollback did not select the pre-automation release"
grep -Fxq 'Description=assist-ai-bot (claude-code-telegram)' "$home/.config/systemd/user/assist-ai-bot.service" || fail "pre-automation rollback replaced the working unit"
tail -n 1 "$state_dir/status" | grep -Fxq active || fail "pre-automation rollback did not leave the service active"
assert_no_candidates

# The exact free-space threshold succeeds; one block below it fails before a
# release mutation. Successful retry keeps only current and immediate prior.
healthy_output=$(bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DF_AVAILABLE=exact DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$healthy_sha'")
grep -Fxq "DEPLOYED_SHA=$healthy_sha" <<<"$healthy_output" || fail "exact disk threshold rejected a safe deployment"
grep -Fxq "commit=$healthy_sha" "$(readlink -f "$repo/current")/.release-meta" || fail "healthy deployment did not select its immutable release"
[[ $(find "$repo/releases" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ') == 2 ]] || fail "retention did not keep exactly current and prior releases"
healthy_output=$(bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DF_AVAILABLE=exact DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$healthy_sha'")
grep -Fxq "DEPLOYED_SHA=$healthy_sha" <<<"$healthy_output" || fail "idempotent deployment retry failed"
[[ $(find "$repo/releases" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ') == 2 ]] || fail "retry changed release retention"

expect_failure bash -c "cd '$repo' && HOME='$home' PATH='$bin_dir:/usr/bin:/bin' DF_AVAILABLE=one-less DEPLOY_PYTHON_BIN='$bin_dir/python3' FAKE_SYSTEMD_STATE='$state_dir' '$root/ops/remote-deploy.sh' deploy '$healthy_sha'"
[[ $(git -C "$repo" rev-parse HEAD) == "$old_sha" ]] || fail "low-disk preflight changed the checkout"
grep -Fxq "commit=$healthy_sha" "$(readlink -f "$repo/current")/.release-meta" || fail "low-disk preflight changed the live release"
assert_no_candidates

echo "host bootstrap, trusted candidate rollback, and pre-automation rollback tests passed"
