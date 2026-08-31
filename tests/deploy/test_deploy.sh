#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$root/ops/deploy-common.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_failure() {
    if "$@" >/dev/null 2>&1; then
        fail "command unexpectedly passed: $*"
    fi
}

valid_sha=0123456789abcdef0123456789abcdef01234567
validate_sha "$valid_sha"
expect_failure validate_sha 0123456
expect_failure validate_sha 0123456789ABCDEF0123456789abcdef01234567
validate_repo_path /home/mzored/projects/assist-ai/bot
expect_failure validate_repo_path 'relative/repo'
expect_failure validate_repo_path '/tmp/repo;echo-bad'

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
git init --bare -q "$tmp_dir/origin.git"
git init -q "$tmp_dir/work"
git -C "$tmp_dir/work" config user.email test@example.invalid
git -C "$tmp_dir/work" config user.name deploy-test
git -C "$tmp_dir/work" remote add origin "$tmp_dir/origin.git"
touch "$tmp_dir/work/tracked"
git -C "$tmp_dir/work" add tracked
git -C "$tmp_dir/work" commit -qm initial
git -C "$tmp_dir/work" branch -M main
git -C "$tmp_dir/work" push -qu origin main
git -C "$tmp_dir/work" fetch -q origin main
base_sha=$(git -C "$tmp_dir/work" rev-parse HEAD)

(
    cd "$tmp_dir/work"
    require_clean_checkout
    require_nondivergent_checkout
    require_origin_commit "$base_sha"
)

touch "$tmp_dir/work/untracked"
expect_failure bash -c "cd '$tmp_dir/work'; source '$root/ops/deploy-common.sh'; require_clean_checkout"
rm "$tmp_dir/work/untracked"

touch "$tmp_dir/work/local-only"
git -C "$tmp_dir/work" add local-only
git -C "$tmp_dir/work" commit -qm local-only
expect_failure bash -c "cd '$tmp_dir/work'; source '$root/ops/deploy-common.sh'; require_nondivergent_checkout"

fake_ssh="$tmp_dir/fake-ssh"
cat >"$fake_ssh" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' "DEPLOYED_SHA=${FAKE_DEPLOYED_SHA}"
EOF
chmod +x "$fake_ssh"

git -C "$tmp_dir/work" reset -q --hard "$base_sha"
expect_failure env DEPLOY_HOST=test DEPLOY_LOCAL_REPO="$tmp_dir/work" \
    SSH_BIN="$fake_ssh" FAKE_DEPLOYED_SHA=ffffffffffffffffffffffffffffffffffffffff \
    "$root/ops/deploy.sh" deploy "$base_sha"

expect_failure env DEPLOY_HOST=-oProxyCommand=bad DEPLOY_LOCAL_REPO="$tmp_dir/work" \
    SSH_BIN="$fake_ssh" FAKE_DEPLOYED_SHA="$base_sha" \
    "$root/ops/deploy.sh" deploy "$base_sha"

matching_output=$(
    env DEPLOY_HOST=test DEPLOY_LOCAL_REPO="$tmp_dir/work" SSH_BIN="$fake_ssh" \
        FAKE_DEPLOYED_SHA="$base_sha" "$root/ops/deploy.sh" rollback "$base_sha"
)
grep -Fxq "DEPLOYED_SHA=$base_sha" <<<"$matching_output" || fail "matching handshake failed"

echo "deployment preflight and handshake tests passed"
