#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
sha=${2:-}
canonical_repo="$HOME/projects/assist-ai/bot"
canonical_origin=https://github.com/mzored/claude-code-telegram.git
unit_path="$HOME/.config/systemd/user/assist-ai-bot.service"

if [[ $# -ne 2 || ( $action != deploy && $action != rollback ) ]]; then
    echo "error: action must be deploy or rollback" >&2
    exit 1
fi
if [[ $(uname -s) != Linux ]]; then
    echo "error: remote deployment is Linux-only" >&2
    exit 1
fi
if [[ $(readlink -f "$canonical_repo") != "$canonical_repo" || ! -d $canonical_repo/.git ]]; then
    echo "error: canonical deployment checkout is missing" >&2
    exit 1
fi
if [[ $(git -C "$canonical_repo" config --get remote.origin.url 2>/dev/null || true) != "$canonical_origin" ]]; then
    echo "error: canonical checkout origin must be $canonical_origin" >&2
    exit 1
fi

cd "$canonical_repo"

validate_sha() {
    [[ ${1:-} =~ ^[0-9a-f]{40}$ ]] || {
        echo "error: commit must be a full lowercase 40-character SHA" >&2
        return 1
    }
}

require_clean_checkout() {
    [[ -z $(git status --porcelain --untracked-files=normal) ]] || {
        echo "error: checkout has tracked or untracked changes" >&2
        return 1
    }
}

require_origin_commit() {
    if ! git cat-file -e "${1}^{commit}" 2>/dev/null ||
        ! git merge-base --is-ancestor "$1" origin/main; then
        echo "error: commit is not on origin/main" >&2
        return 1
    fi
}

require_nondivergent_checkout() {
    git merge-base --is-ancestor HEAD origin/main || {
        echo "error: checkout contains commits not on origin/main" >&2
        return 1
    }
}

verify_loaded_unit() {
    [[ $(systemctl --user show assist-ai-bot.service -p WorkingDirectory --value) == "$canonical_repo" ]] || {
        echo "error: loaded unit working directory is not the canonical checkout" >&2
        return 1
    }
    local exec_start
    exec_start=$(systemctl --user show assist-ai-bot.service -p ExecStart --value)
    [[ $exec_start == *"path=$canonical_repo/.venv/bin/python"* ]] || {
        echo "error: loaded unit executable is not the canonical service environment" >&2
        return 1
    }
}

verify_service_stable() {
    local restarts_before restarts_after
    restarts_before=$(systemctl --user show assist-ai-bot.service -p NRestarts --value)
    for _ in {1..5}; do
        sleep 1
        if ! systemctl --user is-active --quiet assist-ai-bot.service; then
            echo "error: service stopped during stabilization" >&2
            return 1
        fi
    done
    restarts_after=$(systemctl --user show assist-ai-bot.service -p NRestarts --value)
    [[ $restarts_after == "$restarts_before" ]] || {
        echo "error: service restarted during stabilization" >&2
        return 1
    }
    verify_loaded_unit
}

validate_sha "$sha"

exec 9>"$canonical_repo/.git/assist-ai-deploy.lock"
flock -n 9 || {
    echo "error: another deployment is active" >&2
    exit 1
}

require_clean_checkout
git fetch --quiet origin main
require_nondivergent_checkout
require_origin_commit "$sha"

old_sha=$(git rev-parse HEAD)
was_enabled=0
was_active=0
systemctl --user is-enabled --quiet assist-ai-bot.service && was_enabled=1 || true
systemctl --user is-active --quiet assist-ai-bot.service && was_active=1 || true
release_tmp_dir=$(mktemp -d)
sync_script="$release_tmp_dir/sync-production-env.sh"
unit_backup="$release_tmp_dir/assist-ai-bot.service"
unit_existed=0
if [[ -f $unit_path ]]; then
    install -m 600 "$unit_path" "$unit_backup"
    unit_existed=1
fi

restore_old_release() {
    local exit_status=${1:-$?}
    local restore_failed=0
    trap - ERR
    set +e
    echo "error: restoring ${old_sha} after failed ${action}" >&2
    git checkout --quiet --detach "$old_sha" || restore_failed=1
    DEPLOY_REPO_DIR="$canonical_repo" "$sync_script" || restore_failed=1
    if (( unit_existed )); then
        install -m 644 "$unit_backup" "$unit_path" || restore_failed=1
    else
        rm -f "$unit_path" || restore_failed=1
    fi
    systemctl --user daemon-reload || restore_failed=1
    if (( was_enabled )); then
        systemctl --user enable assist-ai-bot.service || restore_failed=1
    else
        systemctl --user disable assist-ai-bot.service || restore_failed=1
    fi
    if (( was_active )); then
        systemctl --user restart assist-ai-bot.service || restore_failed=1
        verify_service_stable || restore_failed=1
    else
        systemctl --user stop assist-ai-bot.service || restore_failed=1
    fi
    rm -rf "$release_tmp_dir"
    if (( restore_failed )); then
        echo "error: restoration after failed ${action} was incomplete" >&2
        exit 1
    fi
    exit "$exit_status"
}
trap restore_old_release ERR
trap 'rm -rf "$release_tmp_dir"' EXIT

git checkout --quiet --detach "$sha"
[[ -x ops/sync-production-env.sh ]] || {
    echo "error: target release does not contain the tracked environment bootstrap" >&2
    exit 1
}
install -m 700 ops/sync-production-env.sh "$sync_script"
chmod 600 .env
install -d -m 700 data "$HOME/.config/systemd/user"
find data -type d -exec chmod 700 {} +
find data -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -exec chmod 600 {} +
DEPLOY_REPO_DIR="$canonical_repo" "$sync_script"
install -m 644 ops/systemd/assist-ai-bot.service "$unit_path"
systemctl --user daemon-reload
systemctl --user enable assist-ai-bot.service
systemctl --user restart assist-ai-bot.service
if ! verify_service_stable; then
    restore_old_release 1
fi

running_sha=$(git rev-parse HEAD)
[[ $running_sha == "$sha" ]]
trap - ERR
echo "DEPLOYED_SHA=$running_sha"
