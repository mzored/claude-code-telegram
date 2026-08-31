#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
sha=${2:-}
repo_dir=${3:-}

if [[ $action != deploy && $action != rollback ]]; then
    echo "error: action must be deploy or rollback" >&2
    exit 1
fi
if [[ $(uname -s) != Linux ]]; then
    echo "error: remote deployment is Linux-only" >&2
    exit 1
fi
if [[ ! ${repo_dir:-} =~ ^/[A-Za-z0-9._/-]+$ || ! -d $repo_dir/.git ]]; then
    echo "error: remote repository is missing" >&2
    exit 1
fi

cd "$repo_dir"

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

validate_sha "$sha"

exec 9>"$repo_dir/.git/assist-ai-deploy.lock"
flock -n 9 || {
    echo "error: another deployment is active" >&2
    exit 1
}

require_clean_checkout
git fetch --quiet origin main
require_nondivergent_checkout
require_origin_commit "$sha"

old_sha=$(git rev-parse HEAD)
restore_old_release() {
    local exit_status=$?
    trap - ERR
    echo "error: restoring ${old_sha} after failed ${action}" >&2
    git checkout --quiet --detach "$old_sha"
    poetry sync --only main
    systemctl --user restart assist-ai-bot.service
    exit "$exit_status"
}
trap restore_old_release ERR

git checkout --quiet --detach "$sha"
chmod 600 .env
install -d -m 700 data "$HOME/.config/systemd/user"
find data -type d -exec chmod 700 {} +
find data -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -exec chmod 600 {} +
poetry sync --only main
if [[ -f ops/systemd/assist-ai-bot.service ]]; then
    install -m 644 ops/systemd/assist-ai-bot.service "$HOME/.config/systemd/user/assist-ai-bot.service"
fi
systemctl --user daemon-reload
systemctl --user restart assist-ai-bot.service
systemctl --user is-active --quiet assist-ai-bot.service

running_sha=$(git rev-parse HEAD)
[[ $running_sha == "$sha" ]]
trap - ERR
echo "DEPLOYED_SHA=$running_sha"
