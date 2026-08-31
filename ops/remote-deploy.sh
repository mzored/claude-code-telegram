#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
sha=${2:-}
canonical_repo="$HOME/projects/assist-ai/bot"
canonical_origin=https://github.com/mzored/claude-code-telegram.git
unit_path="$HOME/.config/systemd/user/assist-ai-bot.service"
poetry_version=2.4.1
candidate_reserve_kb=524288

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

cleanup_candidates() {
    find "$canonical_repo" -maxdepth 1 -type d -name '.venv.next.*' -exec rm -rf {} +
    find "$canonical_repo/.cache" -maxdepth 1 -type d -name 'deploy-build.*' -exec rm -rf {} + 2>/dev/null || true
}

check_candidate_disk_space() {
    local live_kb available_kb required_kb
    live_kb=$(du -sk "$canonical_repo/.venv" | awk '{print $1}')
    available_kb=$(df -Pk "$canonical_repo" | awk 'NR == 2 {print $4}')
    required_kb=$((live_kb + candidate_reserve_kb))
    [[ $available_kb =~ ^[0-9]+$ && $available_kb -ge $required_kb ]] || {
        echo "error: insufficient free disk for a candidate environment (need ${required_kb}KB)" >&2
        return 1
    }
}

build_candidate_environment() {
    local build_dir tool_dir poetry_bin python_bin python_version candidate_version
    build_dir="$canonical_repo/.cache/deploy-build.$sha"
    candidate_venv="$canonical_repo/.venv.next.$sha"
    python_bin=${DEPLOY_PYTHON_BIN:-$(command -v python3 || true)}
    [[ -n $python_bin && -x $python_bin ]] || {
        echo "error: python3 is required on the deployment host" >&2
        return 1
    }
    python_version=$($python_bin -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    case "$python_version" in
        3.11|3.12) ;;
        *) echo "error: production requires Python 3.11 or 3.12, found $python_version" >&2; return 1 ;;
    esac
    check_candidate_disk_space || return 1
    rm -rf "$build_dir" "$candidate_venv"
    mkdir -p "$build_dir"
    git show "$sha:pyproject.toml" >"$build_dir/pyproject.toml" || return 1
    git show "$sha:poetry.lock" >"$build_dir/poetry.lock" || return 1
    git show "$sha:README.md" >"$build_dir/README.md" 2>/dev/null || true
    tool_dir="$canonical_repo/.cache/deploy-poetry-$poetry_version"
    poetry_bin="$tool_dir/bin/poetry"
    if [[ ! -x $poetry_bin ]]; then
        "$python_bin" -m venv "$tool_dir" || return 1
        "$tool_dir/bin/python" -m pip install --disable-pip-version-check "poetry==$poetry_version" || return 1
    fi
    export POETRY_VIRTUALENVS_CREATE=true
    export POETRY_VIRTUALENVS_IN_PROJECT=true
    export POETRY_CONFIG_DIR="$canonical_repo/.cache/poetry-config"
    export POETRY_CACHE_DIR="$canonical_repo/.cache/poetry-cache"
    export POETRY_DATA_DIR="$canonical_repo/.cache/poetry-data"
    (
        cd "$build_dir"
        "$poetry_bin" env use "$python_bin" &&
            DEPLOY_RELEASE_SHA="$sha" "$poetry_bin" sync --only main --no-root
    ) || return 1
    [[ -x $build_dir/.venv/bin/python ]] || return 1
    candidate_version=$("$build_dir/.venv/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || "$build_dir/.venv/bin/python" --version)
    [[ $candidate_version == "$python_version" || $candidate_version == "Python $python_version"* ]] || return 1
    mv "$build_dir/.venv" "$candidate_venv"
    rm -rf "$build_dir"
}

validate_sha "$sha"
exec 9>"$canonical_repo/.git/assist-ai-deploy.lock"
flock -n 9 || { echo "error: another deployment is active" >&2; exit 1; }
require_clean_checkout
git fetch --quiet origin main
require_nondivergent_checkout
require_origin_commit "$sha"
[[ -d .venv && -x .venv/bin/python ]] || { echo "error: live service environment is missing" >&2; exit 1; }

cleanup_candidates
if ! build_candidate_environment; then
    cleanup_candidates
    echo "error: candidate environment build failed before cutover" >&2
    exit 1
fi

unit_candidate="$unit_path.next.$sha"
target_has_unit=0
if git cat-file -e "$sha:ops/systemd/assist-ai-bot.service" 2>/dev/null; then
    git show "$sha:ops/systemd/assist-ai-bot.service" >"$unit_candidate"
    chmod 644 "$unit_candidate"
    target_has_unit=1
fi

old_sha=$(git rev-parse HEAD)
was_enabled=0
was_active=0
systemctl --user is-enabled --quiet assist-ai-bot.service && was_enabled=1 || true
systemctl --user is-active --quiet assist-ai-bot.service && was_active=1 || true
release_dir="$canonical_repo/.cache/deploy-release.$sha"
old_venv="$release_dir/.venv"
old_unit="$unit_path.previous.$sha"
mkdir -p "$release_dir"
venv_swapped=0
unit_swapped=0

restore_old_release() {
    local exit_status=${1:-$?}
    local restore_failed=0
    trap - ERR
    set +e
    echo "error: restoring ${old_sha} after failed ${action}" >&2
    git checkout --quiet --detach "$old_sha" || restore_failed=1
    if (( venv_swapped )); then
        rm -rf "$canonical_repo/.venv"
        mv "$old_venv" "$canonical_repo/.venv" || restore_failed=1
    fi
    if (( unit_swapped )); then
        rm -f "$unit_path"
        mv "$old_unit" "$unit_path" || restore_failed=1
    fi
    systemctl --user daemon-reload || restore_failed=1
    if (( was_enabled )); then systemctl --user enable assist-ai-bot.service || restore_failed=1; else systemctl --user disable assist-ai-bot.service || restore_failed=1; fi
    if (( was_active )); then systemctl --user restart assist-ai-bot.service || restore_failed=1; verify_service_stable || restore_failed=1; else systemctl --user stop assist-ai-bot.service || restore_failed=1; fi
    rm -rf "$release_dir" "$candidate_venv" "$unit_candidate"
    cleanup_candidates
    (( restore_failed == 0 )) || { echo "error: restoration after failed ${action} was incomplete" >&2; exit 1; }
    exit "$exit_status"
}
trap restore_old_release ERR

if (( was_active )); then systemctl --user stop assist-ai-bot.service; fi
git checkout --quiet --detach "$sha"
mv "$canonical_repo/.venv" "$old_venv"
mv "$candidate_venv" "$canonical_repo/.venv"
venv_swapped=1
if (( target_has_unit )); then
    if [[ -f $unit_path ]]; then mv "$unit_path" "$old_unit"; fi
    mv "$unit_candidate" "$unit_path"
    unit_swapped=1
fi
systemctl --user daemon-reload
if (( was_enabled )); then systemctl --user enable assist-ai-bot.service; fi
if (( was_active )); then systemctl --user restart assist-ai-bot.service; verify_service_stable || restore_old_release 1; fi

running_sha=$(git rev-parse HEAD)
[[ $running_sha == "$sha" ]]
rm -rf "$release_dir" "$unit_candidate"
cleanup_candidates
trap - ERR
echo "DEPLOYED_SHA=$running_sha"
