#!/usr/bin/env bash

validate_sha() {
    if [[ ! ${1:-} =~ ^[0-9a-f]{40}$ ]]; then
        echo "error: commit must be a full lowercase 40-character SHA" >&2
        return 1
    fi
}

validate_repo_path() {
    if [[ ! ${1:-} =~ ^/[A-Za-z0-9._/-]+$ ]]; then
        echo "error: deployment repository must be an absolute path without spaces" >&2
        return 1
    fi
}

require_clean_checkout() {
    if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
        echo "error: checkout has tracked or untracked changes" >&2
        return 1
    fi
}

require_origin_commit() {
    local sha=$1
    git cat-file -e "${sha}^{commit}" 2>/dev/null || {
        echo "error: commit is not available from origin" >&2
        return 1
    }
    git merge-base --is-ancestor "$sha" origin/main || {
        echo "error: commit is not on origin/main" >&2
        return 1
    }
}

require_nondivergent_checkout() {
    git merge-base --is-ancestor HEAD origin/main || {
        echo "error: checkout contains commits not on origin/main" >&2
        return 1
    }
}
