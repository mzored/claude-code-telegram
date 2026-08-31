#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
sha=${2:-}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)
local_repo=${DEPLOY_LOCAL_REPO:-$repo_dir}
deploy_host=mybots
ssh_bin=${SSH_BIN:-ssh}

if [[ $action != deploy && $action != rollback ]]; then
    echo "usage: $0 <deploy|rollback> <full-commit-sha>" >&2
    exit 2
fi

# shellcheck source=ops/deploy-common.sh
source "$script_dir/deploy-common.sh"
validate_sha "$sha"
cd "$local_repo"
require_clean_checkout
git fetch --quiet origin main
require_nondivergent_checkout
require_origin_commit "$sha"

output=$(
    "$ssh_bin" "$deploy_host" bash -s -- "$action" "$sha" \
        < "$script_dir/remote-deploy.sh"
)
printf '%s\n' "$output"
if ! grep -Fxq "DEPLOYED_SHA=$sha" <<<"$output"; then
    echo "error: mybots did not confirm the requested commit" >&2
    exit 1
fi
