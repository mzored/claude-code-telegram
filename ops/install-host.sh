#!/usr/bin/env bash
set -euo pipefail

# Cutover is separate from normal deployment. It never removes the legacy checkout,
# credentials, or data, and leaves the host running that checkout before the first
# immutable release is selected.
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sha=$(git -C "$repo" rev-parse HEAD)
"$repo/ops/deploy.sh" cutover "$sha"
exec "$repo/ops/deploy.sh" deploy "$sha"
