#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_dir/ops/deploy-common.sh"

if [[ $(uname -s) != Linux ]]; then
    echo "error: host installation is Linux-only" >&2
    exit 1
fi

cd "$repo_dir"
require_clean_checkout
git fetch --quiet origin main
require_nondivergent_checkout
require_origin_commit "$(git rev-parse HEAD)"

if [[ ! -f .env ]]; then
    echo "error: create the production .env on this host before installation" >&2
    exit 1
fi

chmod 600 .env
install -d -m 700 data "$HOME/.config/systemd/user"
find data -type d -exec chmod 700 {} +
find data -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -exec chmod 600 {} +
poetry sync --only main
install -m 644 ops/systemd/assist-ai-bot.service "$HOME/.config/systemd/user/assist-ai-bot.service"
systemctl --user daemon-reload
systemctl --user enable --now assist-ai-bot.service
systemctl --user is-active --quiet assist-ai-bot.service
echo "INSTALLED_SHA=$(git rev-parse HEAD)"
