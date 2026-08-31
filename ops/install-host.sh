#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_dir/ops/deploy-common.sh"
CANONICAL_ORIGIN=https://github.com/mzored/claude-code-telegram.git
canonical_repo="$HOME/projects/assist-ai/bot"

if [[ $(uname -s) != Linux ]]; then
    echo "error: host installation is Linux-only" >&2
    exit 1
fi

cd "$repo_dir"
if [[ $(readlink -f "$repo_dir") != "$canonical_repo" ]]; then
    echo "error: host checkout must be $canonical_repo" >&2
    exit 1
fi
if [[ $(git config --get remote.origin.url 2>/dev/null || true) != "$CANONICAL_ORIGIN" ]]; then
    echo "error: origin URL must be $CANONICAL_ORIGIN" >&2
    exit 1
fi
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
install -m 644 ops/systemd/assist-ai-bot.service "$HOME/.config/systemd/user/assist-ai-bot.service"
systemctl --user daemon-reload
ops/remote-deploy.sh deploy "$(git rev-parse HEAD)"
systemctl --user enable assist-ai-bot.service
restarts_before=$(systemctl --user show assist-ai-bot.service -p NRestarts --value)
systemctl --user restart assist-ai-bot.service
for _ in {1..10}; do
    sleep 1
    systemctl --user is-active --quiet assist-ai-bot.service
done
[[ $(systemctl --user show assist-ai-bot.service -p NRestarts --value) == "$restarts_before" ]]
[[ $(systemctl --user show assist-ai-bot.service -p WorkingDirectory --value) == "$canonical_repo/current" ]]
exec_start=$(systemctl --user show assist-ai-bot.service -p ExecStart --value)
[[ $exec_start == *"path=$canonical_repo/current/.venv/bin/python"* ]]
echo "INSTALLED_SHA=$(git rev-parse HEAD)"
