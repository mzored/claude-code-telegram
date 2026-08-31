#!/usr/bin/env bash
# Reviewed host controller: requested Git trees are data, never executable helpers.
set -euo pipefail

action=${1:-}
sha=${2:-}
repo="$HOME/projects/assist-ai/bot"
origin=https://github.com/mzored/claude-code-telegram.git
releases="$repo/releases"
current="$repo/current"
journal="$repo/.deploy-transaction"
unit="$HOME/.config/systemd/user/assist-ai-bot.service"
reserve_kb=524288
unit_next="$unit.next.assist-ai"
unit_previous="$unit.previous.assist-ai"
current_next="$repo/.current.next.assist-ai"
release=
release_created=0
legacy=
legacy_created=0
previous_current=
unit_existed=0
unit_changed=0
pointer_changed=0
was_enabled=0
was_active=0
cutover_started=0

die() { echo "error: $*" >&2; exit 1; }
fault() {
    if [[ ${DEPLOY_FAULT_AT:-} == "$1" ]]; then
        die "injected failure at $1"
    fi
}
valid_sha() { [[ ${1:-} =~ ^[0-9a-f]{40}$ ]]; }
origin_commit() {
    git -C "$repo" cat-file -e "${1}^{commit}" 2>/dev/null &&
        git -C "$repo" merge-base --is-ancestor "$1" origin/main
}
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
source_digest() {
    (cd "$1" && find . -path './.venv' -prune -o -name .release-meta -prune -o -name .complete -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | awk '{print $1}'
}
python_shebang() {
    if LC_ALL=C grep -aq '^#!' "$1/.venv/bin/python"; then
        head -n 1 "$1/.venv/bin/python" | tr -d '\r'
    else
        printf 'binary\n'
    fi
}
python_identity() { "$1/.venv/bin/python" -c 'import sys; print(f"{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}")'; }
has_secret() { find "$1" -xdev \( -name .env -o -name '*.pem' -o -name id_rsa \) -print -quit | grep -q .; }
journal_write() {
    local phase=$1
    printf 'phase=%s\ncandidate=%s\nlegacy=%s\nprevious=%s\npointer_changed=%s\nunit_changed=%s\nunit_existed=%s\nwas_enabled=%s\nwas_active=%s\n' \
        "$phase" "${release##*/}" "${legacy##*/}" "${previous_current##*/}" "$pointer_changed" "$unit_changed" "$unit_existed" "$was_enabled" "$was_active" >"$journal"
    chmod 600 "$journal"
}
release_name_valid() { [[ ${1:-} =~ ^[0-9a-f]{40}-py3\.(11|12)$ ]]; }
prune_releases() {
    local retained_current retained_previous path name
    retained_current=$(basename "$(readlink -f "$current")")
    retained_previous=${previous_current##*/}
    if [[ $retained_previous == "$retained_current" ]]; then
        for path in "$releases"/*; do
            [[ -d $path ]] || continue
            name=$(basename "$path")
            if [[ $name != "$retained_current" && -f $path/.complete ]]; then
                retained_previous=$name
                break
            fi
        done
    fi
    for path in "$releases"/*; do
        [[ -d $path ]] || continue
        name=$(basename "$path")
        release_name_valid "$name" || die "unexpected release directory requires manual review: $name"
        if [[ ! -f $path/.complete ]]; then
            rm -rf -- "$path"
        elif [[ $name != "$retained_current" && $name != "$retained_previous" ]]; then
            rm -rf -- "$path"
        fi
    done
}
write_manifest() {
    local path=$1 expected=$2 version=$3 migration=$4
    has_secret "$path" && die "release contains a credential-shaped file"
    chmod 700 "$path" "$path/.venv"
    printf 'format=immutable-release-v2\ncommit=%s\ntree=%s\nlock_sha256=%s\nsource_sha256=%s\npython=%s\npython_identity=%s\npython_shebang=%s\nbuilder=immutable-release-v2\nmigration=%s\nrelease_mode=700\nvenv_mode=700\npython_mode=755\n' \
        "$expected" "$(git -C "$repo" rev-parse "$expected^{tree}")" "$(sha256_file "$path/poetry.lock")" \
        "$(source_digest "$path")" "$version" "$(python_identity "$path")" "$(python_shebang "$path")" "$migration" >"$path/.release-meta"
    chmod 600 "$path/.release-meta"
    : >"$path/.complete"
    chmod 600 "$path/.complete"
}
complete_release() {
    local path=$1 expected=$2 version manifest
    version=${3:-$python_version}
    manifest="$path/.release-meta"
    [[ -d $path && -f $path/.complete && -x $path/.venv/bin/python && -f $manifest ]] || return 1
    [[ $(stat -c %a "$path") == 700 && $(stat -c %a "$path/.venv") == 700 && $(stat -c %a "$path/.venv/bin/python") == 755 && $(stat -c %a "$manifest") == 600 && $(stat -c %a "$path/.complete") == 600 ]] || return 1
    ! has_secret "$path" || return 1
    grep -Fxq 'format=immutable-release-v2' "$manifest" &&
        grep -Fxq "commit=$expected" "$manifest" &&
        grep -Fxq "tree=$(git -C "$repo" rev-parse "$expected^{tree}")" "$manifest" &&
        grep -Fxq "lock_sha256=$(sha256_file "$path/poetry.lock")" "$manifest" &&
        grep -Fxq "source_sha256=$(source_digest "$path")" "$manifest" &&
        grep -Fxq "python=$version" "$manifest" &&
        grep -Fxq "python_identity=$(python_identity "$path")" "$manifest" &&
        grep -Fxq "python_shebang=$(python_shebang "$path")" "$manifest" &&
        grep -Fxq 'builder=immutable-release-v2' "$manifest" &&
        grep -Fxq 'release_mode=700' "$manifest" && grep -Fxq 'venv_mode=700' "$manifest" && grep -Fxq 'python_mode=755' "$manifest"
}
verify_service_stable() {
    local restarts_before restarts_after exec_start
    restarts_before=$(systemctl --user show assist-ai-bot.service -p NRestarts --value)
    for _ in {1..5}; do
        sleep 1
        systemctl --user is-active --quiet assist-ai-bot.service || die "service stopped during stabilization"
    done
    restarts_after=$(systemctl --user show assist-ai-bot.service -p NRestarts --value)
    [[ $restarts_after == "$restarts_before" ]] || die "service restarted during stabilization"
    [[ $(systemctl --user show assist-ai-bot.service -p WorkingDirectory --value) == "$repo/current" ]] || die "loaded unit working directory is not current"
    exec_start=$(systemctl --user show assist-ai-bot.service -p ExecStart --value)
    [[ $exec_start == *"path=$repo/current/.venv/bin/python"* ]] || die "loaded unit executable is not current"
}
cleanup_failed_release() {
    (( release_created )) && rm -rf -- "$release"
    (( legacy_created )) && [[ -n $legacy && ! -f $legacy/.complete ]] && rm -rf -- "$legacy"
}
restore() {
    local result=${1:-1} broken=0
    trap - EXIT
    set +e
    if (( !cutover_started )); then
        rm -f "$current_next" "$unit_next" "$unit_previous" "$journal"
        cleanup_failed_release
        exit "$result"
    fi
    if (( pointer_changed )); then
        if [[ -n $previous_current ]]; then
            ln -s "$previous_current" "$current_next" && mv -Tf "$current_next" "$current" || broken=1
        elif [[ -n $legacy && -f $legacy/.complete ]]; then
            ln -s "releases/$(basename "$legacy")" "$current_next" && mv -Tf "$current_next" "$current" || broken=1
        else
            rm -f "$current"
        fi
    fi
    if (( unit_changed )); then
        if (( unit_existed )); then mv -f "$unit_previous" "$unit" || broken=1; else rm -f "$unit"; fi
    fi
    systemctl --user daemon-reload || broken=1
    if (( was_enabled )); then systemctl --user enable assist-ai-bot.service || broken=1; else systemctl --user disable assist-ai-bot.service || broken=1; fi
    if (( was_active )); then
        systemctl --user restart assist-ai-bot.service || broken=1
        if ! (verify_service_stable); then
            broken=1
            echo "error: restored service did not stabilize; manual review is required" >&2
        fi
    else
        systemctl --user stop assist-ai-bot.service || broken=1
    fi
    rm -f "$current_next" "$unit_next" "$unit_previous" "$journal"
    cleanup_failed_release
    (( broken == 0 )) || echo "error: immutable release rollback was incomplete" >&2
    exit "$result"
}
journal_value() { sed -n "s/^$1=//p" "$journal"; }
recover_interrupted_transaction() {
    local phase candidate legacy_name previous pointer unit_changed_j unit_existed_j enabled active broken=0
    [[ -f $journal ]] || return 0
    phase=$(journal_value phase); candidate=$(journal_value candidate); legacy_name=$(journal_value legacy); previous=$(journal_value previous)
    pointer=$(journal_value pointer_changed); unit_changed_j=$(journal_value unit_changed); unit_existed_j=$(journal_value unit_existed)
    enabled=$(journal_value was_enabled); active=$(journal_value was_active)
    [[ $phase =~ ^(prepared|legacy-assembly|release-assembly|cutover-ready|stopping|unit-replaced|pointer-replaced)$ ]] || die "invalid deployment journal requires manual review"
    for flag in "$pointer" "$unit_changed_j" "$unit_existed_j" "$enabled" "$active"; do [[ $flag =~ ^[01]$ ]] || die "invalid deployment journal requires manual review"; done
    if [[ -n $candidate ]] && ! release_name_valid "$candidate"; then die "invalid deployment journal requires manual review"; fi
    if [[ -n $legacy_name ]] && ! release_name_valid "$legacy_name"; then die "invalid deployment journal requires manual review"; fi
    if [[ -n $previous ]] && ! release_name_valid "$previous"; then die "invalid deployment journal requires manual review"; fi
    if [[ $pointer == 1 ]]; then
        if [[ -n $previous ]]; then ln -s "releases/$previous" "$current_next" && mv -Tf "$current_next" "$current" || broken=1
        elif [[ -n $legacy_name && -f $releases/$legacy_name/.complete ]]; then ln -s "releases/$legacy_name" "$current_next" && mv -Tf "$current_next" "$current" || broken=1
        else rm -f "$current"; fi
    fi
    if [[ $unit_changed_j == 1 ]]; then
        if [[ $unit_existed_j == 1 && -f $unit_previous ]]; then mv -Tf "$unit_previous" "$unit" || broken=1; else rm -f "$unit"; fi
    fi
    if [[ $phase == stopping || $phase == unit-replaced || $phase == pointer-replaced ]]; then
        systemctl --user daemon-reload || broken=1
        if [[ $enabled == 1 ]]; then systemctl --user enable assist-ai-bot.service || broken=1; else systemctl --user disable assist-ai-bot.service || broken=1; fi
        if [[ $active == 1 ]]; then
            systemctl --user restart assist-ai-bot.service || broken=1
            if ! (verify_service_stable); then broken=1; echo "error: recovered service did not stabilize; manual review is required" >&2; fi
        else systemctl --user stop assist-ai-bot.service || broken=1; fi
    fi
    [[ -z $candidate || -f $releases/$candidate/.complete ]] || rm -rf -- "$releases/${candidate:?}"
    [[ -z $legacy_name || -f $releases/$legacy_name/.complete ]] || rm -rf -- "$releases/${legacy_name:?}"
    rm -f "$current_next" "$unit_next" "$unit_previous"
    (( broken == 0 )) || die "interrupted deployment recovery needs manual review"
    rm -f "$journal"
}
trap 'restore $?' EXIT

[[ $# -eq 2 && ( $action == deploy || $action == rollback ) ]] || die "action must be deploy or rollback"
valid_sha "$sha" || die "commit must be a full lowercase 40-character SHA"
[[ $(uname -s) == Linux ]] || die "remote deployment is Linux-only"
[[ $(readlink -f "$repo") == "$repo" && -d $repo/.git ]] || die "canonical deployment checkout is missing"
[[ $(git -C "$repo" config --get remote.origin.url 2>/dev/null || true) == "$origin" ]] || die "canonical checkout origin must be $origin"
exec 9>"$repo/.git/assist-ai-deploy.lock"
flock -n 9 || die "another deployment is active"
recover_interrupted_transaction
[[ -z $(git -C "$repo" status --porcelain --untracked-files=normal) ]] || die "checkout has tracked or untracked changes"
git -C "$repo" fetch --quiet origin main
git -C "$repo" merge-base --is-ancestor HEAD origin/main || die "checkout contains commits not on origin/main"
origin_commit "$sha" || die "commit is not on origin/main"

python=${DEPLOY_PYTHON_BIN:-$(command -v python3 || true)}
[[ -n $python && -x $python ]] || die "python3 is required on the deployment host"
python_version=$($python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
case "$python_version" in 3.11|3.12) ;; *) die "production requires Python 3.11 or 3.12, found $python_version";; esac
if [[ -L $current ]]; then live_path=$(readlink -f "$current"); else live_path="$repo/.venv"; fi
if [[ -d $live_path ]]; then live_kb=$(du -sk "$live_path" | awk '{print $1}'); else live_kb=0; fi
available_kb=$(df -Pk "$repo" | awk 'NR == 2 {print $4}')
[[ $available_kb =~ ^[0-9]+$ && $available_kb -ge $((live_kb * 2 + reserve_kb)) ]] || die "insufficient free disk for current release, candidate, and reserve"
release="$releases/${sha}-py${python_version}"
journal_write prepared

# First immutable deployment preserves the live checkout and environment as a
# complete rollback release without checking out or executing a target helper.
if [[ ! -L $current ]]; then
    if [[ -x $repo/.venv/bin/python ]]; then
        old_sha=$(git -C "$repo" rev-parse HEAD)
        origin_commit "$old_sha" || die "live checkout commit is not on origin/main"
        old_python=$("$repo"/.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || "$repo"/.venv/bin/python --version)
        old_python=${old_python#Python }
        legacy="$releases/${old_sha}-py${old_python}"
        if ! complete_release "$legacy" "$old_sha" "$old_python"; then
            [[ ! -e $legacy ]] || rm -rf -- "$legacy"
            mkdir -p "$legacy"
            legacy_created=1
            journal_write legacy-assembly
            fault legacy-assembly
            git -C "$repo" archive "$old_sha" | tar -x -C "$legacy"
            cp -a "$repo/.venv" "$legacy/.venv"
            write_manifest "$legacy" "$old_sha" "$old_python" legacy-copy-v1
        fi
    fi
fi

if ! complete_release "$release" "$sha"; then
    [[ ! -e $release ]] || die "incomplete release already exists"
    mkdir -p "$releases" "$release"
    release_created=1
    journal_write release-assembly
    fault release-assembly
    git -C "$repo" archive "$sha" | tar -x -C "$release"
    [[ -f $release/pyproject.toml && -f $release/poetry.lock ]] || die "target release lacks a lockfile"
    has_secret "$release" && die "target release contains a credential-shaped file"
    tool="$repo/.cache/deploy-poetry-2.4.1"
    poetry="$tool/bin/poetry"
    if [[ ! -x $poetry ]]; then "$python" -m venv "$tool"; "$tool/bin/python" -m pip install --disable-pip-version-check 'poetry==2.4.1'; fi
    export POETRY_VIRTUALENVS_CREATE=true POETRY_VIRTUALENVS_IN_PROJECT=true
    export POETRY_CONFIG_DIR="$repo/.cache/poetry-config" POETRY_CACHE_DIR="$repo/.cache/poetry-cache" POETRY_DATA_DIR="$repo/.cache/poetry-data"
    (cd "$release"; "$poetry" env use "$python"; DEPLOY_RELEASE_SHA="$sha" "$poetry" sync --only main --no-root)
    [[ -x $release/.venv/bin/python ]] || die "release environment was not created"
    "$release/.venv/bin/python" -c 'import src.main'
    write_manifest "$release" "$sha" "$python_version" fresh-archive-v1
    fault after-complete
fi

if [[ -L $current ]]; then previous_current=$(readlink "$current"); fi
if [[ -e $unit ]]; then cp -p "$unit" "$unit_previous"; unit_existed=1; fi
if git -C "$repo" cat-file -e "$sha:ops/systemd/assist-ai-bot.service" 2>/dev/null; then
    git -C "$repo" show "$sha:ops/systemd/assist-ai-bot.service" >"$unit_next"
    grep -Fxq 'WorkingDirectory=%h/projects/assist-ai/bot/current' "$unit_next" || die "candidate unit must use current"
    grep -Fxq 'ExecStart=%h/projects/assist-ai/bot/current/.venv/bin/python -m src.main' "$unit_next" || die "candidate unit must use current environment"
    chmod 644 "$unit_next"
fi
systemctl --user is-enabled --quiet assist-ai-bot.service && was_enabled=1 || true
systemctl --user is-active --quiet assist-ai-bot.service && was_active=1 || true
journal_write cutover-ready
fault before-service-stop
cutover_started=1
journal_write stopping
if (( was_active )); then systemctl --user stop assist-ai-bot.service; fi
fault before-unit-replace
if [[ -f $unit_next ]]; then mv -Tf "$unit_next" "$unit"; unit_changed=1; journal_write unit-replaced; fi
fault after-unit-replace
systemctl --user daemon-reload
fault after-daemon-reload
ln -s "releases/$(basename "$release")" "$current_next"
fault before-pointer-replace
mv -Tf "$current_next" "$current"
pointer_changed=1
journal_write pointer-replaced
fault after-pointer-replace
if (( was_enabled )); then systemctl --user enable assist-ai-bot.service; fi
if (( was_active )); then systemctl --user restart assist-ai-bot.service; fi
[[ $(readlink -f "$current") == "$release" ]] || die "current pointer did not select requested release"
complete_release "$release" "$sha" || die "current release is incomplete"
if (( was_active )); then verify_service_stable; fi
prune_releases
rm -f "$unit_previous"
rm -f "$journal"
trap - EXIT
echo "DEPLOYED_SHA=$sha"
