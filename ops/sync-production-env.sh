#!/usr/bin/env bash
set -euo pipefail

repo_dir=${DEPLOY_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
poetry_version=2.4.1
python_bin=${DEPLOY_PYTHON_BIN:-$(command -v python3 || true)}

if [[ $(uname -s) != Linux ]]; then
    echo "error: production environment bootstrap is Linux-only" >&2
    exit 1
fi
if [[ ! -f $repo_dir/pyproject.toml || ! -f $repo_dir/poetry.lock ]]; then
    echo "error: production checkout is missing its locked Python project" >&2
    exit 1
fi
if [[ -z $python_bin || ! -x $python_bin ]]; then
    echo "error: python3 is required on the deployment host" >&2
    exit 1
fi

python_version=$($python_bin -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
case "$python_version" in
    3.11|3.12) ;;
    *) echo "error: production requires Python 3.11 or 3.12, found $python_version" >&2; exit 1 ;;
esac

tool_dir="$repo_dir/.cache/deploy-poetry-$poetry_version"
poetry_bin="$tool_dir/bin/poetry"
if [[ ! -x $poetry_bin ]]; then
    "$python_bin" -m venv "$tool_dir"
    "$tool_dir/bin/python" -m pip install --disable-pip-version-check \
        "poetry==$poetry_version"
fi

export POETRY_VIRTUALENVS_CREATE=true
export POETRY_VIRTUALENVS_IN_PROJECT=true
export POETRY_CONFIG_DIR="$repo_dir/.cache/poetry-config"
export POETRY_CACHE_DIR="$repo_dir/.cache/poetry-cache"
export POETRY_DATA_DIR="$repo_dir/.cache/poetry-data"

cd "$repo_dir"
"$poetry_bin" env use "$python_bin"
"$poetry_bin" sync --only main

if [[ ! -x .venv/bin/python ]]; then
    echo "error: Poetry did not create the in-repository service environment" >&2
    exit 1
fi
venv_version=$(.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || .venv/bin/python --version)
if [[ $venv_version != "$python_version" && $venv_version != "Python $python_version"* ]]; then
    echo "error: service environment uses $venv_version instead of Python $python_version" >&2
    exit 1
fi
echo "SERVICE_PYTHON=$repo_dir/.venv/bin/python ($python_version)"
