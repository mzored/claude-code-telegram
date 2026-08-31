.PHONY: install dev test lint typecheck check check-lock test-deploy format clean help run run-watch \
       bump-patch bump-minor bump-major release version

# Default target
help:
	@echo "Available commands:"
	@echo "  install       - Install production dependencies"
	@echo "  dev           - Install development dependencies"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linting checks"
	@echo "  typecheck     - Run mypy (known debt is tracked separately)"
	@echo "  check         - Run the same required checks as CI"
	@echo "  format        - Format code"
	@echo "  clean         - Clean up generated files"
	@echo "  run           - Run the bot"
	@echo "  run-watch     - Run the bot with auto-restart on code changes"
	@echo "  version       - Show current version"
	@echo "  bump-patch    - Bump patch version (1.2.0 -> 1.2.1), commit, and tag"
	@echo "  bump-minor    - Bump minor version (1.2.0 -> 1.3.0), commit, and tag"
	@echo "  bump-major    - Bump major version (1.2.0 -> 2.0.0), commit, and tag"
	@echo "  release       - Push current version tag to trigger release workflow"

install:
	poetry sync --only main

dev:
	poetry install
	poetry run pre-commit install --install-hooks || echo "pre-commit not configured yet"

test:
	poetry run pytest

lint:
	poetry run black --check src tests ops/control
	poetry run isort --check-only src tests ops/control
	poetry run flake8 src tests ops/control

typecheck:
	poetry run mypy src

check-lock:
	poetry check --lock

test-deploy:
	poetry run pytest tests/deploy/test_control_plane.py tests/deploy/test_bootstrap.py

check: check-lock lint test test-deploy

format:
	poetry run black src tests ops/control
	poetry run isort src tests ops/control

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/ .pytest_cache/ dist/ build/

run:
	poetry run claude-telegram-bot

run-watch:  ## Run the bot with auto-restart on src/ changes (uses watchfiles)
	poetry run watchfiles "claude-telegram-bot" src/

# For debugging
run-debug:
	poetry run claude-telegram-bot --debug

# --- Version Management ---

version:  ## Show current version
	@poetry version -s

bump-patch:  ## Bump patch version, commit, and tag
	poetry version patch && \
	NEW_VERSION=$$(poetry version -s) && \
	git add pyproject.toml && \
	git commit -m "release: v$$NEW_VERSION" && \
	git tag "v$$NEW_VERSION" && \
	git push && git push origin "v$$NEW_VERSION" && \
	echo "Released v$$NEW_VERSION. Tag pushed — release workflow will run on GitHub."

bump-minor:  ## Bump minor version, commit, and tag
	poetry version minor && \
	NEW_VERSION=$$(poetry version -s) && \
	git add pyproject.toml && \
	git commit -m "release: v$$NEW_VERSION" && \
	git tag "v$$NEW_VERSION" && \
	git push && git push origin "v$$NEW_VERSION" && \
	echo "Released v$$NEW_VERSION. Tag pushed — release workflow will run on GitHub."

bump-major:  ## Bump major version, commit, and tag
	poetry version major && \
	NEW_VERSION=$$(poetry version -s) && \
	git add pyproject.toml && \
	git commit -m "release: v$$NEW_VERSION" && \
	git tag "v$$NEW_VERSION" && \
	git push && git push origin "v$$NEW_VERSION" && \
	echo "Released v$$NEW_VERSION. Tag pushed — release workflow will run on GitHub."

release:  ## Push the current version tag to trigger the release workflow
	CURRENT_VERSION=$$(poetry version -s) && \
	git push && git push origin "v$$CURRENT_VERSION" && \
	echo "Pushed v$$CURRENT_VERSION. Release workflow will run on GitHub."
