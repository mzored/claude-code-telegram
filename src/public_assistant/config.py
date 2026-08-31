"""Fail-closed configuration and credential-file loading for Unit 1."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class PublicAssistantConfigurationError(ValueError):
    """Raised before network or database access when isolation is invalid."""


PUBLISHED_CONTENT_RETENTION_SECONDS = 90 * 24 * 60 * 60


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise PublicAssistantConfigurationError(f"{name} is required")
    return value


def _positive_int(environment: Mapping[str, str], name: str) -> int:
    raw = _required(environment, name)
    try:
        value = int(raw)
    except ValueError as exc:
        raise PublicAssistantConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise PublicAssistantConfigurationError(f"{name} must be positive")
    return value


def _positive_float(environment: Mapping[str, str], name: str) -> float:
    raw = _required(environment, name)
    try:
        value = float(raw)
    except ValueError as exc:
        raise PublicAssistantConfigurationError(f"{name} must be a number") from exc
    if value <= 0:
        raise PublicAssistantConfigurationError(f"{name} must be positive")
    return value


def _credential_path(environment: Mapping[str, str], name: str) -> Path:
    path = Path(_required(environment, name))
    if not path.is_absolute():
        raise PublicAssistantConfigurationError(f"{name} must be an absolute path")
    return path


def read_credential(path: Path, label: str, *, minimum_bytes: int = 1) -> str:
    """Read one owner-only regular file without following symlinks."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicAssistantConfigurationError(
            f"cannot read {label} credential file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PublicAssistantConfigurationError(
                f"{label} credential must be a regular file"
            )
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PublicAssistantConfigurationError(
                f"{label} credential file must have mode 0600"
            )
        if metadata.st_uid != os.geteuid():
            raise PublicAssistantConfigurationError(
                f"{label} credential file must be owned by the process user"
            )
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            descriptor = -1
            value = stream.read().strip()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value.encode("utf-8")) < minimum_bytes:
        raise PublicAssistantConfigurationError(
            f"{label} credential is missing or too short"
        )
    return value


def validate_separate_roots(data_dir: Path, backup_dir: Path) -> tuple[Path, Path]:
    data = data_dir.resolve()
    backup = backup_dir.resolve()
    if data == backup or data.is_relative_to(backup) or backup.is_relative_to(data):
        raise PublicAssistantConfigurationError(
            "live data and encrypted backups require non-overlapping directories"
        )
    return data, backup


def validate_credential_paths(
    paths: tuple[Path, ...], data_dir: Path, backup_dir: Path
) -> tuple[Path, ...]:
    repository_root = Path(__file__).resolve().parents[2]
    resolved = tuple(path.resolve() for path in paths)
    if len(set(resolved)) != len(resolved):
        raise PublicAssistantConfigurationError(
            "credential files must use distinct paths"
        )
    protected_roots = (data_dir.resolve(), backup_dir.resolve(), repository_root)
    if any(
        path == root or path.is_relative_to(root)
        for path in resolved
        for root in protected_roots
    ):
        raise PublicAssistantConfigurationError(
            "credential files must be outside data, backup, and repository roots"
        )
    return resolved


@dataclass(frozen=True)
class RuntimeCredentials:
    """Ephemeral runtime secrets with a deliberately redacted representation."""

    bot_token: str
    pending_database_key: str
    public_database_key: str
    pseudonym_key: bytes

    def __repr__(self) -> str:
        return "RuntimeCredentials(<redacted>)"


@dataclass(frozen=True)
class PublicAssistantConfig:
    """Non-secret settings for the isolated long-running public process."""

    bot_token_file: Path
    pending_database_key_file: Path
    public_database_key_file: Path
    pseudonym_key_file: Path
    owner_id: int
    selected_sender_ids: frozenset[int]
    data_dir: Path
    backup_dir: Path
    privacy_url: str
    privacy_policy_version: str
    processing_authorization_version: str
    pending_ttl_seconds: int = 24 * 60 * 60
    reply_window_seconds: int = 24 * 60 * 60
    retention_seconds: int = PUBLISHED_CONTENT_RETENTION_SECONDS
    rate_limit_count: int = 20
    rate_limit_window_seconds: int = 60

    def load_runtime_credentials(self) -> RuntimeCredentials:
        data, backup = validate_separate_roots(self.data_dir, self.backup_dir)
        validate_credential_paths(
            (
                self.bot_token_file,
                self.pending_database_key_file,
                self.public_database_key_file,
                self.pseudonym_key_file,
            ),
            data,
            backup,
        )
        token = read_credential(self.bot_token_file, "Telegram bot token")
        pending = read_credential(
            self.pending_database_key_file, "pending database key", minimum_bytes=32
        )
        public = read_credential(
            self.public_database_key_file, "public database key", minimum_bytes=32
        )
        pseudonym = read_credential(
            self.pseudonym_key_file, "pseudonym key", minimum_bytes=32
        ).encode("utf-8")
        material = {token.encode(), pending.encode(), public.encode(), pseudonym}
        if len(material) != 4:
            raise PublicAssistantConfigurationError(
                "runtime credential material must be distinct"
            )
        return RuntimeCredentials(token, pending, public, pseudonym)

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "PublicAssistantConfig":
        env = os.environ if environment is None else environment
        forbidden_secret_values = {
            "PUBLIC_ASSISTANT_BOT_TOKEN",
            "PUBLIC_ASSISTANT_PENDING_DATABASE_KEY",
            "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY",
            "PUBLIC_ASSISTANT_BACKUP_DATABASE_KEY",
            "PUBLIC_ASSISTANT_PSEUDONYM_KEY",
        }
        if any(env.get(name, "").strip() for name in forbidden_secret_values):
            raise PublicAssistantConfigurationError(
                "credential values are forbidden in environment variables; use files"
            )
        sender_text = _required(env, "PUBLIC_ASSISTANT_SELECTED_SENDERS")
        try:
            selected = frozenset(
                int(item.strip()) for item in sender_text.split(",") if item.strip()
            )
        except ValueError as exc:
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_SELECTED_SENDERS must contain numeric IDs"
            ) from exc
        if not selected or any(sender <= 0 for sender in selected):
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_SELECTED_SENDERS must contain positive numeric IDs"
            )
        owner_id = _positive_int(env, "PUBLIC_ASSISTANT_OWNER_ID")
        if owner_id in selected:
            raise PublicAssistantConfigurationError(
                "the owner cannot be included in selected senders"
            )
        privacy_url = _required(env, "PUBLIC_ASSISTANT_PRIVACY_URL")
        if not privacy_url.startswith("https://"):
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_PRIVACY_URL must use HTTPS"
            )
        data, backup = validate_separate_roots(
            Path(_required(env, "PUBLIC_ASSISTANT_DATA_DIR")),
            Path(_required(env, "PUBLIC_ASSISTANT_BACKUP_DIR")),
        )
        credential_paths = validate_credential_paths(
            (
                _credential_path(env, "PUBLIC_ASSISTANT_BOT_TOKEN_FILE"),
                _credential_path(env, "PUBLIC_ASSISTANT_PENDING_DATABASE_KEY_FILE"),
                _credential_path(env, "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY_FILE"),
                _credential_path(env, "PUBLIC_ASSISTANT_PSEUDONYM_KEY_FILE"),
            ),
            data,
            backup,
        )
        return cls(
            bot_token_file=credential_paths[0],
            pending_database_key_file=credential_paths[1],
            public_database_key_file=credential_paths[2],
            pseudonym_key_file=credential_paths[3],
            owner_id=owner_id,
            selected_sender_ids=selected,
            data_dir=data,
            backup_dir=backup,
            privacy_url=privacy_url,
            privacy_policy_version=_required(
                env, "PUBLIC_ASSISTANT_PRIVACY_POLICY_VERSION"
            ),
            processing_authorization_version=_required(
                env, "PUBLIC_ASSISTANT_PROCESSING_AUTHORIZATION_VERSION"
            ),
        )


@dataclass(frozen=True)
class BackupConfig:
    """Separate maintenance-process settings; never loaded by polling."""

    data_dir: Path
    backup_dir: Path
    public_database_key_file: Path
    backup_database_key_file: Path
    backup_retention_seconds: int = PUBLISHED_CONTENT_RETENTION_SECONDS

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "BackupConfig":
        env = os.environ if environment is None else environment
        if env.get("PUBLIC_ASSISTANT_BACKUP_DATABASE_KEY", "").strip():
            raise PublicAssistantConfigurationError(
                "credential values are forbidden in environment variables; use files"
            )
        data, backup = validate_separate_roots(
            Path(_required(env, "PUBLIC_ASSISTANT_DATA_DIR")),
            Path(_required(env, "PUBLIC_ASSISTANT_BACKUP_DIR")),
        )
        credential_paths = validate_credential_paths(
            (
                _credential_path(env, "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY_FILE"),
                _credential_path(env, "PUBLIC_ASSISTANT_BACKUP_DATABASE_KEY_FILE"),
            ),
            data,
            backup,
        )
        retention = _positive_int(env, "PUBLIC_ASSISTANT_BACKUP_RETENTION_SECONDS")
        if retention > PUBLISHED_CONTENT_RETENTION_SECONDS:
            raise PublicAssistantConfigurationError(
                "backup retention cannot exceed the published content retention"
            )
        return cls(
            data_dir=data,
            backup_dir=backup,
            public_database_key_file=credential_paths[0],
            backup_database_key_file=credential_paths[1],
            backup_retention_seconds=retention,
        )


@dataclass(frozen=True)
class Unit2Config:
    """Unit 2 model, Inbox, alert, and retention limits."""

    openai_api_key_file: Path
    model: str
    owner_alert_chat_id: int
    timeout_seconds: float
    max_output_tokens: int
    max_context_items: int
    max_context_characters: int
    daily_call_limit: int
    daily_input_token_limit: int
    daily_output_token_limit: int
    daily_cost_microusd_limit: int
    input_microusd_per_million: int
    output_microusd_per_million: int
    concurrency_limit: int
    backup_retention_seconds: int

    def read_openai_api_key(self) -> str:
        return read_credential(self.openai_api_key_file, "OpenAI API key")

    @classmethod
    def from_environment(
        cls,
        base: PublicAssistantConfig,
        environment: Mapping[str, str] | None = None,
    ) -> "Unit2Config":
        env = os.environ if environment is None else environment
        if env.get("PUBLIC_ASSISTANT_OPENAI_API_KEY", "").strip():
            raise PublicAssistantConfigurationError(
                "OpenAI credential values are forbidden in environment variables; use files"
            )
        path = _credential_path(env, "PUBLIC_ASSISTANT_OPENAI_API_KEY_FILE")
        validate_credential_paths(
            (
                base.bot_token_file,
                base.pending_database_key_file,
                base.public_database_key_file,
                base.pseudonym_key_file,
                path,
            ),
            base.data_dir,
            base.backup_dir,
        )
        retention = _positive_int(env, "PUBLIC_ASSISTANT_BACKUP_RETENTION_SECONDS")
        if retention > base.retention_seconds:
            raise PublicAssistantConfigurationError(
                "backup retention cannot exceed the published content retention"
            )
        owner_alert_chat_id = _positive_int(env, "PUBLIC_ASSISTANT_OWNER_ALERT_CHAT_ID")
        if owner_alert_chat_id != base.owner_id:
            raise PublicAssistantConfigurationError(
                "owner alert chat must be the configured owner"
            )
        return cls(
            openai_api_key_file=path,
            model=_required(env, "PUBLIC_ASSISTANT_OPENAI_MODEL"),
            owner_alert_chat_id=owner_alert_chat_id,
            timeout_seconds=_positive_float(
                env, "PUBLIC_ASSISTANT_MODEL_TIMEOUT_SECONDS"
            ),
            max_output_tokens=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_MAX_OUTPUT_TOKENS"
            ),
            max_context_items=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_MAX_CONTEXT_ITEMS"
            ),
            max_context_characters=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_MAX_CONTEXT_CHARACTERS"
            ),
            daily_call_limit=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_DAILY_CALL_LIMIT"
            ),
            daily_input_token_limit=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_DAILY_INPUT_TOKEN_LIMIT"
            ),
            daily_output_token_limit=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_DAILY_OUTPUT_TOKEN_LIMIT"
            ),
            daily_cost_microusd_limit=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_DAILY_COST_MICROUSD_LIMIT"
            ),
            input_microusd_per_million=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_INPUT_MICROUSD_PER_MILLION"
            ),
            output_microusd_per_million=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_OUTPUT_MICROUSD_PER_MILLION"
            ),
            concurrency_limit=_positive_int(
                env, "PUBLIC_ASSISTANT_MODEL_CONCURRENCY_LIMIT"
            ),
            backup_retention_seconds=retention,
        )


@dataclass(frozen=True)
class Unit3Config:
    """Optional mock-only Gate client boundary; disabled unless explicit."""

    enabled: bool = False
    socket_path: Path | None = None

    @classmethod
    def from_environment(
        cls,
        base: PublicAssistantConfig,
        environment: Mapping[str, str] | None = None,
    ) -> "Unit3Config":
        env = os.environ if environment is None else environment
        raw_enabled = env.get("PUBLIC_ASSISTANT_POLICY_GATE_ENABLED", "false")
        normalized = raw_enabled.strip().casefold()
        if normalized not in {"true", "false"}:
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_POLICY_GATE_ENABLED must be true or false"
            )
        if normalized == "false":
            if env.get("PUBLIC_ASSISTANT_POLICY_GATE_SOCKET_PATH", "").strip():
                raise PublicAssistantConfigurationError(
                    "Policy Gate socket requires the Unit 3 boundary to be enabled"
                )
            return cls()
        socket_path = Path(_required(env, "PUBLIC_ASSISTANT_POLICY_GATE_SOCKET_PATH"))
        if not socket_path.is_absolute():
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_POLICY_GATE_SOCKET_PATH must be absolute"
            )
        socket_path = socket_path.resolve(strict=False)
        if socket_path == base.data_dir or socket_path.is_relative_to(base.data_dir):
            raise PublicAssistantConfigurationError(
                "Policy Gate socket must stay outside public data"
            )
        return cls(True, socket_path)
