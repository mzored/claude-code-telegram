"""Configuration for the isolated public-assistant process."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class PublicAssistantConfigurationError(ValueError):
    """Raised before polling when required isolation settings are invalid."""


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


@dataclass(frozen=True)
class PublicAssistantConfig:
    """Validated settings that do not load the private bot configuration."""

    bot_token: str
    owner_id: int
    selected_sender_ids: frozenset[int]
    data_dir: Path
    backup_dir: Path
    pending_database_key: str
    public_database_key: str
    backup_database_key: str
    pseudonym_key: bytes
    privacy_url: str
    privacy_policy_version: str
    processing_authorization_version: str
    pending_ttl_seconds: int = 24 * 60 * 60
    reply_window_seconds: int = 24 * 60 * 60
    rate_limit_count: int = 20
    rate_limit_window_seconds: int = 60

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "PublicAssistantConfig":
        """Read only public-assistant variables and fail before opening a store."""

        env = os.environ if environment is None else environment
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

        keys = {
            "pending": _required(env, "PUBLIC_ASSISTANT_PENDING_DATABASE_KEY"),
            "public": _required(env, "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY"),
            "backup": _required(env, "PUBLIC_ASSISTANT_BACKUP_DATABASE_KEY"),
        }
        if any(len(key.encode("utf-8")) < 32 for key in keys.values()):
            raise PublicAssistantConfigurationError(
                "database keys must each contain at least 32 bytes"
            )
        if len(set(keys.values())) != len(keys):
            raise PublicAssistantConfigurationError(
                "pending, public, and backup database keys must be distinct"
            )

        pseudonym = _required(env, "PUBLIC_ASSISTANT_PSEUDONYM_KEY").encode()
        if len(pseudonym) < 32:
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_PSEUDONYM_KEY must contain at least 32 bytes"
            )

        privacy_url = _required(env, "PUBLIC_ASSISTANT_PRIVACY_URL")
        if not privacy_url.startswith("https://"):
            raise PublicAssistantConfigurationError(
                "PUBLIC_ASSISTANT_PRIVACY_URL must use HTTPS"
            )

        data_dir = Path(_required(env, "PUBLIC_ASSISTANT_DATA_DIR")).resolve()
        backup_dir = Path(_required(env, "PUBLIC_ASSISTANT_BACKUP_DIR")).resolve()
        if data_dir == backup_dir:
            raise PublicAssistantConfigurationError(
                "live data and encrypted backups require separate directories"
            )

        return cls(
            bot_token=_required(env, "PUBLIC_ASSISTANT_BOT_TOKEN"),
            owner_id=owner_id,
            selected_sender_ids=selected,
            data_dir=data_dir,
            backup_dir=backup_dir,
            pending_database_key=keys["pending"],
            public_database_key=keys["public"],
            backup_database_key=keys["backup"],
            pseudonym_key=pseudonym,
            privacy_url=privacy_url,
            privacy_policy_version=_required(
                env, "PUBLIC_ASSISTANT_PRIVACY_POLICY_VERSION"
            ),
            processing_authorization_version=_required(
                env, "PUBLIC_ASSISTANT_PROCESSING_AUTHORIZATION_VERSION"
            ),
        )
