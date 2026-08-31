"""Log helpers that make raw Telegram identifiers and bodies unrepresentable."""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Any


def pseudonym(key: bytes, namespace: str, value: int | str) -> str:
    """Return a stable, bounded reference without retaining the source value."""

    digest = hmac.new(
        key, f"{namespace}:{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{namespace}_{digest[:16]}"


@dataclass(frozen=True)
class PrivacyLog:
    """Emit state transitions using only derived references and fixed strings."""

    key: bytes
    logger: logging.Logger

    def event(
        self,
        event: str,
        *,
        connection_id: str | None = None,
        chat_id: int | None = None,
        sender_id: int | None = None,
        update_id: int | None = None,
        state: str | None = None,
    ) -> None:
        fields: dict[str, Any] = {"event": event}
        for namespace, value in (
            ("connection", connection_id),
            ("chat", chat_id),
            ("sender", sender_id),
            ("update", update_id),
        ):
            if value is not None:
                fields[f"{namespace}_ref"] = pseudonym(self.key, namespace, value)
        if state is not None:
            fields["state"] = state
        self.logger.info("public_assistant_event", extra={"public_fields": fields})
