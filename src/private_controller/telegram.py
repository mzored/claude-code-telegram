"""Trusted Telegram-envelope normalization for private run origins."""

from __future__ import annotations

import hashlib
from typing import Any

from src.private_controller.origin import RunSource, RunTrigger


def telegram_run_trigger(update: Any, *, resumed_session: bool = False) -> RunTrigger:
    """Build provenance from Telegram objects, never from message text."""

    message = getattr(update, "effective_message", None)
    actor = getattr(update, "effective_user", None)
    chat = getattr(update, "effective_chat", None)
    if actor is None or chat is None or message is None:
        raise ValueError("fresh Telegram envelope is incomplete")
    forwarded = bool(
        getattr(message, "forward_origin", None)
        or getattr(message, "forward_date", None)
    )
    return RunTrigger(
        source=RunSource.TELEGRAM,
        actor_id=int(actor.id),
        chat_id=int(chat.id),
        update_id=int(update.update_id),
        message_id=int(message.message_id),
        fresh=True,
        forwarded=forwarded,
        resumed_session=resumed_session,
    )


def telegram_callback_run_trigger(
    query: Any, *, resumed_session: bool = False
) -> RunTrigger:
    """Build callback provenance without pretending it is a message update."""

    message = getattr(query, "message", None)
    actor = getattr(query, "from_user", None)
    chat = None if message is None else getattr(message, "chat", None)
    query_id = getattr(query, "id", None)
    if (
        actor is None
        or chat is None
        or message is None
        or not isinstance(query_id, str)
    ):
        raise ValueError("fresh Telegram callback envelope is incomplete")
    callback_update_id = (
        int.from_bytes(
            hashlib.sha256(query_id.encode("utf-8")).digest()[:8],
            "big",
            signed=False,
        )
        & ((1 << 63) - 1)
    ) or 1
    return RunTrigger(
        source=RunSource.TELEGRAM,
        actor_id=int(actor.id),
        chat_id=int(chat.id),
        update_id=callback_update_id,
        message_id=int(message.message_id),
        fresh=True,
        forwarded=bool(
            getattr(message, "forward_origin", None)
            or getattr(message, "forward_date", None)
        ),
        resumed_session=resumed_session,
    )
