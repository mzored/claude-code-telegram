"""Small domain contract between Telegram ingress and the Unit 1 core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class DeliveryState(str, Enum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    DELIVERY_UNCERTAIN = "delivery_uncertain"
    DEFINITE_FAILURE = "definite_failure"
    RETRY_PENDING = "retry_pending"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ConnectionObservation:
    connection_id: str
    owner_id: int
    enabled: bool
    can_reply: bool | None
    observed_at: datetime


@dataclass(frozen=True)
class InboundMessage:
    connection_id: str
    conversation_id: int
    sender_id: int
    message_id: int
    update_id: int
    text: str
    sent_at: datetime
    chat_type: str = "private"
    edited_at: datetime | None = None


@dataclass(frozen=True)
class DeleteNotice:
    connection_id: str
    conversation_id: int
    message_ids: tuple[int, ...]
    update_id: int
    chat_type: str = "private"


@dataclass(frozen=True)
class OwnerMessage:
    connection_id: str
    conversation_id: int
    owner_id: int
    update_id: int
    message_id: int
    sender_business_bot_id: int | None
    chat_type: str = "private"
    is_from_offline: bool = False


@dataclass(frozen=True)
class ReplyRecord:
    reply_id: str
    connection_id: str
    conversation_id: int
    text: str
    keyboard_json: str
    state: DeliveryState
    inbound_sent_at: int
    next_attempt_at: int | None = None


@dataclass(frozen=True)
class ProcessingResult:
    outcome: str
    reply: ReplyRecord | None = None


@dataclass(frozen=True)
class ControlRecord:
    control_id: str
    action: str
    connection_id: str
    conversation_id: int
    sender_id: int
    subject_ref: str
    pending_key: str | None
    privacy_policy_version: str
    processing_authorization_version: str
    expires_at: int
    consumed_at: int | None
    origin_reply_id: str | None
    origin_message_id: int | None
