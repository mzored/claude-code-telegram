"""Durable state for deterministic Telegram Business delivery unit 1."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.public_assistant.sqlcipher import SqlCipherDatabase
from src.public_assistant.types import (
    ConnectionObservation,
    ControlRecord,
    DeliveryState,
    InboundMessage,
    ReplyRecord,
)

PENDING_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_messages (
    message_key TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    update_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'authorized')),
    privacy_policy_version TEXT NOT NULL,
    processing_authorization_version TEXT NOT NULL,
    consent_control_id TEXT NOT NULL,
    decline_control_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_expiry
    ON pending_messages(state, expires_at);
"""

PUBLIC_SCHEMA = """
CREATE TABLE IF NOT EXISTS business_connections (
    connection_id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    can_reply INTEGER,
    observed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_state (
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    takeover_at INTEGER,
    PRIMARY KEY(connection_id, conversation_id)
);
CREATE TABLE IF NOT EXISTS privacy_state (
    subject_ref TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('revoked', 'erased')),
    changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS consents (
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    privacy_policy_version TEXT NOT NULL,
    processing_authorization_version TEXT NOT NULL,
    processors TEXT NOT NULL,
    purposes TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY(connection_id, conversation_id, sender_id)
);
CREATE TABLE IF NOT EXISTS controls (
    control_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL CHECK(action IN ('consent', 'decline', 'revoke', 'delete')),
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    pending_key TEXT,
    processing_authorization_version TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS processed_updates (
    update_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    connection_id TEXT,
    conversation_id INTEGER,
    sender_id INTEGER,
    subject_ref TEXT,
    message_id INTEGER,
    content_digest TEXT,
    outcome TEXT NOT NULL,
    reply_id TEXT,
    erased INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    message_key TEXT PRIMARY KEY,
    connection_id TEXT,
    conversation_id INTEGER,
    sender_id INTEGER,
    subject_ref TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    update_id INTEGER NOT NULL,
    body TEXT,
    created_at INTEGER NOT NULL,
    edited_at INTEGER,
    deleted_at INTEGER
);
CREATE TABLE IF NOT EXISTS transfer_receipts (
    message_key TEXT PRIMARY KEY,
    copied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS replies (
    reply_id TEXT PRIMARY KEY,
    source_update_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    connection_id TEXT,
    conversation_id INTEGER,
    subject_ref TEXT NOT NULL,
    text TEXT NOT NULL,
    keyboard_json TEXT NOT NULL,
    state TEXT NOT NULL,
    telegram_message_id INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(source_update_id, purpose)
);
CREATE TABLE IF NOT EXISTS rate_windows (
    subject_ref TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    request_count INTEGER NOT NULL,
    PRIMARY KEY(subject_ref, window_start)
);
"""

TRANSFER_STAGES = frozenset(
    {"before_copy", "after_copy", "after_receipt", "before_pending_delete"}
)


class TransferInterrupted(RuntimeError):
    """Test-only failure signal raised by an injected crash hook."""


def _row_value(row: Any, key: str) -> Any:
    return row[key]


class Unit1Store:
    """Coordinate encrypted pending and public stores without cross-DB commits."""

    def __init__(
        self,
        data_dir: Path,
        pending_key: str,
        public_key: str,
        backup_key: str,
        pseudonym_key: bytes,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.data_dir = data_dir
        self.backup_key = backup_key
        self.pseudonym_key = pseudonym_key
        self.clock = clock
        self.pending = SqlCipherDatabase(
            data_dir / "pending.db", pending_key, PENDING_SCHEMA
        )
        try:
            self.public = SqlCipherDatabase(
                data_dir / "public.db", public_key, PUBLIC_SCHEMA
            )
        except BaseException:
            self.pending.close()
            raise
        self.recover_sending_replies()
        self.recover_transfers()

    def now(self) -> int:
        return int(self.clock())

    def digest(self, namespace: str, value: str) -> str:
        return hmac.new(
            self.pseudonym_key,
            f"{namespace}:{value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def subject_ref(self, connection_id: str, chat_id: int, sender_id: int) -> str:
        return (
            "subject_"
            + self.digest("subject", f"{connection_id}:{chat_id}:{sender_id}")[:24]
        )

    def message_key(self, connection_id: str, chat_id: int, message_id: int) -> str:
        return (
            "message_"
            + self.digest("message", f"{connection_id}:{chat_id}:{message_id}")[:32]
        )

    def content_digest(self, body: str) -> str:
        return self.digest("body", body)

    def observe_connection(self, observation: ConnectionObservation) -> None:
        can_reply = (
            None if observation.can_reply is None else int(observation.can_reply)
        )
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO business_connections(
                    connection_id, owner_id, enabled, can_reply, observed_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(connection_id) DO UPDATE SET
                    owner_id=excluded.owner_id,
                    enabled=excluded.enabled,
                    can_reply=excluded.can_reply,
                    observed_at=excluded.observed_at
                WHERE excluded.observed_at >= business_connections.observed_at
                """,
                (
                    observation.connection_id,
                    observation.owner_id,
                    int(observation.enabled),
                    can_reply,
                    int(observation.observed_at.timestamp()),
                ),
            )

    def connection_can_reply(self, connection_id: str, owner_id: int) -> bool:
        row = self.public.execute(
            """
            SELECT owner_id, enabled, can_reply
            FROM business_connections WHERE connection_id = ?
            """,
            (connection_id,),
        ).fetchone()
        return bool(
            row is not None
            and _row_value(row, "owner_id") == owner_id
            and _row_value(row, "enabled") == 1
            and _row_value(row, "can_reply") == 1
        )

    def begin_update(
        self,
        message: InboundMessage,
        kind: str,
        outcome: str,
    ) -> tuple[bool, ReplyRecord | None]:
        subject_ref = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.public.transaction() as connection:
            existing = connection.execute(
                """
                SELECT reply_id, kind, connection_id, conversation_id, sender_id,
                       message_id, content_digest, outcome
                FROM processed_updates WHERE update_id = ?
                """,
                (message.update_id,),
            ).fetchone()
            if existing is not None:
                same_binding = bool(
                    _row_value(existing, "connection_id") == message.connection_id
                    and _row_value(existing, "conversation_id")
                    == message.conversation_id
                    and _row_value(existing, "sender_id") == message.sender_id
                    and _row_value(existing, "message_id") == message.message_id
                    and _row_value(existing, "content_digest")
                    == self.content_digest(message.text)
                    and _row_value(existing, "kind") == kind
                )
                if not same_binding:
                    return False, None
                reply_id = _row_value(existing, "reply_id")
                if reply_id:
                    return False, self.get_reply(reply_id)
                if _row_value(existing, "outcome") in {
                    "received",
                    "received_edit",
                }:
                    return True, None
                return False, None
            connection.execute(
                """
                INSERT INTO processed_updates(
                    update_id, kind, connection_id, conversation_id, sender_id,
                    subject_ref, message_id, content_digest, outcome, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.update_id,
                    kind,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject_ref,
                    message.message_id,
                    self.content_digest(message.text),
                    outcome,
                    self.now(),
                ),
            )
        return True, None

    def begin_non_message_update(
        self,
        *,
        update_id: int,
        kind: str,
        connection_id: str,
        conversation_id: int,
        outcome: str,
    ) -> bool:
        with self.public.transaction() as connection:
            existing = connection.execute(
                """
                SELECT kind, connection_id, conversation_id, outcome
                FROM processed_updates WHERE update_id = ?
                """,
                (update_id,),
            ).fetchone()
            if existing is not None:
                same_binding = bool(
                    _row_value(existing, "kind") == kind
                    and _row_value(existing, "connection_id") == connection_id
                    and _row_value(existing, "conversation_id") == conversation_id
                )
                if same_binding and _row_value(existing, "outcome") == "deleting":
                    return True
                return False
            connection.execute(
                """
                INSERT INTO processed_updates(
                    update_id, kind, connection_id, conversation_id,
                    outcome, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    update_id,
                    kind,
                    connection_id,
                    conversation_id,
                    outcome,
                    self.now(),
                ),
            )
        return True

    def set_update_outcome(
        self, update_id: int, outcome: str, reply_id: str | None = None
    ) -> None:
        with self.public.transaction() as connection:
            connection.execute(
                """
                UPDATE processed_updates SET outcome = ?, reply_id = ?
                WHERE update_id = ?
                """,
                (outcome, reply_id, update_id),
            )

    def rate_limit(self, subject_ref: str, *, limit: int, window_seconds: int) -> bool:
        now = self.now()
        window = now - (now % window_seconds)
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO rate_windows(subject_ref, window_start, request_count)
                VALUES (?, ?, 1)
                ON CONFLICT(subject_ref, window_start) DO UPDATE SET
                    request_count=request_count + 1
                """,
                (subject_ref, window),
            )
            row = connection.execute(
                """
                SELECT request_count FROM rate_windows
                WHERE subject_ref = ? AND window_start = ?
                """,
                (subject_ref, window),
            ).fetchone()
        return row is not None and _row_value(row, "request_count") <= limit

    def privacy_state(self, subject_ref: str) -> str | None:
        row = self.public.execute(
            "SELECT state FROM privacy_state WHERE subject_ref = ?", (subject_ref,)
        ).fetchone()
        return None if row is None else str(_row_value(row, "state"))

    def is_taken_over(self, connection_id: str, conversation_id: int) -> bool:
        row = self.public.execute(
            """
            SELECT takeover_at FROM chat_state
            WHERE connection_id = ? AND conversation_id = ?
            """,
            (connection_id, conversation_id),
        ).fetchone()
        return row is not None and _row_value(row, "takeover_at") is not None

    def record_takeover(
        self,
        connection_id: str,
        conversation_id: int,
        sender_id: int,
        update_id: int,
        message_id: int,
    ) -> bool:
        subject_ref = self.subject_ref(connection_id, conversation_id, sender_id)
        now = self.now()
        with self.public.transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM processed_updates WHERE update_id = ?", (update_id,)
            ).fetchone()
            if existing is not None:
                return False
            connection.execute(
                """
                INSERT INTO processed_updates(
                    update_id, kind, connection_id, conversation_id, sender_id,
                    subject_ref, message_id, outcome, created_at
                ) VALUES (?, 'owner_business_message', ?, ?, ?, ?, ?,
                          'owner_takeover', ?)
                """,
                (
                    update_id,
                    connection_id,
                    conversation_id,
                    sender_id,
                    subject_ref,
                    message_id,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO chat_state(
                    connection_id, conversation_id, sender_id, subject_ref, takeover_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(connection_id, conversation_id) DO UPDATE SET
                    sender_id=excluded.sender_id,
                    subject_ref=excluded.subject_ref,
                    takeover_at=excluded.takeover_at
                """,
                (connection_id, conversation_id, sender_id, subject_ref, now),
            )
            connection.execute(
                """
                UPDATE replies SET state = ?, updated_at = ?
                WHERE connection_id = ? AND conversation_id = ? AND state = ?
                """,
                (
                    DeliveryState.CANCELLED.value,
                    now,
                    connection_id,
                    conversation_id,
                    DeliveryState.PENDING.value,
                ),
            )
        return True

    def has_active_consent(
        self,
        connection_id: str,
        conversation_id: int,
        sender_id: int,
        processing_authorization_version: str,
    ) -> bool:
        subject_ref = self.subject_ref(connection_id, conversation_id, sender_id)
        if self.privacy_state(subject_ref) is not None:
            return False
        row = self.public.execute(
            """
            SELECT 1 FROM consents
            WHERE connection_id = ? AND conversation_id = ? AND sender_id = ?
              AND processing_authorization_version = ?
            """,
            (
                connection_id,
                conversation_id,
                sender_id,
                processing_authorization_version,
            ),
        ).fetchone()
        return row is not None

    def _new_control(
        self,
        *,
        action: str,
        message: InboundMessage,
        pending_key: str | None,
        processing_authorization_version: str,
        expires_at: int,
    ) -> tuple[str, str]:
        token = secrets.token_urlsafe(24)
        control_id = uuid.uuid4().hex
        token_hash = self.digest("control", token)
        subject_ref = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO controls(
                    control_id, token_hash, action, connection_id, conversation_id,
                    sender_id, subject_ref, pending_key,
                    processing_authorization_version, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    control_id,
                    token_hash,
                    action,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject_ref,
                    pending_key,
                    processing_authorization_version,
                    expires_at,
                ),
            )
        return control_id, f"pa:{token}"

    def stage_pending(
        self,
        message: InboundMessage,
        *,
        privacy_policy_version: str,
        processing_authorization_version: str,
        ttl_seconds: int,
    ) -> tuple[str, str, str]:
        message_key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        expires_at = self.now() + ttl_seconds
        consent_id, consent_token = self._new_control(
            action="consent",
            message=message,
            pending_key=message_key,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires_at,
        )
        decline_id, decline_token = self._new_control(
            action="decline",
            message=message,
            pending_key=message_key,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires_at,
        )
        subject_ref = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.pending.transaction() as connection:
            connection.execute(
                """
                INSERT INTO pending_messages(
                    message_key, connection_id, conversation_id, sender_id,
                    subject_ref, message_id, update_id, body, content_digest,
                    created_at, expires_at, state, privacy_policy_version,
                    processing_authorization_version, consent_control_id,
                    decline_control_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                ON CONFLICT(message_key) DO UPDATE SET
                    update_id=excluded.update_id,
                    body=excluded.body,
                    content_digest=excluded.content_digest,
                    expires_at=excluded.expires_at,
                    privacy_policy_version=excluded.privacy_policy_version,
                    processing_authorization_version=
                        excluded.processing_authorization_version,
                    consent_control_id=excluded.consent_control_id,
                    decline_control_id=excluded.decline_control_id
                """,
                (
                    message_key,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject_ref,
                    message.message_id,
                    message.update_id,
                    message.text,
                    self.content_digest(message.text),
                    self.now(),
                    expires_at,
                    privacy_policy_version,
                    processing_authorization_version,
                    consent_id,
                    decline_id,
                ),
            )
        return message_key, consent_token, decline_token

    def create_maintenance_controls(
        self,
        message: InboundMessage,
        processing_authorization_version: str,
        ttl_seconds: int,
    ) -> tuple[str, str]:
        expires_at = self.now() + ttl_seconds
        _, revoke_token = self._new_control(
            action="revoke",
            message=message,
            pending_key=None,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires_at,
        )
        _, delete_token = self._new_control(
            action="delete",
            message=message,
            pending_key=None,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires_at,
        )
        return revoke_token, delete_token

    def resolve_control(
        self, token: str, actor_id: int, conversation_id: int
    ) -> ControlRecord | None:
        if not token.startswith("pa:"):
            return None
        token_hash = self.digest("control", token[3:])
        row = self.public.execute(
            "SELECT * FROM controls WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return None
        if (
            _row_value(row, "sender_id") != actor_id
            or _row_value(row, "conversation_id") != conversation_id
        ):
            return None
        return ControlRecord(
            control_id=str(_row_value(row, "control_id")),
            action=str(_row_value(row, "action")),
            connection_id=str(_row_value(row, "connection_id")),
            conversation_id=int(_row_value(row, "conversation_id")),
            sender_id=int(_row_value(row, "sender_id")),
            subject_ref=str(_row_value(row, "subject_ref")),
            pending_key=_row_value(row, "pending_key"),
            processing_authorization_version=str(
                _row_value(row, "processing_authorization_version")
            ),
            expires_at=int(_row_value(row, "expires_at")),
            consumed_at=_row_value(row, "consumed_at"),
        )

    def _consume_controls(self, control_ids: tuple[str, ...], when: int) -> None:
        placeholders = ",".join("?" for _ in control_ids)
        with self.public.transaction() as connection:
            connection.execute(
                f"UPDATE controls SET consumed_at = COALESCE(consumed_at, ?) "
                f"WHERE control_id IN ({placeholders})",
                (when, *control_ids),
            )

    def accept_consent(
        self,
        control: ControlRecord,
        *,
        expected_processing_version: str,
        crash_hook: Callable[[str], None] | None = None,
    ) -> str:
        now = self.now()
        if control.action != "consent":
            return "invalid"
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= now:
            return "expired"
        if control.processing_authorization_version != expected_processing_version:
            return "stale_version"
        if control.pending_key is None:
            return "invalid"
        with self.pending.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM pending_messages WHERE message_key = ?",
                (control.pending_key,),
            ).fetchone()
            if row is None:
                return "replayed"
            if _row_value(row, "expires_at") <= now:
                connection.execute(
                    "DELETE FROM pending_messages WHERE message_key = ?",
                    (control.pending_key,),
                )
                return "expired"
            if (
                _row_value(row, "sender_id") != control.sender_id
                or _row_value(row, "conversation_id") != control.conversation_id
                or _row_value(row, "connection_id") != control.connection_id
                or _row_value(row, "consent_control_id") != control.control_id
            ):
                return "invalid"
            connection.execute(
                "UPDATE pending_messages SET state = 'authorized' WHERE message_key = ?",
                (control.pending_key,),
            )
        self._finish_transfer(control.pending_key, crash_hook=crash_hook)
        return "accepted"

    def _finish_transfer(
        self,
        message_key: str,
        *,
        crash_hook: Callable[[str], None] | None = None,
    ) -> None:
        row = self.pending.execute(
            "SELECT * FROM pending_messages WHERE message_key = ? AND state = 'authorized'",
            (message_key,),
        ).fetchone()
        if row is None:
            return
        consent_id = str(_row_value(row, "consent_control_id"))
        decline_id = str(_row_value(row, "decline_control_id"))
        now = self.now()
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO consents(
                    connection_id, conversation_id, sender_id, subject_ref,
                    privacy_policy_version, processing_authorization_version,
                    processors, purposes, granted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(connection_id, conversation_id, sender_id) DO UPDATE SET
                    privacy_policy_version=excluded.privacy_policy_version,
                    processing_authorization_version=
                        excluded.processing_authorization_version,
                    processors=excluded.processors,
                    purposes=excluded.purposes,
                    granted_at=excluded.granted_at
                """,
                (
                    _row_value(row, "connection_id"),
                    _row_value(row, "conversation_id"),
                    _row_value(row, "sender_id"),
                    _row_value(row, "subject_ref"),
                    _row_value(row, "privacy_policy_version"),
                    _row_value(row, "processing_authorization_version"),
                    json.dumps(["OpenAI", "Google Calendar", "Todoist"]),
                    json.dumps(
                        ["assistant replies", "meeting actions", "external tasks"]
                    ),
                    now,
                ),
            )
            connection.execute(
                "UPDATE controls SET consumed_at = COALESCE(consumed_at, ?) "
                "WHERE control_id IN (?, ?)",
                (now, consent_id, decline_id),
            )
        if crash_hook is not None:
            crash_hook("before_copy")
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO messages(
                    message_key, connection_id, conversation_id, sender_id,
                    subject_ref, message_id, update_id, body, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(message_key) DO UPDATE SET
                    body=excluded.body,
                    update_id=excluded.update_id
                """,
                (
                    message_key,
                    _row_value(row, "connection_id"),
                    _row_value(row, "conversation_id"),
                    _row_value(row, "sender_id"),
                    _row_value(row, "subject_ref"),
                    _row_value(row, "message_id"),
                    _row_value(row, "update_id"),
                    _row_value(row, "body"),
                    _row_value(row, "created_at"),
                ),
            )
        if crash_hook is not None:
            crash_hook("after_copy")
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO transfer_receipts(message_key, copied_at)
                VALUES (?, ?)
                """,
                (message_key, now),
            )
        if crash_hook is not None:
            crash_hook("after_receipt")
            crash_hook("before_pending_delete")
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE message_key = ?", (message_key,)
            )

    def recover_transfers(self) -> int:
        rows = self.pending.execute(
            "SELECT message_key FROM pending_messages WHERE state = 'authorized'"
        ).fetchall()
        for row in rows:
            self._finish_transfer(str(_row_value(row, "message_key")))
        return len(rows)

    def decline(self, control: ControlRecord) -> str:
        now = self.now()
        if control.action != "decline":
            return "invalid"
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= now:
            return "expired"
        if control.pending_key is None:
            return "invalid"
        row = self.pending.execute(
            "SELECT consent_control_id, decline_control_id FROM pending_messages "
            "WHERE message_key = ?",
            (control.pending_key,),
        ).fetchone()
        if row is None:
            return "replayed"
        self._consume_controls(
            (
                str(_row_value(row, "consent_control_id")),
                str(_row_value(row, "decline_control_id")),
            ),
            now,
        )
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE message_key = ?",
                (control.pending_key,),
            )
        return "declined"

    def expire_pending(self) -> int:
        now = self.now()
        with self.pending.transaction() as connection:
            rows = connection.execute(
                """
                SELECT consent_control_id, decline_control_id
                FROM pending_messages WHERE state = 'pending' AND expires_at <= ?
                """,
                (now,),
            ).fetchall()
            connection.execute(
                "DELETE FROM pending_messages "
                "WHERE state = 'pending' AND expires_at <= ?",
                (now,),
            )
        for row in rows:
            self._consume_controls(
                (
                    str(_row_value(row, "consent_control_id")),
                    str(_row_value(row, "decline_control_id")),
                ),
                now,
            )
        return len(rows)

    def store_consented_message(self, message: InboundMessage) -> None:
        key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        subject_ref = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO messages(
                    message_key, connection_id, conversation_id, sender_id,
                    subject_ref, message_id, update_id, body, created_at, edited_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(message_key) DO UPDATE SET
                    update_id=excluded.update_id,
                    body=excluded.body,
                    edited_at=excluded.edited_at,
                    deleted_at=NULL
                """,
                (
                    key,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject_ref,
                    message.message_id,
                    message.update_id,
                    message.text,
                    int(message.sent_at.timestamp()),
                    (
                        int(message.edited_at.timestamp())
                        if message.edited_at is not None
                        else None
                    ),
                ),
            )

    def edit_pending(self, message: InboundMessage) -> bool:
        key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        with self.pending.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE pending_messages SET body = ?, content_digest = ?, update_id = ?
                WHERE message_key = ? AND state = 'pending'
                """,
                (
                    message.text,
                    self.content_digest(message.text),
                    message.update_id,
                    key,
                ),
            )
        return int(cursor.rowcount) == 1

    def delete_messages(
        self,
        connection_id: str,
        conversation_id: int,
        message_ids: tuple[int, ...],
    ) -> int:
        deleted = 0
        now = self.now()
        for message_id in message_ids:
            key = self.message_key(connection_id, conversation_id, message_id)
            with self.pending.transaction() as connection:
                pending = connection.execute(
                    "SELECT consent_control_id, decline_control_id, update_id "
                    "FROM pending_messages "
                    "WHERE message_key = ?",
                    (key,),
                ).fetchone()
                cursor = connection.execute(
                    "DELETE FROM pending_messages WHERE message_key = ?", (key,)
                )
                deleted += max(cursor.rowcount, 0)
            if pending is not None:
                self._consume_controls(
                    (
                        str(_row_value(pending, "consent_control_id")),
                        str(_row_value(pending, "decline_control_id")),
                    ),
                    now,
                )
                with self.public.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE replies SET state = ?, updated_at = ?
                        WHERE source_update_id = ? AND state = ?
                        """,
                        (
                            DeliveryState.CANCELLED.value,
                            now,
                            _row_value(pending, "update_id"),
                            DeliveryState.PENDING.value,
                        ),
                    )
            with self.public.transaction() as connection:
                cursor = connection.execute(
                    """
                    UPDATE messages SET body = NULL, deleted_at = ?
                    WHERE message_key = ? AND deleted_at IS NULL
                    """,
                    (now, key),
                )
                deleted += max(cursor.rowcount, 0)
                source = connection.execute(
                    "SELECT update_id FROM messages WHERE message_key = ?", (key,)
                ).fetchone()
                if source is not None:
                    connection.execute(
                        """
                        UPDATE replies SET state = ?, updated_at = ?
                        WHERE source_update_id = ? AND state = ?
                        """,
                        (
                            DeliveryState.CANCELLED.value,
                            now,
                            _row_value(source, "update_id"),
                            DeliveryState.PENDING.value,
                        ),
                    )
        return deleted

    def create_reply(
        self,
        message: InboundMessage,
        purpose: str,
        text: str,
        keyboard: list[list[dict[str, str]]],
    ) -> ReplyRecord:
        reply_id = uuid.uuid5(
            uuid.UUID("91c1e00b-d0b9-4abe-b377-5bd1f7dc08b1"),
            f"{message.update_id}:{purpose}",
        ).hex
        now = self.now()
        subject_ref = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        keyboard_json = json.dumps(keyboard, separators=(",", ":"), sort_keys=True)
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO replies(
                    reply_id, source_update_id, purpose, connection_id,
                    conversation_id, subject_ref, text, keyboard_json,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reply_id,
                    message.update_id,
                    purpose,
                    message.connection_id,
                    message.conversation_id,
                    subject_ref,
                    text,
                    keyboard_json,
                    DeliveryState.PENDING.value,
                    now,
                    now,
                ),
            )
            connection.execute(
                "UPDATE processed_updates SET reply_id = ? WHERE update_id = ?",
                (reply_id, message.update_id),
            )
        record = self.get_reply(reply_id)
        if record is None:
            raise RuntimeError("durable reply was not created")
        return record

    def get_reply(self, reply_id: str) -> ReplyRecord | None:
        row = self.public.execute(
            "SELECT * FROM replies WHERE reply_id = ?", (reply_id,)
        ).fetchone()
        if row is None:
            return None
        if (
            _row_value(row, "connection_id") is None
            or _row_value(row, "conversation_id") is None
        ):
            return None
        return ReplyRecord(
            reply_id=str(_row_value(row, "reply_id")),
            connection_id=str(_row_value(row, "connection_id")),
            conversation_id=int(_row_value(row, "conversation_id")),
            text=str(_row_value(row, "text")),
            keyboard_json=str(_row_value(row, "keyboard_json")),
            state=DeliveryState(str(_row_value(row, "state"))),
        )

    def mark_reply_sending(self, reply_id: str) -> bool:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE replies SET state = ?, updated_at = ?
                WHERE reply_id = ? AND state = ?
                """,
                (
                    DeliveryState.SENDING.value,
                    self.now(),
                    reply_id,
                    DeliveryState.PENDING.value,
                ),
            )
        return int(cursor.rowcount) == 1

    def reply_allowed(
        self, reply_id: str, *, owner_id: int, reply_window_seconds: int
    ) -> bool:
        """Recheck rights, takeover, and age immediately before Telegram I/O."""

        row = self.public.execute(
            """
            SELECT r.state, u.created_at, c.owner_id, c.enabled, c.can_reply,
                   s.takeover_at
            FROM replies r
            JOIN processed_updates u ON u.update_id = r.source_update_id
            LEFT JOIN business_connections c
              ON c.connection_id = r.connection_id
            LEFT JOIN chat_state s
              ON s.connection_id = r.connection_id
             AND s.conversation_id = r.conversation_id
            WHERE r.reply_id = ?
            """,
            (reply_id,),
        ).fetchone()
        return bool(
            row is not None
            and _row_value(row, "state") == DeliveryState.PENDING.value
            and _row_value(row, "owner_id") == owner_id
            and _row_value(row, "enabled") == 1
            and _row_value(row, "can_reply") == 1
            and _row_value(row, "takeover_at") is None
            and self.now() - int(_row_value(row, "created_at")) < reply_window_seconds
        )

    def finalize_reply(
        self,
        reply_id: str,
        state: DeliveryState,
        telegram_message_id: int | None = None,
    ) -> None:
        with self.public.transaction() as connection:
            connection.execute(
                """
                UPDATE replies
                SET state = ?, telegram_message_id = ?, updated_at = ?
                WHERE reply_id = ?
                """,
                (state.value, telegram_message_id, self.now(), reply_id),
            )

    def recover_sending_replies(self) -> int:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE replies SET state = ?, updated_at = ? WHERE state = ?
                """,
                (
                    DeliveryState.DELIVERY_UNCERTAIN.value,
                    self.now(),
                    DeliveryState.SENDING.value,
                ),
            )
        return max(int(cursor.rowcount), 0)

    def apply_privacy_control(self, control: ControlRecord) -> str:
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= self.now():
            return "expired"
        if control.action not in {"revoke", "delete"}:
            return "invalid"
        now = self.now()
        state = "revoked" if control.action == "revoke" else "erased"
        with self.public.transaction() as connection:
            connection.execute(
                "UPDATE controls SET consumed_at = ? WHERE control_id = ?",
                (now, control.control_id),
            )
            connection.execute(
                """
                INSERT INTO privacy_state(subject_ref, state, changed_at)
                VALUES (?, ?, ?)
                ON CONFLICT(subject_ref) DO UPDATE SET
                    state=excluded.state, changed_at=excluded.changed_at
                """,
                (control.subject_ref, state, now),
            )
            connection.execute(
                "DELETE FROM consents WHERE subject_ref = ?", (control.subject_ref,)
            )
            connection.execute(
                "DELETE FROM controls WHERE subject_ref = ?", (control.subject_ref,)
            )
            connection.execute(
                "DELETE FROM chat_state WHERE subject_ref = ?", (control.subject_ref,)
            )
            connection.execute(
                """
                UPDATE replies SET connection_id = NULL, conversation_id = NULL,
                    text = '', keyboard_json = '[]', state = ?, updated_at = ?
                WHERE subject_ref = ?
                """,
                (DeliveryState.CANCELLED.value, now, control.subject_ref),
            )
            connection.execute(
                """
                UPDATE processed_updates
                SET connection_id = NULL, conversation_id = NULL, sender_id = NULL,
                    content_digest = NULL, erased = 1
                WHERE subject_ref = ?
                """,
                (control.subject_ref,),
            )
            if state == "erased":
                connection.execute(
                    "DELETE FROM messages WHERE subject_ref = ?", (control.subject_ref,)
                )
            else:
                connection.execute(
                    """
                    UPDATE messages
                    SET connection_id = NULL, conversation_id = NULL, sender_id = NULL
                    WHERE subject_ref = ?
                    """,
                    (control.subject_ref,),
                )
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE subject_ref = ?",
                (control.subject_ref,),
            )
        return state

    def backup_public(self, destination: Path) -> None:
        self.public.encrypted_backup(destination, self.backup_key)

    def close(self) -> None:
        self.pending.close()
        self.public.close()

    def counts(self) -> dict[str, int]:
        return {
            "pending": int(
                self.pending.execute(
                    "SELECT count(*) FROM pending_messages"
                ).fetchone()[0]
            ),
            "messages": int(
                self.public.execute("SELECT count(*) FROM messages").fetchone()[0]
            ),
            "receipts": int(
                self.public.execute(
                    "SELECT count(*) FROM transfer_receipts"
                ).fetchone()[0]
            ),
        }
