"""Encrypted durable state for public-assistant delivery unit 1."""

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
    source_update_id INTEGER NOT NULL,
    last_update_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    sent_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'authorized')),
    privacy_policy_version TEXT NOT NULL,
    processing_authorization_version TEXT NOT NULL,
    consent_control_id TEXT NOT NULL,
    decline_control_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_expiry ON pending_messages(state, expires_at);
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
    chat_key TEXT PRIMARY KEY,
    takeover_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS privacy_state (
    subject_ref TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('revoked', 'erased')),
    changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS restrictive_tombstones (
    message_key TEXT PRIMARY KEY,
    subject_ref TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('declined', 'deleted')),
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
    action TEXT NOT NULL CHECK(action IN
        ('consent', 'reconsent', 'decline', 'revoke', 'delete')),
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    pending_key TEXT,
    privacy_policy_version TEXT NOT NULL,
    processing_authorization_version TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    origin_reply_id TEXT,
    origin_message_id INTEGER
);
CREATE TABLE IF NOT EXISTS processed_updates (
    update_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    connection_id TEXT,
    conversation_id INTEGER,
    sender_id INTEGER,
    subject_ref TEXT,
    message_id INTEGER,
    message_key TEXT,
    content_digest TEXT,
    inbound_sent_at INTEGER,
    outcome TEXT NOT NULL,
    reply_id TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    message_key TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    source_update_id INTEGER NOT NULL,
    last_update_id INTEGER NOT NULL,
    body TEXT,
    sent_at INTEGER NOT NULL,
    content_updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    deleted_at INTEGER
);
CREATE TABLE IF NOT EXISTS transfer_receipts (
    message_key TEXT PRIMARY KEY,
    copied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deletion_links (
    update_id INTEGER NOT NULL,
    message_key TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    PRIMARY KEY(update_id, message_key)
);
CREATE TABLE IF NOT EXISTS replies (
    reply_id TEXT PRIMARY KEY,
    source_update_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    text TEXT NOT NULL,
    keyboard_json TEXT NOT NULL,
    state TEXT NOT NULL,
    telegram_message_id INTEGER,
    inbound_sent_at INTEGER NOT NULL,
    next_attempt_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(source_update_id, purpose)
);
CREATE TABLE IF NOT EXISTS rate_admissions (
    update_id INTEGER PRIMARY KEY,
    subject_ref TEXT NOT NULL,
    window_start INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS poll_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    next_update_id INTEGER
);
INSERT OR IGNORE INTO poll_state(singleton, next_update_id) VALUES (1, NULL);
"""

TRANSFER_STAGES = frozenset(
    {"before_copy", "after_copy", "after_receipt", "before_pending_delete"}
)
RESTRICTIVE_STAGES = frozenset({"after_tombstone", "before_pending_delete"})
AUTHORIZED_PROCESSORS = ("OpenAI", "Google Calendar", "Todoist")
AUTHORIZED_PURPOSES = (
    "assistant replies",
    "meeting actions",
    "external tasks",
)


class TransferInterrupted(RuntimeError):
    """Failure signal used by crash-boundary integration tests."""


def _value(row: Any, key: str) -> Any:
    return row[key]


class Unit1Store:
    """Coordinate encrypted pending/public stores with recovery invariants."""

    def __init__(
        self,
        data_dir: Path,
        pending_key: str,
        public_key: str,
        pseudonym_key: bytes,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.data_dir = data_dir
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
        self.recover_restrictions()
        self.recover_transfers()

    def now(self) -> int:
        return int(self.clock())

    def digest(self, namespace: str, value: str) -> str:
        return hmac.new(
            self.pseudonym_key,
            f"{namespace}:{value}".encode(),
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

    def chat_key(self, connection_id: str, chat_id: int) -> str:
        return "chat_" + self.digest("chat", f"{connection_id}:{chat_id}")[:32]

    def content_digest(self, body: str) -> str:
        return self.digest("body", body)

    def observe_connection(self, observation: ConnectionObservation) -> None:
        can_reply = (
            None if observation.can_reply is None else int(observation.can_reply)
        )
        with self.public.transaction() as connection:
            connection.execute(
                """
                INSERT INTO business_connections VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(connection_id) DO UPDATE SET owner_id=excluded.owner_id,
                    enabled=excluded.enabled, can_reply=excluded.can_reply,
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

    def has_connection(self, connection_id: str) -> bool:
        return (
            self.public.execute(
                "SELECT 1 FROM business_connections WHERE connection_id=?",
                (connection_id,),
            ).fetchone()
            is not None
        )

    def connection_owner_matches(self, connection_id: str, owner_id: int) -> bool:
        row = self.public.execute(
            "SELECT owner_id FROM business_connections WHERE connection_id=?",
            (connection_id,),
        ).fetchone()
        return row is not None and int(row[0]) == owner_id

    def connection_can_reply(self, connection_id: str, owner_id: int) -> bool:
        row = self.public.execute(
            "SELECT owner_id, enabled, can_reply FROM business_connections WHERE connection_id=?",
            (connection_id,),
        ).fetchone()
        return bool(row and row[0] == owner_id and row[1] == 1 and row[2] == 1)

    def deny_connection(self, connection_id: str) -> None:
        with self.public.transaction() as connection:
            connection.execute(
                """UPDATE business_connections SET enabled=0, can_reply=0,
                   observed_at=? WHERE connection_id=?""",
                (self.now(), connection_id),
            )

    def purge_unconsented_connection(
        self,
        connection_id: str,
        crash_hook: Callable[[str], None] | None = None,
    ) -> int:
        rows = self.pending.execute(
            """SELECT message_key, subject_ref FROM pending_messages
               WHERE connection_id=?""",
            (connection_id,),
        ).fetchall()
        if not rows:
            return 0
        now = self.now()
        with self.public.transaction() as connection:
            for row in rows:
                connection.execute(
                    """INSERT OR IGNORE INTO restrictive_tombstones
                       VALUES (?, ?, 'deleted', ?)""",
                    (row["message_key"], row["subject_ref"], now),
                )
        if crash_hook is not None:
            crash_hook("after_tombstone")
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE connection_id=?", (connection_id,)
            )
        if crash_hook is not None:
            crash_hook("after_pending_delete")
        for row in rows:
            self.cancel_linked_replies(str(row["message_key"]))
        return len(rows)

    def get_next_update_id(self) -> int | None:
        row = self.public.execute(
            "SELECT next_update_id FROM poll_state WHERE singleton=1"
        ).fetchone()
        return None if row is None or row[0] is None else int(row[0])

    def commit_update_offset(self, update_id: int) -> None:
        next_id = update_id + 1
        with self.public.transaction() as connection:
            row = connection.execute(
                "SELECT next_update_id FROM poll_state WHERE singleton=1"
            ).fetchone()
            current = None if row is None else row[0]
            if current is not None and update_id < int(current):
                return
            if current is not None and update_id > int(current):
                # Telegram update IDs may have gaps, but an already committed lower
                # offset may only advance through the update actually fetched.
                pass
            pending = connection.execute(
                """SELECT 1 FROM replies WHERE source_update_id=?
                   AND state=?""",
                (update_id, DeliveryState.SENDING.value),
            ).fetchone()
            if pending is not None:
                raise RuntimeError("cannot acknowledge update with unfinished reply")
            connection.execute(
                "UPDATE poll_state SET next_update_id=? WHERE singleton=1", (next_id,)
            )

    def begin_update(
        self,
        message: InboundMessage,
        kind: str,
        outcome: str,
        *,
        store_digest: bool = True,
    ) -> tuple[bool, ReplyRecord | None]:
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        digest = self.content_digest(message.text) if store_digest else None
        with self.public.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM processed_updates WHERE update_id=?",
                (message.update_id,),
            ).fetchone()
            if row is not None:
                same = bool(
                    row["kind"] == kind
                    and row["connection_id"] == message.connection_id
                    and row["conversation_id"] == message.conversation_id
                    and row["sender_id"] == message.sender_id
                    and row["message_id"] == message.message_id
                    and row["content_digest"] == digest
                )
                if not same:
                    return False, None
                if (
                    row["outcome"] in {"received", "received_edit"}
                    and not row["reply_id"]
                ):
                    return True, None
                return False, (
                    self.get_reply(row["reply_id"]) if row["reply_id"] else None
                )
            connection.execute(
                """INSERT INTO processed_updates(
                    update_id, kind, connection_id, conversation_id, sender_id,
                    subject_ref, message_id, message_key, content_digest,
                    inbound_sent_at, outcome, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    message.update_id,
                    kind,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject,
                    message.message_id,
                    self.message_key(
                        message.connection_id,
                        message.conversation_id,
                        message.message_id,
                    ),
                    digest,
                    int(message.sent_at.timestamp()),
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
        sender_id: int,
        subject_ref: str,
        message_keys: tuple[str, ...],
        outcome: str,
    ) -> bool:
        if not message_keys:
            return False
        message_key = message_keys[0]
        with self.public.transaction() as connection:
            row = connection.execute(
                """SELECT kind, connection_id, conversation_id, sender_id,
                   subject_ref, message_key FROM processed_updates WHERE update_id=?""",
                (update_id,),
            ).fetchone()
            if row is not None:
                linked_keys = tuple(
                    str(item[0])
                    for item in connection.execute(
                        """SELECT message_key FROM deletion_links
                           WHERE update_id=? ORDER BY message_key""",
                        (update_id,),
                    ).fetchall()
                )
                return bool(
                    row["kind"] == kind
                    and row["connection_id"] == connection_id
                    and row["conversation_id"] == conversation_id
                    and row["sender_id"] == sender_id
                    and row["subject_ref"] == subject_ref
                    and row["message_key"] == message_key
                    and linked_keys == tuple(sorted(message_keys))
                    and connection.execute(
                        "SELECT outcome FROM processed_updates WHERE update_id=?",
                        (update_id,),
                    ).fetchone()[0]
                    == "deleting"
                )
            connection.execute(
                """INSERT INTO processed_updates(update_id, kind, connection_id,
                   conversation_id, sender_id, subject_ref, message_key, outcome,
                   created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    update_id,
                    kind,
                    connection_id,
                    conversation_id,
                    sender_id,
                    subject_ref,
                    message_key,
                    outcome,
                    self.now(),
                ),
            )
            for linked_key in message_keys:
                connection.execute(
                    "INSERT OR IGNORE INTO deletion_links VALUES (?, ?, ?)",
                    (update_id, linked_key, subject_ref),
                )
        return True

    def set_update_outcome(
        self, update_id: int, outcome: str, reply_id: str | None = None
    ) -> None:
        with self.public.transaction() as connection:
            connection.execute(
                "UPDATE processed_updates SET outcome=?, reply_id=COALESCE(?, reply_id) WHERE update_id=?",
                (outcome, reply_id, update_id),
            )

    def rate_limit(
        self, update_id: int, subject_ref: str, *, limit: int, window_seconds: int
    ) -> bool:
        now = self.now()
        window = now - now % window_seconds
        with self.public.transaction() as connection:
            prior = connection.execute(
                "SELECT window_start FROM rate_admissions WHERE update_id=?",
                (update_id,),
            ).fetchone()
            if prior is not None:
                return True
            count = connection.execute(
                "SELECT count(*) FROM rate_admissions WHERE subject_ref=? AND window_start=?",
                (subject_ref, window),
            ).fetchone()[0]
            if int(count) >= limit:
                return False
            connection.execute(
                "INSERT INTO rate_admissions VALUES (?, ?, ?)",
                (update_id, subject_ref, window),
            )
        return True

    def privacy_state(self, subject_ref: str) -> str | None:
        row = self.public.execute(
            "SELECT state FROM privacy_state WHERE subject_ref=?", (subject_ref,)
        ).fetchone()
        return None if row is None else str(row[0])

    def is_taken_over(self, connection_id: str, conversation_id: int) -> bool:
        row = self.public.execute(
            "SELECT takeover_at FROM chat_state WHERE chat_key=?",
            (self.chat_key(connection_id, conversation_id),),
        ).fetchone()
        return row is not None

    def known_conversation(self, connection_id: str, conversation_id: int) -> bool:
        return self.is_taken_over(connection_id, conversation_id) or (
            self.public.execute(
                """SELECT 1 FROM processed_updates
                   WHERE connection_id=? AND conversation_id=?""",
                (connection_id, conversation_id),
            ).fetchone()
            is not None
        )

    def record_takeover(
        self,
        connection_id: str,
        conversation_id: int,
        sender_id: int,
        update_id: int,
        message_id: int,
    ) -> bool:
        subject = self.subject_ref(connection_id, conversation_id, sender_id)
        now = self.now()
        with self.public.transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM processed_updates WHERE update_id=?", (update_id,)
            ).fetchone():
                return False
            connection.execute(
                """INSERT INTO processed_updates(update_id, kind, connection_id,
                   conversation_id, sender_id, subject_ref, message_id, outcome,
                   created_at) VALUES (?, 'owner_business_message', ?, ?, ?, ?, ?,
                   'owner_takeover', ?)""",
                (
                    update_id,
                    connection_id,
                    conversation_id,
                    sender_id,
                    subject,
                    message_id,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO chat_state VALUES (?, ?)
                   ON CONFLICT(chat_key) DO UPDATE SET
                   takeover_at=excluded.takeover_at""",
                (self.chat_key(connection_id, conversation_id), now),
            )
            connection.execute(
                """UPDATE replies SET state=?, updated_at=? WHERE connection_id=?
                   AND conversation_id=? AND state IN (?, ?)""",
                (
                    DeliveryState.CANCELLED.value,
                    now,
                    connection_id,
                    conversation_id,
                    DeliveryState.PENDING.value,
                    DeliveryState.RETRY_PENDING.value,
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
        subject = self.subject_ref(connection_id, conversation_id, sender_id)
        if self.privacy_state(subject) is not None:
            return False
        return (
            self.public.execute(
                """SELECT 1 FROM consents WHERE connection_id=? AND conversation_id=?
               AND sender_id=? AND processing_authorization_version=?""",
                (
                    connection_id,
                    conversation_id,
                    sender_id,
                    processing_authorization_version,
                ),
            ).fetchone()
            is not None
        )

    def _new_control(
        self,
        *,
        action: str,
        message: InboundMessage,
        pending_key: str | None,
        privacy_policy_version: str,
        processing_authorization_version: str,
        expires_at: int,
    ) -> tuple[str, str]:
        token = secrets.token_urlsafe(24)
        control_id = uuid.uuid4().hex
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.public.transaction() as connection:
            connection.execute(
                """INSERT INTO controls(control_id, token_hash, action, connection_id,
                   conversation_id, sender_id, subject_ref, pending_key,
                   privacy_policy_version, processing_authorization_version,
                   expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    control_id,
                    self.digest("control", token),
                    action,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject,
                    pending_key,
                    privacy_policy_version,
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
        key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        expires = min(self.now(), int(message.sent_at.timestamp())) + ttl_seconds
        consent_id, consent = self._new_control(
            action="consent",
            message=message,
            pending_key=key,
            privacy_policy_version=privacy_policy_version,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires,
        )
        decline_id, decline = self._new_control(
            action="decline",
            message=message,
            pending_key=key,
            privacy_policy_version=privacy_policy_version,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires,
        )
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.pending.transaction() as connection:
            connection.execute(
                """INSERT INTO pending_messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                   'pending', ?, ?, ?, ?)
                   ON CONFLICT(message_key) DO UPDATE SET
                   last_update_id=excluded.last_update_id,
                   body=excluded.body, content_digest=excluded.content_digest,
                   sent_at=excluded.sent_at, created_at=excluded.created_at,
                   expires_at=excluded.expires_at, state='pending',
                   privacy_policy_version=excluded.privacy_policy_version,
                   processing_authorization_version=excluded.processing_authorization_version,
                   consent_control_id=excluded.consent_control_id,
                   decline_control_id=excluded.decline_control_id""",
                (
                    key,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject,
                    message.message_id,
                    message.update_id,
                    message.update_id,
                    message.text,
                    self.content_digest(message.text),
                    int(message.sent_at.timestamp()),
                    self.now(),
                    expires,
                    privacy_policy_version,
                    processing_authorization_version,
                    consent_id,
                    decline_id,
                ),
            )
        return key, consent, decline

    def create_maintenance_controls(
        self,
        message: InboundMessage,
        privacy_policy_version: str,
        processing_authorization_version: str,
        ttl_seconds: int,
        *,
        reconsent: bool = False,
    ) -> tuple[str, str]:
        expires = self.now() + ttl_seconds
        action = "reconsent" if reconsent else "revoke"
        _, first = self._new_control(
            action=action,
            message=message,
            pending_key=None,
            privacy_policy_version=privacy_policy_version,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires,
        )
        _, delete = self._new_control(
            action="delete",
            message=message,
            pending_key=None,
            privacy_policy_version=privacy_policy_version,
            processing_authorization_version=processing_authorization_version,
            expires_at=expires,
        )
        return first, delete

    def resolve_control(
        self,
        token: str,
        actor_id: int,
        conversation_id: int,
        connection_id: str,
        origin_message_id: int,
    ) -> ControlRecord | None:
        if not token.startswith("pa:"):
            return None
        row = self.public.execute(
            "SELECT * FROM controls WHERE token_hash=?",
            (self.digest("control", token[3:]),),
        ).fetchone()
        if row is None or any(
            (
                row["sender_id"] != actor_id,
                row["conversation_id"] != conversation_id,
                row["connection_id"] != connection_id,
                row["origin_message_id"] != origin_message_id,
                row["origin_reply_id"] is None,
            )
        ):
            return None
        return ControlRecord(
            control_id=str(row["control_id"]),
            action=str(row["action"]),
            connection_id=str(row["connection_id"]),
            conversation_id=int(row["conversation_id"]),
            sender_id=int(row["sender_id"]),
            subject_ref=str(row["subject_ref"]),
            pending_key=row["pending_key"],
            privacy_policy_version=str(row["privacy_policy_version"]),
            processing_authorization_version=str(
                row["processing_authorization_version"]
            ),
            expires_at=int(row["expires_at"]),
            consumed_at=row["consumed_at"],
            origin_reply_id=str(row["origin_reply_id"]),
            origin_message_id=int(row["origin_message_id"]),
        )

    def _consume(self, control_ids: tuple[str, ...], when: int) -> None:
        if not control_ids:
            return
        marks = ",".join("?" for _ in control_ids)
        with self.public.transaction() as connection:
            connection.execute(
                f"UPDATE controls SET consumed_at=COALESCE(consumed_at, ?) WHERE control_id IN ({marks})",
                (when, *control_ids),
            )

    def _is_restricted(self, message_key: str, subject_ref: str) -> bool:
        return bool(
            self.public.execute(
                "SELECT 1 FROM privacy_state WHERE subject_ref=?", (subject_ref,)
            ).fetchone()
            or self.public.execute(
                "SELECT 1 FROM restrictive_tombstones WHERE message_key=?",
                (message_key,),
            ).fetchone()
        )

    def accept_consent(
        self,
        control: ControlRecord,
        *,
        expected_processing_version: str,
        crash_hook: Callable[[str], None] | None = None,
    ) -> str:
        now = self.now()
        if control.action != "consent" or control.pending_key is None:
            return "invalid"
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= now:
            return "expired"
        if control.processing_authorization_version != expected_processing_version:
            return "stale_version"
        with self.pending.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM pending_messages WHERE message_key=?",
                (control.pending_key,),
            ).fetchone()
            if row is None:
                return "replayed"
            if row["expires_at"] <= now:
                connection.execute(
                    "DELETE FROM pending_messages WHERE message_key=?",
                    (control.pending_key,),
                )
                return "expired"
            if row["consent_control_id"] != control.control_id:
                return "invalid"
            connection.execute(
                "UPDATE pending_messages SET state='authorized' WHERE message_key=?",
                (control.pending_key,),
            )
        self._finish_transfer(control.pending_key, crash_hook=crash_hook)
        return "accepted"

    def reconsent(
        self, control: ControlRecord, expected_processing_version: str
    ) -> str:
        if control.action != "reconsent":
            return "invalid"
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= self.now():
            return "expired"
        if control.processing_authorization_version != expected_processing_version:
            return "stale_version"
        now = self.now()
        with self.public.transaction() as connection:
            connection.execute(
                "DELETE FROM privacy_state WHERE subject_ref=?", (control.subject_ref,)
            )
            connection.execute(
                """INSERT INTO consents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(connection_id, conversation_id, sender_id) DO UPDATE SET
                   privacy_policy_version=excluded.privacy_policy_version,
                   processing_authorization_version=excluded.processing_authorization_version,
                   processors=excluded.processors,
                   purposes=excluded.purposes,
                   granted_at=excluded.granted_at""",
                (
                    control.connection_id,
                    control.conversation_id,
                    control.sender_id,
                    control.subject_ref,
                    control.privacy_policy_version,
                    expected_processing_version,
                    json.dumps(AUTHORIZED_PROCESSORS),
                    json.dumps(AUTHORIZED_PURPOSES),
                    now,
                ),
            )
            connection.execute(
                "UPDATE controls SET consumed_at=? WHERE control_id=?",
                (now, control.control_id),
            )
        return "accepted"

    def _finish_transfer(
        self, message_key: str, *, crash_hook: Callable[[str], None] | None = None
    ) -> None:
        row = self.pending.execute(
            "SELECT * FROM pending_messages WHERE message_key=? AND state='authorized'",
            (message_key,),
        ).fetchone()
        if row is None:
            return
        if self._is_restricted(message_key, row["subject_ref"]):
            with self.pending.transaction() as connection:
                connection.execute(
                    "DELETE FROM pending_messages WHERE message_key=?", (message_key,)
                )
            return
        if crash_hook:
            crash_hook("before_copy")
        now = self.now()
        with self.public.transaction() as connection:
            restricted = connection.execute(
                """SELECT 1 FROM privacy_state WHERE subject_ref=? UNION
                   SELECT 1 FROM restrictive_tombstones WHERE message_key=?""",
                (row["subject_ref"], message_key),
            ).fetchone()
            if restricted is None:
                connection.execute(
                    """INSERT INTO consents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(connection_id, conversation_id, sender_id) DO UPDATE SET
                       privacy_policy_version=excluded.privacy_policy_version,
                       processing_authorization_version=excluded.processing_authorization_version,
                       processors=excluded.processors,
                       purposes=excluded.purposes,
                       granted_at=excluded.granted_at""",
                    (
                        row["connection_id"],
                        row["conversation_id"],
                        row["sender_id"],
                        row["subject_ref"],
                        row["privacy_policy_version"],
                        row["processing_authorization_version"],
                        json.dumps(AUTHORIZED_PROCESSORS),
                        json.dumps(AUTHORIZED_PURPOSES),
                        now,
                    ),
                )
                connection.execute(
                    """INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                       ON CONFLICT(message_key) DO UPDATE SET body=excluded.body,
                       last_update_id=excluded.last_update_id,
                       content_updated_at=excluded.content_updated_at,
                       expires_at=excluded.expires_at, deleted_at=NULL""",
                    (
                        message_key,
                        row["connection_id"],
                        row["conversation_id"],
                        row["sender_id"],
                        row["subject_ref"],
                        row["message_id"],
                        row["source_update_id"],
                        row["last_update_id"],
                        row["body"],
                        row["sent_at"],
                        row["sent_at"],
                        row["sent_at"] + 90 * 24 * 60 * 60,
                    ),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO transfer_receipts VALUES (?, ?)",
                    (message_key, now),
                )
                connection.execute(
                    "UPDATE controls SET consumed_at=COALESCE(consumed_at, ?) WHERE control_id IN (?, ?)",
                    (now, row["consent_control_id"], row["decline_control_id"]),
                )
        if crash_hook:
            crash_hook("after_copy")
            crash_hook("after_receipt")
            crash_hook("before_pending_delete")
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE message_key=?", (message_key,)
            )

    def recover_transfers(self) -> int:
        rows = self.pending.execute(
            "SELECT message_key FROM pending_messages WHERE state='authorized'"
        ).fetchall()
        for row in rows:
            self._finish_transfer(str(row[0]))
        return len(rows)

    def recover_restrictions(self) -> int:
        tombstones = [
            str(row[0])
            for row in self.public.execute(
                "SELECT message_key FROM restrictive_tombstones"
            ).fetchall()
        ]
        for message_key in tombstones:
            self.cancel_linked_replies(message_key)
        rows = self.pending.execute(
            "SELECT message_key, subject_ref FROM pending_messages"
        ).fetchall()
        restricted = [
            str(row["message_key"])
            for row in rows
            if self._is_restricted(str(row["message_key"]), str(row["subject_ref"]))
        ]
        if restricted:
            marks = ",".join("?" for _ in restricted)
            with self.pending.transaction() as connection:
                connection.execute(
                    f"DELETE FROM pending_messages WHERE message_key IN ({marks})",
                    tuple(restricted),
                )
            for message_key in restricted:
                self.cancel_linked_replies(message_key)
        self.prune_restrictive_tombstones()
        return len(restricted)

    def prune_restrictive_tombstones(self) -> int:
        rows = self.public.execute(
            "SELECT message_key FROM restrictive_tombstones"
        ).fetchall()
        stale = [
            str(row[0])
            for row in rows
            if self.pending.execute(
                "SELECT 1 FROM pending_messages WHERE message_key=?", (row[0],)
            ).fetchone()
            is None
        ]
        if stale:
            marks = ",".join("?" for _ in stale)
            with self.public.transaction() as connection:
                connection.execute(
                    f"DELETE FROM restrictive_tombstones WHERE message_key IN ({marks})",
                    tuple(stale),
                )
        return len(stale)

    def decline(
        self, control: ControlRecord, crash_hook: Callable[[str], None] | None = None
    ) -> str:
        if control.action != "decline" or control.pending_key is None:
            return "invalid"
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= self.now():
            return "expired"
        row = self.pending.execute(
            "SELECT consent_control_id, decline_control_id FROM pending_messages WHERE message_key=?",
            (control.pending_key,),
        ).fetchone()
        if row is None:
            return "replayed"
        now = self.now()
        with self.public.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO restrictive_tombstones VALUES (?, ?, 'declined', ?)",
                (control.pending_key, control.subject_ref, now),
            )
            connection.execute(
                "UPDATE controls SET consumed_at=COALESCE(consumed_at, ?) WHERE control_id IN (?, ?)",
                (now, row[0], row[1]),
            )
        if crash_hook:
            crash_hook("after_tombstone")
            crash_hook("before_pending_delete")
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE message_key=?",
                (control.pending_key,),
            )
        return "declined"

    def expire_pending(self) -> int:
        now = self.now()
        with self.pending.transaction() as connection:
            rows = connection.execute(
                """SELECT message_key, consent_control_id,
                   decline_control_id FROM pending_messages WHERE expires_at<=?""",
                (now,),
            ).fetchall()
            connection.execute(
                "DELETE FROM pending_messages WHERE expires_at<=?", (now,)
            )
        with self.public.transaction() as connection:
            for row in rows:
                connection.execute(
                    "DELETE FROM controls WHERE control_id IN (?, ?)",
                    (row["consent_control_id"], row["decline_control_id"]),
                )
                update_ids = [
                    int(item[0])
                    for item in connection.execute(
                        """SELECT update_id FROM processed_updates
                           WHERE message_key=? AND kind!='deleted_business_messages'""",
                        (row["message_key"],),
                    ).fetchall()
                ]
                for update_id in update_ids:
                    connection.execute(
                        "DELETE FROM replies WHERE source_update_id=?", (update_id,)
                    )
                    connection.execute(
                        "DELETE FROM rate_admissions WHERE update_id=?", (update_id,)
                    )
                connection.execute(
                    """DELETE FROM processed_updates WHERE message_key=?
                       AND kind!='deleted_business_messages'""",
                    (row["message_key"],),
                )
        return len(rows)

    def expire_public(self, retention_seconds: int) -> int:
        cutoff = self.now()
        with self.public.transaction() as connection:
            connection.execute("DELETE FROM controls WHERE expires_at<=?", (cutoff,))
            rows = connection.execute(
                """SELECT message_key, subject_ref FROM messages
                   WHERE content_updated_at + ? <= ?""",
                (retention_seconds, cutoff),
            ).fetchall()
            for row in rows:
                update_ids = [
                    int(item[0])
                    for item in connection.execute(
                        """SELECT update_id FROM processed_updates
                           WHERE message_key=? AND kind!='deleted_business_messages'""",
                        (row["message_key"],),
                    ).fetchall()
                ]
                for update_id in update_ids:
                    connection.execute(
                        "DELETE FROM replies WHERE source_update_id=?", (update_id,)
                    )
                    connection.execute(
                        "DELETE FROM rate_admissions WHERE update_id=?", (update_id,)
                    )
                connection.execute(
                    """DELETE FROM processed_updates WHERE message_key=?
                       AND kind!='deleted_business_messages'""",
                    (row["message_key"],),
                )
                deletion_updates = [
                    int(item[0])
                    for item in connection.execute(
                        "SELECT update_id FROM deletion_links WHERE message_key=?",
                        (row["message_key"],),
                    ).fetchall()
                ]
                for update_id in deletion_updates:
                    connection.execute(
                        "DELETE FROM deletion_links WHERE update_id=?", (update_id,)
                    )
                    connection.execute(
                        "DELETE FROM processed_updates WHERE update_id=?", (update_id,)
                    )
                connection.execute(
                    "DELETE FROM transfer_receipts WHERE message_key=?",
                    (row["message_key"],),
                )
                connection.execute(
                    "DELETE FROM restrictive_tombstones WHERE message_key=?",
                    (row["message_key"],),
                )
                connection.execute(
                    "DELETE FROM messages WHERE message_key=?", (row["message_key"],)
                )
            subjects = {str(row["subject_ref"]) for row in rows}
            for subject in subjects:
                remaining = connection.execute(
                    "SELECT 1 FROM messages WHERE subject_ref=?", (subject,)
                ).fetchone()
                if remaining is None:
                    connection.execute(
                        "DELETE FROM controls WHERE subject_ref=?", (subject,)
                    )
                    connection.execute(
                        "DELETE FROM consents WHERE subject_ref=?", (subject,)
                    )
                    connection.execute(
                        "DELETE FROM rate_admissions WHERE subject_ref=?", (subject,)
                    )
                    connection.execute(
                        "DELETE FROM replies WHERE subject_ref=?", (subject,)
                    )
                    connection.execute(
                        "DELETE FROM processed_updates WHERE subject_ref=?", (subject,)
                    )
                    connection.execute(
                        "DELETE FROM deletion_links WHERE subject_ref=?", (subject,)
                    )
        return len(rows)

    def stored_message_binding(
        self,
        connection_id: str,
        conversation_id: int,
        message_id: int,
        sender_id: int | None = None,
    ) -> bool:
        key = self.message_key(connection_id, conversation_id, message_id)
        params: tuple[Any, ...] = (key,) if sender_id is None else (key, sender_id)
        suffix = "" if sender_id is None else " AND sender_id=?"
        if self.pending.execute(
            f"SELECT 1 FROM pending_messages WHERE message_key=?{suffix}", params
        ).fetchone():
            return True
        return (
            self.public.execute(
                f"SELECT 1 FROM messages WHERE message_key=?{suffix}", params
            ).fetchone()
            is not None
        )

    def stored_subject_binding(
        self, connection_id: str, conversation_id: int, message_id: int
    ) -> tuple[int, str, str] | None:
        key = self.message_key(connection_id, conversation_id, message_id)
        pending = self.pending.execute(
            "SELECT sender_id, subject_ref FROM pending_messages WHERE message_key=?",
            (key,),
        ).fetchone()
        if pending is not None:
            return int(pending["sender_id"]), str(pending["subject_ref"]), key
        public = self.public.execute(
            "SELECT sender_id, subject_ref FROM messages WHERE message_key=?", (key,)
        ).fetchone()
        if public is None:
            return None
        return int(public["sender_id"]), str(public["subject_ref"]), key

    def cancel_linked_replies(self, message_key: str) -> int:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE replies SET state=?, updated_at=? WHERE source_update_id IN
                   (SELECT update_id FROM processed_updates WHERE message_key=?)
                   AND state IN (?, ?)""",
                (
                    DeliveryState.CANCELLED.value,
                    self.now(),
                    message_key,
                    DeliveryState.PENDING.value,
                    DeliveryState.RETRY_PENDING.value,
                ),
            )
        return max(int(cursor.rowcount), 0)

    def store_consented_message(
        self, message: InboundMessage, retention_seconds: int
    ) -> None:
        key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        changed = int((message.edited_at or message.sent_at).timestamp())
        with self.public.transaction() as connection:
            connection.execute(
                """INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(message_key) DO UPDATE SET
                   last_update_id=excluded.last_update_id,
                   body=excluded.body, content_updated_at=excluded.content_updated_at,
                   expires_at=excluded.expires_at, deleted_at=NULL""",
                (
                    key,
                    message.connection_id,
                    message.conversation_id,
                    message.sender_id,
                    subject,
                    message.message_id,
                    message.update_id,
                    message.update_id,
                    message.text,
                    int(message.sent_at.timestamp()),
                    changed,
                    changed + retention_seconds,
                ),
            )

    def edit_pending(
        self, message: InboundMessage, processing_authorization_version: str
    ) -> bool:
        key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        with self.pending.transaction() as connection:
            cursor = connection.execute(
                """UPDATE pending_messages SET body=?, content_digest=?, last_update_id=?
                   WHERE message_key=? AND state='pending'
                     AND processing_authorization_version=?""",
                (
                    message.text,
                    self.content_digest(message.text),
                    message.update_id,
                    key,
                    processing_authorization_version,
                ),
            )
        return int(cursor.rowcount) == 1

    def edit_public(self, message: InboundMessage, retention_seconds: int) -> bool:
        key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        changed = int((message.edited_at or message.sent_at).timestamp())
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE messages SET body=?, last_update_id=?, content_updated_at=?,
                   expires_at=?, deleted_at=NULL WHERE message_key=? AND sender_id=?""",
                (
                    message.text,
                    message.update_id,
                    changed,
                    changed + retention_seconds,
                    key,
                    message.sender_id,
                ),
            )
        return int(cursor.rowcount) == 1

    def delete_messages(
        self, connection_id: str, conversation_id: int, message_ids: tuple[int, ...]
    ) -> int:
        deleted = 0
        now = self.now()
        for message_id in message_ids:
            key = self.message_key(connection_id, conversation_id, message_id)
            with self.public.transaction() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO restrictive_tombstones VALUES (?, '', 'deleted', ?)",
                    (key, now),
                )
                source = connection.execute(
                    "SELECT source_update_id FROM messages WHERE message_key=?", (key,)
                ).fetchone()
                cursor = connection.execute(
                    "UPDATE messages SET body=NULL, deleted_at=? WHERE message_key=? AND deleted_at IS NULL",
                    (now, key),
                )
                deleted += max(cursor.rowcount, 0)
                if source:
                    connection.execute(
                        "UPDATE replies SET state=?, updated_at=? WHERE source_update_id=? AND state IN (?, ?)",
                        (
                            DeliveryState.CANCELLED.value,
                            now,
                            source[0],
                            DeliveryState.PENDING.value,
                            DeliveryState.RETRY_PENDING.value,
                        ),
                    )
            with self.pending.transaction() as connection:
                row = connection.execute(
                    "SELECT source_update_id FROM pending_messages WHERE message_key=?",
                    (key,),
                ).fetchone()
                cursor = connection.execute(
                    "DELETE FROM pending_messages WHERE message_key=?", (key,)
                )
                deleted += max(cursor.rowcount, 0)
            if row:
                with self.public.transaction() as connection:
                    connection.execute(
                        "UPDATE replies SET state=?, updated_at=? WHERE source_update_id=? AND state IN (?, ?)",
                        (
                            DeliveryState.CANCELLED.value,
                            now,
                            row[0],
                            DeliveryState.PENDING.value,
                            DeliveryState.RETRY_PENDING.value,
                        ),
                    )
            self.cancel_linked_replies(key)
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
        keyboard_json = json.dumps(keyboard, separators=(",", ":"), sort_keys=True)
        now = self.now()
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.public.transaction() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO replies(reply_id, source_update_id, purpose,
                   connection_id, conversation_id, subject_ref, text, keyboard_json,
                   state, inbound_sent_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    reply_id,
                    message.update_id,
                    purpose,
                    message.connection_id,
                    message.conversation_id,
                    subject,
                    text,
                    keyboard_json,
                    DeliveryState.PENDING.value,
                    int(message.sent_at.timestamp()),
                    now,
                    now,
                ),
            )
            connection.execute(
                "UPDATE processed_updates SET reply_id=? WHERE update_id=?",
                (reply_id, message.update_id),
            )
            for row in keyboard:
                for item in row:
                    token = item.get("callback_data")
                    if token and token.startswith("pa:"):
                        connection.execute(
                            "UPDATE controls SET origin_reply_id=? WHERE token_hash=?",
                            (reply_id, self.digest("control", token[3:])),
                        )
        record = self.get_reply(reply_id)
        if record is None:
            raise RuntimeError("durable reply was not created")
        return record

    def get_reply(self, reply_id: str) -> ReplyRecord | None:
        row = self.public.execute(
            "SELECT * FROM replies WHERE reply_id=?", (reply_id,)
        ).fetchone()
        if row is None:
            return None
        return ReplyRecord(
            reply_id=str(row["reply_id"]),
            connection_id=str(row["connection_id"]),
            conversation_id=int(row["conversation_id"]),
            text=str(row["text"]),
            keyboard_json=str(row["keyboard_json"]),
            state=DeliveryState(str(row["state"])),
            inbound_sent_at=int(row["inbound_sent_at"]),
            next_attempt_at=row["next_attempt_at"],
        )

    def due_replies(self) -> list[ReplyRecord]:
        rows = self.public.execute(
            """SELECT reply_id FROM replies WHERE state=? OR
               (state=? AND next_attempt_at<=?) ORDER BY created_at""",
            (
                DeliveryState.PENDING.value,
                DeliveryState.RETRY_PENDING.value,
                self.now(),
            ),
        ).fetchall()
        return [
            reply for row in rows if (reply := self.get_reply(str(row[0]))) is not None
        ]

    def mark_reply_sending(self, reply_id: str) -> bool:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE replies SET state=?, next_attempt_at=NULL, updated_at=?
                   WHERE reply_id=? AND (state=? OR (state=? AND next_attempt_at<=?))""",
                (
                    DeliveryState.SENDING.value,
                    self.now(),
                    reply_id,
                    DeliveryState.PENDING.value,
                    DeliveryState.RETRY_PENDING.value,
                    self.now(),
                ),
            )
        return int(cursor.rowcount) == 1

    def reply_allowed(
        self, reply_id: str, *, owner_id: int, reply_window_seconds: int
    ) -> bool:
        row = self.public.execute(
            """SELECT r.state, r.inbound_sent_at, r.connection_id,
               r.conversation_id, c.owner_id, c.enabled, c.can_reply
               FROM replies r LEFT JOIN business_connections c
               ON c.connection_id=r.connection_id
               WHERE r.reply_id=?""",
            (reply_id,),
        ).fetchone()
        return bool(
            row
            and row["state"]
            in {DeliveryState.PENDING.value, DeliveryState.RETRY_PENDING.value}
            and row["owner_id"] == owner_id
            and row["enabled"] == 1
            and row["can_reply"] == 1
            and not self.is_taken_over(
                str(row["connection_id"]), int(row["conversation_id"])
            )
            and self.now() - int(row["inbound_sent_at"]) < reply_window_seconds
        )

    def finalize_reply(
        self,
        reply_id: str,
        state: DeliveryState,
        telegram_message_id: int | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        next_attempt = (
            None if retry_after_seconds is None else self.now() + retry_after_seconds
        )
        with self.public.transaction() as connection:
            connection.execute(
                """UPDATE replies SET state=?, telegram_message_id=COALESCE(?, telegram_message_id),
                   next_attempt_at=?, updated_at=? WHERE reply_id=?""",
                (state.value, telegram_message_id, next_attempt, self.now(), reply_id),
            )
            if state is DeliveryState.SENT and telegram_message_id is not None:
                connection.execute(
                    "UPDATE controls SET origin_message_id=? WHERE origin_reply_id=?",
                    (telegram_message_id, reply_id),
                )

    def recover_sending_replies(self) -> int:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                "UPDATE replies SET state=?, updated_at=? WHERE state=?",
                (
                    DeliveryState.DELIVERY_UNCERTAIN.value,
                    self.now(),
                    DeliveryState.SENDING.value,
                ),
            )
        return max(int(cursor.rowcount), 0)

    def apply_privacy_control(
        self, control: ControlRecord, crash_hook: Callable[[str], None] | None = None
    ) -> str:
        if control.action not in {"revoke", "delete"}:
            return "invalid"
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= self.now():
            return "expired"
        state = "revoked" if control.action == "revoke" else "erased"
        now = self.now()
        with self.public.transaction() as connection:
            message_keys = [
                str(row[0])
                for row in connection.execute(
                    "SELECT message_key FROM messages WHERE subject_ref=?",
                    (control.subject_ref,),
                ).fetchall()
            ]
            connection.execute(
                """INSERT INTO privacy_state VALUES (?, ?, ?)
                   ON CONFLICT(subject_ref) DO UPDATE SET state=excluded.state,
                   changed_at=excluded.changed_at""",
                (control.subject_ref, state, now),
            )
            for table in (
                "consents",
                "controls",
                "messages",
                "replies",
                "processed_updates",
                "rate_admissions",
                "deletion_links",
            ):
                connection.execute(
                    f"DELETE FROM {table} WHERE subject_ref=?", (control.subject_ref,)
                )
            for message_key in message_keys:
                connection.execute(
                    "DELETE FROM transfer_receipts WHERE message_key=?", (message_key,)
                )
            connection.execute(
                "DELETE FROM restrictive_tombstones WHERE subject_ref=?",
                (control.subject_ref,),
            )
        if crash_hook:
            crash_hook("after_tombstone")
            crash_hook("before_pending_delete")
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE subject_ref=?",
                (control.subject_ref,),
            )
        return state

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
