"""Encrypted Unit 2 state for conversation, Inbox, privacy, and alerts."""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from src.public_assistant.config import Unit2Config
from src.public_assistant.model import (
    ConversationItem,
    ModelResult,
    estimate_input_tokens,
)
from src.public_assistant.sqlcipher import SqlCipherDatabase
from src.public_assistant.storage import Unit1Store
from src.public_assistant.types import ControlRecord, InboundMessage

UNIT2_SCHEMA = """
CREATE TABLE IF NOT EXISTS assistant_context (
    item_id TEXT PRIMARY KEY,
    subject_ref TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('assistant')),
    body TEXT NOT NULL,
    source_update_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    content_updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE(source_update_id, role)
);
CREATE INDEX IF NOT EXISTS idx_assistant_context_subject
    ON assistant_context(subject_ref, created_at);
CREATE TABLE IF NOT EXISTS inbox_requests (
    request_id TEXT PRIMARY KEY,
    subject_ref TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open', 'closed')),
    source_update_id INTEGER NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    content_updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inbox_subject
    ON inbox_requests(subject_ref, created_at);
CREATE TABLE IF NOT EXISTS request_sources (
    message_key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    source_update_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_request_sources_request
    ON request_sources(request_id);
CREATE TABLE IF NOT EXISTS notification_outbox (
    notification_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    text TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('pending', 'sending', 'sent', 'uncertain', 'failed')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS model_reservations (
    reservation_id TEXT PRIMARY KEY,
    source_update_id INTEGER NOT NULL UNIQUE,
    subject_ref TEXT NOT NULL,
    day TEXT NOT NULL,
    reserved_input_tokens INTEGER NOT NULL,
    reserved_output_tokens INTEGER NOT NULL,
    reserved_cost_microusd INTEGER NOT NULL,
    actual_input_tokens INTEGER,
    actual_output_tokens INTEGER,
    actual_cost_microusd INTEGER,
    provider_request_ref TEXT,
    state TEXT NOT NULL CHECK(state IN ('reserved', 'complete', 'uncertain')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_reservations_day
    ON model_reservations(day, state);
CREATE TABLE IF NOT EXISTS privacy_references (
    reference_hash TEXT PRIMARY KEY,
    subject_ref TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS privacy_previews (
    preview_id TEXT PRIMARY KEY,
    subject_ref TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action='erase_subject'),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS privacy_attempts (
    attempt_id TEXT PRIMARY KEY,
    attempt_ref TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_privacy_attempts_window
    ON privacy_attempts(attempt_ref, window_start);
"""

ERASURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS erasure_tombstones (
    subject_ref TEXT PRIMARY KEY,
    changed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
"""

ERASURE_TOMBSTONE_RETENTION_SECONDS = 90 * 24 * 60 * 60


def erase_subject_from_public_store(
    database: SqlCipherDatabase, subject_ref: str, now: int
) -> None:
    """Remove all sender-derived public-store content for one tombstoned subject."""

    with database.transaction() as connection:
        message_keys = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT message_key FROM messages WHERE subject_ref=?", (subject_ref,)
            ).fetchall()
        )
        request_ids = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT request_id FROM inbox_requests WHERE subject_ref=?",
                (subject_ref,),
            ).fetchall()
        )
        for table in (
            "assistant_context",
            "inbox_requests",
            "model_reservations",
            "privacy_references",
            "privacy_previews",
            "consents",
            "controls",
            "messages",
            "replies",
            "processed_updates",
            "rate_admissions",
            "deletion_links",
        ):
            connection.execute(
                f"DELETE FROM {table} WHERE subject_ref=?", (subject_ref,)
            )
        for message_key in message_keys:
            connection.execute(
                "DELETE FROM transfer_receipts WHERE message_key=?", (message_key,)
            )
        connection.execute(
            "DELETE FROM restrictive_tombstones WHERE subject_ref=?", (subject_ref,)
        )
        for request_id in request_ids:
            connection.execute(
                "DELETE FROM notification_outbox WHERE request_id=?", (request_id,)
            )
            connection.execute(
                "DELETE FROM request_sources WHERE request_id=?", (request_id,)
            )
        connection.execute(
            """INSERT INTO privacy_state(subject_ref, state, changed_at)
               VALUES (?, 'erased', ?)
               ON CONFLICT(subject_ref) DO UPDATE SET state='erased',
               changed_at=excluded.changed_at""",
            (subject_ref, now),
        )


@dataclass(frozen=True)
class Notification:
    notification_id: str
    request_id: str
    text: str


@dataclass(frozen=True)
class PrivacyPreviewResult:
    outcome: str
    preview_id: str | None = None


class Unit2Store(Unit1Store):
    """Keep Unit 1 invariants while adding isolated Unit 2 state."""

    def __init__(
        self,
        data_dir: Path,
        pending_key: str,
        public_key: str,
        pseudonym_key: bytes,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            data_dir,
            pending_key,
            public_key,
            pseudonym_key,
            clock=clock,
            authorized_processors=("OpenAI",),
            authorized_purposes=("assistant replies", "request capture"),
            recover=False,
        )
        try:
            self.public.connection.executescript(UNIT2_SCHEMA)
            self.erasure = SqlCipherDatabase(
                data_dir / "erasure.db", public_key, ERASURE_SCHEMA
            )
            self.replay_erasure_tombstones()
            self.recover_sending_replies()
            self.recover_pending_expiry_cleanup()
            self.recover_restrictions()
            self.recover_transfers()
            self.recover_model_reservations()
            self.recover_sending_notifications()
        except BaseException:
            if hasattr(self, "erasure"):
                self.erasure.close()
            super().close()
            raise

    def _delete_subject_content(self, subject_ref: str) -> None:
        erase_subject_from_public_store(self.public, subject_ref, self.now())
        with self.pending.transaction() as connection:
            connection.execute(
                "DELETE FROM pending_messages WHERE subject_ref=?", (subject_ref,)
            )

    def replay_erasure_tombstones(self) -> int:
        rows = self.erasure.execute(
            "SELECT subject_ref FROM erasure_tombstones WHERE expires_at>?",
            (self.now(),),
        ).fetchall()
        for row in rows:
            self._delete_subject_content(str(row[0]))
        with self.erasure.transaction() as connection:
            connection.execute(
                "DELETE FROM erasure_tombstones WHERE expires_at<=?", (self.now(),)
            )
        return len(rows)

    def apply_privacy_control(
        self, control: ControlRecord, crash_hook: Callable[[str], None] | None = None
    ) -> str:
        if control.action != "delete":
            return super().apply_privacy_control(control, crash_hook=crash_hook)
        if control.consumed_at is not None:
            return "replayed"
        if control.expires_at <= self.now():
            return "expired"
        with self.erasure.transaction() as connection:
            connection.execute(
                """INSERT INTO erasure_tombstones VALUES (?, ?, ?)
                   ON CONFLICT(subject_ref) DO UPDATE SET
                   changed_at=excluded.changed_at, expires_at=excluded.expires_at""",
                (
                    control.subject_ref,
                    self.now(),
                    self.now() + ERASURE_TOMBSTONE_RETENTION_SECONDS,
                ),
            )
        if crash_hook is not None:
            crash_hook("after_erasure_ledger")
        self._delete_subject_content(control.subject_ref)
        return "erased"

    def message_for_key(self, message_key: str) -> InboundMessage | None:
        row = self.public.execute(
            "SELECT * FROM messages WHERE message_key=? AND body IS NOT NULL",
            (message_key,),
        ).fetchone()
        if row is None:
            return None
        return InboundMessage(
            connection_id=str(row["connection_id"]),
            conversation_id=int(row["conversation_id"]),
            sender_id=int(row["sender_id"]),
            message_id=int(row["message_id"]),
            update_id=int(row["source_update_id"]),
            text=str(row["body"]),
            sent_at=datetime.fromtimestamp(int(row["sent_at"]), tz=UTC),
        )

    def model_safety_identifier(self, message: InboundMessage) -> str:
        """Return a provider-only stable identifier with no Telegram identifier."""

        value = f"{message.connection_id}:{message.conversation_id}:{message.sender_id}"
        return "safety_" + self.digest("openai_safety_identifier", value)[:48]

    def conversation(
        self,
        message: InboundMessage,
        *,
        max_items: int,
        max_characters: int,
    ) -> tuple[ConversationItem, ...]:
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        rows = self.public.execute(
            """SELECT role, body, happened_at FROM (
                   SELECT 'user' AS role, body, content_updated_at AS happened_at
                   FROM messages WHERE subject_ref=? AND connection_id=?
                       AND conversation_id=? AND body IS NOT NULL AND expires_at>?
                   UNION ALL
                   SELECT 'assistant' AS role, body, content_updated_at AS happened_at
                   FROM assistant_context WHERE subject_ref=? AND connection_id=?
                       AND conversation_id=? AND expires_at>?
               ) ORDER BY happened_at DESC LIMIT ?""",
            (
                subject,
                message.connection_id,
                message.conversation_id,
                self.now(),
                subject,
                message.connection_id,
                message.conversation_id,
                self.now(),
                max_items,
            ),
        ).fetchall()
        kept: list[ConversationItem] = []
        characters = 0
        for row in rows:
            text = str(row["body"])
            if characters + len(text) > max_characters:
                remaining = max_characters - characters
                if remaining <= 0:
                    break
                text = text[-remaining:]
            kept.append(ConversationItem(str(row["role"]), text))
            characters += len(text)
        kept.reverse()
        return tuple(kept)

    def add_assistant_context(
        self, message: InboundMessage, text: str, retention_seconds: int
    ) -> None:
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        now = self.now()
        item_id = uuid.uuid5(
            uuid.UUID("a1fb8c5d-ea92-4fc5-b299-d55cd17e9789"),
            f"{message.update_id}:assistant",
        ).hex
        with self.public.transaction() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO assistant_context VALUES
                   (?, ?, ?, ?, 'assistant', ?, ?, ?, ?, ?)""",
                (
                    item_id,
                    subject,
                    message.connection_id,
                    message.conversation_id,
                    text,
                    message.update_id,
                    now,
                    now,
                    now + retention_seconds,
                ),
            )

    @staticmethod
    def _cost(input_tokens: int, output_tokens: int, config: Unit2Config) -> int:
        return (
            input_tokens * config.input_microusd_per_million
            + output_tokens * config.output_microusd_per_million
            + 999_999
        ) // 1_000_000

    def reserve_model_call(
        self,
        message: InboundMessage,
        items: tuple[ConversationItem, ...],
        config: Unit2Config,
    ) -> str | None:
        day = datetime.fromtimestamp(self.now(), tz=UTC).date().isoformat()
        estimate = estimate_input_tokens(items)
        estimated_cost = self._cost(estimate, config.max_output_tokens, config)
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        reservation_id = uuid.uuid5(
            uuid.UUID("5f8c84a8-7148-4c2d-b3a3-a0f3a57c3034"),
            str(message.update_id),
        ).hex
        now = self.now()
        with self.public.transaction() as connection:
            existing = connection.execute(
                "SELECT reservation_id FROM model_reservations WHERE source_update_id=?",
                (message.update_id,),
            ).fetchone()
            if existing is not None:
                return None
            totals = connection.execute(
                """SELECT count(*),
                   COALESCE(sum(CASE WHEN state='reserved' THEN reserved_input_tokens
                       ELSE actual_input_tokens END), 0),
                   COALESCE(sum(CASE WHEN state='reserved' THEN reserved_output_tokens
                       ELSE actual_output_tokens END), 0),
                   COALESCE(sum(CASE WHEN state='reserved' THEN reserved_cost_microusd
                       ELSE actual_cost_microusd END), 0),
                   COALESCE(sum(CASE WHEN state='reserved' THEN 1 ELSE 0 END), 0)
                   FROM model_reservations WHERE day=?""",
                (day,),
            ).fetchone()
            if (
                int(totals[0]) + 1 > config.daily_call_limit
                or int(totals[1]) + estimate > config.daily_input_token_limit
                or int(totals[2]) + config.max_output_tokens
                > config.daily_output_token_limit
                or int(totals[3]) + estimated_cost > config.daily_cost_microusd_limit
                or int(totals[4]) >= config.concurrency_limit
            ):
                return None
            connection.execute(
                """INSERT INTO model_reservations VALUES
                   (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL,
                    'reserved', ?, ?)""",
                (
                    reservation_id,
                    message.update_id,
                    subject,
                    day,
                    estimate,
                    config.max_output_tokens,
                    estimated_cost,
                    now,
                    now,
                ),
            )
        return reservation_id

    def finish_model_call(
        self,
        reservation_id: str,
        result: ModelResult | None,
        config: Unit2Config,
    ) -> None:
        with self.public.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM model_reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            if row is None or row["state"] != "reserved":
                return
            uncertain = result is None
            if result is None:
                input_tokens = int(row["reserved_input_tokens"])
                output_tokens = int(row["reserved_output_tokens"])
                provider_request_ref = None
            else:
                input_tokens = result.input_tokens
                output_tokens = result.output_tokens
                provider_request_ref = result.provider_request_id
            cost = self._cost(input_tokens, output_tokens, config)
            connection.execute(
                """UPDATE model_reservations SET actual_input_tokens=?,
                   actual_output_tokens=?, actual_cost_microusd=?,
                   provider_request_ref=?, state=?, updated_at=?
                   WHERE reservation_id=?""",
                (
                    input_tokens,
                    output_tokens,
                    cost,
                    provider_request_ref,
                    "uncertain" if uncertain else "complete",
                    self.now(),
                    reservation_id,
                ),
            )

    def recover_model_reservations(self) -> int:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE model_reservations SET
                   actual_input_tokens=reserved_input_tokens,
                   actual_output_tokens=reserved_output_tokens,
                   actual_cost_microusd=reserved_cost_microusd,
                   state='uncertain', updated_at=? WHERE state='reserved'""",
                (self.now(),),
            )
        return max(int(cursor.rowcount), 0)

    def upsert_request(
        self, message: InboundMessage, body: str, retention_seconds: int
    ) -> str:
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        default_request_id = (
            "REQ-"
            + uuid.uuid5(
                uuid.UUID("4641cd62-c11d-4167-9218-e713060cb7d5"),
                f"{message.connection_id}:{message.conversation_id}:{message.message_id}",
            )
            .hex[:12]
            .upper()
        )
        now = self.now()
        message_key = self.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        with self.public.transaction() as connection:
            existing = connection.execute(
                """SELECT request_id FROM inbox_requests WHERE subject_ref=?
                   AND connection_id=? AND conversation_id=? AND state='open'
                   ORDER BY content_updated_at DESC LIMIT 1""",
                (subject, message.connection_id, message.conversation_id),
            ).fetchone()
            request_id = (
                str(existing[0]) if existing is not None else default_request_id
            )
            alert = f"Assistant Inbox request {request_id} is ready."
            connection.execute(
                """INSERT INTO inbox_requests VALUES
                   (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
                   ON CONFLICT(request_id) DO UPDATE SET body=excluded.body,
                   state='open', source_update_id=excluded.source_update_id,
                   content_updated_at=excluded.content_updated_at,
                   expires_at=excluded.expires_at""",
                (
                    request_id,
                    subject,
                    message.connection_id,
                    message.conversation_id,
                    body[:4000],
                    message.update_id,
                    now,
                    now,
                    now + retention_seconds,
                ),
            )
            connection.execute(
                """INSERT INTO notification_outbox VALUES
                   (?, ?, ?, 'pending', ?, ?)
                   ON CONFLICT(request_id) DO UPDATE SET state='pending',
                   updated_at=excluded.updated_at""",
                (
                    uuid.uuid5(
                        uuid.UUID("cfa8e9d4-01a2-4938-8e65-16ae17fb222b"),
                        request_id,
                    ).hex,
                    request_id,
                    alert,
                    now,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO request_sources VALUES (?, ?, ?)
                   ON CONFLICT(message_key) DO UPDATE SET
                   request_id=excluded.request_id,
                   source_update_id=excluded.source_update_id""",
                (message_key, request_id, message.update_id),
            )
        return request_id

    def supersede_message_artifacts(
        self, connection_id: str, conversation_id: int, message_ids: tuple[int, ...]
    ) -> None:
        """Remove Inbox/context/undelivered alerts derived from replaced text."""

        if not message_ids:
            return
        message_keys = tuple(
            self.message_key(connection_id, conversation_id, message_id)
            for message_id in message_ids
        )
        marks = ",".join("?" for _ in message_keys)
        with self.public.transaction() as connection:
            request_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    f"SELECT DISTINCT request_id FROM request_sources "
                    f"WHERE message_key IN ({marks})",
                    message_keys,
                ).fetchall()
            )
            if request_ids:
                request_marks = ",".join("?" for _ in request_ids)
                connection.execute(
                    f"DELETE FROM notification_outbox WHERE request_id IN ({request_marks})",
                    request_ids,
                )
                connection.execute(
                    f"DELETE FROM inbox_requests WHERE request_id IN ({request_marks})",
                    request_ids,
                )
                connection.execute(
                    f"DELETE FROM assistant_context WHERE source_update_id IN ("
                    f"SELECT source_update_id FROM request_sources "
                    f"WHERE request_id IN ({request_marks})"
                    f")",
                    request_ids,
                )
                connection.execute(
                    f"DELETE FROM request_sources WHERE request_id IN ({request_marks})",
                    request_ids,
                )
            connection.execute(
                f"""DELETE FROM assistant_context WHERE source_update_id IN (
                    SELECT update_id FROM processed_updates WHERE message_key IN ({marks})
                )""",
                message_keys,
            )

    def due_notifications(self) -> tuple[Notification, ...]:
        rows = self.public.execute(
            """SELECT notification_id, request_id, text FROM notification_outbox
               WHERE state='pending' ORDER BY created_at"""
        ).fetchall()
        return tuple(Notification(str(r[0]), str(r[1]), str(r[2])) for r in rows)

    def mark_notification_sending(self, notification_id: str) -> bool:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE notification_outbox SET state='sending', updated_at=?
                   WHERE notification_id=? AND state='pending'""",
                (self.now(), notification_id),
            )
        return int(cursor.rowcount) == 1

    def finish_notification(self, notification_id: str, state: str) -> None:
        if state not in {"sent", "uncertain", "failed"}:
            raise ValueError("invalid notification outcome")
        with self.public.transaction() as connection:
            connection.execute(
                """UPDATE notification_outbox SET state=?, updated_at=?
                   WHERE notification_id=? AND state='sending'""",
                (state, self.now(), notification_id),
            )

    def recover_sending_notifications(self) -> int:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE notification_outbox SET state='uncertain', updated_at=?
                   WHERE state='sending'""",
                (self.now(),),
            )
        return max(int(cursor.rowcount), 0)

    def create_privacy_reference(
        self, subject_ref: str, retention_seconds: int
    ) -> str | None:
        if self.public.execute(
            "SELECT 1 FROM privacy_references WHERE subject_ref=?",
            (subject_ref,),
        ).fetchone():
            return None
        reference = secrets.token_urlsafe(32)
        with self.public.transaction() as connection:
            connection.execute(
                "INSERT INTO privacy_references VALUES (?, ?, ?, ?, NULL)",
                (
                    self.digest("privacy_reference", reference),
                    subject_ref,
                    self.now(),
                    self.now() + retention_seconds,
                ),
            )
        return reference

    def replace_privacy_reference(
        self, subject_ref: str, retention_seconds: int
    ) -> str:
        """Replace an undisclosed reference after an interrupted callback replay."""

        with self.public.transaction() as connection:
            connection.execute(
                "DELETE FROM privacy_references WHERE subject_ref=?", (subject_ref,)
            )
        reference = self.create_privacy_reference(subject_ref, retention_seconds)
        if reference is None:
            raise RuntimeError("could not replace privacy reference")
        return reference

    def update_outcome(self, update_id: int) -> str | None:
        row = self.public.execute(
            "SELECT outcome FROM processed_updates WHERE update_id=?", (update_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    def extend_privacy_reference(
        self, subject_ref: str, retention_seconds: int
    ) -> None:
        with self.public.transaction() as connection:
            connection.execute(
                """UPDATE privacy_references SET expires_at=MAX(expires_at, ?)
                   WHERE subject_ref=? AND consumed_at IS NULL""",
                (self.now() + retention_seconds, subject_ref),
            )

    def prepare_erasure_preview(
        self,
        reference: str,
        attempt_ref: str,
        *,
        max_attempts: int = 5,
        window_seconds: int = 60 * 60,
    ) -> PrivacyPreviewResult:
        if max_attempts <= 0 or window_seconds <= 0:
            raise ValueError("privacy preview rate limit must be positive")
        window = self.now() - (self.now() % window_seconds)
        attempt_hash = self.digest("privacy_preview_attempt", attempt_ref)
        with self.public.transaction() as connection:
            attempts = connection.execute(
                """SELECT count(*) FROM privacy_attempts
                   WHERE attempt_ref=? AND window_start=?""",
                (attempt_hash, window),
            ).fetchone()[0]
            if int(attempts) >= max_attempts:
                return PrivacyPreviewResult("neutral")
            connection.execute(
                "INSERT INTO privacy_attempts VALUES (?, ?, ?, ?)",
                (secrets.token_hex(8), attempt_hash, window, self.now()),
            )
            row = connection.execute(
                """SELECT subject_ref FROM privacy_references
                   WHERE reference_hash=? AND consumed_at IS NULL AND expires_at>?""",
                (self.digest("privacy_reference", reference), self.now()),
            ).fetchone()
            if row is None:
                return PrivacyPreviewResult("neutral")
            preview_id = "ERASE-" + secrets.token_hex(8).upper()
            connection.execute(
                "INSERT INTO privacy_previews VALUES (?, ?, 'erase_subject', ?, ?, NULL)",
                (preview_id, row[0], self.now(), self.now() + 15 * 60),
            )
            connection.execute(
                """UPDATE privacy_references SET consumed_at=?
                   WHERE reference_hash=? AND consumed_at IS NULL""",
                (self.now(), self.digest("privacy_reference", reference)),
            )
        return PrivacyPreviewResult("preview_ready", preview_id)

    def expire_unit2(self, retention_seconds: int) -> int:
        now = self.now()
        with self.public.transaction() as connection:
            context = connection.execute(
                "DELETE FROM assistant_context WHERE expires_at<=?", (now,)
            ).rowcount
            requests = connection.execute(
                "DELETE FROM inbox_requests WHERE expires_at<=?", (now,)
            ).rowcount
            connection.execute(
                """DELETE FROM notification_outbox WHERE request_id NOT IN
                   (SELECT request_id FROM inbox_requests)"""
            )
            connection.execute(
                """DELETE FROM request_sources WHERE request_id NOT IN
                   (SELECT request_id FROM inbox_requests)"""
            )
            connection.execute(
                "DELETE FROM model_reservations WHERE created_at<=?",
                (now - retention_seconds,),
            )
            connection.execute(
                """DELETE FROM privacy_references WHERE expires_at<=?
                   AND subject_ref NOT IN (
                       SELECT subject_ref FROM messages WHERE expires_at>?
                       UNION SELECT subject_ref FROM assistant_context WHERE expires_at>?
                       UNION SELECT subject_ref FROM inbox_requests WHERE expires_at>?
                       UNION SELECT subject_ref FROM model_reservations
                   )""",
                (now, now, now, now),
            )
            connection.execute(
                "DELETE FROM privacy_previews WHERE expires_at<=?", (now,)
            )
            connection.execute(
                "DELETE FROM privacy_attempts WHERE window_start<?", (now - 86400,)
            )
        return max(int(context), 0) + max(int(requests), 0)

    def expire_public(self, retention_seconds: int) -> int:
        expired = super().expire_public(retention_seconds)
        return expired + self.expire_unit2(retention_seconds)

    def close(self) -> None:
        self.erasure.close()
        super().close()
