"""Persisted run origin assigned before any private-model execution."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from src.encrypted_sqlite import SqlCipherDatabase
from src.external_read import (
    ExternalRecordRef,
    ExternalSourceMetadata,
    external_link_identity,
)
from src.policy_gate.types import ExternalActionLink

_EXTERNAL_LINK_HASH_DOMAIN = b"assist-ai/private-external-link/v1\0"
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _external_link_hash(label: str, value: str) -> str:
    """Return the stable digest format already used by external intent links."""

    return hashlib.sha256(
        _EXTERNAL_LINK_HASH_DOMAIN
        + label.encode("utf-8")
        + b"\0"
        + value.encode("utf-8")
    ).hexdigest()


def external_subject_hash(subject_id: str) -> str:
    """Share the opaque subject identity with the public erasure coordinator."""

    return _external_link_hash("subject", subject_id)


class RunOrigin(str, Enum):
    DIRECT_OWNER = "direct_owner"
    PUBLIC_SENDER = "public_sender"
    EXTERNAL_EVENT = "external_event"
    SCHEDULED = "scheduled"


class RunSource(str, Enum):
    TELEGRAM = "telegram"
    TELEGRAM_CALLBACK = "telegram_callback"
    PUBLIC = "public"
    WEBHOOK = "webhook"
    EXTERNAL_HANDLER = "external_handler"
    SCHEDULED = "scheduled"
    CONTEXT_ONLY = "context_only"


@dataclass(frozen=True)
class RunTrigger:
    source: RunSource
    actor_id: int
    chat_id: int
    update_id: int
    message_id: int
    fresh: bool
    forwarded: bool = False
    context_only: bool = False
    resumed_session: bool = False


@dataclass(frozen=True)
class PersistedRun:
    run_id: str
    sequence: int
    origin: RunOrigin
    source: RunSource
    actor_id: int
    chat_id: int
    update_id: int
    message_id: int
    fresh: bool
    forwarded: bool
    context_only: bool
    resumed_session: bool


@dataclass(frozen=True)
class ExternalIntentLink:
    """Digest-only record needed to revalidate one external action at confirm time."""

    intent_id: str
    source: str
    reference_hash: str
    source_digest: str
    request_hash: str
    subject_hash: str
    prepare_run_id: str
    minimum_confirmation_sequence: int
    terminal_at: int | None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS private_run_origins (
    run_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL UNIQUE,
    origin TEXT NOT NULL,
    source TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
    update_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    fresh INTEGER NOT NULL,
    forwarded INTEGER NOT NULL,
    context_only INTEGER NOT NULL,
    resumed_session INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS controller_intent_runs (
    intent_id TEXT PRIMARY KEY,
    prepare_run_id TEXT NOT NULL,
    minimum_confirmation_sequence INTEGER NOT NULL,
    FOREIGN KEY(prepare_run_id) REFERENCES private_run_origins(run_id)
);
CREATE TABLE IF NOT EXISTS external_intent_links (
    intent_id TEXT PRIMARY KEY,
    source TEXT NOT NULL CHECK(source IN ('inbox', 'todoist')),
    reference_hash TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    subject_hash TEXT NOT NULL,
    prepare_run_id TEXT NOT NULL,
    minimum_confirmation_sequence INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    terminal_at INTEGER,
    FOREIGN KEY(intent_id) REFERENCES controller_intent_runs(intent_id),
    FOREIGN KEY(prepare_run_id) REFERENCES private_run_origins(run_id)
);
CREATE TABLE IF NOT EXISTS external_control_claims (
    run_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
    update_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(run_id) REFERENCES private_run_origins(run_id),
    UNIQUE(source, actor_id, chat_id, update_id, message_id)
);
CREATE TABLE IF NOT EXISTS erased_external_subjects (
    subject_hash TEXT PRIMARY KEY CHECK(
        length(subject_hash) = 64 AND subject_hash NOT GLOB '*[^0-9a-f]*'
    ),
    erased_at INTEGER NOT NULL
);
"""


class RunOriginLedger:
    """Small durable ledger; numeric identity never decides origin by itself."""

    def __init__(self, path: Path, key: str) -> None:
        self.database = SqlCipherDatabase(path, key, _SCHEMA)
        self._migrate_external_links()

    def _migrate_external_links(self) -> None:
        """Keep the digest-only controller link readable across Unit 4 upgrades."""

        columns = {
            str(row["name"])
            for row in self.database.execute(
                "PRAGMA table_info(external_intent_links)"
            ).fetchall()
        }
        if "terminal_at" not in columns:
            with self.database.transaction() as connection:
                connection.execute(
                    "ALTER TABLE external_intent_links ADD COLUMN terminal_at INTEGER"
                )

    @staticmethod
    def classify(
        trigger: RunTrigger, *, owner_id: int, control_chat_id: int
    ) -> RunOrigin:
        if trigger.source is RunSource.SCHEDULED:
            return RunOrigin.SCHEDULED
        if trigger.source in {
            RunSource.WEBHOOK,
            RunSource.EXTERNAL_HANDLER,
            RunSource.CONTEXT_ONLY,
        }:
            return RunOrigin.EXTERNAL_EVENT
        if trigger.source is RunSource.PUBLIC:
            return RunOrigin.PUBLIC_SENDER
        if (
            trigger.source in {RunSource.TELEGRAM, RunSource.TELEGRAM_CALLBACK}
            and trigger.fresh
            and not trigger.forwarded
            and not trigger.context_only
            and trigger.actor_id == owner_id
            and trigger.chat_id == control_chat_id
        ):
            return RunOrigin.DIRECT_OWNER
        return RunOrigin.PUBLIC_SENDER

    def begin(
        self, trigger: RunTrigger, *, owner_id: int, control_chat_id: int
    ) -> PersistedRun:
        origin = self.classify(
            trigger, owner_id=owner_id, control_chat_id=control_chat_id
        )
        run_id = "RUN-" + secrets.token_urlsafe(24)
        with self.database.transaction() as connection:
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM private_run_origins"
                ).fetchone()[0]
            )
            connection.execute(
                """INSERT INTO private_run_origins VALUES
                   (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())""",
                (
                    run_id,
                    sequence,
                    origin.value,
                    trigger.source.value,
                    trigger.actor_id,
                    trigger.chat_id,
                    trigger.update_id,
                    trigger.message_id,
                    int(trigger.fresh),
                    int(trigger.forwarded),
                    int(trigger.context_only),
                    int(trigger.resumed_session),
                ),
            )
        return PersistedRun(run_id, sequence, origin, **trigger.__dict__)

    def require(self, run_id: str) -> PersistedRun:
        row = self.database.execute(
            "SELECT * FROM private_run_origins WHERE run_id=?", (run_id,)
        ).fetchone()
        if row is None:
            raise PermissionError("private run origin was not persisted")
        return PersistedRun(
            run_id=str(row["run_id"]),
            sequence=int(row["sequence"]),
            origin=RunOrigin(str(row["origin"])),
            source=RunSource(str(row["source"])),
            actor_id=int(row["actor_id"]),
            chat_id=int(row["chat_id"]),
            update_id=int(row["update_id"]),
            message_id=int(row["message_id"]),
            fresh=bool(row["fresh"]),
            forwarded=bool(row["forwarded"]),
            context_only=bool(row["context_only"]),
            resumed_session=bool(row["resumed_session"]),
        )

    def origins(self) -> tuple[RunOrigin, ...]:
        """Return origin values only; never expose prompts through diagnostics."""

        rows = self.database.execute(
            "SELECT origin FROM private_run_origins ORDER BY rowid"
        ).fetchall()
        return tuple(RunOrigin(str(row[0])) for row in rows)

    def claim_external_control(self, run_id: str) -> None:
        """Consume one Telegram delivery before any external resolver is called."""

        run = self.require(run_id)
        with self.database.transaction() as connection:
            existing = connection.execute(
                """SELECT 1 FROM external_control_claims
                   WHERE source=? AND actor_id=? AND chat_id=?
                     AND update_id=? AND message_id=?""",
                (
                    run.source.value,
                    run.actor_id,
                    run.chat_id,
                    run.update_id,
                    run.message_id,
                ),
            ).fetchone()
            if existing is not None:
                raise PermissionError("external control delivery was replayed")
            connection.execute(
                """INSERT INTO external_control_claims VALUES
                   (?, ?, ?, ?, ?, ?, unixepoch())""",
                (
                    run.run_id,
                    run.source.value,
                    run.actor_id,
                    run.chat_id,
                    run.update_id,
                    run.message_id,
                ),
            )

    def link_intent(self, intent_id: str, prepare_run_id: str) -> None:
        self.require(prepare_run_id)
        with self.database.transaction() as connection:
            self._link_intent_locked(connection, intent_id, prepare_run_id)

    @staticmethod
    def _hash(label: str, value: str) -> str:
        return _external_link_hash(label, value)

    @staticmethod
    def _minimum_sequence(connection: object) -> int:
        execute = getattr(connection, "execute")
        return int(
            execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM private_run_origins"
            ).fetchone()[0]
        )

    def _link_intent_locked(
        self, connection: object, intent_id: str, prepare_run_id: str
    ) -> int:
        minimum_sequence = self._minimum_sequence(connection)
        execute = getattr(connection, "execute")
        execute(
            "INSERT INTO controller_intent_runs VALUES (?, ?, ?)",
            (intent_id, prepare_run_id, minimum_sequence),
        )
        return minimum_sequence

    def link_external_intent(
        self,
        intent_id: str,
        prepare_run_id: str,
        reference: ExternalRecordRef,
        metadata: ExternalSourceMetadata,
    ) -> None:
        """Persist only source hashes and the digest used to stage the exact action."""

        self.require(prepare_run_id)
        if metadata.reference != reference:
            raise ValueError("external source reference does not match metadata")
        subject_hash = external_subject_hash(metadata.subject_id)
        with self.database.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM erased_external_subjects WHERE subject_hash=?",
                    (subject_hash,),
                ).fetchone()
                is not None
            ):
                raise PermissionError("external subject was erased")
            minimum_sequence = self._link_intent_locked(
                connection, intent_id, prepare_run_id
            )
            connection.execute(
                """INSERT INTO external_intent_links VALUES
                   (?, ?, ?, ?, ?, ?, ?, ?, unixepoch(), NULL)""",
                (
                    intent_id,
                    reference.source.value,
                    reference.reference_hash(),
                    metadata.source_digest,
                    self._hash("request", metadata.request_id),
                    subject_hash,
                    prepare_run_id,
                    minimum_sequence,
                ),
            )

    def erase_external_subject_hash(self, subject_hash: str) -> None:
        """Tombstone one opaque subject and remove only its source-link rows.

        The durable hash tombstone makes a delayed controller activation fail
        closed instead of recreating a link after the public erasure converges.
        It stores no raw subject, reference, source body, or source digest.
        """

        if not isinstance(subject_hash, str) or not _SHA256_HEX.fullmatch(subject_hash):
            raise ValueError("external subject hash is invalid")
        with self.database.transaction() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO erased_external_subjects(subject_hash, erased_at)
                   VALUES (?, unixepoch())""",
                (subject_hash,),
            )
            intent_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT intent_id FROM external_intent_links WHERE subject_hash=?",
                    (subject_hash,),
                ).fetchall()
            )
            connection.execute(
                "DELETE FROM external_intent_links WHERE subject_hash=?",
                (subject_hash,),
            )
            for intent_id in intent_ids:
                connection.execute(
                    "DELETE FROM controller_intent_runs WHERE intent_id=?",
                    (intent_id,),
                )

    def has_external_link(self, intent_id: str) -> bool:
        return (
            self.database.execute(
                "SELECT 1 FROM external_intent_links WHERE intent_id=?", (intent_id,)
            ).fetchone()
            is not None
        )

    @staticmethod
    def _external_link_from_row(row: object) -> ExternalIntentLink:
        get = getattr(row, "__getitem__")
        return ExternalIntentLink(
            intent_id=str(get("intent_id")),
            source=str(get("source")),
            reference_hash=str(get("reference_hash")),
            source_digest=str(get("source_digest")),
            request_hash=str(get("request_hash")),
            subject_hash=str(get("subject_hash")),
            prepare_run_id=str(get("prepare_run_id")),
            minimum_confirmation_sequence=int(get("minimum_confirmation_sequence")),
            terminal_at=(
                None if get("terminal_at") is None else int(get("terminal_at"))
            ),
        )

    def external_intent_link(self, intent_id: str) -> ExternalIntentLink:
        """Load only the digest-only source link for one persisted intent."""

        row = self.database.execute(
            "SELECT * FROM external_intent_links WHERE intent_id=?", (intent_id,)
        ).fetchone()
        if row is None:
            raise PermissionError("administration intent has no external source link")
        return self._external_link_from_row(row)

    def external_gate_link(self, intent_id: str) -> ExternalActionLink:
        """Translate a durable controller link into Gate's strict opaque DTO."""

        link = self.external_intent_link(intent_id)
        return ExternalActionLink(
            external_link_identity(link.reference_hash, link.source_digest),
            link.source_digest,
        )

    def require_external_reference(
        self, intent_id: str, reference: ExternalRecordRef
    ) -> ExternalIntentLink:
        """Check a supplied opaque ref against the durable link without reading it."""

        link = self.external_intent_link(intent_id)
        if (
            link.source != reference.source.value
            or link.reference_hash != reference.reference_hash()
        ):
            raise PermissionError("external source reference does not match preview")
        return link

    def require_external_source_link(
        self,
        intent_id: str,
        reference: ExternalRecordRef,
        metadata: ExternalSourceMetadata,
    ) -> ExternalIntentLink:
        """Reject any source substitution or source-byte change before execution."""

        link = self.require_external_reference(intent_id, reference)
        if link.request_hash != self._hash(
            "request", metadata.request_id
        ) or link.subject_hash != external_subject_hash(metadata.subject_id):
            raise PermissionError("external source reference does not match preview")
        if link.source_digest != metadata.source_digest:
            raise PermissionError("external source changed after preview")
        return link

    def mark_external_terminal(self, intent_id: str) -> None:
        """Record only the time an exact external action reached Gate terminal state."""

        with self.database.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM external_intent_links WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
                is None
            ):
                raise PermissionError("external action has no terminal source link")
            connection.execute(
                """UPDATE external_intent_links SET terminal_at=unixepoch()
                   WHERE intent_id=? AND terminal_at IS NULL""",
                (intent_id,),
            )

    def require_second_fresh_control(
        self, intent_id: str, confirmation_run_id: str
    ) -> PersistedRun:
        confirmation = self.require(confirmation_run_id)
        row = self.database.execute(
            """SELECT prepare_run_id, minimum_confirmation_sequence
               FROM controller_intent_runs WHERE intent_id=?""",
            (intent_id,),
        ).fetchone()
        if row is None:
            raise PermissionError("administration intent has no trusted preparation")
        prepared = self.require(str(row[0]))
        if (
            confirmation.sequence <= int(row["minimum_confirmation_sequence"])
            or confirmation.run_id == prepared.run_id
            or confirmation.update_id == prepared.update_id
            or confirmation.message_id == prepared.message_id
            or not confirmation.fresh
            or confirmation.origin is not RunOrigin.DIRECT_OWNER
        ):
            raise PermissionError(
                "confirmation requires a fresh owner control after the preview"
            )
        return confirmation

    def close(self) -> None:
        self.database.close()


def origin_ledger_key(telegram_bot_token: str) -> str:
    """Derive a domain-separated at-rest key without persisting bot credentials."""

    if len(telegram_bot_token.encode("utf-8")) < 16:
        raise ValueError("Telegram credential is too short for key derivation")
    material = b"assist-ai/private-run-origin-ledger/v1\0" + telegram_bot_token.encode(
        "utf-8"
    )
    return hashlib.sha256(material).hexdigest()
