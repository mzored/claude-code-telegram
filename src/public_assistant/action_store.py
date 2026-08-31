"""Public-side durable action intents for the Unit 3 Gate boundary."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from src.external_read import ExternalRecord, ExternalRecordRef, ExternalSource
from src.policy_gate.types import ActionBinding, ActionResult, Operation, canonical_json
from src.public_assistant.inbox import Unit2Store
from src.public_assistant.types import InboundMessage

UNIT3_PUBLIC_SCHEMA = """
CREATE TABLE IF NOT EXISTS public_action_intents (
    action_id TEXT PRIMARY KEY,
    source_update_id INTEGER NOT NULL UNIQUE,
    subject_ref TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    processing_authorization_version TEXT NOT NULL,
    processing_authorization_revision INTEGER NOT NULL,
    processor_purpose TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('prepared', 'succeeded', 'definite_failure', 'uncertain', 'denied')),
    result_code TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_public_action_subject
    ON public_action_intents(subject_ref, created_at);
CREATE TABLE IF NOT EXISTS integration_processing_receipts (
    subject_ref TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    revision INTEGER NOT NULL,
    processor_purposes_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('pending_activation', 'active', 'pending_revocation', 'revoked')),
    changed_at INTEGER NOT NULL
);
"""


_PURPOSES = {
    Operation.MEETING_OPTIONS: "meeting options",
    Operation.MEETING_SCHEDULE: "meeting scheduling",
    Operation.TASK_CREATE: "external task creation",
}


@dataclass(frozen=True)
class IntegrationAuthorization:
    subject_id: str
    version: str
    revision: int
    processor_purposes: Mapping[str, tuple[str, ...]]


class Unit3Store(Unit2Store):
    """Add action intents without changing Unit 1 or Unit 2 table contracts."""

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
        )
        self.public.connection.executescript(UNIT3_PUBLIC_SCHEMA)

    def managed_chat_reference(self, message: InboundMessage) -> str:
        envelope = (
            f"{message.connection_id}:{message.conversation_id}:{message.sender_id}"
        )
        return "MCHAT-" + self.digest("unit3_managed_chat", envelope)[:32]

    def begin_integration_activation(
        self,
        message: InboundMessage,
        version: str,
        revision: int,
        processor_purposes: Mapping[str, tuple[str, ...]],
    ) -> IntegrationAuthorization:
        if not version or revision <= 0 or not processor_purposes:
            raise ValueError("integration authorization receipt is incomplete")
        grants = {
            processor: tuple(sorted(set(purposes)))
            for processor, purposes in processor_purposes.items()
        }
        if any(not processor or not purposes for processor, purposes in grants.items()):
            raise ValueError("integration processor purposes are incomplete")
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        encoded = canonical_json(
            {processor: list(purposes) for processor, purposes in grants.items()}
        )
        with self.public.transaction() as connection:
            existing = connection.execute(
                """SELECT version, revision, processor_purposes_json, state
                   FROM integration_processing_receipts WHERE subject_ref=?""",
                (subject,),
            ).fetchone()
            if existing is not None and int(existing["revision"]) >= revision:
                if (
                    int(existing["revision"]) == revision
                    and str(existing["version"]) == version
                    and str(existing["processor_purposes_json"]) == encoded
                    and str(existing["state"]) in {"pending_activation", "active"}
                ):
                    return IntegrationAuthorization(subject, version, revision, grants)
                raise ValueError("integration authorization revision is stale")
            connection.execute(
                """INSERT INTO integration_processing_receipts
                   VALUES (?, ?, ?, ?, 'pending_activation', ?)
                   ON CONFLICT(subject_ref) DO UPDATE SET version=excluded.version,
                   revision=excluded.revision,
                   processor_purposes_json=excluded.processor_purposes_json,
                   state='pending_activation', changed_at=excluded.changed_at""",
                (subject, version, revision, encoded, self.now()),
            )
        return IntegrationAuthorization(subject, version, revision, grants)

    def acknowledge_integration_activation(
        self, authorization: IntegrationAuthorization
    ) -> None:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE integration_processing_receipts SET state='active',
                   changed_at=? WHERE subject_ref=? AND version=? AND revision=?
                   AND state IN ('pending_activation', 'active')""",
                (
                    self.now(),
                    authorization.subject_id,
                    authorization.version,
                    authorization.revision,
                ),
            )
            if int(cursor.rowcount) != 1:
                raise ValueError("integration activation acknowledgement is stale")

    def begin_integration_revocation(
        self, message: InboundMessage, revision: int
    ) -> str:
        if revision <= 0:
            raise ValueError("integration revocation revision must be positive")
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self.public.transaction() as connection:
            existing = connection.execute(
                """SELECT revision, state FROM integration_processing_receipts
                   WHERE subject_ref=?""",
                (subject,),
            ).fetchone()
            if existing is not None and int(existing["revision"]) >= revision:
                if int(existing["revision"]) == revision and str(existing["state"]) in {
                    "pending_revocation",
                    "revoked",
                }:
                    return subject
                raise ValueError("integration revocation revision is stale")
            if existing is None:
                connection.execute(
                    """INSERT INTO integration_processing_receipts VALUES
                       (?, '', ?, '{}', 'pending_revocation', ?)""",
                    (subject, revision, self.now()),
                )
            else:
                connection.execute(
                    """UPDATE integration_processing_receipts SET revision=?,
                       state='pending_revocation', changed_at=? WHERE subject_ref=?""",
                    (revision, self.now(), subject),
                )
        return subject

    def acknowledge_integration_revocation(
        self, subject_id: str, revision: int
    ) -> None:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """UPDATE integration_processing_receipts SET state='revoked',
                   changed_at=? WHERE subject_ref=? AND revision=?
                   AND state IN ('pending_revocation', 'revoked')""",
                (self.now(), subject_id, revision),
            )
            if int(cursor.rowcount) != 1:
                raise ValueError("integration revocation acknowledgement is stale")

    def active_integration_authorization(
        self, message: InboundMessage
    ) -> IntegrationAuthorization | None:
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        row = self.public.execute(
            """SELECT version, revision, processor_purposes_json
               FROM integration_processing_receipts
               WHERE subject_ref=? AND state='active'""",
            (subject,),
        ).fetchone()
        if row is None:
            return None
        raw = json.loads(str(row["processor_purposes_json"]))
        if not isinstance(raw, dict):
            raise ValueError("stored integration authorization is invalid")
        purposes = {
            str(processor): tuple(str(purpose) for purpose in values)
            for processor, values in raw.items()
            if isinstance(values, list)
        }
        if len(purposes) != len(raw):
            raise ValueError("stored integration authorization is invalid")
        return IntegrationAuthorization(
            subject,
            str(row["version"]),
            int(row["revision"]),
            purposes,
        )

    def resolve_external_inbox(
        self, reference: ExternalRecordRef
    ) -> ExternalRecord | None:
        """Resolve one unexpired Inbox body for the isolated Unit 4 broker only."""

        if reference.source is not ExternalSource.INBOX:
            return None
        row = self.public.execute(
            """SELECT inbox.request_id, inbox.subject_ref, inbox.connection_id,
                      inbox.conversation_id, inbox.source_update_id, inbox.body,
                      receipt.version, receipt.revision
               FROM inbox_requests AS inbox
               JOIN integration_processing_receipts AS receipt
                 ON receipt.subject_ref=inbox.subject_ref AND receipt.state='active'
               WHERE inbox.request_id=? AND inbox.state='open' AND inbox.expires_at>?""",
            (reference.value, self.now()),
        ).fetchone()
        if row is None:
            return None
        return ExternalRecord.create(
            reference,
            subject_id=str(row["subject_ref"]),
            connection_id=str(row["connection_id"]),
            conversation_id=int(row["conversation_id"]),
            update_id=int(row["source_update_id"]),
            request_id=str(row["request_id"]),
            processing_authorization_version=str(row["version"]),
            processing_authorization_revision=int(row["revision"]),
            content=str(row["body"]),
        )

    def active_erasure_subjects(self) -> tuple[str, ...]:
        """Return durable tombstones that must remain erased in Policy Gate."""

        rows = self.erasure.execute(
            "SELECT subject_ref FROM erasure_tombstones WHERE expires_at>?",
            (self.now(),),
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def prepare_action(
        self,
        message: InboundMessage,
        request_id: str,
        operation: Operation,
        arguments: Mapping[str, object],
        processing_authorization_version: str,
        processing_authorization_revision: int,
        retention_seconds: int,
    ) -> ActionBinding:
        subject = self.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        binding = ActionBinding.create(
            subject_id=subject,
            connection_id=message.connection_id,
            conversation_id=message.conversation_id,
            update_id=message.update_id,
            request_id=request_id,
            operation=operation,
            arguments=arguments,
            processing_authorization_version=processing_authorization_version,
            processing_authorization_revision=processing_authorization_revision,
            processor_purpose=_PURPOSES[operation],
        )
        now = self.now()
        with self.public.transaction() as connection:
            row = connection.execute(
                """SELECT action_id, arguments_json FROM public_action_intents
                   WHERE source_update_id=?""",
                (message.update_id,),
            ).fetchone()
            if row is not None:
                if str(row["action_id"]) != binding.action_id or str(
                    row["arguments_json"]
                ) != canonical_json(dict(arguments)):
                    raise ValueError(
                        "one update cannot change its durable action binding"
                    )
                return binding
            connection.execute(
                """INSERT INTO public_action_intents VALUES
                   (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, ?, ?, ?)""",
                (
                    binding.action_id,
                    message.update_id,
                    subject,
                    request_id,
                    operation.value,
                    canonical_json(dict(arguments)),
                    processing_authorization_version,
                    processing_authorization_revision,
                    binding.processor_purpose,
                    now,
                    now,
                    now + retention_seconds,
                ),
            )
        return binding

    def request_id_for_update(self, update_id: int) -> str | None:
        row = self.public.execute(
            "SELECT request_id FROM inbox_requests WHERE source_update_id=?",
            (update_id,),
        ).fetchone()
        return None if row is None else str(row["request_id"])

    @staticmethod
    def action_request_id(message: InboundMessage) -> str:
        return (
            "REQ-"
            + uuid.uuid5(
                uuid.UUID("4641cd62-c11d-4167-9218-e713060cb7d5"),
                f"{message.connection_id}:{message.conversation_id}:{message.message_id}",
            )
            .hex[:12]
            .upper()
        )

    def finish_action(self, result: ActionResult) -> None:
        public_state = {
            "verified_success": "succeeded",
            "replayed_success": "succeeded",
            "definite_failure": "definite_failure",
            "uncertain": "uncertain",
        }.get(result.outcome, "denied")
        with self.public.transaction() as connection:
            connection.execute(
                """UPDATE public_action_intents SET state=?, result_code=?, updated_at=?
                   WHERE action_id=? AND state!='succeeded'""",
                (public_state, result.outcome, self.now(), result.action_id),
            )

    def action_state(self, action_id: str) -> str | None:
        row = self.public.execute(
            "SELECT state FROM public_action_intents WHERE action_id=?", (action_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    def expire_unit3(self) -> int:
        with self.public.transaction() as connection:
            cursor = connection.execute(
                """DELETE FROM public_action_intents WHERE expires_at<=?
                   AND state IN ('succeeded', 'definite_failure', 'denied')""",
                (self.now(),),
            )
        return max(int(cursor.rowcount), 0)

    def expire_public(self, retention_seconds: int) -> int:
        return super().expire_public(retention_seconds) + self.expire_unit3()
