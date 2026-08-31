"""Public-side durable action intents for the Unit 3 Gate boundary."""

from __future__ import annotations

import json
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from src.external_read import ExternalRecord, ExternalRecordRef, ExternalSource
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    ActionResult,
    Operation,
    canonical_json,
)
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
CREATE TABLE IF NOT EXISTS meeting_offer_controls (
    control_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    options_action_id TEXT NOT NULL,
    offer_ref TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    processing_authorization_version TEXT NOT NULL,
    processing_authorization_revision INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    schedule_action_id TEXT,
    selection_update_id INTEGER,
    origin_reply_id TEXT,
    origin_message_id INTEGER,
    CHECK(
        (schedule_action_id IS NULL AND selection_update_id IS NULL)
        OR (schedule_action_id IS NOT NULL AND selection_update_id IS NOT NULL)
    ),
    UNIQUE(options_action_id, offer_ref, control_id)
);
CREATE INDEX IF NOT EXISTS idx_meeting_offer_controls_subject
    ON meeting_offer_controls(subject_ref, expires_at);
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


@dataclass(frozen=True)
class MeetingOfferControl:
    """One sender-bound Telegram callback carrying no Calendar detail."""

    callback_data: str
    start_at: int
    end_at: int
    duration_minutes: int


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
                if str(row["arguments_json"]) != canonical_json(dict(arguments)):
                    raise ValueError(
                        "one update cannot change its durable action binding"
                    )
                existing_action_id = str(row["action_id"])
                if existing_action_id == binding.action_id:
                    return binding
                legacy_fields = binding.as_dict()
                legacy_fields.pop("origin")
                legacy_fields["action_id"] = existing_action_id
                try:
                    return ActionBinding.from_legacy_public_dict(legacy_fields)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        "one update cannot change its durable action binding"
                    ) from exc
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

    def create_meeting_offer_controls(
        self,
        message: InboundMessage,
        binding: ActionBinding,
        slots: tuple[tuple[str, int, int, int], ...],
        retention_seconds: int,
    ) -> tuple[MeetingOfferControl, ...]:
        """Persist one sender-bound callback for each Gate-produced offer.

        The public store keeps an opaque offer reference and a token hash.  It
        never receives Calendar event data, free/busy responses, or a provider
        credential.
        """

        if (
            binding.operation is not Operation.MEETING_OPTIONS
            or binding.subject_id
            != self.subject_ref(
                message.connection_id, message.conversation_id, message.sender_id
            )
            or not binding.verify()
            or retention_seconds <= 0
        ):
            raise ValueError("meeting offer control binding is invalid")
        if any(
            not isinstance(offer_ref, str)
            or not offer_ref.startswith("OFR-")
            or not isinstance(start_at, int)
            or not isinstance(end_at, int)
            or end_at <= start_at
            or not isinstance(duration_minutes, int)
            or duration_minutes <= 0
            for offer_ref, start_at, end_at, duration_minutes in slots
        ):
            raise ValueError("meeting offer slots are invalid")
        now = self.now()
        expires_at = now + min(retention_seconds, 60 * 60)
        controls: list[MeetingOfferControl] = []
        with self.public.transaction() as connection:
            action = connection.execute(
                """SELECT subject_ref, operation, processing_authorization_version,
                          processing_authorization_revision
                   FROM public_action_intents WHERE action_id=?""",
                (binding.action_id,),
            ).fetchone()
            if (
                action is None
                or str(action["subject_ref"]) != binding.subject_id
                or str(action["operation"]) != Operation.MEETING_OPTIONS.value
                or str(action["processing_authorization_version"])
                != binding.processing_authorization_version
                or int(action["processing_authorization_revision"])
                != binding.processing_authorization_revision
            ):
                raise ValueError("meeting offer action is not durable")
            for offer_ref, start_at, end_at, duration_minutes in slots:
                token = secrets.token_urlsafe(18)
                callback_data = f"pa:mo:{token}"
                connection.execute(
                    """INSERT INTO meeting_offer_controls(
                           control_id, token_hash, options_action_id, offer_ref,
                           connection_id, conversation_id, sender_id, subject_ref,
                           processing_authorization_version,
                           processing_authorization_revision, expires_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        uuid.uuid4().hex,
                        self.digest("meeting_offer_control", token),
                        binding.action_id,
                        offer_ref,
                        message.connection_id,
                        message.conversation_id,
                        message.sender_id,
                        binding.subject_id,
                        binding.processing_authorization_version,
                        binding.processing_authorization_revision,
                        expires_at,
                    ),
                )
                controls.append(
                    MeetingOfferControl(
                        callback_data, start_at, end_at, duration_minutes
                    )
                )
        return tuple(controls)

    def prepare_meeting_selection(
        self,
        token: str,
        *,
        actor_id: int,
        conversation_id: int,
        connection_id: str,
        origin_message_id: int,
        callback_update_id: int,
    ) -> ActionBinding | None:
        """Consume a delivered offer control into one immutable schedule binding.

        Replays return the same binding.  A click cannot change the offer,
        identity, receipt revision, or action origin.
        """

        if (
            not token.startswith("pa:mo:")
            or callback_update_id < 0
            or origin_message_id < 0
        ):
            return None
        now = self.now()
        token_hash = self.digest("meeting_offer_control", token[6:])
        with self.public.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM meeting_offer_controls WHERE token_hash=?", (token_hash,)
            ).fetchone()
            if row is None or any(
                (
                    int(row["sender_id"]) != actor_id,
                    int(row["conversation_id"]) != conversation_id,
                    str(row["connection_id"]) != connection_id,
                    row["origin_reply_id"] is None,
                    row["origin_message_id"] is None,
                    int(row["origin_message_id"]) != origin_message_id,
                )
            ):
                return None
            selection_update_id = row["selection_update_id"]
            if (
                row["schedule_action_id"] is not None
                and selection_update_id is not None
            ):
                return ActionBinding.create(
                    subject_id=str(row["subject_ref"]),
                    connection_id=str(row["connection_id"]),
                    conversation_id=int(row["conversation_id"]),
                    update_id=int(selection_update_id),
                    request_id="SEL-" + str(row["control_id"]),
                    operation=Operation.MEETING_SCHEDULE,
                    arguments={"offer_ref": str(row["offer_ref"])},
                    processing_authorization_version=str(
                        row["processing_authorization_version"]
                    ),
                    processing_authorization_revision=int(
                        row["processing_authorization_revision"]
                    ),
                    processor_purpose=_PURPOSES[Operation.MEETING_SCHEDULE],
                )
            if row["consumed_at"] is not None or int(row["expires_at"]) <= now:
                return None
            binding = ActionBinding.create(
                subject_id=str(row["subject_ref"]),
                connection_id=str(row["connection_id"]),
                conversation_id=int(row["conversation_id"]),
                update_id=callback_update_id,
                request_id="SEL-" + str(row["control_id"]),
                operation=Operation.MEETING_SCHEDULE,
                arguments={"offer_ref": str(row["offer_ref"])},
                processing_authorization_version=str(
                    row["processing_authorization_version"]
                ),
                processing_authorization_revision=int(
                    row["processing_authorization_revision"]
                ),
                processor_purpose=_PURPOSES[Operation.MEETING_SCHEDULE],
            )
            existing = connection.execute(
                """SELECT action_id, arguments_json FROM public_action_intents
                   WHERE source_update_id=?""",
                (callback_update_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["action_id"]) != binding.action_id or str(
                    existing["arguments_json"]
                ) != canonical_json(dict(binding.arguments)):
                    return None
            else:
                connection.execute(
                    """INSERT INTO public_action_intents VALUES
                       (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, ?, ?, ?)""",
                    (
                        binding.action_id,
                        callback_update_id,
                        binding.subject_id,
                        binding.request_id,
                        binding.operation.value,
                        canonical_json(dict(binding.arguments)),
                        binding.processing_authorization_version,
                        binding.processing_authorization_revision,
                        binding.processor_purpose,
                        now,
                        now,
                        now + 90 * 24 * 60 * 60,
                    ),
                )
            cursor = connection.execute(
                """UPDATE meeting_offer_controls SET consumed_at=?,
                   schedule_action_id=?, selection_update_id=?
                   WHERE token_hash=? AND consumed_at IS NULL""",
                (now, binding.action_id, callback_update_id, token_hash),
            )
            if int(cursor.rowcount) != 1:
                return None
            return binding

    def create_meeting_owner_confirmation_request(self, binding: ActionBinding) -> str:
        """Publish one opaque, owner-confirmable Inbox request for a selection.

        The Inbox/outbox tables are the established public-to-owner notification
        path.  This request deliberately carries only the immutable action
        reference: Calendar offer detail remains in Policy Gate.
        """

        if (
            binding.operation is not Operation.MEETING_SCHEDULE
            or binding.origin is not ActionOrigin.PUBLIC_SENDER
            or not binding.verify()
        ):
            raise ValueError("meeting confirmation binding is invalid")
        now = self.now()
        request_id = (
            "REQ-"
            + self.digest("meeting_confirmation_request", binding.action_id)[
                :12
            ].upper()
        )
        body = (
            "Meeting selection requires exact owner confirmation. "
            f"Action reference: {binding.action_id}."
        )
        alert = f"Assistant Inbox request {request_id} is ready."
        with self.public.transaction() as connection:
            action = connection.execute(
                """SELECT subject_ref, request_id, source_update_id, operation,
                          processing_authorization_version,
                          processing_authorization_revision, expires_at
                   FROM public_action_intents WHERE action_id=?""",
                (binding.action_id,),
            ).fetchone()
            if (
                action is None
                or str(action["subject_ref"]) != binding.subject_id
                or str(action["request_id"]) != binding.request_id
                or int(action["source_update_id"]) != binding.update_id
                or str(action["operation"]) != Operation.MEETING_SCHEDULE.value
                or str(action["processing_authorization_version"])
                != binding.processing_authorization_version
                or int(action["processing_authorization_revision"])
                != binding.processing_authorization_revision
                or int(action["expires_at"]) <= now
            ):
                raise ValueError("meeting confirmation action is not durable")
            connection.execute(
                """INSERT INTO inbox_requests VALUES
                   (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
                   ON CONFLICT(request_id) DO UPDATE SET body=excluded.body,
                   state='open', source_update_id=excluded.source_update_id,
                   content_updated_at=excluded.content_updated_at,
                   expires_at=excluded.expires_at""",
                (
                    request_id,
                    binding.subject_id,
                    binding.connection_id,
                    binding.conversation_id,
                    body,
                    binding.update_id,
                    now,
                    now,
                    int(action["expires_at"]),
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
        return request_id

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
            "awaiting_owner_confirmation": "prepared",
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
            controls = connection.execute(
                "DELETE FROM meeting_offer_controls WHERE expires_at<=?",
                (self.now(),),
            )
        return max(int(cursor.rowcount), 0) + max(int(controls.rowcount), 0)

    def expire_public(self, retention_seconds: int) -> int:
        return super().expire_public(retention_seconds) + self.expire_unit3()
