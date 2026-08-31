"""Transactional authorization, administration, journal, and recovery logic."""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, Callable, Mapping

from src.policy_gate.calendar import (
    CalendarApi,
    CalendarEvent,
    CalendarPolicy,
    candidate_blocks,
    deterministic_event_id,
    fresh_offer_ref,
)
from src.policy_gate.executors import (
    ExecutionOutcome,
    MockExecutor,
    ReconcileOutcome,
)
from src.policy_gate.store import GateStore
from src.policy_gate.todoist import (
    TodoistAddResult,
    TodoistApi,
    TodoistDeleteApi,
    TodoistPolicy,
    command_identity,
    item_add_command,
)
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    ActionResult,
    AdminDraft,
    AdminKind,
    AdminResult,
    CandidateProvenance,
    ExternalActionConfirmation,
    ExternalActionLink,
    MeetingOptionsResult,
    Operation,
    PreparedIntent,
    Scope,
    TrustedReference,
    canonical_json,
    digest,
)

_PURPOSES: dict[Operation, tuple[str, str]] = {
    Operation.MEETING_OPTIONS: ("Google Calendar", "meeting options"),
    Operation.MEETING_SCHEDULE: ("Google Calendar", "meeting scheduling"),
    Operation.TASK_CREATE: ("Todoist", "external task creation"),
}


@dataclass(frozen=True)
class PolicyConfig:
    """Reviewed code/deployment policy; operations are disabled by default."""

    enabled_operations: frozenset[Operation] = frozenset()
    allowed_durations: tuple[int, ...] = (30, 60)
    max_option_candidates: int = 3
    per_subject_daily_options: int = 8
    global_daily_options: int = 20
    per_subject_daily_meetings: int = 3
    per_subject_daily_tasks: int = 5
    global_daily_writes: int = 20
    attempts_per_subject_minute: int = 10
    attempts_global_minute: int = 30
    claim_lease_seconds: int = 60
    unresolved_write_breaker_threshold: int = 3
    minimum_meeting_notice_seconds: int = 2 * 60 * 60
    maximum_meeting_horizon_seconds: int = 30 * 24 * 60 * 60
    task_due_horizon_days: int = 90
    working_days: frozenset[int] = frozenset({0, 1, 2, 3, 4})
    working_hour_start_utc: int = 9
    working_hour_end_utc: int = 18
    calendar: CalendarPolicy = CalendarPolicy()
    todoist: TodoistPolicy = TodoistPolicy()


class PolicyGateService:
    """The only component that can turn persisted authority into an effect."""

    def __init__(
        self,
        store: GateStore,
        executor: MockExecutor,
        *,
        policy: PolicyConfig | None = None,
        calendar_api: CalendarApi | None = None,
        todoist_api: TodoistApi | None = None,
        todoist_erasure_api: TodoistDeleteApi | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not getattr(executor, "is_mock", False):
            raise ValueError("non-Calendar actions require a declared mock executor")
        selected_policy = policy or PolicyConfig()
        if selected_policy.calendar.enabled != (calendar_api is not None):
            raise ValueError("Calendar adapter and enablement must agree")
        if selected_policy.todoist.enabled != (todoist_api is not None):
            raise ValueError("Todoist adapter and enablement must agree")
        if selected_policy.calendar.enabled and not {
            Operation.MEETING_OPTIONS,
            Operation.MEETING_SCHEDULE,
        }.issubset(selected_policy.enabled_operations):
            raise ValueError("enabled Calendar requires both reviewed operations")
        if (
            selected_policy.todoist.enabled
            and Operation.TASK_CREATE not in selected_policy.enabled_operations
        ):
            raise ValueError("enabled Todoist requires task creation policy")
        self.store = store
        self.executor = executor
        self.policy = selected_policy
        self.calendar_api = calendar_api
        self.todoist_api = todoist_api
        self.todoist_erasure_api = todoist_erasure_api
        self._clock = clock
        self._locks_guard = threading.Lock()
        self._action_locks: dict[str, threading.Lock] = {}
        self._calendar_locks: dict[str, threading.Lock] = {}
        now = self.now()
        with self.store.database.transaction() as connection:
            for operation in Operation:
                connection.execute(
                    """INSERT INTO operation_policies(operation, enabled, changed_at)
                       VALUES (?, ?, ?) ON CONFLICT(operation) DO UPDATE SET
                       enabled=excluded.enabled, changed_at=excluded.changed_at""",
                    (
                        operation.value,
                        int(operation in self.policy.enabled_operations),
                        now,
                    ),
                )
            for name in ("reads", "writes"):
                connection.execute(
                    "INSERT OR IGNORE INTO breakers VALUES (?, 0, ?)", (name, now)
                )

    def now(self) -> int:
        return int(self._clock())

    def _action_lock(self, action_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._action_locks.setdefault(action_id, threading.Lock())

    def _calendar_lock(self) -> threading.Lock:
        with self._locks_guard:
            return self._calendar_locks.setdefault(
                self.policy.calendar.booking_calendar_id, threading.Lock()
            )

    @staticmethod
    def _stored_binding(value: object, *, allow_legacy_public: bool) -> ActionBinding:
        """Load a new binding or one verified pre-origin public envelope."""

        if not isinstance(value, dict):
            raise ValueError("stored action binding is invalid")
        try:
            return ActionBinding.from_dict(value)
        except (TypeError, ValueError):
            if not allow_legacy_public:
                raise
        return ActionBinding.from_legacy_public_dict(value)

    def register_subject(self, subject_id: str, references: Mapping[str, str]) -> None:
        if not subject_id or not references:
            raise ValueError("subject and trusted references are required")
        now = self.now()
        with self.store.database.transaction() as connection:
            subject = connection.execute(
                "SELECT blocked FROM subjects WHERE subject_id=?", (subject_id,)
            ).fetchone()
            if subject is not None and bool(subject["blocked"]):
                return
            connection.execute(
                "INSERT OR IGNORE INTO subjects VALUES (?, 0, 0, ?)",
                (subject_id, now),
            )
            for kind, value in references.items():
                if kind not in {"managed_chat", "request", "action"}:
                    raise ValueError("unsupported trusted subject reference kind")
                if len(value) < 8 or value.isdecimal():
                    raise ValueError("trusted subject references must be opaque")
                reference_hash = self.store.reference_hash(kind, value)
                existing = connection.execute(
                    "SELECT subject_id FROM subject_references WHERE reference_hash=?",
                    (reference_hash,),
                ).fetchone()
                if existing is not None and str(existing[0]) != subject_id:
                    raise ValueError("ambiguous trusted subject reference")
                connection.execute(
                    "INSERT OR IGNORE INTO subject_references VALUES (?, ?, ?, ?)",
                    (reference_hash, kind, subject_id, now),
                )

    def _resolve(self, reference: TrustedReference) -> str:
        if reference.kind not in {"managed_chat", "request", "action"}:
            raise ValueError("invalid trusted subject reference")
        if len(reference.value) < 8 or reference.value.isdecimal():
            raise ValueError("invalid trusted subject reference")
        row = self.store.database.execute(
            """SELECT subject_id FROM subject_references
               WHERE reference_hash=? AND kind=?""",
            (
                self.store.reference_hash(reference.kind, reference.value),
                reference.kind,
            ),
        ).fetchone()
        if row is None:
            raise ValueError("invalid trusted subject reference")
        return str(row[0])

    def _stage_candidate(
        self,
        binding: ActionBinding,
        provenance: CandidateProvenance,
        external_link: ExternalActionLink | None = None,
    ) -> bool:
        """Persist one immutable action with a provenance that cannot be relabelled."""

        if (
            not isinstance(provenance, CandidateProvenance)
            or not isinstance(binding.origin, ActionOrigin)
            or not binding.verify()
            or not self._validate_arguments(binding)
        ):
            return False
        if provenance is CandidateProvenance.ORDINARY_PUBLIC:
            if (
                external_link is not None
                or binding.origin is not ActionOrigin.PUBLIC_SENDER
            ):
                return False
        elif (
            not isinstance(external_link, ExternalActionLink)
            or binding.origin is not ActionOrigin.OWNER_EXTERNAL
        ):
            return False
        with self.store.database.transaction() as connection:
            subject = connection.execute(
                "SELECT blocked FROM subjects WHERE subject_id=?", (binding.subject_id,)
            ).fetchone()
            action_reference = connection.execute(
                """SELECT subject_id FROM subject_references
                   WHERE reference_hash=? AND kind='action'""",
                (self.store.reference_hash("action", binding.action_id),),
            ).fetchone()
            if (
                subject is None
                or bool(subject["blocked"])
                or action_reference is None
                or str(action_reference["subject_id"]) != binding.subject_id
                or not self._policy_allows(connection, binding.operation)
                or not self._receipt_allows(
                    connection,
                    binding.subject_id,
                    binding.processing_authorization_version,
                    binding.processing_authorization_revision,
                    binding.operation,
                )
            ):
                return False
            existing = connection.execute(
                """SELECT binding_digest, provenance, external_link_identity,
                          external_source_digest, binding_json
                   FROM candidate_actions WHERE action_id=?""",
                (binding.action_id,),
            ).fetchone()
            if existing is not None:
                return (
                    str(existing["binding_digest"]) == binding.binding_digest
                    and str(existing["binding_json"])
                    == canonical_json(binding.as_dict())
                    and str(existing["provenance"]) == provenance.value
                    and (
                        provenance is CandidateProvenance.ORDINARY_PUBLIC
                        or (
                            external_link is not None
                            and str(existing["external_link_identity"])
                            == external_link.link_identity
                            and str(existing["external_source_digest"])
                            == external_link.source_digest
                        )
                    )
                )
            if binding.uses_legacy_public_identity:
                # A pre-origin identity is recoverable only when the migrated
                # candidate already proves it.  No post-upgrade caller may
                # manufacture a second origin-free action ID.
                return False
            connection.execute(
                """INSERT INTO candidate_actions(
                       action_id, binding_digest, binding_json, subject_id, created_at,
                       provenance, external_link_identity, external_source_digest
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    binding.action_id,
                    binding.binding_digest,
                    canonical_json(binding.as_dict()),
                    binding.subject_id,
                    self.now(),
                    provenance.value,
                    None if external_link is None else external_link.link_identity,
                    None if external_link is None else external_link.source_digest,
                ),
            )
        return True

    def stage_action(self, binding: ActionBinding) -> bool:
        """Persist one immutable public proposal for possible exact approval."""

        return self._stage_candidate(binding, CandidateProvenance.ORDINARY_PUBLIC)

    def stage_owner_exact_action(
        self,
        request_reference: TrustedReference,
        binding: ActionBinding,
        external_link: ExternalActionLink,
    ) -> bool:
        """Stage one owner-authored Unit 4 task from an existing request reference.

        The controller cannot register arbitrary subjects or stage a generic public
        proposal. This narrow method binds one task-create action to the already
        registered request before reusing the normal immutable candidate path.
        """

        if (
            request_reference.kind != "request"
            or binding.operation is not Operation.TASK_CREATE
            or binding.request_id != request_reference.value
            or not isinstance(external_link, ExternalActionLink)
            or binding.origin is not ActionOrigin.OWNER_EXTERNAL
            or not binding.verify()
            or not self._validate_arguments(binding)
        ):
            return False
        try:
            subject_id = self._resolve(request_reference)
        except ValueError:
            return False
        if subject_id != binding.subject_id:
            return False
        try:
            self.register_subject(
                binding.subject_id,
                {"action": binding.action_id},
            )
        except ValueError:
            return False
        return self._stage_candidate(
            binding,
            CandidateProvenance.EXTERNAL_UNTRUSTED,
            external_link,
        )

    def _candidate_exact(
        self, reference: TrustedReference, subject_id: str
    ) -> tuple[ActionBinding, CandidateProvenance, ExternalActionLink | None]:
        row = self.store.database.execute(
            """SELECT binding_json, provenance, external_link_identity,
                      external_source_digest
               FROM candidate_actions WHERE action_id=? AND subject_id=?""",
            (reference.value, subject_id),
        ).fetchone()
        if row is None:
            raise ValueError("exact action reference is not staged")
        try:
            provenance = CandidateProvenance(str(row["provenance"]))
            value = json.loads(str(row["binding_json"]))
            binding = self._stored_binding(
                value,
                allow_legacy_public=(provenance is CandidateProvenance.ORDINARY_PUBLIC),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("staged exact action is invalid") from exc
        if not binding.verify() or binding.subject_id != subject_id:
            raise ValueError("staged exact action binding is invalid")
        if provenance is CandidateProvenance.ORDINARY_PUBLIC:
            if (
                row["external_link_identity"] is not None
                or row["external_source_digest"] is not None
                or binding.origin is not ActionOrigin.PUBLIC_SENDER
            ):
                raise ValueError("ordinary action provenance is invalid")
            return binding, provenance, None
        if binding.origin is not ActionOrigin.OWNER_EXTERNAL:
            raise ValueError("external action origin is invalid")
        try:
            external_link = ExternalActionLink(
                str(row["external_link_identity"]),
                str(row["external_source_digest"]),
            )
        except ValueError as exc:
            raise ValueError("external action provenance is invalid") from exc
        return binding, provenance, external_link

    def _hydrate_exact_draft(
        self, reference: TrustedReference, subject_id: str, draft: AdminDraft
    ) -> AdminDraft:
        if not (
            draft.kind is AdminKind.GRANT
            and draft.scope is Scope.EXACT
            and draft.operation is None
            and draft.exact_binding is None
            and reference.kind == "action"
        ):
            return draft
        binding, provenance, _ = self._candidate_exact(reference, subject_id)
        if provenance is not CandidateProvenance.ORDINARY_PUBLIC:
            raise ValueError("external action requires external controller preparation")
        return replace(draft, operation=binding.operation, exact_binding=binding)

    def _hydrate_external_exact_draft(
        self,
        reference: TrustedReference,
        subject_id: str,
        draft: AdminDraft,
        external_link: ExternalActionLink,
    ) -> AdminDraft:
        """Hydrate only a matching externally staged immutable task binding."""

        if not isinstance(external_link, ExternalActionLink):
            raise ValueError("external action link is invalid")
        if not (
            draft.kind is AdminKind.GRANT
            and draft.scope is Scope.EXACT
            and draft.operation is None
            and draft.exact_binding is None
            and reference.kind == "action"
        ):
            raise ValueError("external route requires one exact action")
        binding, provenance, staged_link = self._candidate_exact(reference, subject_id)
        if (
            provenance is not CandidateProvenance.EXTERNAL_UNTRUSTED
            or staged_link != external_link
        ):
            raise ValueError("external action provenance does not match")
        return replace(draft, operation=binding.operation, exact_binding=binding)

    def _external_exact_binding_from_payload(
        self, payload: object, subject_id: str
    ) -> ActionBinding | None:
        """Recover only the narrow immutable payload that Unit 4 may execute.

        This is deliberately independent of the normal administration-draft
        parser.  An encrypted-row mismatch must not turn an external intent
        into a block, a general delegation, or a public-origin exact action.
        """

        if not isinstance(payload, dict) or set(payload) != {
            "kind",
            "operation",
            "scope",
            "constraints",
            "expires_at",
            "remaining_uses",
            "exact_binding",
        }:
            return None
        exact = payload.get("exact_binding")
        if (
            payload.get("kind") != AdminKind.GRANT.value
            or payload.get("operation") != Operation.TASK_CREATE.value
            or payload.get("scope") != Scope.EXACT.value
            or payload.get("constraints") != {}
            or payload.get("expires_at") is not None
            or payload.get("remaining_uses") is not None
            or not isinstance(exact, dict)
        ):
            return None
        try:
            binding = ActionBinding.from_dict(exact)
        except (TypeError, ValueError):
            return None
        if (
            binding.subject_id != subject_id
            or binding.operation is not Operation.TASK_CREATE
            or binding.origin is not ActionOrigin.OWNER_EXTERNAL
            or not binding.verify()
            or not self._validate_arguments(binding)
        ):
            return None
        return binding

    def activate_receipt(
        self,
        subject_id: str,
        version: str,
        revision: int,
        processor_purposes: Mapping[str, tuple[str, ...]],
    ) -> bool:
        """Acknowledge only a newer locally durable integration receipt."""

        if revision <= 0 or not version or not processor_purposes:
            raise ValueError("processing receipt is incomplete")
        grants = {
            processor: sorted(set(purposes))
            for processor, purposes in processor_purposes.items()
        }
        now = self.now()
        with self.store.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO subjects VALUES (?, 0, 0, ?)",
                (subject_id, now),
            )
            subject = connection.execute(
                "SELECT blocked FROM subjects WHERE subject_id=?", (subject_id,)
            ).fetchone()
            if subject is None or bool(subject["blocked"]):
                return False
            row = connection.execute(
                """SELECT version, revision, grants_json, state
                   FROM processing_receipts WHERE subject_id=?""",
                (subject_id,),
            ).fetchone()
            encoded_grants = canonical_json(grants)
            if row is not None and int(row["revision"]) >= revision:
                return bool(
                    int(row["revision"]) == revision
                    and str(row["version"]) == version
                    and str(row["grants_json"]) == encoded_grants
                    and str(row["state"]) == "active"
                )
            connection.execute(
                """INSERT INTO processing_receipts
                   VALUES (?, ?, ?, ?, 'active', ?)
                   ON CONFLICT(subject_id) DO UPDATE SET version=excluded.version,
                   revision=excluded.revision, grants_json=excluded.grants_json,
                   state='active', changed_at=excluded.changed_at""",
                (subject_id, version, revision, encoded_grants, now),
            )
        return True

    def revoke_receipt(self, subject_id: str, revision: int) -> bool:
        if revision <= 0:
            raise ValueError("receipt revision must be positive")
        now = self.now()
        with self.store.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO subjects VALUES (?, 0, 0, ?)",
                (subject_id, now),
            )
            row = connection.execute(
                """SELECT revision, version, grants_json, state
                   FROM processing_receipts WHERE subject_id=?""",
                (subject_id,),
            ).fetchone()
            if row is not None and int(row[0]) >= revision:
                return bool(int(row[0]) == revision and str(row["state"]) == "revoked")
            if row is None:
                connection.execute(
                    "INSERT INTO processing_receipts VALUES (?, '', ?, '{}', 'revoked', ?)",
                    (subject_id, revision, now),
                )
            else:
                connection.execute(
                    """UPDATE processing_receipts SET revision=?, state='revoked',
                       changed_at=? WHERE subject_id=?""",
                    (revision, now, subject_id),
                )
            connection.execute(
                """UPDATE action_journal SET state='cancelled', outcome='consent_revoked',
                   updated_at=? WHERE subject_id=? AND state='definite_failure'""",
                (now, subject_id),
            )
        return True

    def _validate_draft(self, draft: AdminDraft) -> None:
        if draft.kind in {AdminKind.BLOCK, AdminKind.UNBLOCK}:
            if any(
                value is not None
                for value in (
                    draft.operation,
                    draft.scope,
                    draft.constraints,
                    draft.expires_at,
                    draft.remaining_uses,
                    draft.exact_binding,
                )
            ):
                raise ValueError("block controls accept no delegation fields")
            return
        if draft.kind is AdminKind.REVOKE:
            if draft.operation is None or any(
                value is not None
                for value in (
                    draft.scope,
                    draft.constraints,
                    draft.expires_at,
                    draft.remaining_uses,
                    draft.exact_binding,
                )
            ):
                raise ValueError("revocation requires only an operation")
            return
        if draft.kind is not AdminKind.GRANT or draft.operation is None:
            raise ValueError("delegation grant requires an operation")
        if draft.operation is Operation.MEETING_OPTIONS:
            raise ValueError("meeting options use global policy, not delegation")
        if draft.scope is Scope.EXACT:
            if (
                draft.exact_binding is None
                or draft.exact_binding.operation is not draft.operation
                or draft.expires_at is not None
                or draft.remaining_uses is not None
            ):
                raise ValueError("exact authority requires one matching binding")
            if not draft.exact_binding.verify():
                raise ValueError("exact action binding is invalid")
        elif draft.scope is Scope.BOUNDED:
            if draft.exact_binding is not None:
                raise ValueError("bounded authority cannot bind an exact action")
            if draft.expires_at is None and draft.remaining_uses is None:
                raise ValueError("bounded authority needs expiry or finite uses")
            if draft.expires_at is not None and draft.expires_at <= self.now():
                raise ValueError("bounded authority expiry must be in the future")
            if draft.remaining_uses is not None and draft.remaining_uses <= 0:
                raise ValueError("bounded authority uses must be positive")
        elif draft.scope is Scope.STANDING:
            if any(
                value is not None
                for value in (
                    draft.exact_binding,
                    draft.expires_at,
                    draft.remaining_uses,
                )
            ):
                raise ValueError("standing authority cannot expire or carry uses")
        else:
            raise ValueError("grant scope is required")
        allowed_constraints = {
            "allowed_durations",
            "max_title_length",
            "not_before",
            "before",
        }
        if draft.constraints and not set(draft.constraints).issubset(
            allowed_constraints
        ):
            raise ValueError("delegation contains an unknown constraint")
        constraints = dict(draft.constraints or {})
        if draft.operation is Operation.MEETING_SCHEDULE:
            allowed_for_operation = {"allowed_durations", "not_before", "before"}
        elif draft.operation is Operation.TASK_CREATE:
            allowed_for_operation = {"max_title_length"}
        else:
            allowed_for_operation = set()
        if not set(constraints).issubset(allowed_for_operation):
            raise ValueError("delegation constraint does not match its operation")
        durations = constraints.get("allowed_durations")
        if durations is not None:
            if (
                not isinstance(durations, (list, tuple))
                or not durations
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value not in self.policy.allowed_durations
                    for value in durations
                )
                or len(set(durations)) != len(durations)
            ):
                raise ValueError("allowed-durations constraint is invalid")
        maximum_title = constraints.get("max_title_length")
        if maximum_title is not None and (
            isinstance(maximum_title, bool)
            or not isinstance(maximum_title, int)
            or not 1 <= maximum_title <= 200
        ):
            raise ValueError("title-length constraint is invalid")
        not_before = constraints.get("not_before")
        before = constraints.get("before")
        for value in (not_before, before):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise ValueError("schedule-bound constraint is invalid")
        assert not_before is None or (
            isinstance(not_before, int) and not isinstance(not_before, bool)
        )
        assert before is None or (
            isinstance(before, int) and not isinstance(before, bool)
        )
        if (
            not_before is not None
            and before is not None
            and int(not_before) >= int(before)
        ):
            raise ValueError("schedule-bound constraints are inverted")
        if not_before is not None and int(not_before) < (
            self.now() + self.policy.minimum_meeting_notice_seconds
        ):
            raise ValueError("not-before constraint violates minimum notice")
        if before is not None and int(before) > (
            self.now() + self.policy.maximum_meeting_horizon_seconds
        ):
            raise ValueError("before constraint exceeds the schedule horizon")
        canonical_json(constraints)

    @staticmethod
    def _draft_payload(draft: AdminDraft) -> dict[str, object]:
        return {
            "kind": draft.kind.value,
            "operation": None if draft.operation is None else draft.operation.value,
            "scope": None if draft.scope is None else draft.scope.value,
            "constraints": dict(draft.constraints or {}),
            "expires_at": draft.expires_at,
            "remaining_uses": draft.remaining_uses,
            "exact_binding": (
                None if draft.exact_binding is None else draft.exact_binding.as_dict()
            ),
        }

    def prepare_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent:
        """Prepare only an ordinary-public administration intent."""

        return self._prepare_admin(
            reference,
            draft,
            owner_id,
            control_chat_id,
            preview_message_id,
            ttl_seconds,
            CandidateProvenance.ORDINARY_PUBLIC,
        )

    def prepare_external_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_link: ExternalActionLink,
        minimum_confirmation_sequence: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent:
        """Prepare one controller-only external-untrusted exact intent."""

        if not isinstance(external_link, ExternalActionLink):
            raise ValueError("external action link is invalid")
        if (
            not isinstance(minimum_confirmation_sequence, int)
            or isinstance(minimum_confirmation_sequence, bool)
            or minimum_confirmation_sequence <= 0
        ):
            raise ValueError("external confirmation sequence is invalid")
        return self._prepare_admin(
            reference,
            draft,
            owner_id,
            control_chat_id,
            preview_message_id,
            ttl_seconds,
            CandidateProvenance.EXTERNAL_UNTRUSTED,
            external_link,
            minimum_confirmation_sequence,
        )

    def _prepare_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        ttl_seconds: int,
        provenance: CandidateProvenance,
        external_link: ExternalActionLink | None = None,
        minimum_confirmation_sequence: int | None = None,
    ) -> PreparedIntent:
        if owner_id <= 0 or control_chat_id <= 0 or preview_message_id <= 0:
            raise ValueError("owner preview binding is incomplete")
        if ttl_seconds <= 0 or ttl_seconds > 900:
            raise ValueError("administration preview TTL is invalid")
        subject_id = self._resolve(reference)
        if provenance is CandidateProvenance.ORDINARY_PUBLIC:
            if external_link is not None or minimum_confirmation_sequence is not None:
                raise ValueError("ordinary preparation cannot carry external evidence")
            draft = self._hydrate_exact_draft(reference, subject_id, draft)
            if draft.exact_binding is not None:
                if draft.exact_binding.origin is not ActionOrigin.PUBLIC_SENDER:
                    raise ValueError(
                        "external action requires external controller preparation"
                    )
                existing = self.store.database.execute(
                    "SELECT provenance FROM candidate_actions WHERE action_id=?",
                    (draft.exact_binding.action_id,),
                ).fetchone()
                if existing is not None and str(existing["provenance"]) != (
                    CandidateProvenance.ORDINARY_PUBLIC.value
                ):
                    raise ValueError(
                        "external action requires external controller preparation"
                    )
        elif provenance is CandidateProvenance.EXTERNAL_UNTRUSTED:
            if external_link is None or minimum_confirmation_sequence is None:
                raise ValueError("external preparation evidence is incomplete")
            draft = self._hydrate_external_exact_draft(
                reference, subject_id, draft, external_link
            )
        else:
            raise ValueError("administration provenance is invalid")
        self._validate_draft(draft)
        if (
            draft.exact_binding is not None
            and draft.exact_binding.subject_id != subject_id
        ):
            raise ValueError("exact binding does not belong to the resolved subject")
        payload = self._draft_payload(draft)
        intent_id = "INT-" + secrets.token_urlsafe(24)
        now = self.now()
        expires = now + ttl_seconds
        with self.store.database.transaction() as connection:
            subject = connection.execute(
                "SELECT blocked, revision FROM subjects WHERE subject_id=?",
                (subject_id,),
            ).fetchone()
            if subject is None:
                raise ValueError("invalid trusted subject reference")
            revision = int(subject["revision"])
            old_state = {
                "blocked": bool(subject["blocked"]),
                "subject_revision": revision,
            }
            affected_delegation_ids: list[str] = []
            if draft.kind is AdminKind.REVOKE:
                assert draft.operation is not None
                affected_delegation_ids = [
                    str(row[0])
                    for row in connection.execute(
                        """SELECT delegation_id FROM delegations
                           WHERE subject_id=? AND operation=? AND status='active'
                           ORDER BY delegation_id""",
                        (subject_id, draft.operation.value),
                    ).fetchall()
                ]
            new_state = {
                "blocked": (
                    draft.kind is AdminKind.BLOCK
                    if draft.kind in {AdminKind.BLOCK, AdminKind.UNBLOCK}
                    else old_state["blocked"]
                ),
                "subject_revision": revision + 1,
                "delegation": payload if draft.kind is AdminKind.GRANT else None,
            }
            authority_delta = {
                "kind": draft.kind.value,
                "operation": (
                    None if draft.operation is None else draft.operation.value
                ),
                "affected_delegation_ids": affected_delegation_ids,
            }
            preview = {
                "old_state": old_state,
                "new_state": new_state,
                "authority_delta": authority_delta,
                **payload,
            }
            connection.execute(
                """INSERT INTO administration_intents(
                       intent_id, subject_id, kind, payload_json, old_state_json,
                       new_state_json, base_subject_revision, owner_id,
                       control_chat_id, preview_message_id, created_at, expires_at,
                       provenance, external_link_identity, external_source_digest,
                       external_minimum_confirmation_sequence, state, consumed_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL)""",
                (
                    intent_id,
                    subject_id,
                    draft.kind.value,
                    canonical_json(payload),
                    canonical_json(old_state),
                    canonical_json(new_state),
                    revision,
                    owner_id,
                    control_chat_id,
                    preview_message_id,
                    now,
                    expires,
                    provenance.value,
                    None if external_link is None else external_link.link_identity,
                    None if external_link is None else external_link.source_digest,
                    minimum_confirmation_sequence,
                ),
            )
        return PreparedIntent(intent_id, preview, expires)

    def confirm_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        *,
        crash_hook: Callable[[str], None] | None = None,
    ) -> AdminResult:
        """Confirm only an ordinary-public administration intent."""

        return self._confirm_admin(
            intent_id,
            owner_id,
            control_chat_id,
            preview_message_id,
            CandidateProvenance.ORDINARY_PUBLIC,
            crash_hook=crash_hook,
        )

    def confirm_external_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_confirmation: ExternalActionConfirmation,
        *,
        crash_hook: Callable[[str], None] | None = None,
    ) -> AdminResult:
        """Confirm one revalidated external-untrusted exact intent."""

        if not isinstance(external_confirmation, ExternalActionConfirmation):
            return AdminResult("denied")
        return self._confirm_admin(
            intent_id,
            owner_id,
            control_chat_id,
            preview_message_id,
            CandidateProvenance.EXTERNAL_UNTRUSTED,
            external_confirmation,
            crash_hook,
        )

    def _confirm_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        expected_provenance: CandidateProvenance,
        external_confirmation: ExternalActionConfirmation | None = None,
        crash_hook: Callable[[str], None] | None = None,
    ) -> AdminResult:
        exact_binding: ActionBinding | None = None
        exact_is_new = False
        now = self.now()
        with self.store.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM administration_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                return AdminResult("denied")
            if (
                int(row["owner_id"]) != owner_id
                or int(row["control_chat_id"]) != control_chat_id
                or int(row["preview_message_id"]) != preview_message_id
            ):
                return AdminResult("denied")
            try:
                provenance = CandidateProvenance(str(row["provenance"]))
            except ValueError:
                return AdminResult("denied")
            if provenance is not expected_provenance:
                return AdminResult("denied")
            if provenance is CandidateProvenance.ORDINARY_PUBLIC:
                if (
                    row["external_link_identity"] is not None
                    or row["external_source_digest"] is not None
                    or row["external_minimum_confirmation_sequence"] is not None
                ):
                    return AdminResult("denied")
            else:
                if external_confirmation is None:
                    return AdminResult("denied")
                try:
                    minimum_sequence = int(
                        row["external_minimum_confirmation_sequence"]
                    )
                except (TypeError, ValueError):
                    return AdminResult("denied")
                if (
                    str(row["external_link_identity"])
                    != external_confirmation.link.link_identity
                    or str(row["external_source_digest"])
                    != external_confirmation.link.source_digest
                    or external_confirmation.confirmation_sequence <= minimum_sequence
                ):
                    return AdminResult("denied")
            try:
                payload = json.loads(str(row["payload_json"]))
                kind = AdminKind(str(row["kind"]))
            except (TypeError, ValueError, json.JSONDecodeError):
                return AdminResult("denied")
            if not isinstance(payload, dict):
                return AdminResult("denied")
            external_exact_binding: ActionBinding | None = None
            if provenance is CandidateProvenance.EXTERNAL_UNTRUSTED:
                external_exact_binding = self._external_exact_binding_from_payload(
                    payload, str(row["subject_id"])
                )
                if kind is not AdminKind.GRANT or external_exact_binding is None:
                    return AdminResult("denied")
            if row["state"] == "applied":
                return AdminResult("replayed")
            if row["state"] in {"expired", "stale"}:
                return AdminResult(str(row["state"]))
            if row["state"] == "executing":
                if provenance is CandidateProvenance.EXTERNAL_UNTRUSTED:
                    exact_binding = external_exact_binding
                else:
                    if (
                        kind is not AdminKind.GRANT
                        or payload.get("scope") != Scope.EXACT.value
                    ):
                        return AdminResult("denied")
                    exact = payload.get("exact_binding")
                    if not isinstance(exact, dict):
                        return AdminResult("denied")
                    try:
                        exact_binding = self._stored_binding(
                            exact, allow_legacy_public=True
                        )
                    except (TypeError, ValueError):
                        return AdminResult("denied")
                    if (
                        exact_binding.subject_id != str(row["subject_id"])
                        or exact_binding.origin is not ActionOrigin.PUBLIC_SENDER
                        or not exact_binding.verify()
                        or not self._validate_arguments(exact_binding)
                    ):
                        return AdminResult("denied")
            else:
                exact_is_new = True
            # An executing exact intent already committed its authority mutation;
            # the immutable binding below resumes its idempotent action claim.
            if exact_binding is None and int(row["expires_at"]) <= now:
                connection.execute(
                    "UPDATE administration_intents SET state='expired' WHERE intent_id=?",
                    (intent_id,),
                )
                return AdminResult("expired")
            if exact_binding is None:
                subject = connection.execute(
                    "SELECT revision FROM subjects WHERE subject_id=?",
                    (row["subject_id"],),
                ).fetchone()
                if subject is None or int(subject[0]) != int(
                    row["base_subject_revision"]
                ):
                    connection.execute(
                        "UPDATE administration_intents SET state='stale' WHERE intent_id=?",
                        (intent_id,),
                    )
                    return AdminResult("stale")
                subject_id = str(row["subject_id"])
                revision = int(subject[0]) + 1
                if kind in {AdminKind.BLOCK, AdminKind.UNBLOCK}:
                    connection.execute(
                        "UPDATE subjects SET blocked=?, revision=?, changed_at=? WHERE subject_id=?",
                        (int(kind is AdminKind.BLOCK), revision, now, subject_id),
                    )
                elif kind is AdminKind.REVOKE:
                    connection.execute(
                        """UPDATE delegations SET status='revoked', revision=revision+1
                           WHERE subject_id=? AND operation=? AND status='active'""",
                        (subject_id, payload["operation"]),
                    )
                    connection.execute(
                        "UPDATE subjects SET revision=?, changed_at=? WHERE subject_id=?",
                        (revision, now, subject_id),
                    )
                else:
                    delegation_id = "DEL-" + secrets.token_urlsafe(18)
                    if provenance is CandidateProvenance.EXTERNAL_UNTRUSTED:
                        exact_binding = external_exact_binding
                    else:
                        exact = payload.get("exact_binding")
                        try:
                            exact_binding = (
                                None
                                if exact is None
                                else self._stored_binding(
                                    exact, allow_legacy_public=True
                                )
                            )
                        except (TypeError, ValueError):
                            return AdminResult("denied")
                    if exact_binding is not None and (
                        exact_binding.subject_id != subject_id
                        or not exact_binding.verify()
                        or not self._validate_arguments(exact_binding)
                        or (
                            provenance is CandidateProvenance.ORDINARY_PUBLIC
                            and exact_binding.origin is not ActionOrigin.PUBLIC_SENDER
                        )
                        or (
                            provenance is CandidateProvenance.EXTERNAL_UNTRUSTED
                            and exact_binding.origin is not ActionOrigin.OWNER_EXTERNAL
                        )
                    ):
                        return AdminResult("denied")
                    connection.execute(
                        """INSERT INTO delegations VALUES
                           (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                        (
                            delegation_id,
                            subject_id,
                            payload["operation"],
                            payload["scope"],
                            canonical_json(payload["constraints"]),
                            payload["expires_at"],
                            (
                                1
                                if payload["scope"] == Scope.EXACT.value
                                else payload["remaining_uses"]
                            ),
                            None if exact_binding is None else exact_binding.action_id,
                            (
                                None
                                if exact_binding is None
                                else exact_binding.payload_digest
                            ),
                            (
                                None
                                if exact_binding is None
                                else canonical_json(exact_binding.as_dict())
                            ),
                            intent_id,
                            now,
                            revision,
                        ),
                    )
                    connection.execute(
                        "UPDATE subjects SET revision=?, changed_at=? WHERE subject_id=?",
                        (revision, now, subject_id),
                    )
                intent_state = "executing" if exact_binding is not None else "applied"
                connection.execute(
                    """UPDATE administration_intents SET state=?, consumed_at=?
                       WHERE intent_id=? AND state='prepared'""",
                    (intent_state, now, intent_id),
                )
                connection.execute(
                    "INSERT INTO administration_audit VALUES (?, ?, ?, ?, ?)",
                    (
                        secrets.token_hex(16),
                        intent_id,
                        self.store.reference_hash("subject", subject_id),
                        intent_state,
                        now,
                    ),
                )
        if exact_binding is not None:
            if exact_is_new and crash_hook is not None:
                crash_hook("after_exact_intent_committed")
            action_result = (
                self._submit_owner_external_action(exact_binding)
                if expected_provenance is CandidateProvenance.EXTERNAL_UNTRUSTED
                else self.submit_action(exact_binding)
            )
            if action_result.outcome in {"verified_success", "replayed_success"}:
                with self.store.database.transaction() as connection:
                    connection.execute(
                        """UPDATE administration_intents SET state='applied',
                           consumed_at=? WHERE intent_id=? AND state='executing'""",
                        (self.now(), intent_id),
                    )
            return AdminResult("executed", action_result)
        return AdminResult("applied")

    def external_intent_execution_started(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_link: ExternalActionLink,
    ) -> bool:
        """Report only whether one matching external intent crossed commit."""

        if not isinstance(external_link, ExternalActionLink):
            return False

        row = self.store.database.execute(
            """SELECT subject_id, kind, payload_json, state, owner_id, control_chat_id,
                      preview_message_id, provenance, external_link_identity,
                      external_source_digest
               FROM administration_intents WHERE intent_id=?""",
            (intent_id,),
        ).fetchone()
        if row is None or (
            int(row["owner_id"]) != owner_id
            or int(row["control_chat_id"]) != control_chat_id
            or int(row["preview_message_id"]) != preview_message_id
            or str(row["kind"]) != AdminKind.GRANT.value
            or str(row["state"]) not in {"executing", "applied"}
            or str(row["provenance"]) != CandidateProvenance.EXTERNAL_UNTRUSTED.value
            or str(row["external_link_identity"]) != external_link.link_identity
            or str(row["external_source_digest"]) != external_link.source_digest
        ):
            return False
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, json.JSONDecodeError):
            return False
        return (
            self._external_exact_binding_from_payload(payload, str(row["subject_id"]))
            is not None
        )

    def subject_blocked(self, subject_id: str) -> bool:
        row = self.store.database.execute(
            "SELECT blocked FROM subjects WHERE subject_id=?", (subject_id,)
        ).fetchone()
        return bool(row and row[0])

    def erase_subject(self, subject_id: str) -> str:
        """Remove resolvers and payloads only after effects are reconcilable."""

        now = self.now()
        with self.store.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO subjects VALUES (?, 1, 0, ?)",
                (subject_id, now),
            )
            connection.execute(
                """UPDATE processing_receipts SET state='revoked', revision=revision+1,
                   grants_json='{}', changed_at=? WHERE subject_id=? AND state!='revoked'""",
                (now, subject_id),
            )
            connection.execute(
                """UPDATE delegations SET status='revoked', revision=revision+1
                   WHERE subject_id=? AND status='active'""",
                (subject_id,),
            )
            connection.execute(
                """UPDATE subjects SET blocked=1, revision=revision+1,
                   changed_at=? WHERE subject_id=?""",
                (now, subject_id),
            )
            connection.execute(
                "DELETE FROM candidate_actions WHERE subject_id=?", (subject_id,)
            )

        # A worker may have claimed an action immediately before the subject was
        # blocked.  Only an expired lease is safe to turn into recovery work;
        # a live claim remains pending so erasure never races an in-flight effect.
        self.recover_claimed_actions()
        rows = self.store.database.execute(
            """SELECT action_id FROM action_journal WHERE subject_id=?
               AND state='uncertain' AND origin=? ORDER BY created_at, action_id""",
            (subject_id, ActionOrigin.OWNER_EXTERNAL.value),
        ).fetchall()
        for row in rows:
            self._reconcile_owner_external_for_erasure(str(row["action_id"]))

        mappings = self.store.database.execute(
            """SELECT action_id, provider_task_id FROM todoist_task_mappings
               WHERE subject_id=? AND state='succeeded' AND provider_task_id IS NOT NULL
               ORDER BY action_id""",
            (subject_id,),
        ).fetchall()
        for mapping in mappings:
            if self.todoist_erasure_api is None:
                return "pending_erasure"
            try:
                deleted = self.todoist_erasure_api.delete_mapped_task(
                    str(mapping["provider_task_id"])
                )
            except BaseException:
                return "pending_erasure"
            if deleted is not True:
                return "pending_erasure"

        # Recheck after the private recovery pass.  Ordinary public uncertainty
        # deliberately remains generic reconciliation work; neither path can
        # submit a fresh effect during erasure.
        with self.store.database.transaction() as connection:
            unresolved = int(
                connection.execute(
                    """SELECT count(*) FROM action_journal WHERE subject_id=?
                       AND state IN ('claimed', 'uncertain')""",
                    (subject_id,),
                ).fetchone()[0]
            )
            if unresolved:
                return "pending_reconciliation"
            connection.execute(
                "DELETE FROM subject_references WHERE subject_id=?", (subject_id,)
            )
            connection.execute(
                """UPDATE delegations SET status='revoked', exact_binding_json=NULL,
                   revision=revision+1 WHERE subject_id=? AND status!='consumed'""",
                (subject_id,),
            )
            connection.execute(
                """UPDATE delegations SET exact_binding_json=NULL
                   WHERE subject_id=?""",
                (subject_id,),
            )
            connection.execute(
                "DELETE FROM administration_intents WHERE subject_id=?", (subject_id,)
            )
            connection.execute(
                "DELETE FROM calendar_offers WHERE subject_id=?", (subject_id,)
            )
            connection.execute(
                "DELETE FROM calendar_reservations WHERE subject_id=?", (subject_id,)
            )
            connection.execute(
                "DELETE FROM todoist_task_mappings WHERE subject_id=?", (subject_id,)
            )
            connection.execute(
                "INSERT OR IGNORE INTO todoist_erasure_tombstones VALUES (?, ?)",
                (digest({"todoist_subject": subject_id}), now),
            )
            connection.execute(
                """UPDATE action_journal SET binding_json='{}', updated_at=?
                   WHERE subject_id=?""",
                (now, subject_id),
            )
            connection.execute(
                "DELETE FROM quota_events WHERE subject_id=?", (subject_id,)
            )
        return "erased"

    def set_breaker(self, name: str, is_open: bool) -> None:
        if name not in {"reads", "writes"}:
            raise ValueError("unknown breaker")
        with self.store.database.transaction() as connection:
            connection.execute(
                "UPDATE breakers SET is_open=?, changed_at=? WHERE name=?",
                (int(is_open), self.now(), name),
            )

    def _receipt_allows(
        self,
        connection: Any,
        subject_id: str,
        version: str,
        revision: int,
        operation: Operation,
    ) -> bool:
        row = connection.execute(
            """SELECT version, revision, grants_json, state FROM processing_receipts
               WHERE subject_id=?""",
            (subject_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] != "active"
            or str(row["version"]) != version
            or int(row["revision"]) != revision
        ):
            return False
        processor, purpose = _PURPOSES[operation]
        grants = json.loads(str(row["grants_json"]))
        return purpose in grants.get(processor, [])

    def _policy_allows(self, connection: Any, operation: Operation) -> bool:
        row = connection.execute(
            "SELECT enabled FROM operation_policies WHERE operation=?",
            (operation.value,),
        ).fetchone()
        breaker = "reads" if operation is Operation.MEETING_OPTIONS else "writes"
        breaker_row = connection.execute(
            "SELECT is_open FROM breakers WHERE name=?", (breaker,)
        ).fetchone()
        return bool(row and row[0] and breaker_row and not breaker_row[0])

    def _active_delegations(
        self, connection: Any, subject_id: str, operation: Operation
    ) -> list[Any]:
        rows = connection.execute(
            """SELECT * FROM delegations WHERE subject_id=? AND operation=?
               AND status='active' ORDER BY
               CASE scope WHEN 'exact' THEN 0 WHEN 'bounded' THEN 1 ELSE 2 END,
               confirmed_at, delegation_id""",
            (subject_id, operation.value),
        ).fetchall()
        now = self.now()
        active: list[Any] = []
        for row in rows:
            if row["expires_at"] is not None and int(row["expires_at"]) <= now:
                connection.execute(
                    "UPDATE delegations SET status='expired' WHERE delegation_id=?",
                    (row["delegation_id"],),
                )
                continue
            if row["remaining_uses"] is not None and int(row["remaining_uses"]) <= 0:
                continue
            active.append(row)
        return active

    def allowed_actions(
        self,
        subject_id: str,
        processing_authorization_version: str,
        processing_authorization_revision: int,
    ) -> tuple[Operation, ...]:
        allowed: list[Operation] = []
        with self.store.database.transaction() as connection:
            subject = connection.execute(
                "SELECT blocked FROM subjects WHERE subject_id=?", (subject_id,)
            ).fetchone()
            if subject is None or subject["blocked"]:
                return ()
            for operation in Operation:
                # A reservation is created only by a trusted option callback.
                # It is deliberately never a public-model schema.
                if (
                    self.policy.calendar.enabled
                    and operation is Operation.MEETING_SCHEDULE
                ):
                    continue
                if not self._policy_allows(connection, operation):
                    continue
                if not self._receipt_allows(
                    connection,
                    subject_id,
                    processing_authorization_version,
                    processing_authorization_revision,
                    operation,
                ):
                    continue
                if operation is Operation.MEETING_OPTIONS:
                    if self._quota_available(connection, subject_id, operation):
                        allowed.append(operation)
                    continue
                delegations = self._active_delegations(
                    connection, subject_id, operation
                )
                if any(row["scope"] in {"bounded", "standing"} for row in delegations):
                    if self._quota_available(connection, subject_id, operation):
                        allowed.append(operation)
        return tuple(allowed)

    def meeting_options(self, binding: ActionBinding) -> MeetingOptionsResult:
        """Return only persisted safe slots for one policy-shaped request."""

        if (
            not self.policy.calendar.enabled
            or self.calendar_api is None
            or binding.operation is not Operation.MEETING_OPTIONS
            or binding.origin is not ActionOrigin.PUBLIC_SENDER
            or not binding.verify()
            or not self._validate_arguments(binding)
        ):
            return MeetingOptionsResult(
                "denied", binding.action_id, timezone=self.policy.calendar.timezone
            )
        with self._action_lock(binding.action_id):
            now = self.now()
            with self.store.database.transaction() as connection:
                existing = connection.execute(
                    """SELECT offer_ref, start_at, end_at, duration_minutes
                       FROM calendar_offers WHERE action_id=? AND subject_id=?
                       AND expires_at>? AND consumed_at IS NULL ORDER BY start_at""",
                    (binding.action_id, binding.subject_id, now),
                ).fetchall()
                if existing:
                    return MeetingOptionsResult(
                        "verified_success",
                        binding.action_id,
                        tuple(
                            (
                                str(row["offer_ref"]),
                                int(row["start_at"]),
                                int(row["end_at"]),
                                int(row["duration_minutes"]),
                            )
                            for row in existing
                        ),
                        self.policy.calendar.timezone,
                    )
                if self._authorize_claim(connection, binding) is not None:
                    return MeetingOptionsResult(
                        "denied",
                        binding.action_id,
                        timezone=self.policy.calendar.timezone,
                    )
            args = binding.arguments
            assert isinstance(args["date"], str)
            assert isinstance(args["duration_minutes"], int)
            assert isinstance(args["candidate_count"], int)
            requested_date = date.fromisoformat(args["date"])
            blocks = tuple(
                block
                for block in candidate_blocks(
                    self.policy.calendar,
                    requested_date,
                    args["duration_minutes"],
                    now + self.policy.minimum_meeting_notice_seconds,
                )
                if block.start_at <= now + self.policy.maximum_meeting_horizon_seconds
            )
            if not blocks:
                return MeetingOptionsResult(
                    "verified_success",
                    binding.action_id,
                    timezone=self.policy.calendar.timezone,
                )
            # Provider reads are a quota-bearing capability, not an idempotent
            # action result.  A cached offer returns above without a new read;
            # every real free/busy attempt gets an independent durable debit.
            read_attempt_id = "calendar-read-" + secrets.token_hex(16)
            with self.store.database.transaction() as connection:
                if self._authorize_claim(connection, binding) is not None:
                    return MeetingOptionsResult(
                        "denied",
                        binding.action_id,
                        timezone=self.policy.calendar.timezone,
                    )
                connection.execute(
                    "INSERT INTO quota_events VALUES (?, ?, ?, ?, ?, 'succeeded', ?)",
                    (
                        read_attempt_id,
                        binding.subject_id,
                        binding.operation.value,
                        now // 86400,
                        now // 60,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO action_attempts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        secrets.token_hex(16),
                        binding.action_id,
                        binding.subject_id,
                        binding.operation.value,
                        now // 60,
                        now,
                    ),
                )
            try:
                busy = self.calendar_api.free_busy(
                    self.policy.calendar.availability_calendar_ids,
                    min(item.start_at for item in blocks),
                    max(item.end_at for item in blocks),
                )
            except BaseException:
                self.set_breaker("reads", True)
                return MeetingOptionsResult(
                    "unavailable",
                    binding.action_id,
                    timezone=self.policy.calendar.timezone,
                )
            available = [
                block
                for block in blocks
                if not any(
                    item.start_at < block.end_at and item.end_at > block.start_at
                    for item in busy
                )
            ][: args["candidate_count"]]
            policy_digest = self._calendar_policy_digest(args["duration_minutes"])
            with self.store.database.transaction() as connection:
                if (
                    self._authorize_claim(connection, binding, require_quota=False)
                    is not None
                ):
                    return MeetingOptionsResult(
                        "denied",
                        binding.action_id,
                        timezone=self.policy.calendar.timezone,
                    )
                slots: list[tuple[str, int, int, int]] = []
                for block in available:
                    offer = fresh_offer_ref()
                    start_at = (
                        block.start_at + self.policy.calendar.before_buffer_minutes * 60
                    )
                    end_at = (
                        block.end_at - self.policy.calendar.after_buffer_minutes * 60
                    )
                    if end_at - start_at != args["duration_minutes"] * 60:
                        continue
                    connection.execute(
                        "INSERT INTO calendar_offers VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                        (
                            offer,
                            binding.action_id,
                            binding.subject_id,
                            start_at,
                            end_at,
                            args["duration_minutes"],
                            policy_digest,
                            now + self.policy.calendar.offer_ttl_seconds,
                        ),
                    )
                    slots.append((offer, start_at, end_at, args["duration_minutes"]))
            return MeetingOptionsResult(
                "verified_success",
                binding.action_id,
                tuple(slots),
                self.policy.calendar.timezone,
            )

    def _calendar_policy_digest(self, duration_minutes: int) -> str:
        return digest(
            {
                "booking": self.policy.calendar.booking_calendar_id,
                "availability": self.policy.calendar.availability_calendar_ids,
                "timezone": self.policy.calendar.timezone,
                "days": sorted(self.policy.calendar.working_days),
                "hours": [
                    self.policy.calendar.working_hour_start,
                    self.policy.calendar.working_hour_end,
                ],
                "grid": self.policy.calendar.grid_minutes,
                "buffers": [
                    self.policy.calendar.before_buffer_minutes,
                    self.policy.calendar.after_buffer_minutes,
                ],
                "offer_ttl": self.policy.calendar.offer_ttl_seconds,
                "namespace": self.policy.calendar.namespace,
                "duration": duration_minutes,
                "allowed_durations": self.policy.allowed_durations,
                "minimum_notice": self.policy.minimum_meeting_notice_seconds,
                "maximum_horizon": self.policy.maximum_meeting_horizon_seconds,
            }
        )

    def _calendar_offer(
        self, connection: Any, binding: ActionBinding, *, include_consumed: bool = False
    ) -> Any | None:
        if (
            not self.policy.calendar.enabled
            or binding.operation is not Operation.MEETING_SCHEDULE
        ):
            return None
        reference = binding.arguments.get("offer_ref")
        if not isinstance(reference, str):
            return None
        query = """SELECT * FROM calendar_offers WHERE offer_ref=? AND subject_id=?
                   AND expires_at>?"""
        if not include_consumed:
            query += " AND consumed_at IS NULL"
        offer = connection.execute(
            query, (reference, binding.subject_id, self.now())
        ).fetchone()
        if offer is None or str(offer["policy_digest"]) != self._calendar_policy_digest(
            int(offer["duration_minutes"])
        ):
            return None
        return offer

    def _validate_arguments(self, binding: ActionBinding) -> bool:
        try:
            canonical_json(dict(binding.arguments))
        except ValueError:
            return False
        args = binding.arguments
        if binding.operation is Operation.MEETING_OPTIONS:
            if not (
                set(args) == {"date", "duration_minutes", "candidate_count"}
                and isinstance(args["date"], str)
                and isinstance(args["duration_minutes"], int)
                and args["duration_minutes"] in self.policy.allowed_durations
                and isinstance(args["candidate_count"], int)
                and 1 <= args["candidate_count"] <= self.policy.max_option_candidates
            ):
                return False
            try:
                requested_date = date.fromisoformat(args["date"])
            except ValueError:
                return False
            zone = self.policy.calendar.zone if self.policy.calendar.enabled else UTC
            today = datetime.fromtimestamp(self.now(), tz=zone).date()
            return (
                today
                <= requested_date
                <= today
                + timedelta(seconds=self.policy.maximum_meeting_horizon_seconds)
            )
        if binding.operation is Operation.MEETING_SCHEDULE:
            if self.policy.calendar.enabled:
                return (
                    set(args) == {"offer_ref"}
                    and isinstance(args["offer_ref"], str)
                    and args["offer_ref"].startswith("OFR-")
                    and 12 <= len(args["offer_ref"]) <= 128
                )
            if not (
                set(args) == {"start_at", "duration_minutes"}
                and isinstance(args["start_at"], int)
                and isinstance(args["duration_minutes"], int)
                and args["duration_minutes"] in self.policy.allowed_durations
                and self.now() + self.policy.minimum_meeting_notice_seconds
                <= args["start_at"]
                <= self.now() + self.policy.maximum_meeting_horizon_seconds
            ):
                return False
            start = datetime.fromtimestamp(args["start_at"], tz=UTC)
            end = start + timedelta(minutes=args["duration_minutes"])
            return (
                start.weekday() in self.policy.working_days
                and start.hour >= self.policy.working_hour_start_utc
                and (
                    end.hour < self.policy.working_hour_end_utc
                    or (
                        end.hour == self.policy.working_hour_end_utc and end.minute == 0
                    )
                )
            )
        if not (
            set(args) == {"title", "due_date"}
            and isinstance(args["title"], str)
            and 0 < len(args["title"].strip()) <= 200
            and (args["due_date"] is None or isinstance(args["due_date"], str))
        ):
            return False
        if args["due_date"] is None:
            return True
        try:
            due_date = date.fromisoformat(args["due_date"])
        except ValueError:
            return False
        today = datetime.fromtimestamp(self.now(), tz=UTC).date()
        return (
            today
            <= due_date
            <= today + timedelta(days=self.policy.task_due_horizon_days)
        )

    def _constraints_allow(
        self, delegation: Any, binding: ActionBinding, offer: Any | None = None
    ) -> bool:
        constraints = json.loads(str(delegation["constraints_json"]))
        args = binding.arguments
        durations = constraints.get("allowed_durations")
        duration = (
            args.get("duration_minutes")
            if offer is None
            else int(offer["duration_minutes"])
        )
        if durations is not None and duration not in durations:
            return False
        maximum = constraints.get("max_title_length")
        if maximum is not None and len(str(args.get("title", ""))) > int(maximum):
            return False
        offered_start = None if offer is None else int(offer["start_at"])
        before = constraints.get("before")
        if before is not None:
            start_at = (
                offered_start if offered_start is not None else args.get("start_at")
            )
            if not isinstance(start_at, int) or start_at >= int(before):
                return False
        not_before = constraints.get("not_before")
        if not_before is not None:
            start_at = (
                offered_start if offered_start is not None else args.get("start_at")
            )
            if not isinstance(start_at, int) or start_at < int(not_before):
                return False
        return True

    def _quota_available(
        self, connection: Any, subject_id: str, operation: Operation
    ) -> bool:
        now = self.now()
        day = now // 86400
        minute = now // 60
        subject_attempts = int(
            connection.execute(
                """SELECT count(*) FROM action_attempts WHERE subject_id=?
                   AND created_at>=?""",
                (subject_id, minute * 60),
            ).fetchone()[0]
        )
        global_attempts = int(
            connection.execute(
                "SELECT count(*) FROM action_attempts WHERE created_at>=?",
                (minute * 60,),
            ).fetchone()[0]
        )
        if (
            subject_attempts >= self.policy.attempts_per_subject_minute
            or global_attempts >= self.policy.attempts_global_minute
        ):
            return False
        active_states = ("reserved", "succeeded", "uncertain")
        placeholders = ",".join("?" for _ in active_states)
        subject_count = int(
            connection.execute(
                f"""SELECT count(*) FROM quota_events WHERE subject_id=?
                    AND operation=? AND day=? AND state IN ({placeholders})""",
                (subject_id, operation.value, day, *active_states),
            ).fetchone()[0]
        )
        global_count = int(
            connection.execute(
                f"""SELECT count(*) FROM quota_events WHERE operation=? AND day=?
                    AND state IN ({placeholders})""",
                (operation.value, day, *active_states),
            ).fetchone()[0]
        )
        if operation is Operation.MEETING_OPTIONS:
            return (
                subject_count < self.policy.per_subject_daily_options
                and global_count < self.policy.global_daily_options
            )
        limit = (
            self.policy.per_subject_daily_meetings
            if operation is Operation.MEETING_SCHEDULE
            else self.policy.per_subject_daily_tasks
        )
        global_writes = int(
            connection.execute(
                f"""SELECT count(*) FROM quota_events WHERE day=?
                    AND operation IN (?, ?) AND state IN ({placeholders})""",
                (
                    day,
                    Operation.MEETING_SCHEDULE.value,
                    Operation.TASK_CREATE.value,
                    *active_states,
                ),
            ).fetchone()[0]
        )
        return subject_count < limit and global_writes < self.policy.global_daily_writes

    def _authorize_claim(
        self,
        connection: Any,
        binding: ActionBinding,
        *,
        require_unused_offer: bool = True,
        require_quota: bool = True,
    ) -> Any | None | bool:
        subject = connection.execute(
            "SELECT blocked FROM subjects WHERE subject_id=?", (binding.subject_id,)
        ).fetchone()
        if subject is None or subject["blocked"]:
            return False
        if not self._policy_allows(connection, binding.operation):
            return False
        if not self._receipt_allows(
            connection,
            binding.subject_id,
            binding.processing_authorization_version,
            binding.processing_authorization_revision,
            binding.operation,
        ):
            return False
        expected_purpose = _PURPOSES[binding.operation][1]
        if binding.processor_purpose != expected_purpose:
            return False
        if require_quota and not self._quota_available(
            connection, binding.subject_id, binding.operation
        ):
            return False
        if binding.operation is Operation.MEETING_OPTIONS:
            return None
        offer = None
        if binding.operation is Operation.MEETING_SCHEDULE:
            offer = self._calendar_offer(
                connection, binding, include_consumed=not require_unused_offer
            )
            if self.policy.calendar.enabled and offer is None:
                return False
        delegations = self._active_delegations(
            connection, binding.subject_id, binding.operation
        )
        for row in delegations:
            if row["scope"] == Scope.EXACT.value:
                if (
                    row["exact_action_id"] == binding.action_id
                    and row["exact_payload_digest"] == binding.payload_digest
                ):
                    return row
                continue
            if (
                binding.origin is ActionOrigin.PUBLIC_SENDER
                and self._constraints_allow(row, binding, offer)
            ):
                return row
        return False

    def _reservation_is_still_authorized(
        self, connection: Any, binding: ActionBinding, claim_token: str
    ) -> bool:
        """Recheck revocation without re-consuming the already-reserved scope."""

        subject = connection.execute(
            "SELECT blocked FROM subjects WHERE subject_id=?", (binding.subject_id,)
        ).fetchone()
        if (
            subject is None
            or subject["blocked"]
            or not self._policy_allows(connection, binding.operation)
        ):
            return False
        if not self._receipt_allows(
            connection,
            binding.subject_id,
            binding.processing_authorization_version,
            binding.processing_authorization_revision,
            binding.operation,
        ):
            return False
        row = connection.execute(
            """SELECT * FROM delegations WHERE delegation_id=(
                   SELECT authority_id FROM action_journal
                   WHERE action_id=? AND state='claimed' AND claim_token=?
               ) AND status='active' AND (expires_at IS NULL OR expires_at>?)""",
            (binding.action_id, claim_token, self.now()),
        ).fetchone()
        offer = None
        if binding.operation is Operation.MEETING_SCHEDULE:
            offer = self._calendar_offer(connection, binding, include_consumed=True)
        if row is None or (
            binding.operation is Operation.MEETING_SCHEDULE and offer is None
        ):
            return False
        if row["scope"] == Scope.EXACT.value:
            return bool(
                row["exact_action_id"] == binding.action_id
                and row["exact_payload_digest"] == binding.payload_digest
            )
        return binding.origin is ActionOrigin.PUBLIC_SENDER and self._constraints_allow(
            row, binding, offer
        )

    def submit_action(
        self,
        binding: ActionBinding,
        *,
        crash_hook: Callable[[str], None] | None = None,
    ) -> ActionResult:
        """Public RPC execution accepts only public-sender bindings."""

        if binding.origin is not ActionOrigin.PUBLIC_SENDER or (
            binding.uses_legacy_public_identity
            and not self._legacy_public_binding_is_recoverable(binding)
        ):
            return ActionResult("denied", binding.action_id)
        with self._action_lock(binding.action_id):
            return self._submit_locked(binding, ActionOrigin.PUBLIC_SENDER, crash_hook)

    def _legacy_public_binding_is_recoverable(self, binding: ActionBinding) -> bool:
        """Require a durable Unit 3 record before accepting old wire identity.

        An origin-free binding can only represent an already-persisted Unit 3
        candidate or journal.  Fresh callers must use the explicit public
        origin form, so no RPC or recovery path can create an owner-external
        effect by omitting an origin.
        """

        if not binding.uses_legacy_public_identity:
            return True
        stored_json = canonical_json(binding.as_dict())
        candidate = self.store.database.execute(
            """SELECT binding_digest FROM candidate_actions WHERE action_id=?
               AND provenance='ordinary_public'
               AND external_link_identity IS NULL
               AND external_source_digest IS NULL AND binding_json=?""",
            (binding.action_id, stored_json),
        ).fetchone()
        if (
            candidate is not None
            and str(candidate["binding_digest"]) == binding.binding_digest
        ):
            return True
        journal = self.store.database.execute(
            """SELECT binding_digest FROM action_journal WHERE action_id=?
               AND origin=? AND binding_json=?""",
            (binding.action_id, ActionOrigin.PUBLIC_SENDER.value, stored_json),
        ).fetchone()
        return (
            journal is not None
            and str(journal["binding_digest"]) == binding.binding_digest
        )

    def _submit_owner_external_action(self, binding: ActionBinding) -> ActionResult:
        """Execute only from a confirmed external exact-intent commit path."""

        if binding.origin is not ActionOrigin.OWNER_EXTERNAL:
            return ActionResult("denied", binding.action_id)
        with self._action_lock(binding.action_id):
            return self._submit_locked(
                binding, ActionOrigin.OWNER_EXTERNAL, crash_hook=None
            )

    def _submit_locked(
        self,
        binding: ActionBinding,
        expected_origin: ActionOrigin,
        crash_hook: Callable[[str], None] | None,
    ) -> ActionResult:
        if (
            binding.origin is not expected_origin
            or not binding.verify()
            or not self._validate_arguments(binding)
        ):
            return ActionResult("binding_mismatch", binding.action_id)
        now = self.now()
        authority_id: str | None = None
        claim_token = secrets.token_hex(16)
        with self.store.database.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM action_journal WHERE action_id=?", (binding.action_id,)
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["binding_digest"]) != binding.binding_digest
                    or str(existing["origin"]) != binding.origin.value
                ):
                    return ActionResult("binding_mismatch", binding.action_id)
                if existing["state"] == "succeeded":
                    return ActionResult("replayed_success", binding.action_id)
                if expected_origin is ActionOrigin.OWNER_EXTERNAL and existing[
                    "state"
                ] in {"definite_failure", "cancelled"}:
                    # The exact owner confirmation is consumed by its first
                    # claim.  A later fresh confirmation may observe the
                    # durable outcome, but cannot turn a failed external exact
                    # action into a new claim or executor call.
                    outcome = existing["outcome"]
                    return ActionResult(
                        (
                            str(outcome)
                            if isinstance(outcome, str) and outcome
                            else str(existing["state"])
                        ),
                        binding.action_id,
                    )
                if existing["state"] in {"claimed", "uncertain"}:
                    return ActionResult(str(existing["state"]), binding.action_id)
                if (
                    self.policy.calendar.enabled
                    and binding.operation is Operation.MEETING_SCHEDULE
                    and str(existing["state"]) == "definite_failure"
                    and str(existing["outcome"]) != "verified_absent"
                ):
                    return ActionResult("definite_failure", binding.action_id)
            authority = self._authorize_claim(connection, binding)
            if authority is False:
                return ActionResult("denied", binding.action_id)
            if authority is True:
                return ActionResult("denied", binding.action_id)
            if authority is not None:
                authority_id = str(authority["delegation_id"])
            if (
                self.policy.calendar.enabled
                and binding.operation is Operation.MEETING_SCHEDULE
            ):
                # Consume the server-generated offer before consuming a bounded
                # delegation.  A stale offer therefore cannot burn authority.
                offer_ref = binding.arguments.get("offer_ref")
                assert isinstance(offer_ref, str)
                cursor = connection.execute(
                    """UPDATE calendar_offers SET consumed_at=? WHERE offer_ref=?
                       AND subject_id=? AND consumed_at IS NULL AND expires_at>?""",
                    (now, offer_ref, binding.subject_id, now),
                )
                if int(cursor.rowcount) != 1:
                    return ActionResult("denied", binding.action_id)
            if authority_id is not None:
                remaining = connection.execute(
                    "SELECT remaining_uses FROM delegations WHERE delegation_id=?",
                    (authority_id,),
                ).fetchone()
                if remaining is None:
                    return ActionResult("denied", binding.action_id)
                if remaining["remaining_uses"] is not None:
                    cursor = connection.execute(
                        """UPDATE delegations SET remaining_uses=remaining_uses-1
                           WHERE delegation_id=? AND status='active'
                           AND remaining_uses>0""",
                        (authority_id,),
                    )
                    if int(cursor.rowcount) != 1:
                        return ActionResult("denied", binding.action_id)
            binding_json = canonical_json(binding.as_dict())
            if existing is None:
                connection.execute(
                    """INSERT INTO action_journal(
                           action_id, binding_digest, binding_json, subject_id,
                           operation, origin, state, authority_id, claim_token,
                           outcome, created_at, updated_at
                       ) VALUES (?, ?, ?, ?, ?, ?, 'claimed', ?, ?, NULL, ?, ?)""",
                    (
                        binding.action_id,
                        binding.binding_digest,
                        binding_json,
                        binding.subject_id,
                        binding.operation.value,
                        binding.origin.value,
                        authority_id,
                        claim_token,
                        now,
                        now,
                    ),
                )
            else:
                connection.execute(
                    """UPDATE action_journal SET state='claimed', authority_id=?,
                       claim_token=?, outcome=NULL, updated_at=? WHERE action_id=?""",
                    (authority_id, claim_token, now, binding.action_id),
                )
            if (
                self.policy.calendar.enabled
                and binding.operation is Operation.MEETING_SCHEDULE
            ):
                offer = self._calendar_offer(connection, binding, include_consumed=True)
                if offer is None:
                    raise RuntimeError("calendar offer disappeared during claim")
                self._remember_calendar_reservation_in_transaction(
                    connection,
                    binding,
                    CalendarEvent(
                        deterministic_event_id(
                            self.policy.calendar.namespace, binding.action_id
                        ),
                        int(offer["start_at"]),
                        int(offer["end_at"]),
                    ),
                    "uncertain",
                )
            if (
                binding.operation is Operation.TASK_CREATE
                and self.policy.todoist.enabled
            ):
                command_uuid, temp_id = command_identity(binding.action_id)
                connection.execute(
                    """INSERT INTO todoist_task_mappings(
                           action_id, subject_id, command_uuid, temp_id,
                           provider_task_id, state, updated_at
                       ) VALUES (?, ?, ?, ?, NULL, 'claimed', ?)
                       ON CONFLICT(action_id) DO UPDATE SET state='claimed',
                       updated_at=excluded.updated_at""",
                    (
                        binding.action_id,
                        binding.subject_id,
                        command_uuid,
                        temp_id,
                        now,
                    ),
                )
            connection.execute(
                """INSERT INTO quota_events VALUES (?, ?, ?, ?, ?, 'reserved', ?)
                   ON CONFLICT(action_id) DO UPDATE SET state='reserved',
                   changed_at=excluded.changed_at""",
                (
                    binding.action_id,
                    binding.subject_id,
                    binding.operation.value,
                    now // 86400,
                    now // 60,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO action_attempts VALUES (?, ?, ?, ?, ?, ?)",
                (
                    secrets.token_hex(16),
                    binding.action_id,
                    binding.subject_id,
                    binding.operation.value,
                    now // 60,
                    now,
                ),
            )
        if crash_hook is not None:
            crash_hook("after_claim")
        if (
            self.policy.calendar.enabled
            and binding.operation is Operation.MEETING_SCHEDULE
        ):
            return self._execute_calendar_schedule(binding, claim_token)
        if binding.operation is Operation.TASK_CREATE and self.policy.todoist.enabled:
            return self._execute_todoist_task(binding, claim_token, crash_hook)
        try:
            outcome = self.executor.execute(binding)
        except BaseException:
            self._finalize(binding.action_id, claim_token, ExecutionOutcome.UNCERTAIN)
            return ActionResult("uncertain", binding.action_id)
        if not self._finalize(binding.action_id, claim_token, outcome):
            return ActionResult("uncertain", binding.action_id)
        return ActionResult(outcome.value, binding.action_id)

    def _execute_todoist_task(
        self,
        binding: ActionBinding,
        claim_token: str,
        crash_hook: Callable[[str], None] | None,
    ) -> ActionResult:
        """Submit one fixed item_add and record its exact task ID before success."""

        if not self.policy.todoist.enabled or self.todoist_api is None:
            self._finalize(
                binding.action_id, claim_token, ExecutionOutcome.DEFINITE_FAILURE
            )
            return ActionResult("definite_failure", binding.action_id)
        row = self.store.database.execute(
            """SELECT command_uuid, temp_id FROM todoist_task_mappings
               WHERE action_id=? AND subject_id=? AND state='claimed'""",
            (binding.action_id, binding.subject_id),
        ).fetchone()
        if row is None:
            self._finalize(binding.action_id, claim_token, ExecutionOutcome.UNCERTAIN)
            return ActionResult("uncertain", binding.action_id)
        try:
            result = self.todoist_api.item_add(
                item_add_command(
                    self.policy.todoist,
                    binding.action_id,
                    str(binding.arguments["title"]),
                    (
                        binding.arguments["due_date"]
                        if isinstance(binding.arguments["due_date"], str)
                        else None
                    ),
                )
            )
        except BaseException:
            result = TodoistAddResult.uncertain()
        if result.provider_task_id is not None:
            with self.store.database.transaction() as connection:
                cursor = connection.execute(
                    """UPDATE todoist_task_mappings SET provider_task_id=?, state='succeeded', updated_at=?
                       WHERE action_id=? AND state='claimed'""",
                    (result.provider_task_id, self.now(), binding.action_id),
                )
                if int(cursor.rowcount) != 1:
                    self._finalize(
                        binding.action_id, claim_token, ExecutionOutcome.UNCERTAIN
                    )
                    return ActionResult("uncertain", binding.action_id)
            if crash_hook is not None:
                crash_hook("after_todoist_mapping")
            outcome = ExecutionOutcome.VERIFIED_SUCCESS
        elif result.definite_failure:
            outcome = ExecutionOutcome.DEFINITE_FAILURE
        else:
            outcome = ExecutionOutcome.UNCERTAIN
        if not self._finalize(binding.action_id, claim_token, outcome):
            return ActionResult("uncertain", binding.action_id)
        return ActionResult(outcome.value, binding.action_id)

    def _execute_calendar_schedule(
        self, binding: ActionBinding, claim_token: str
    ) -> ActionResult:
        """Final provider recheck and one deterministic anonymous Calendar block."""

        assert self.calendar_api is not None
        with self._calendar_lock():
            row = self.store.database.execute(
                """SELECT start_at, end_at, duration_minutes FROM calendar_offers WHERE offer_ref=?
                   AND subject_id=?""",
                (binding.arguments["offer_ref"], binding.subject_id),
            ).fetchone()
            if row is None:
                self._finalize(
                    binding.action_id, claim_token, ExecutionOutcome.DEFINITE_FAILURE
                )
                return ActionResult("denied", binding.action_id)
            start_at, end_at = int(row["start_at"]), int(row["end_at"])
            conflict_start = start_at - self.policy.calendar.before_buffer_minutes * 60
            conflict_end = end_at + self.policy.calendar.after_buffer_minutes * 60
            event_id = deterministic_event_id(
                self.policy.calendar.namespace, binding.action_id
            )
            event = CalendarEvent(event_id, start_at, end_at)
            try:
                busy = self.calendar_api.free_busy(
                    self.policy.calendar.availability_calendar_ids,
                    conflict_start,
                    conflict_end,
                )
                if any(
                    item.start_at < conflict_end and item.end_at > conflict_start
                    for item in busy
                ):
                    self._finalize(
                        binding.action_id,
                        claim_token,
                        ExecutionOutcome.DEFINITE_FAILURE,
                    )
                    return ActionResult("definite_failure", binding.action_id)
                # Revocation may have raced the initial claim while the Gate was
                # reading free/busy.  Re-read all authority state immediately
                # before the irreversible provider call.
                with self.store.database.transaction() as connection:
                    revoked = not self._reservation_is_still_authorized(
                        connection, binding, claim_token
                    )
                if revoked:
                    self._finalize(
                        binding.action_id,
                        claim_token,
                        ExecutionOutcome.DEFINITE_FAILURE,
                    )
                    return ActionResult("denied", binding.action_id)
                self.calendar_api.insert_private_block(
                    self.policy.calendar.booking_calendar_id, event
                )
            except BaseException:
                self._remember_calendar_reservation(binding, event, "uncertain")
                self._finalize(
                    binding.action_id, claim_token, ExecutionOutcome.UNCERTAIN
                )
                return ActionResult("uncertain", binding.action_id)
            self._remember_calendar_reservation(binding, event, "succeeded")
            if not self._finalize(
                binding.action_id, claim_token, ExecutionOutcome.VERIFIED_SUCCESS
            ):
                return ActionResult("uncertain", binding.action_id)
            return ActionResult("verified_success", binding.action_id)

    def _remember_calendar_reservation(
        self, binding: ActionBinding, event: CalendarEvent, state: str
    ) -> None:
        with self.store.database.transaction() as connection:
            self._remember_calendar_reservation_in_transaction(
                connection, binding, event, state
            )

    def _remember_calendar_reservation_in_transaction(
        self,
        connection: Any,
        binding: ActionBinding,
        event: CalendarEvent,
        state: str,
    ) -> None:
        connection.execute(
            """INSERT INTO calendar_reservations VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(action_id) DO UPDATE SET state=excluded.state,
               updated_at=excluded.updated_at""",
            (
                binding.action_id,
                binding.subject_id,
                self.policy.calendar.booking_calendar_id,
                event.event_id,
                event.start_at,
                event.end_at,
                state,
                self.now(),
            ),
        )

    def _finalize(
        self, action_id: str, claim_token: str, outcome: ExecutionOutcome
    ) -> bool:
        now = self.now()
        state = {
            ExecutionOutcome.VERIFIED_SUCCESS: "succeeded",
            ExecutionOutcome.DEFINITE_FAILURE: "definite_failure",
            ExecutionOutcome.UNCERTAIN: "uncertain",
        }[outcome]
        quota_state = {
            ExecutionOutcome.VERIFIED_SUCCESS: "succeeded",
            ExecutionOutcome.DEFINITE_FAILURE: "released",
            ExecutionOutcome.UNCERTAIN: "uncertain",
        }[outcome]
        with self.store.database.transaction() as connection:
            row = connection.execute(
                """SELECT authority_id, origin FROM action_journal WHERE action_id=?
                   AND state='claimed' AND claim_token=?""",
                (action_id, claim_token),
            ).fetchone()
            if row is None:
                return False
            authority_id = row["authority_id"]
            connection.execute(
                """UPDATE action_journal SET state=?, outcome=?, updated_at=?
                   WHERE action_id=? AND claim_token=?""",
                (state, outcome.value, now, action_id, claim_token),
            )
            connection.execute(
                "UPDATE quota_events SET state=?, changed_at=? WHERE action_id=?",
                (quota_state, now, action_id),
            )
            connection.execute(
                """UPDATE todoist_task_mappings SET state=?, updated_at=?
                   WHERE action_id=? AND state='claimed'""",
                (state, now, action_id),
            )
            if authority_id is not None:
                authority = connection.execute(
                    "SELECT remaining_uses FROM delegations WHERE delegation_id=?",
                    (authority_id,),
                ).fetchone()
                owner_external = str(row["origin"]) == ActionOrigin.OWNER_EXTERNAL.value
                if owner_external and outcome is not ExecutionOutcome.UNCERTAIN:
                    connection.execute(
                        """UPDATE delegations SET status='consumed' WHERE delegation_id=?
                           AND remaining_uses IS NOT NULL""",
                        (authority_id,),
                    )
                elif outcome is ExecutionOutcome.DEFINITE_FAILURE:
                    connection.execute(
                        """UPDATE delegations SET remaining_uses=remaining_uses+1,
                           status='active' WHERE delegation_id=?
                           AND remaining_uses IS NOT NULL""",
                        (authority_id,),
                    )
                elif (
                    outcome is ExecutionOutcome.VERIFIED_SUCCESS
                    and authority is not None
                    and authority["remaining_uses"] is not None
                    and int(authority["remaining_uses"]) == 0
                ):
                    connection.execute(
                        "UPDATE delegations SET status='consumed' WHERE delegation_id=?",
                        (authority_id,),
                    )
            if outcome is ExecutionOutcome.UNCERTAIN:
                self._open_write_breaker_if_needed(connection, now)
        return True

    def _open_write_breaker_if_needed(self, connection: Any, now: int) -> None:
        unresolved_writes = int(
            connection.execute(
                """SELECT count(*) FROM action_journal
                   WHERE operation IN (?, ?) AND state='uncertain'""",
                (
                    Operation.MEETING_SCHEDULE.value,
                    Operation.TASK_CREATE.value,
                ),
            ).fetchone()[0]
        )
        if unresolved_writes >= self.policy.unresolved_write_breaker_threshold:
            connection.execute(
                "UPDATE breakers SET is_open=1, changed_at=? WHERE name='writes'",
                (now,),
            )

    def recover_claimed_actions(self) -> int:
        now = self.now()
        cutoff = now - self.policy.claim_lease_seconds
        calendar_actions: list[tuple[str, ActionOrigin]] = []
        with self.store.database.transaction() as connection:
            rows = connection.execute(
                """SELECT action_id FROM action_journal
                   WHERE state='claimed' AND updated_at<=?""",
                (cutoff,),
            ).fetchall()
            connection.execute(
                """UPDATE action_journal SET state='uncertain',
                   outcome='expired_worker_lease', updated_at=?
                   WHERE state='claimed' AND updated_at<=?""",
                (now, cutoff),
            )
            for row in rows:
                connection.execute(
                    "UPDATE quota_events SET state='uncertain' WHERE action_id=?",
                    (row["action_id"],),
                )
            self._open_write_breaker_if_needed(connection, now)
            if self.policy.calendar.enabled:
                calendar_actions = [
                    (str(row["action_id"]), ActionOrigin(str(row["origin"])))
                    for row in connection.execute(
                        """SELECT action_id, origin FROM action_journal
                           WHERE operation=? AND state='uncertain'""",
                        (Operation.MEETING_SCHEDULE.value,),
                    ).fetchall()
                ]
        for action_id, origin in calendar_actions:
            self._reconcile_action_for_origin(action_id, origin)
        return len(rows)

    def reconcile_action(self, action_id: str) -> ActionResult:
        """Public reconciliation is intentionally limited to public-origin work."""

        return self._reconcile_action_for_origin(action_id, ActionOrigin.PUBLIC_SENDER)

    def _reconcile_owner_external_for_erasure(self, action_id: str) -> ActionResult:
        """Settle one pre-existing external effect while erasure is pending.

        This is deliberately not an RPC operation.  It accepts only an already
        uncertain owner-external journal, calls the fixed executor reconciler,
        and has no route to action claiming, authority lookup, or execution.
        """

        return self._reconcile_action_for_origin(action_id, ActionOrigin.OWNER_EXTERNAL)

    def _reconcile_action_for_origin(
        self,
        action_id: str,
        expected_origin: ActionOrigin,
    ) -> ActionResult:
        with self._action_lock(action_id):
            row = self.store.database.execute(
                "SELECT * FROM action_journal WHERE action_id=?", (action_id,)
            ).fetchone()
            if (
                row is None
                or row["state"] != "uncertain"
                or str(row["origin"]) != expected_origin.value
            ):
                return ActionResult("denied", action_id)
            binding = self._journal_binding_for_reconciliation(
                row,
                expected_origin,
            )
            if binding is None:
                # A malformed owner-external legacy journal is retained as
                # uncertain: erasure must not scrub an effect it cannot prove
                # terminal, and cannot promote it into a generic public route.
                return ActionResult(
                    (
                        "uncertain"
                        if expected_origin is ActionOrigin.OWNER_EXTERNAL
                        else "denied"
                    ),
                    action_id,
                )
            if (
                self.policy.calendar.enabled
                and binding.operation is Operation.MEETING_SCHEDULE
            ):
                assert self.calendar_api is not None
                reservation = self.store.database.execute(
                    "SELECT * FROM calendar_reservations WHERE action_id=?",
                    (action_id,),
                ).fetchone()
                if reservation is None:
                    return ActionResult("uncertain", action_id)
                try:
                    event = self.calendar_api.get_event(
                        str(reservation["booking_calendar_id"]),
                        str(reservation["event_id"]),
                    )
                except BaseException:
                    return ActionResult("uncertain", action_id)
                if event is None:
                    offer_ref = binding.arguments.get("offer_ref")
                    if not isinstance(offer_ref, str):
                        return ActionResult("uncertain", action_id)
                    self._resolve_uncertain(
                        action_id,
                        success=False,
                        retry_offer_ref=offer_ref,
                    )
                    return ActionResult("definite_failure", action_id)
                if (
                    event.event_id != str(reservation["event_id"])
                    or event.start_at != int(reservation["start_at"])
                    or event.end_at != int(reservation["end_at"])
                ):
                    return ActionResult("uncertain", action_id)
                self._resolve_uncertain(action_id, success=True)
                return ActionResult("verified_success", action_id)
            if (
                binding.operation is Operation.TASK_CREATE
                and self.policy.todoist.enabled
            ):
                mapping = self.store.database.execute(
                    """SELECT command_uuid, temp_id, provider_task_id, state
                       FROM todoist_task_mappings WHERE action_id=?
                       AND state IN ('uncertain', 'succeeded')""",
                    (action_id,),
                ).fetchone()
                if mapping is None:
                    return ActionResult("uncertain", action_id)
                if str(mapping["state"]) == "succeeded" and mapping["provider_task_id"]:
                    self._resolve_uncertain(action_id, success=True)
                    return ActionResult("verified_success", action_id)
                if self.todoist_api is None:
                    return ActionResult("uncertain", action_id)
                try:
                    todoist_result = self.todoist_api.reconcile(
                        item_add_command(
                            self.policy.todoist,
                            binding.action_id,
                            str(binding.arguments["title"]),
                            (
                                binding.arguments["due_date"]
                                if isinstance(binding.arguments["due_date"], str)
                                else None
                            ),
                        )
                    )
                except BaseException:
                    return ActionResult("uncertain", action_id)
                if todoist_result.provider_task_id is not None:
                    with self.store.database.transaction() as connection:
                        connection.execute(
                            """UPDATE todoist_task_mappings
                               SET provider_task_id=?, state='succeeded', updated_at=?
                               WHERE action_id=? AND state='uncertain'""",
                            (todoist_result.provider_task_id, self.now(), action_id),
                        )
                    self._resolve_uncertain(action_id, success=True)
                    return ActionResult("verified_success", action_id)
                if todoist_result.definite_failure:
                    self._resolve_uncertain(action_id, success=False)
                    return ActionResult("definite_failure", action_id)
                return ActionResult("uncertain", action_id)
            outcome = self.executor.reconcile(binding)
            if outcome is ReconcileOutcome.UNRESOLVED:
                return ActionResult("uncertain", action_id)
            if outcome is ReconcileOutcome.VERIFIED_SUCCESS:
                self._resolve_uncertain(action_id, success=True)
                return ActionResult("verified_success", action_id)
            self._resolve_uncertain(action_id, success=False)
            return ActionResult("definite_failure", action_id)

    def _journal_binding_for_reconciliation(
        self,
        row: Any,
        expected_origin: ActionOrigin,
    ) -> ActionBinding | None:
        """Validate a durable binding without ever assigning or changing origin."""

        action_id = str(row["action_id"])
        try:
            value = json.loads(str(row["binding_json"]))
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        try:
            binding = self._stored_binding(
                value,
                allow_legacy_public=(expected_origin is ActionOrigin.PUBLIC_SENDER),
            )
        except (TypeError, ValueError):
            return None
        if (
            binding.origin is not expected_origin
            or binding.action_id != action_id
            or binding.binding_digest != str(row["binding_digest"])
            or binding.subject_id != str(row["subject_id"])
            or binding.operation.value != str(row["operation"])
            or not binding.verify()
            or not self._validate_arguments(binding)
        ):
            return None
        return binding

    def _resolve_uncertain(
        self,
        action_id: str,
        *,
        success: bool,
        retry_offer_ref: str | None = None,
    ) -> None:
        now = self.now()
        with self.store.database.transaction() as connection:
            row = connection.execute(
                """SELECT authority_id, origin, subject_id, operation
                   FROM action_journal WHERE action_id=?
                   AND state='uncertain'""",
                (action_id,),
            ).fetchone()
            if row is None:
                return
            connection.execute(
                """UPDATE action_journal SET state=?, outcome=?, updated_at=?
                   WHERE action_id=? AND state='uncertain'""",
                (
                    "succeeded" if success else "definite_failure",
                    "reconciled_success" if success else "verified_absent",
                    now,
                    action_id,
                ),
            )
            connection.execute(
                "UPDATE quota_events SET state=?, changed_at=? WHERE action_id=?",
                ("succeeded" if success else "released", now, action_id),
            )
            connection.execute(
                """UPDATE todoist_task_mappings SET state=?, updated_at=?
                   WHERE action_id=? AND state='uncertain'""",
                ("succeeded" if success else "definite_failure", now, action_id),
            )
            if (
                not success
                and retry_offer_ref is not None
                and str(row["operation"]) == Operation.MEETING_SCHEDULE.value
            ):
                # A verified 404 is the only path that reopens the exact same
                # action.  The offer remains subject-bound, unexpired, and
                # policy-digest checked when the retry claims it again.
                connection.execute(
                    """UPDATE calendar_offers SET consumed_at=NULL
                       WHERE offer_ref=? AND subject_id=? AND consumed_at IS NOT NULL
                       AND expires_at>?""",
                    (retry_offer_ref, str(row["subject_id"]), now),
                )
            authority_id = row["authority_id"]
            if authority_id is None:
                return
            authority = connection.execute(
                "SELECT remaining_uses FROM delegations WHERE delegation_id=?",
                (authority_id,),
            ).fetchone()
            owner_external = str(row["origin"]) == ActionOrigin.OWNER_EXTERNAL.value
            if owner_external:
                connection.execute(
                    """UPDATE delegations SET status='consumed' WHERE delegation_id=?
                       AND remaining_uses IS NOT NULL""",
                    (authority_id,),
                )
            elif not success:
                connection.execute(
                    """UPDATE delegations SET remaining_uses=remaining_uses+1,
                       status='active' WHERE delegation_id=?
                       AND remaining_uses IS NOT NULL""",
                    (authority_id,),
                )
            elif (
                authority is not None
                and authority["remaining_uses"] is not None
                and int(authority["remaining_uses"]) == 0
            ):
                connection.execute(
                    "UPDATE delegations SET status='consumed' WHERE delegation_id=?",
                    (authority_id,),
                )
