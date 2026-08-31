"""Transactional authorization, administration, journal, and recovery logic."""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, Callable, Mapping

from src.policy_gate.executors import (
    ExecutionOutcome,
    MockExecutor,
    ReconcileOutcome,
)
from src.policy_gate.store import GateStore
from src.policy_gate.types import (
    ActionBinding,
    ActionResult,
    AdminDraft,
    AdminKind,
    AdminResult,
    Operation,
    PreparedIntent,
    Scope,
    TrustedReference,
    canonical_json,
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


class PolicyGateService:
    """The only component that can turn persisted authority into an effect."""

    def __init__(
        self,
        store: GateStore,
        executor: MockExecutor,
        *,
        policy: PolicyConfig | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not getattr(executor, "is_mock", False):
            raise ValueError("Unit 3 accepts only a declared mock executor")
        self.store = store
        self.executor = executor
        self.policy = policy or PolicyConfig()
        self._clock = clock
        self._locks_guard = threading.Lock()
        self._action_locks: dict[str, threading.Lock] = {}
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

    def stage_action(self, binding: ActionBinding) -> bool:
        """Persist one immutable public proposal for possible exact approval."""

        if not binding.verify() or not self._validate_arguments(binding):
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
                "SELECT binding_digest FROM candidate_actions WHERE action_id=?",
                (binding.action_id,),
            ).fetchone()
            if existing is not None:
                return str(existing["binding_digest"]) == binding.binding_digest
            connection.execute(
                "INSERT INTO candidate_actions VALUES (?, ?, ?, ?, ?)",
                (
                    binding.action_id,
                    binding.binding_digest,
                    canonical_json(binding.as_dict()),
                    binding.subject_id,
                    self.now(),
                ),
            )
        return True

    def stage_owner_exact_action(
        self, request_reference: TrustedReference, binding: ActionBinding
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
        return self.stage_action(binding)

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
        row = self.store.database.execute(
            """SELECT binding_json FROM candidate_actions
               WHERE action_id=? AND subject_id=?""",
            (reference.value, subject_id),
        ).fetchone()
        if row is None:
            raise ValueError("exact action reference is not staged")
        binding = ActionBinding.from_dict(json.loads(str(row["binding_json"])))
        if not binding.verify() or binding.subject_id != subject_id:
            raise ValueError("staged exact action binding is invalid")
        return replace(draft, operation=binding.operation, exact_binding=binding)

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
        if owner_id <= 0 or control_chat_id <= 0 or preview_message_id <= 0:
            raise ValueError("owner preview binding is incomplete")
        if ttl_seconds <= 0 or ttl_seconds > 900:
            raise ValueError("administration preview TTL is invalid")
        subject_id = self._resolve(reference)
        draft = self._hydrate_exact_draft(reference, subject_id, draft)
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
                """INSERT INTO administration_intents VALUES
                   (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL)""",
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
            if row["state"] == "applied":
                return AdminResult("replayed")
            if row["state"] in {"expired", "stale"}:
                return AdminResult(str(row["state"]))
            payload = json.loads(str(row["payload_json"]))
            kind = AdminKind(str(row["kind"]))
            if row["state"] == "executing":
                if kind is not AdminKind.GRANT or payload["scope"] != Scope.EXACT.value:
                    return AdminResult("denied")
                exact = payload["exact_binding"]
                if exact is None:
                    return AdminResult("denied")
                exact_binding = ActionBinding.from_dict(exact)
                if exact_binding.subject_id != str(row["subject_id"]):
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
                    exact = payload["exact_binding"]
                    exact_binding = (
                        None if exact is None else ActionBinding.from_dict(exact)
                    )
                    if (
                        exact_binding is not None
                        and exact_binding.subject_id != subject_id
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
            action_result = self.submit_action(exact_binding)
            if action_result.outcome in {"verified_success", "replayed_success"}:
                with self.store.database.transaction() as connection:
                    connection.execute(
                        """UPDATE administration_intents SET state='applied',
                           consumed_at=? WHERE intent_id=? AND state='executing'""",
                        (self.now(), intent_id),
                    )
            return AdminResult("executed", action_result)
        return AdminResult("applied")

    def exact_intent_execution_started(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
    ) -> bool:
        """Report only whether one exact intent crossed its immutable commit point."""

        row = self.store.database.execute(
            """SELECT kind, payload_json, state, owner_id, control_chat_id,
                      preview_message_id
               FROM administration_intents WHERE intent_id=?""",
            (intent_id,),
        ).fetchone()
        if row is None or (
            int(row["owner_id"]) != owner_id
            or int(row["control_chat_id"]) != control_chat_id
            or int(row["preview_message_id"]) != preview_message_id
            or str(row["kind"]) != AdminKind.GRANT.value
            or str(row["state"]) not in {"executing", "applied"}
        ):
            return False
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, json.JSONDecodeError):
            return False
        return (
            isinstance(payload, dict)
            and payload.get("scope") == Scope.EXACT.value
            and isinstance(payload.get("exact_binding"), dict)
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
            today = datetime.fromtimestamp(self.now(), tz=UTC).date()
            return (
                today
                <= requested_date
                <= today
                + timedelta(seconds=self.policy.maximum_meeting_horizon_seconds)
            )
        if binding.operation is Operation.MEETING_SCHEDULE:
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

    def _constraints_allow(self, delegation: Any, binding: ActionBinding) -> bool:
        constraints = json.loads(str(delegation["constraints_json"]))
        args = binding.arguments
        durations = constraints.get("allowed_durations")
        if durations is not None and args.get("duration_minutes") not in durations:
            return False
        maximum = constraints.get("max_title_length")
        if maximum is not None and len(str(args.get("title", ""))) > int(maximum):
            return False
        before = constraints.get("before")
        if before is not None:
            start_at = args.get("start_at")
            if not isinstance(start_at, int) or start_at >= int(before):
                return False
        not_before = constraints.get("not_before")
        if not_before is not None:
            start_at = args.get("start_at")
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
        self, connection: Any, binding: ActionBinding
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
        if not self._quota_available(connection, binding.subject_id, binding.operation):
            return False
        if binding.operation is Operation.MEETING_OPTIONS:
            return None
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
            if self._constraints_allow(row, binding):
                return row
        return False

    def submit_action(
        self,
        binding: ActionBinding,
        *,
        crash_hook: Callable[[str], None] | None = None,
    ) -> ActionResult:
        with self._action_lock(binding.action_id):
            return self._submit_locked(binding, crash_hook)

    def _submit_locked(
        self,
        binding: ActionBinding,
        crash_hook: Callable[[str], None] | None,
    ) -> ActionResult:
        if not binding.verify() or not self._validate_arguments(binding):
            return ActionResult("binding_mismatch", binding.action_id)
        now = self.now()
        authority_id: str | None = None
        claim_token = secrets.token_hex(16)
        with self.store.database.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM action_journal WHERE action_id=?", (binding.action_id,)
            ).fetchone()
            if existing is not None:
                if str(existing["binding_digest"]) != binding.binding_digest:
                    return ActionResult("binding_mismatch", binding.action_id)
                if existing["state"] == "succeeded":
                    return ActionResult("replayed_success", binding.action_id)
                if existing["state"] in {"claimed", "uncertain"}:
                    return ActionResult(str(existing["state"]), binding.action_id)
            authority = self._authorize_claim(connection, binding)
            if authority is False:
                return ActionResult("denied", binding.action_id)
            if authority is True:
                return ActionResult("denied", binding.action_id)
            if authority is not None:
                authority_id = str(authority["delegation_id"])
                if authority["remaining_uses"] is not None:
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
                    """INSERT INTO action_journal VALUES
                       (?, ?, ?, ?, ?, 'claimed', ?, ?, NULL, ?, ?)""",
                    (
                        binding.action_id,
                        binding.binding_digest,
                        binding_json,
                        binding.subject_id,
                        binding.operation.value,
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
        try:
            outcome = self.executor.execute(binding)
        except BaseException:
            self._finalize(binding.action_id, claim_token, ExecutionOutcome.UNCERTAIN)
            return ActionResult("uncertain", binding.action_id)
        if not self._finalize(binding.action_id, claim_token, outcome):
            return ActionResult("uncertain", binding.action_id)
        return ActionResult(outcome.value, binding.action_id)

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
                """SELECT authority_id FROM action_journal WHERE action_id=?
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
            if authority_id is not None:
                authority = connection.execute(
                    "SELECT remaining_uses FROM delegations WHERE delegation_id=?",
                    (authority_id,),
                ).fetchone()
                if outcome is ExecutionOutcome.DEFINITE_FAILURE:
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
        return len(rows)

    def reconcile_action(self, action_id: str) -> ActionResult:
        with self._action_lock(action_id):
            row = self.store.database.execute(
                "SELECT * FROM action_journal WHERE action_id=?", (action_id,)
            ).fetchone()
            if row is None or row["state"] != "uncertain":
                return ActionResult("denied", action_id)
            binding = ActionBinding.from_dict(json.loads(str(row["binding_json"])))
            outcome = self.executor.reconcile(binding)
            if outcome is ReconcileOutcome.UNRESOLVED:
                return ActionResult("uncertain", action_id)
            if outcome is ReconcileOutcome.VERIFIED_SUCCESS:
                self._resolve_uncertain(action_id, success=True)
                return ActionResult("verified_success", action_id)
            self._resolve_uncertain(action_id, success=False)
            return ActionResult("definite_failure", action_id)

    def _resolve_uncertain(self, action_id: str, *, success: bool) -> None:
        now = self.now()
        with self.store.database.transaction() as connection:
            row = connection.execute(
                """SELECT authority_id FROM action_journal WHERE action_id=?
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
            authority_id = row["authority_id"]
            if authority_id is None:
                return
            authority = connection.execute(
                "SELECT remaining_uses FROM delegations WHERE delegation_id=?",
                (authority_id,),
            ).fetchone()
            if not success:
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
