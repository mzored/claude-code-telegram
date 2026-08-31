from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlcipher3 import dbapi2 as sqlcipher

from src.policy_gate.executors import ExecutionOutcome, MockExecutor, ReconcileOutcome
from src.policy_gate.service import PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import (
    ActionBinding,
    AdminDraft,
    AdminKind,
    Operation,
    Scope,
    TrustedReference,
)


def binding(
    service: object,
    *,
    update_id: int = 10,
    operation: Operation = Operation.TASK_CREATE,
    arguments: dict[str, object] | None = None,
    authorization_revision: int = 2,
) -> ActionBinding:
    payload = arguments or {"title": "Send the bounded outcome", "due_date": None}
    return ActionBinding.create(
        subject_id="subject-a",
        connection_id="connection-a",
        conversation_id=202002,
        update_id=update_id,
        request_id="REQ-OPAQUE-A",
        operation=operation,
        arguments=payload,
        processing_authorization_version="integration-v2",
        processing_authorization_revision=authorization_revision,
        processor_purpose={
            Operation.MEETING_OPTIONS: "meeting options",
            Operation.MEETING_SCHEDULE: "meeting scheduling",
            Operation.TASK_CREATE: "external task creation",
        }[operation],
    )


def test_default_code_policy_exposes_and_executes_nothing(tmp_path: Path) -> None:
    now = 1_788_177_600
    store = GateStore(tmp_path / "default-gate.db", "g" * 40, clock=lambda: now)
    executor = MockExecutor()
    service = PolicyGateService(store, executor, clock=lambda: now)
    service.register_subject("subject-default", {"managed_chat": "opaque-default"})
    service.activate_receipt(
        "subject-default",
        "integration-v2",
        1,
        {"Google Calendar": ("meeting options",)},
    )
    action = ActionBinding.create(
        subject_id="subject-default",
        connection_id="connection-default",
        conversation_id=303003,
        update_id=1,
        request_id="REQ-DEFAULT",
        operation=Operation.MEETING_OPTIONS,
        arguments={
            "date": "2026-08-31",
            "duration_minutes": 30,
            "candidate_count": 3,
        },
        processing_authorization_version="integration-v2",
        processing_authorization_revision=1,
        processor_purpose="meeting options",
    )
    assert service.allowed_actions("subject-default", "integration-v2", 1) == ()
    assert service.submit_action(action).outcome == "denied"
    assert executor.calls == []
    store.close()


def test_candidate_provenance_schema_rejects_incomplete_external_link(
    gate: tuple,
) -> None:
    _, store, _ = gate
    with pytest.raises(sqlcipher.IntegrityError):
        store.database.execute(
            """INSERT INTO candidate_actions(
                   action_id, binding_digest, binding_json, subject_id, created_at,
                   provenance, external_link_identity, external_source_digest
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "a" * 64,
                "b" * 64,
                "{}",
                "subject-a",
                1,
                "external_untrusted",
                None,
                None,
            ),
        )
    with pytest.raises(sqlcipher.IntegrityError):
        store.database.execute(
            """INSERT INTO candidate_actions(
                   action_id, binding_digest, binding_json, subject_id, created_at,
                   provenance, external_link_identity, external_source_digest
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "c" * 64,
                "d" * 64,
                "{}",
                "subject-a",
                1,
                "external_untrusted",
                "e" * 64,
                "not-a-sha256-digest",
            ),
        )


def confirm(service: object, draft: AdminDraft, *, preview: int = 900) -> str:
    prepared = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        draft,
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=preview,
        ttl_seconds=300,
    )
    result = service.confirm_admin(
        prepared.intent_id,
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=preview,
    )
    assert result.outcome in {"applied", "executed"}
    return prepared.intent_id


@pytest.mark.parametrize(
    "reference",
    [
        TrustedReference("name", "Alice"),
        TrustedReference("username", "@alice"),
        TrustedReference("role", "friend"),
        TrustedReference("managed_chat", "202002"),
        TrustedReference("managed_chat", "missing"),
    ],
)
def test_only_registered_opaque_references_resolve(
    gate: tuple, reference: TrustedReference
) -> None:
    service, _, _ = gate
    with pytest.raises(ValueError, match="trusted subject reference"):
        service.prepare_admin(
            reference,
            AdminDraft(AdminKind.BLOCK),
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=1,
        )


def test_prepare_is_non_authorizing_and_confirmation_is_immutable(gate: tuple) -> None:
    service, _, _ = gate
    prepared = service.prepare_admin(
        TrustedReference("request", "REQ-OPAQUE-A"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=2,
        ),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=77,
    )
    assert Operation.TASK_CREATE not in service.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    assert prepared.preview["remaining_uses"] == 2
    for kwargs in (
        {"owner_id": 2, "control_chat_id": 101001, "preview_message_id": 77},
        {"owner_id": 101001, "control_chat_id": 2, "preview_message_id": 77},
        {"owner_id": 101001, "control_chat_id": 101001, "preview_message_id": 78},
    ):
        assert service.confirm_admin(prepared.intent_id, **kwargs).outcome == "denied"
    assert (
        service.confirm_admin(
            prepared.intent_id,
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=77,
        ).outcome
        == "applied"
    )
    assert (
        service.confirm_admin(
            prepared.intent_id,
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=77,
        ).outcome
        == "replayed"
    )


def test_stale_expired_and_concurrent_confirmations_fail_closed(
    gate: tuple, clock: object
) -> None:
    service, _, _ = gate
    first = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(AdminKind.BLOCK),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=50,
        ttl_seconds=1,
    )
    clock.advance(2)
    assert (
        service.confirm_admin(
            first.intent_id,
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=50,
        ).outcome
        == "expired"
    )

    stale = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(AdminKind.BLOCK),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=51,
    )
    confirm(service, AdminDraft(AdminKind.BLOCK), preview=52)
    assert (
        service.confirm_admin(
            stale.intent_id,
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=51,
        ).outcome
        == "stale"
    )

    service.confirm_admin(
        service.prepare_admin(
            TrustedReference("managed_chat", "chat-ref-a"),
            AdminDraft(AdminKind.UNBLOCK),
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=53,
        ).intent_id,
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=53,
    )
    prepared = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(AdminKind.BLOCK),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=54,
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(
                lambda _: service.confirm_admin(
                    prepared.intent_id,
                    owner_id=101001,
                    control_chat_id=101001,
                    preview_message_id=54,
                ).outcome,
                range(8),
            )
        )
    assert outcomes.count("applied") == 1
    assert outcomes.count("replayed") == 7


def test_exact_is_hidden_executes_stored_binding_once_and_never_promotes(
    gate: tuple,
) -> None:
    service, store, executor = gate
    action = binding(service)
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.EXACT,
            exact_binding=action,
        ),
    )
    assert executor.calls == [action]
    assert Operation.TASK_CREATE not in service.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    assert service.submit_action(action).outcome == "replayed_success"
    assert len(executor.calls) == 1
    assert store.delegations("subject-a") == ((Scope.EXACT.value, "consumed", 0),)


def test_exact_binding_must_belong_to_resolved_subject(gate: tuple) -> None:
    service, _, executor = gate
    other = ActionBinding.create(
        subject_id="subject-b",
        connection_id="connection-b",
        conversation_id=303003,
        update_id=11,
        request_id="REQ-OPAQUE-B",
        operation=Operation.TASK_CREATE,
        arguments={"title": "Must not cross subjects", "due_date": None},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
    )
    with pytest.raises(ValueError, match="resolved subject"):
        service.prepare_admin(
            TrustedReference("managed_chat", "chat-ref-a"),
            AdminDraft(
                AdminKind.GRANT,
                operation=Operation.TASK_CREATE,
                scope=Scope.EXACT,
                exact_binding=other,
            ),
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=904,
        )
    assert executor.calls == []


def test_preview_contains_exact_old_new_state_and_authority_delta(gate: tuple) -> None:
    service, _, _ = gate
    block = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(AdminKind.BLOCK),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=905,
    )
    assert block.preview["old_state"]["blocked"] is False
    assert block.preview["new_state"]["blocked"] is True
    assert block.preview["authority_delta"] == {
        "kind": "block",
        "operation": None,
        "affected_delegation_ids": [],
    }

    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=2,
        ),
        preview=906,
    )
    revoke = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(AdminKind.REVOKE, operation=Operation.TASK_CREATE),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=907,
    )
    assert revoke.preview["authority_delta"]["kind"] == "revoke"
    assert revoke.preview["authority_delta"]["operation"] == "task.create"
    assert len(revoke.preview["authority_delta"]["affected_delegation_ids"]) == 1


def test_exact_confirmation_resumes_after_crash_before_action_claim(
    gate: tuple,
) -> None:
    service, store, executor = gate
    action = binding(service, update_id=23)
    prepared = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.EXACT,
            exact_binding=action,
        ),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=908,
    )

    def crash(point: str) -> None:
        if point == "after_exact_intent_committed":
            raise RuntimeError("simulated exact-confirm crash")

    with pytest.raises(RuntimeError, match="exact-confirm crash"):
        service.confirm_admin(
            prepared.intent_id,
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=908,
            crash_hook=crash,
        )
    assert executor.calls == []
    assert store.journal_count(action.action_id) == 0

    resumed = service.confirm_admin(
        prepared.intent_id,
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=908,
    )
    assert resumed.outcome == "executed"
    assert resumed.action_result is not None
    assert resumed.action_result.outcome == "verified_success"
    assert executor.calls == [action]


def test_exact_confirmation_stays_resumable_through_uncertain_reconciliation(
    gate: tuple,
) -> None:
    service, _, executor = gate
    action = binding(service, update_id=24)
    prepared = service.prepare_admin(
        TrustedReference("managed_chat", "chat-ref-a"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.EXACT,
            exact_binding=action,
        ),
        owner_id=101001,
        control_chat_id=101001,
        preview_message_id=909,
    )
    executor.queue(ExecutionOutcome.UNCERTAIN)
    first = service.confirm_admin(prepared.intent_id, 101001, 101001, 909)
    assert first.action_result is not None
    assert first.action_result.outcome == "uncertain"
    second = service.confirm_admin(prepared.intent_id, 101001, 101001, 909)
    assert second.action_result is not None
    assert second.action_result.outcome == "uncertain"
    assert executor.calls == [action]
    executor.queue_reconcile(ReconcileOutcome.VERIFIED_SUCCESS)
    assert service.reconcile_action(action.action_id).outcome == "verified_success"
    resumed = service.confirm_admin(prepared.intent_id, 101001, 101001, 909)
    assert resumed.action_result is not None
    assert resumed.action_result.outcome == "replayed_success"
    assert service.confirm_admin(prepared.intent_id, 101001, 101001, 909).outcome == (
        "replayed"
    )


def test_repeated_exact_approvals_create_no_standing_or_background_intent(
    gate: tuple,
) -> None:
    service, store, _ = gate
    for update_id in (20, 21, 22):
        confirm(
            service,
            AdminDraft(
                AdminKind.GRANT,
                operation=Operation.TASK_CREATE,
                scope=Scope.EXACT,
                exact_binding=binding(service, update_id=update_id),
            ),
            preview=update_id,
        )
    assert all(
        scope == Scope.EXACT.value for scope, _, _ in store.delegations("subject-a")
    )
    assert store.pending_intent_count() == 0


@pytest.mark.parametrize(
    ("scope", "expires_at", "remaining_uses", "valid"),
    [
        (Scope.BOUNDED, None, None, False),
        (Scope.BOUNDED, 1_788_181_200, None, True),
        (Scope.BOUNDED, None, 2, True),
        (Scope.STANDING, None, None, True),
        (Scope.STANDING, 1_788_181_200, None, False),
        (Scope.STANDING, None, 2, False),
    ],
)
def test_bounded_and_standing_shapes_are_deterministic(
    gate: tuple,
    scope: Scope,
    expires_at: int | None,
    remaining_uses: int | None,
    valid: bool,
) -> None:
    service, _, _ = gate
    draft = AdminDraft(
        AdminKind.GRANT,
        operation=Operation.TASK_CREATE,
        scope=scope,
        expires_at=expires_at,
        remaining_uses=remaining_uses,
    )
    if not valid:
        with pytest.raises(ValueError):
            service.prepare_admin(
                TrustedReference("managed_chat", "chat-ref-a"),
                draft,
                owner_id=101001,
                control_chat_id=101001,
                preview_message_id=1,
            )
    else:
        confirm(service, draft)


def test_revocation_block_expiry_and_last_use_are_rechecked_at_claim(
    gate: tuple, clock: object
) -> None:
    service, store, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=1,
        ),
    )
    assert Operation.TASK_CREATE in service.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    actions = [binding(service, update_id=31), binding(service, update_id=32)]
    barrier = threading.Barrier(2)

    def submit(action: ActionBinding) -> str:
        barrier.wait()
        return service.submit_action(action).outcome

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, actions))
    assert sorted(outcomes) == ["denied", "verified_success"]
    assert len(executor.calls) == 1
    assert store.remaining_uses("subject-a", Operation.TASK_CREATE) == 0

    confirm(service, AdminDraft(AdminKind.BLOCK), preview=901)
    assert service.submit_action(binding(service, update_id=33)).outcome == "denied"
    confirm(service, AdminDraft(AdminKind.UNBLOCK), preview=902)
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            expires_at=int(clock.now()) + 1,
        ),
        preview=903,
    )
    clock.advance(2)
    assert service.submit_action(binding(service, update_id=34)).outcome == "denied"


def test_sixteen_identical_submissions_converge_on_one_effect(gate: tuple) -> None:
    service, store, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    action = binding(service, update_id=40)
    barrier = threading.Barrier(16)

    def submit(_: int) -> str:
        barrier.wait()
        return service.submit_action(action).outcome

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(submit, range(16)))
    assert outcomes.count("verified_success") == 1
    assert outcomes.count("replayed_success") == 15
    assert store.journal_count(action.action_id) == 1
    assert executor.calls == [action]


def test_payload_mismatch_never_reuses_a_journal_identity(gate: tuple) -> None:
    service, _, _ = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    action = binding(service, update_id=45)
    assert service.submit_action(action).outcome == "verified_success"
    altered = ActionBinding(
        action_id=action.action_id,
        subject_id=action.subject_id,
        connection_id=action.connection_id,
        conversation_id=action.conversation_id,
        update_id=action.update_id,
        request_id=action.request_id,
        operation=action.operation,
        arguments={"title": "altered", "due_date": None},
        processing_authorization_version=action.processing_authorization_version,
        processing_authorization_revision=action.processing_authorization_revision,
        processor_purpose=action.processor_purpose,
    )
    assert service.submit_action(altered).outcome == "binding_mismatch"


def test_definite_failure_releases_use_uncertain_holds_and_reconcile_releases(
    gate: tuple,
) -> None:
    service, store, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=1,
        ),
    )
    executor.queue(ExecutionOutcome.DEFINITE_FAILURE, ExecutionOutcome.UNCERTAIN)
    first = binding(service, update_id=50)
    assert service.submit_action(first).outcome == "definite_failure"
    assert store.remaining_uses("subject-a", Operation.TASK_CREATE) == 1
    second = binding(service, update_id=51)
    assert service.submit_action(second).outcome == "uncertain"
    assert store.remaining_uses("subject-a", Operation.TASK_CREATE) == 0
    executor.queue_reconcile(ReconcileOutcome.VERIFIED_ABSENT)
    assert service.reconcile_action(second.action_id).outcome == "definite_failure"
    assert store.remaining_uses("subject-a", Operation.TASK_CREATE) == 1


def test_crash_after_claim_never_reexecutes_without_reconciliation(
    gate: tuple, clock: object
) -> None:
    service, store, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=1,
        ),
    )
    action = binding(service, update_id=60)

    def crash(point: str) -> None:
        if point == "after_claim":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        service.submit_action(action, crash_hook=crash)
    assert executor.calls == []
    clock.advance(61)
    assert service.recover_claimed_actions() == 1
    assert service.submit_action(action).outcome == "uncertain"
    assert executor.calls == []
    executor.queue_reconcile(ReconcileOutcome.VERIFIED_ABSENT)
    assert service.reconcile_action(action.action_id).outcome == "definite_failure"
    assert store.remaining_uses("subject-a", Operation.TASK_CREATE) == 1


def test_recovery_cannot_turn_an_active_worker_into_false_success(
    gate: tuple, clock: object
) -> None:
    service, _, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    entered = threading.Event()
    release = threading.Event()
    original_execute = executor.execute

    def delayed_execute(action: ActionBinding) -> ExecutionOutcome:
        entered.set()
        assert release.wait(timeout=5)
        return original_execute(action)

    executor.execute = delayed_execute
    action = binding(service, update_id=62)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(service.submit_action, action)
        assert entered.wait(timeout=5)
        clock.advance(61)
        assert service.recover_claimed_actions() == 1
        release.set()
        assert future.result(timeout=5).outcome == "uncertain"
    assert executor.calls == [action]
    executor.queue_reconcile(ReconcileOutcome.VERIFIED_SUCCESS)
    assert service.reconcile_action(action.action_id).outcome == "verified_success"


def test_receipt_revision_revocation_quota_and_breakers_fail_closed(
    gate: tuple,
) -> None:
    service, _, _ = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    service.revoke_receipt("subject-a", revision=3)
    assert service.allowed_actions("subject-a", "integration-v2", 2) == ()
    assert service.submit_action(binding(service, update_id=70)).outcome == "denied"
    service.activate_receipt(
        "subject-a",
        version="integration-v2",
        revision=2,
        processor_purposes={"Todoist": ("external task creation",)},
    )
    assert service.allowed_actions("subject-a", "integration-v2", 2) == ()
    service.activate_receipt(
        "subject-a",
        version="integration-v2",
        revision=4,
        processor_purposes={
            "Google Calendar": ("meeting options", "meeting scheduling"),
            "Todoist": ("external task creation",),
        },
    )
    service.set_breaker("writes", True)
    assert Operation.TASK_CREATE not in service.allowed_actions(
        "subject-a", "integration-v2", 4
    )
    service.set_breaker("writes", False)


def test_reactivation_at_same_version_cannot_replay_old_receipt_binding(
    gate: tuple,
) -> None:
    service, _, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    old_binding = binding(service, update_id=71)
    service.revoke_receipt("subject-a", revision=3)
    service.activate_receipt(
        "subject-a",
        version="integration-v2",
        revision=4,
        processor_purposes={"Todoist": ("external task creation",)},
    )

    assert service.allowed_actions("subject-a", "integration-v2", 2) == ()
    assert Operation.TASK_CREATE in service.allowed_actions(
        "subject-a", "integration-v2", 4
    )
    assert service.submit_action(old_binding).outcome == "denied"
    fresh_binding = binding(service, update_id=72, authorization_revision=4)
    assert service.submit_action(fresh_binding).outcome == "verified_success"
    assert executor.calls == [fresh_binding]


def test_daily_quotas_and_independent_breakers_are_enforced(gate: tuple) -> None:
    service, _, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    for update_id in range(80, 85):
        assert service.submit_action(binding(service, update_id=update_id)).outcome == (
            "verified_success"
        )
    assert service.submit_action(binding(service, update_id=85)).outcome == "denied"
    assert len(executor.calls) == 5
    service.set_breaker("reads", True)
    allowed = service.allowed_actions("subject-a", "integration-v2", 2)
    assert Operation.MEETING_OPTIONS not in allowed
    service.set_breaker("reads", False)
    service.set_breaker("writes", True)
    allowed = service.allowed_actions("subject-a", "integration-v2", 2)
    assert Operation.MEETING_OPTIONS in allowed
    assert Operation.TASK_CREATE not in allowed


def test_constraints_and_block_survive_without_silent_delegation_revocation(
    gate: tuple,
) -> None:
    service, store, _ = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
            constraints={"max_title_length": 5},
        ),
    )
    assert (
        service.submit_action(
            binding(
                service,
                update_id=90,
                arguments={"title": "too long", "due_date": None},
            )
        ).outcome
        == "denied"
    )
    confirm(service, AdminDraft(AdminKind.BLOCK), preview=91)
    assert Operation.TASK_CREATE not in service.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    assert any(
        scope == Scope.STANDING.value for scope, _, _ in store.delegations("subject-a")
    )
    confirm(service, AdminDraft(AdminKind.UNBLOCK), preview=92)
    assert Operation.TASK_CREATE in service.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    assert (
        service.submit_action(
            binding(
                service,
                update_id=93,
                arguments={"title": "short", "due_date": None},
            )
        ).outcome
        == "verified_success"
    )


def test_definite_retry_uses_same_journal_and_unexpected_exception_is_uncertain(
    gate: tuple,
) -> None:
    service, store, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    action = binding(service, update_id=100)
    executor.queue(ExecutionOutcome.DEFINITE_FAILURE)
    assert service.submit_action(action).outcome == "definite_failure"
    assert service.submit_action(action).outcome == "verified_success"
    assert store.journal_count(action.action_id) == 1
    assert executor.calls == [action, action]

    uncertain = binding(service, update_id=101)
    executor.queue(RuntimeError("lost after dispatch"))
    assert service.submit_action(uncertain).outcome == "uncertain"
    assert service.submit_action(uncertain).outcome == "uncertain"
    assert executor.calls.count(uncertain) == 1
    executor.queue_reconcile(ReconcileOutcome.VERIFIED_SUCCESS)
    assert service.reconcile_action(uncertain.action_id).outcome == "verified_success"
    assert service.submit_action(uncertain).outcome == "replayed_success"


def test_same_binding_retries_count_toward_attempt_limit(gate: tuple) -> None:
    service, _, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    action = binding(service, update_id=102)
    executor.queue(*([ExecutionOutcome.DEFINITE_FAILURE] * 11))
    for _ in range(10):
        assert service.submit_action(action).outcome == "definite_failure"
    assert service.submit_action(action).outcome == "denied"
    assert len(executor.calls) == 10


def test_repeated_unresolved_writes_open_the_write_breaker(gate: tuple) -> None:
    service, _, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    executor.queue(*([ExecutionOutcome.UNCERTAIN] * 3))
    for update_id in (103, 104, 105):
        assert service.submit_action(binding(service, update_id=update_id)).outcome == (
            "uncertain"
        )
    assert service.submit_action(binding(service, update_id=106)).outcome == "denied"
    assert Operation.TASK_CREATE not in service.allowed_actions(
        "subject-a", "integration-v2", 2
    )


@pytest.mark.parametrize(
    "constraints",
    [
        {"allowed_durations": 30},
        {"allowed_durations": [15]},
        {"max_title_length": "20"},
        {"not_before": "tomorrow"},
        {"before": 1_788_177_500, "not_before": 1_788_177_900},
    ],
)
def test_malformed_constraints_are_rejected_at_prepare(
    gate: tuple, constraints: dict[str, object]
) -> None:
    service, _, _ = gate
    with pytest.raises(ValueError, match="constraint"):
        service.prepare_admin(
            TrustedReference("managed_chat", "chat-ref-a"),
            AdminDraft(
                AdminKind.GRANT,
                operation=Operation.TASK_CREATE,
                scope=Scope.STANDING,
                constraints=constraints,
            ),
            101001,
            101001,
            110,
        )


def test_erasure_waits_for_uncertain_effect_then_scrubs_payloads(gate: tuple) -> None:
    service, store, executor = gate
    confirm(
        service,
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
    )
    action = binding(service, update_id=110)
    service.register_subject("subject-a", {"action": action.action_id})
    assert service.stage_action(action)
    executor.queue(ExecutionOutcome.UNCERTAIN)
    assert service.submit_action(action).outcome == "uncertain"
    assert service.erase_subject("subject-a") == "pending_reconciliation"
    executor.queue_reconcile(ReconcileOutcome.VERIFIED_SUCCESS)
    assert service.reconcile_action(action.action_id).outcome == "verified_success"
    assert service.erase_subject("subject-a") == "erased"
    row = store.database.execute(
        "SELECT binding_json FROM action_journal WHERE action_id=?", (action.action_id,)
    ).fetchone()
    assert str(row[0]) == "{}"
    assert (
        store.database.execute(
            "SELECT count(*) FROM candidate_actions WHERE subject_id='subject-a'"
        ).fetchone()[0]
        == 0
    )
    with pytest.raises(ValueError, match="trusted subject reference"):
        service.prepare_admin(
            TrustedReference("managed_chat", "chat-ref-a"),
            AdminDraft(AdminKind.UNBLOCK),
            101001,
            101001,
            111,
        )
