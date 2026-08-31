from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import (
    ActionBinding,
    ActionResult,
    AdminDraft,
    AdminKind,
    Operation,
    Scope,
    TrustedReference,
)
from src.public_assistant.action_store import Unit3Store
from src.public_assistant.actions import ActionCoordinator
from src.public_assistant.config import (
    PublicAssistantConfig,
    PublicAssistantConfigurationError,
    Unit3Config,
)
from src.public_assistant.inbox import Unit2Store, erase_subject_from_public_store
from src.public_assistant.model import (
    ActionProposal,
    ConversationItem,
    ModelResult,
    OpenAIResponsesModel,
    action_schemas,
)
from src.public_assistant.types import InboundMessage

PENDING_KEY = "pending-" + "p" * 40
PUBLIC_KEY = "public-" + "u" * 40
PSEUDONYM_KEY = b"pseudonym-" + b"s" * 40


def inbound(update_id: int = 1) -> InboundMessage:
    return InboundMessage(
        connection_id="connection-a",
        conversation_id=202002,
        sender_id=202002,
        message_id=11,
        update_id=update_id,
        text="Please create this bounded task outcome.",
        sent_at=datetime(2026, 8, 31, 12, 0, tzinfo=UTC),
    )


class Responses:
    def __init__(self) -> None:
        self.kwargs: dict[str, object] = {}

    def create(self, **kwargs: object) -> object:
        self.kwargs = kwargs
        return SimpleNamespace(
            status="completed",
            output_text=json.dumps(
                {
                    "reply_text": "Here are the available actions.",
                    "turn_kind": "answer",
                    "missing_information": [],
                    "request_patch": None,
                    "action_proposal": None,
                }
            ),
            usage=SimpleNamespace(input_tokens=20, output_tokens=10),
            _request_id="safe",
        )


def make_gate(tmp_path: object) -> tuple[PolicyGateService, GateStore]:
    store = GateStore(tmp_path / "gate.db", "g" * 40)
    gate = PolicyGateService(
        store,
        MockExecutor(),
        policy=PolicyConfig(enabled_operations=frozenset(Operation)),
    )
    gate.register_subject("subject-a", {"managed_chat": "opaque-chat"})
    return gate, store


def test_unit2_consent_alone_exposes_no_integration_schema(tmp_path: object) -> None:
    gate, store = make_gate(tmp_path)
    assert gate.allowed_actions("subject-a", "processing-scope-1", 1) == ()
    store.close()


def test_gate_receipt_alone_cannot_upgrade_local_openai_consent(
    tmp_path: Path,
) -> None:
    public = Unit3Store(tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    message = inbound(13)
    subject = public.subject_ref(
        message.connection_id, message.conversation_id, message.sender_id
    )
    gate, gate_store = make_gate(tmp_path)
    gate.activate_receipt(
        subject,
        "integration-v2",
        revision=2,
        processor_purposes={"Google Calendar": ("meeting options",)},
    )
    coordinator = ActionCoordinator(public, gate)
    assert coordinator.discover(message).schemas == ()
    assert coordinator.activate_integration_authorization(
        message,
        "integration-v2",
        2,
        {"Google Calendar": ("meeting options",)},
    )
    assert [item.operation for item in coordinator.discover(message).schemas] == [
        Operation.MEETING_OPTIONS
    ]
    public.close()
    gate_store.close()


def test_real_responses_request_contains_only_current_dynamic_action_schemas(
    tmp_path: object,
) -> None:
    gate, store = make_gate(tmp_path)
    gate.activate_receipt(
        "subject-a",
        "integration-v2",
        revision=2,
        processor_purposes={
            "Google Calendar": ("meeting options", "meeting scheduling"),
            "Todoist": ("external task creation",),
        },
    )
    allowed = gate.allowed_actions("subject-a", "integration-v2", 2)
    assert allowed == (Operation.MEETING_OPTIONS,)
    responses = Responses()
    model = OpenAIResponsesModel(
        "unused",
        "gpt-test",
        timeout_seconds=1,
        max_output_tokens=80,
        client=SimpleNamespace(responses=responses),
    )
    result = model.generate(
        [ConversationItem("user", "Can we meet next week?")],
        "safe-id",
        policy_context={"processing_authorization_version": "integration-v2"},
        allowed_actions=action_schemas(allowed),
    )
    assert isinstance(result, ModelResult)
    request = responses.kwargs
    assert request["tools"] == []
    assert request["max_tool_calls"] == 0
    schema = request["text"]["format"]["schema"]
    encoded = json.dumps(schema, sort_keys=True)
    assert Operation.MEETING_OPTIONS.value in encoded
    assert Operation.MEETING_SCHEDULE.value not in encoded
    assert Operation.TASK_CREATE.value not in encoded
    for forbidden in ("sender_id", "subject_id", "provider", "executor", "credential"):
        assert forbidden not in encoded
    store.close()


def test_bounded_schema_appears_then_disappears_immediately_on_revoke(
    tmp_path: object,
) -> None:
    gate, store = make_gate(tmp_path)
    gate.activate_receipt(
        "subject-a",
        "integration-v2",
        revision=2,
        processor_purposes={
            "Google Calendar": ("meeting options", "meeting scheduling"),
            "Todoist": ("external task creation",),
        },
    )
    prepared = gate.prepare_admin(
        TrustedReference("managed_chat", "opaque-chat"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=2,
        ),
        owner_id=101,
        control_chat_id=101,
        preview_message_id=1,
    )
    gate.confirm_admin(prepared.intent_id, 101, 101, 1)
    assert Operation.TASK_CREATE in gate.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    revoke = gate.prepare_admin(
        TrustedReference("managed_chat", "opaque-chat"),
        AdminDraft(AdminKind.REVOKE, operation=Operation.TASK_CREATE),
        owner_id=101,
        control_chat_id=101,
        preview_message_id=2,
    )
    gate.confirm_admin(revoke.intent_id, 101, 101, 2)
    assert Operation.TASK_CREATE not in gate.allowed_actions(
        "subject-a", "integration-v2", 2
    )
    store.close()


def test_action_contract_allows_at_most_one_strict_proposal() -> None:
    schemas = action_schemas((Operation.MEETING_OPTIONS, Operation.TASK_CREATE))
    assert len(schemas) == 2
    for schema in schemas:
        assert schema.arguments_schema["additionalProperties"] is False
        assert not any(
            key in schema.arguments_schema.get("properties", {})
            for key in ("sender_id", "subject_id", "provider", "executor")
        )


def test_public_proposal_is_persisted_then_claimed_by_mock_gate(tmp_path: Path) -> None:
    public = Unit3Store(
        tmp_path / "public",
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
    )
    message = inbound()
    subject = public.subject_ref(
        message.connection_id, message.conversation_id, message.sender_id
    )
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    executor = MockExecutor()
    gate = PolicyGateService(
        gate_store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset(Operation)),
    )
    gate.register_subject(subject, {"request": "REQ-OPAQUE-A"})
    prepared = gate.prepare_admin(
        TrustedReference("request", "REQ-OPAQUE-A"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=1,
        ),
        owner_id=101,
        control_chat_id=101,
        preview_message_id=5,
    )
    gate.confirm_admin(prepared.intent_id, 101, 101, 5)
    coordinator = ActionCoordinator(public, gate)
    assert coordinator.discover(message).schemas == ()
    assert coordinator.activate_integration_authorization(
        message,
        "integration-v2",
        2,
        {
            "Google Calendar": ("meeting options", "meeting scheduling"),
            "Todoist": ("external task creation",),
        },
    )
    discovery = coordinator.discover(message)
    assert [item.operation for item in discovery.schemas] == [
        Operation.MEETING_OPTIONS,
        Operation.TASK_CREATE,
    ]
    result = coordinator.submit(
        message,
        "REQ-OPAQUE-A",
        ActionProposal(
            Operation.TASK_CREATE,
            {"title": "Send the bounded outcome", "due_date": None},
        ),
        90 * 24 * 60 * 60,
        discovery,
    )
    assert result.outcome == "verified_success"
    assert public.action_state(result.action_id) == "succeeded"
    assert len(executor.calls) == 1
    assert executor.is_mock is True
    public.close()
    gate_store.close()


def test_inbox_request_reference_can_create_the_first_delegation(
    tmp_path: Path,
) -> None:
    public = Unit3Store(tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    message = inbound(22)
    gate, gate_store = make_gate(tmp_path)
    coordinator = ActionCoordinator(public, gate)
    request_id = public.upsert_request(
        message, "Please create a bounded task.", 90 * 24 * 60 * 60
    )

    coordinator.register_request(message, request_id)
    prepared = gate.prepare_admin(
        TrustedReference("request", request_id),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.BOUNDED,
            remaining_uses=1,
        ),
        owner_id=101,
        control_chat_id=101,
        preview_message_id=22,
    )
    assert prepared.preview["scope"] == Scope.BOUNDED.value
    public.close()
    gate_store.close()


def test_revocation_between_discovery_and_claim_denies_mock_effect(
    tmp_path: Path,
) -> None:
    public = Unit3Store(
        tmp_path / "public",
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
    )
    message = inbound(2)
    subject = public.subject_ref(
        message.connection_id, message.conversation_id, message.sender_id
    )
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    executor = MockExecutor()
    gate = PolicyGateService(
        gate_store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset(Operation)),
    )
    gate.register_subject(subject, {"request": "REQ-OPAQUE-B"})
    prepared = gate.prepare_admin(
        TrustedReference("request", "REQ-OPAQUE-B"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
        101,
        101,
        6,
    )
    gate.confirm_admin(prepared.intent_id, 101, 101, 6)
    coordinator = ActionCoordinator(public, gate)
    assert coordinator.activate_integration_authorization(
        message,
        "integration-v2",
        2,
        {"Todoist": ("external task creation",)},
    )
    discovery = coordinator.discover(message)
    assert Operation.TASK_CREATE in {item.operation for item in discovery.schemas}
    revoke = gate.prepare_admin(
        TrustedReference("request", "REQ-OPAQUE-B"),
        AdminDraft(AdminKind.REVOKE, operation=Operation.TASK_CREATE),
        101,
        101,
        7,
    )
    gate.confirm_admin(revoke.intent_id, 101, 101, 7)
    result = coordinator.submit(
        message,
        "REQ-OPAQUE-B",
        ActionProposal(
            Operation.TASK_CREATE,
            {"title": "Still must be denied", "due_date": None},
        ),
        90 * 24 * 60 * 60,
        discovery,
    )
    assert result.outcome == "denied"
    assert executor.calls == []
    public.close()
    gate_store.close()


def test_local_integration_revocation_hides_schema_before_gate_ack(
    tmp_path: Path,
) -> None:
    public = Unit3Store(tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    message = inbound(14)
    gate, gate_store = make_gate(tmp_path)
    coordinator = ActionCoordinator(public, gate)
    assert coordinator.activate_integration_authorization(
        message,
        "integration-v2",
        2,
        {"Google Calendar": ("meeting options",)},
    )
    stale_discovery = coordinator.discover(message)
    assert stale_discovery.schemas
    original_revoke = gate.revoke_receipt

    def unavailable(subject_id: str, revision: int) -> bool:
        del subject_id, revision
        raise RuntimeError("simulated Gate interruption")

    gate.revoke_receipt = unavailable
    with pytest.raises(RuntimeError, match="interruption"):
        coordinator.revoke_integration_authorization(message, 3)
    assert coordinator.discover(message).schemas == ()
    stale_result = coordinator.submit(
        message,
        "REQ-STALE-RECEIPT",
        ActionProposal(
            Operation.MEETING_OPTIONS,
            {
                "date": "2026-09-01",
                "duration_minutes": 30,
                "candidate_count": 3,
            },
        ),
        90 * 24 * 60 * 60,
        stale_discovery,
    )
    assert stale_result.outcome == "denied"
    assert gate.executor.calls == []
    gate.revoke_receipt = original_revoke
    assert coordinator.revoke_integration_authorization(message, 3)
    public.close()
    gate_store.close()


def test_local_revocation_between_gate_staging_and_claim_denies_effect(
    tmp_path: Path,
) -> None:
    public = Unit3Store(tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    message = inbound(16)
    subject = public.subject_ref(
        message.connection_id, message.conversation_id, message.sender_id
    )
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    executor = MockExecutor()
    gate = PolicyGateService(
        gate_store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset(Operation)),
    )
    gate.register_subject(subject, {"request": "REQ-LOCAL-RACE-001"})
    coordinator = ActionCoordinator(public, gate)
    assert coordinator.activate_integration_authorization(
        message,
        "integration-v2",
        2,
        {"Google Calendar": ("meeting options",)},
    )
    discovery = coordinator.discover(message)
    original_stage = gate.stage_action

    def revoke_after_stage(binding: ActionBinding) -> bool:
        public.begin_integration_revocation(message, 3)
        return original_stage(binding)

    gate.stage_action = revoke_after_stage
    result = coordinator.submit(
        message,
        "REQ-LOCAL-RACE-001",
        ActionProposal(
            Operation.MEETING_OPTIONS,
            {"date": "2026-09-01", "duration_minutes": 30, "candidate_count": 3},
        ),
        90 * 24 * 60 * 60,
        discovery,
    )
    assert result.outcome == "denied"
    assert executor.calls == []
    public.close()
    gate_store.close()


def test_erasure_converges_gate_receipts_and_delegations_without_revival(
    tmp_path: Path,
) -> None:
    public = Unit3Store(tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    message = inbound(15)
    subject = public.subject_ref(
        message.connection_id, message.conversation_id, message.sender_id
    )
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    gate = PolicyGateService(
        gate_store,
        MockExecutor(),
        policy=PolicyConfig(enabled_operations=frozenset(Operation)),
    )
    gate.register_subject(subject, {"managed_chat": "MCHAT-ERASE-0001"})
    coordinator = ActionCoordinator(public, gate)
    assert coordinator.activate_integration_authorization(
        message,
        "integration-v2",
        2,
        {"Todoist": ("external task creation",)},
    )
    prepared = gate.prepare_admin(
        TrustedReference("managed_chat", "MCHAT-ERASE-0001"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
        owner_id=101,
        control_chat_id=101,
        preview_message_id=15,
    )
    assert gate.confirm_admin(prepared.intent_id, 101, 101, 15).outcome == "applied"
    assert Operation.TASK_CREATE in gate.allowed_actions(subject, "integration-v2", 2)

    erase_subject_from_public_store(public.public, subject, public.now())
    assert coordinator.erase_subject(subject) == "erased"
    assert not gate.activate_receipt(
        subject,
        "integration-v3",
        3,
        {"Todoist": ("external task creation",)},
    )
    assert gate.allowed_actions(subject, "integration-v3", 3) == ()
    with pytest.raises(ValueError, match="trusted subject reference"):
        gate.prepare_admin(
            TrustedReference("managed_chat", "MCHAT-ERASE-0001"),
            AdminDraft(AdminKind.UNBLOCK),
            owner_id=101,
            control_chat_id=101,
            preview_message_id=16,
        )
    public.close()
    gate_store.close()


def test_unit3_additive_schema_is_unit2_readable_and_erasure_removes_actions(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "public"
    store = Unit3Store(
        data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
    )
    message = inbound(3)
    subject = store.subject_ref(
        message.connection_id, message.conversation_id, message.sender_id
    )
    action = store.prepare_action(
        message,
        "REQ-OPAQUE-C",
        Operation.TASK_CREATE,
        {"title": "Bounded sender outcome", "due_date": None},
        "integration-v2",
        2,
        1000,
    )
    authorization = store.begin_integration_activation(
        message,
        "integration-v2",
        2,
        {"Todoist": ("external task creation",)},
    )
    store.acknowledge_integration_activation(authorization)
    store.close()

    old_binary = Unit2Store(
        data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
    )
    assert (
        old_binary.public.execute(
            "SELECT count(*) FROM public_action_intents"
        ).fetchone()[0]
        == 1
    )
    erase_subject_from_public_store(old_binary.public, subject, old_binary.now())
    assert (
        old_binary.public.execute(
            "SELECT count(*) FROM public_action_intents WHERE action_id=?",
            (action.action_id,),
        ).fetchone()[0]
        == 0
    )
    assert (
        old_binary.public.execute(
            "SELECT count(*) FROM integration_processing_receipts"
        ).fetchone()[0]
        == 0
    )
    old_binary.close()
    Unit3Store(data_dir, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY).close()


def test_public_action_state_converges_after_retry_and_unresolved_is_retained(
    tmp_path: Path,
) -> None:
    store = Unit3Store(tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    message = inbound(12)
    action = store.prepare_action(
        message,
        "REQ-OPAQUE-RETRY",
        Operation.TASK_CREATE,
        {"title": "Retry bounded action", "due_date": None},
        "integration-v2",
        2,
        1,
    )
    store.finish_action(ActionResult("uncertain", action.action_id))
    store.finish_action(ActionResult("replayed_success", action.action_id))
    assert store.action_state(action.action_id) == "succeeded"
    assert store.expire_unit3() == 0
    store.close()


def test_unit3_runtime_boundary_is_disabled_by_default(tmp_path: Path) -> None:
    base = PublicAssistantConfig(
        bot_token_file=tmp_path / "secrets" / "bot",
        pending_database_key_file=tmp_path / "secrets" / "pending",
        public_database_key_file=tmp_path / "secrets" / "public",
        pseudonym_key_file=tmp_path / "secrets" / "pseudonym",
        owner_id=101,
        selected_sender_ids=frozenset({202}),
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backup",
        privacy_url="https://example.invalid/privacy",
        privacy_policy_version="privacy-v1",
        processing_authorization_version="openai-v1",
    )
    assert Unit3Config.from_environment(base, {}).enabled is False
    enabled = Unit3Config.from_environment(
        base,
        {
            "PUBLIC_ASSISTANT_POLICY_GATE_ENABLED": "true",
            "PUBLIC_ASSISTANT_POLICY_GATE_SOCKET_PATH": str(
                tmp_path / "run" / "gate.sock"
            ),
        },
    )
    assert enabled.enabled is True
    with pytest.raises(PublicAssistantConfigurationError, match="outside public"):
        Unit3Config.from_environment(
            base,
            {
                "PUBLIC_ASSISTANT_POLICY_GATE_ENABLED": "true",
                "PUBLIC_ASSISTANT_POLICY_GATE_SOCKET_PATH": str(
                    base.data_dir / "gate.sock"
                ),
            },
        )
