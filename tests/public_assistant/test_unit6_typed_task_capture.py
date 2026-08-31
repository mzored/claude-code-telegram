"""Unit 6 repair coverage for structured task classification and outcomes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Sequence

import pytest

from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.todoist import TodoistAddResult, TodoistItemAdd, TodoistPolicy
from src.policy_gate.types import (
    AdminDraft,
    AdminKind,
    Operation,
    Scope,
    TrustedReference,
)
from src.public_assistant.action_store import Unit3Store
from src.public_assistant.actions import ActionAssistantService, ActionCoordinator
from src.public_assistant.config import PublicAssistantConfig, Unit2Config
from src.public_assistant.model import (
    ActionProposal,
    AssistantTurn,
    ModelResult,
    TaskCandidate,
    _parse_turn,
)
from src.public_assistant.types import (
    ConnectionObservation,
    DeliveryState,
    InboundMessage,
)

NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)
PENDING_KEY = "pending-" + "p" * 40
PUBLIC_KEY = "public-" + "u" * 40
PSEUDONYM_KEY = b"pseudonym-" + b"s" * 40


@dataclass
class FixedModel:
    result: ModelResult
    allowed: list[tuple[Operation, ...]]

    def generate(
        self,
        conversation: Sequence[object],
        safety_identifier: str,
        *,
        policy_context: Mapping[str, object] | None = None,
        allowed_actions: Sequence[object] = (),
    ) -> ModelResult:
        del conversation, safety_identifier, policy_context
        self.allowed.append(tuple(item.operation for item in allowed_actions))
        return self.result


@dataclass
class FakeTodoist:
    calls: list[TodoistItemAdd]

    def item_add(self, command: TodoistItemAdd) -> TodoistAddResult:
        self.calls.append(command)
        return TodoistAddResult.verified("provider-id-not-public")

    def reconcile(self, command: TodoistItemAdd) -> TodoistAddResult:
        return TodoistAddResult.verified("provider-id-not-public")


def _config(tmp_path: Path) -> tuple[PublicAssistantConfig, Unit2Config]:
    config = PublicAssistantConfig(
        bot_token_file=tmp_path / "unused-bot",
        pending_database_key_file=tmp_path / "unused-pending",
        public_database_key_file=tmp_path / "unused-public",
        pseudonym_key_file=tmp_path / "unused-pseudonym",
        owner_id=101,
        selected_sender_ids=frozenset({202}),
        data_dir=tmp_path / "public",
        backup_dir=tmp_path / "backup",
        privacy_url="https://example.test/privacy",
        privacy_policy_version="privacy-v1",
        processing_authorization_version="processing-v1",
    )
    limits = Unit2Config(
        openai_api_key_file=tmp_path / "unused-openai",
        model="fake",
        owner_alert_chat_id=101,
        timeout_seconds=1,
        max_output_tokens=50,
        max_context_items=8,
        max_context_characters=1000,
        daily_call_limit=10,
        daily_input_token_limit=10000,
        daily_output_token_limit=10000,
        daily_cost_microusd_limit=100000,
        input_microusd_per_million=1,
        output_microusd_per_million=1,
        concurrency_limit=1,
        backup_retention_seconds=100,
    )
    return config, limits


def _message(update_id: int, text: str) -> InboundMessage:
    return InboundMessage(
        connection_id="connection",
        conversation_id=202,
        sender_id=202,
        message_id=update_id,
        update_id=update_id,
        text=text,
        sent_at=datetime.now(UTC),
    )


def _consent(service: ActionAssistantService, store: Unit3Store) -> None:
    initial = service.handle_message(_message(1, "Hello"))
    assert initial.outcome == "awaiting_consent" and initial.reply is not None
    store.finalize_reply(
        initial.reply.reply_id, DeliveryState.SENT, telegram_message_id=9001
    )
    keyboard = json.loads(initial.reply.keyboard_json)
    token = keyboard[0][0]["callback_data"]
    assert service.handle_control(
        token,
        actor_id=202,
        conversation_id=202,
        connection_id="connection",
        origin_message_id=9001,
    ).startswith("accepted:")


def test_strict_structured_task_result_needs_only_typed_candidate_fields() -> None:
    turn = _parse_turn(
        json.dumps(
            {
                "reply_text": "I will pass this along.",
                "turn_kind": "task",
                "missing_information": [],
                "request_patch": None,
                "task_candidate": {"title": "Quarterly notes", "due_date": None},
            }
        )
    )
    assert turn.task_candidate == TaskCandidate("Quarterly notes", None)


@pytest.mark.parametrize(
    ("sender_text", "title"),
    [
        ("Please make sure the quarterly notes are ready Friday.", "Quarterly notes"),
        ("Пожалуйста, напомни про отчёт к пятнице.", "Подготовить отчёт"),
    ],
)
def test_model_classified_task_stages_without_delegation_then_exact_owner_approves(
    tmp_path: Path, sender_text: str, title: str
) -> None:
    config, limits = _config(tmp_path)
    store = Unit3Store(tmp_path / "state", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    executor = MockExecutor()
    gate = PolicyGateService(
        gate_store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset({Operation.TASK_CREATE})),
    )
    model = FixedModel(
        ModelResult(
            AssistantTurn(
                reply_text="I will send this to the owner.",
                turn_kind="task",
                task_candidate=TaskCandidate(title, "2026-09-04"),
            ),
            3,
            2,
        ),
        [],
    )
    coordinator = ActionCoordinator(store, gate)
    service = ActionAssistantService(config, limits, store, model, coordinator)
    try:
        assert service.observe_connection(
            ConnectionObservation("connection", 101, True, True, NOW)
        )
        _consent(service, store)
        item = _message(2, sender_text)
        assert coordinator.activate_integration_authorization(
            item, "integration-v1", 1, {"Todoist": ("external task creation",)}
        )
        result = service.handle_message(item)
        assert result.outcome == "task_exact_staged"
        assert model.allowed == [()]
        row = store.public.execute(
            "SELECT action_id, arguments_json FROM public_action_intents"
        ).fetchone()
        assert row is not None
        action_id, arguments = str(row[0]), str(row[1])
        assert json.loads(arguments) == {"due_date": "2026-09-04", "title": title}
        inbox = store.public.execute("SELECT body FROM inbox_requests").fetchone()
        assert inbox is not None and str(inbox[0]) == arguments
        assert sender_text not in str(inbox[0])
        assert executor.calls == []
        prepared = gate.prepare_admin(
            TrustedReference("action", action_id),
            AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
            101,
            101,
            2,
        )
        assert gate.confirm_admin(prepared.intent_id, 101, 101, 2).outcome == "executed"
        assert executor.calls
    finally:
        store.close()
        gate_store.close()


def test_verified_todoist_submission_has_durable_truthful_public_outcome(
    tmp_path: Path,
) -> None:
    config, limits = _config(tmp_path)
    store = Unit3Store(tmp_path / "state", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY)
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    provider = FakeTodoist([])
    gate = PolicyGateService(
        gate_store,
        MockExecutor(),
        policy=PolicyConfig(
            enabled_operations=frozenset({Operation.TASK_CREATE}),
            todoist=TodoistPolicy(enabled=True, external_requests_project_id="project"),
        ),
        todoist_api=provider,
    )
    model = FixedModel(
        ModelResult(
            AssistantTurn(
                reply_text="",  # replaced by truthful fixed sender text
                turn_kind="action",
                action_proposal=None,
            ),
            3,
            2,
        ),
        [],
    )
    coordinator = ActionCoordinator(store, gate)
    service = ActionAssistantService(config, limits, store, model, coordinator)
    try:
        assert service.observe_connection(
            ConnectionObservation("connection", 101, True, True, NOW)
        )
        _consent(service, store)
        item = _message(2, "Please put the agenda in the list.")
        assert coordinator.activate_integration_authorization(
            item, "integration-v1", 1, {"Todoist": ("external task creation",)}
        )
        subject = store.subject_ref("connection", 202, 202)
        gate.register_subject(
            subject, {"managed_chat": store.managed_chat_reference(item)}
        )
        grant = gate.prepare_admin(
            TrustedReference("managed_chat", store.managed_chat_reference(item)),
            AdminDraft(
                AdminKind.GRANT,
                operation=Operation.TASK_CREATE,
                scope=Scope.BOUNDED,
                remaining_uses=1,
            ),
            101,
            101,
            3,
        )
        assert gate.confirm_admin(grant.intent_id, 101, 101, 3).outcome == "applied"
        model.result = ModelResult(
            AssistantTurn(
                reply_text="I will create it.",
                turn_kind="action",
                action_proposal=ActionProposal(
                    Operation.TASK_CREATE, {"title": "Agenda", "due_date": None}
                ),
            ),
            3,
            2,
        )
        result = service.handle_message(item)
        assert result.outcome == "todoist_task_created"
        assert (
            result.reply is not None
            and "provider-id-not-public" not in result.reply.text
        )
        outcome = store.public.execute(
            "SELECT outcome FROM processed_updates WHERE update_id=?", (item.update_id,)
        ).fetchone()
        assert outcome is not None and outcome[0] == "todoist_task_created"
        assert len(provider.calls) == 1
    finally:
        store.close()
        gate_store.close()
