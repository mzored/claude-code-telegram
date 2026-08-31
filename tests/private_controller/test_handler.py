from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import ActionBinding, AdminKind, Operation, Scope
from src.private_controller.handler import policy_control
from src.private_controller.interpreter import DeterministicIntentInterpreter
from src.private_controller.origin import RunOriginLedger
from src.private_controller.service import PrivateControllerService

ORIGIN_KEY = "origin-key-" + "o" * 40


@pytest.mark.parametrize(
    ("instruction", "kind", "operation", "scope", "uses"),
    [
        ("Block this sender", AdminKind.BLOCK, None, None, None),
        ("Unblock this person", AdminKind.UNBLOCK, None, None, None),
        (
            "Allow task creation for 3 uses",
            AdminKind.GRANT,
            Operation.TASK_CREATE,
            Scope.BOUNDED,
            3,
        ),
        (
            "Grant meeting scheduling from now on",
            AdminKind.GRANT,
            Operation.MEETING_SCHEDULE,
            Scope.STANDING,
            None,
        ),
        (
            "Revoke task creation delegation",
            AdminKind.REVOKE,
            Operation.TASK_CREATE,
            None,
            None,
        ),
        (
            "Approve exact action",
            AdminKind.GRANT,
            None,
            Scope.EXACT,
            None,
        ),
    ],
)
def test_operational_interpreter_has_a_fixed_no_tool_grammar(
    instruction: str,
    kind: AdminKind,
    operation: Operation | None,
    scope: Scope | None,
    uses: int | None,
) -> None:
    draft = DeterministicIntentInterpreter().draft(instruction)
    assert (draft.kind, draft.operation, draft.scope, draft.remaining_uses) == (
        kind,
        operation,
        scope,
        uses,
    )


def update(message_id: int, update_id: int) -> SimpleNamespace:
    message = SimpleNamespace(
        message_id=message_id,
        forward_origin=None,
        forward_date=None,
        reply_text=AsyncMock(),
    )
    return SimpleNamespace(
        effective_message=message,
        effective_user=SimpleNamespace(id=101),
        effective_chat=SimpleNamespace(id=101),
        update_id=update_id,
    )


async def test_policy_command_prepares_then_confirms_without_a_model(
    tmp_path: Path,
) -> None:
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    gate = PolicyGateService(gate_store, MockExecutor())
    gate.register_subject("subject-a", {"managed_chat": "opaque-chat"})
    ledger = RunOriginLedger(tmp_path / "origin.db", ORIGIN_KEY)
    controller = PrivateControllerService(
        gate,
        ledger,
        DeterministicIntentInterpreter(),
        owner_id=101,
        control_chat_id=101,
    )

    prepare_update = update(11, 21)
    placeholder = SimpleNamespace(message_id=777, edit_text=AsyncMock())
    prepare_update.effective_message.reply_text.return_value = placeholder
    context = SimpleNamespace(
        bot_data={"private_controller": controller},
        args=["managed_chat:opaque-chat", "Block", "this", "sender"],
    )
    await policy_control(prepare_update, context)
    rendered = placeholder.edit_text.await_args.args[0]
    intent_id = re.search(r"/policy confirm (INT-[^ ]+) 777", rendered).group(1)
    assert not gate.subject_blocked("subject-a")

    confirm_update = update(12, 22)
    confirm_context = SimpleNamespace(
        bot_data={"private_controller": controller},
        args=["confirm", intent_id, "777"],
    )
    await policy_control(confirm_update, confirm_context)
    assert gate.subject_blocked("subject-a")
    assert "applied" in confirm_update.effective_message.reply_text.await_args.args[0]

    ledger.close()
    gate_store.close()


async def test_policy_command_resolves_and_executes_one_staged_exact_action(
    tmp_path: Path,
) -> None:
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    executor = MockExecutor()
    gate = PolicyGateService(
        gate_store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset({Operation.TASK_CREATE})),
    )
    action = ActionBinding.create(
        subject_id="subject-a",
        connection_id="connection-a",
        conversation_id=202002,
        update_id=31,
        request_id="REQ-EXACT-A",
        operation=Operation.TASK_CREATE,
        arguments={"title": "Approve this exact task", "due_date": None},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
    )
    gate.register_subject(
        "subject-a",
        {"managed_chat": "opaque-chat", "action": action.action_id},
    )
    gate.activate_receipt(
        "subject-a",
        "integration-v2",
        2,
        {"Todoist": ("external task creation",)},
    )
    assert gate.stage_action(action)
    ledger = RunOriginLedger(tmp_path / "origin.db", ORIGIN_KEY)
    controller = PrivateControllerService(
        gate,
        ledger,
        DeterministicIntentInterpreter(),
        owner_id=101,
        control_chat_id=101,
    )

    prepare_update = update(41, 51)
    placeholder = SimpleNamespace(message_id=888, edit_text=AsyncMock())
    prepare_update.effective_message.reply_text.return_value = placeholder
    await policy_control(
        prepare_update,
        SimpleNamespace(
            bot_data={"private_controller": controller},
            args=["action:" + action.action_id, "Approve", "exact", "action"],
        ),
    )
    rendered = placeholder.edit_text.await_args.args[0]
    intent_match = re.search(r"/policy confirm (INT-[^ ]+) 888", rendered)
    assert intent_match is not None

    confirm_update = update(42, 52)
    await policy_control(
        confirm_update,
        SimpleNamespace(
            bot_data={"private_controller": controller},
            args=["confirm", intent_match.group(1), "888"],
        ),
    )
    assert executor.calls == [action]
    assert "executed" in confirm_update.effective_message.reply_text.await_args.args[0]
    ledger.close()
    gate_store.close()
