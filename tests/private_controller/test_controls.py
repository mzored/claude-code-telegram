from __future__ import annotations

from pathlib import Path

import pytest

from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import AdminDraft, AdminKind, TrustedReference
from src.private_controller.origin import RunOriginLedger, RunSource, RunTrigger
from src.private_controller.service import PrivateControllerService

ORIGIN_KEY = "origin-key-" + "o" * 40


class Interpreter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def draft(self, instruction: str) -> AdminDraft:
        self.calls.append(instruction)
        return AdminDraft(AdminKind.BLOCK)


def test_only_fresh_direct_owner_can_draft_and_second_control_confirms(
    tmp_path: Path,
) -> None:
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    gate = PolicyGateService(gate_store, MockExecutor())
    gate.register_subject("subject-a", {"managed_chat": "opaque-chat"})
    ledger = RunOriginLedger(tmp_path / "private.db", ORIGIN_KEY)
    interpreter = Interpreter()
    controller = PrivateControllerService(
        gate,
        ledger,
        interpreter,
        owner_id=101,
        control_chat_id=101,
    )
    direct = ledger.begin(
        RunTrigger(RunSource.TELEGRAM, 101, 101, 10, 20, fresh=True),
        owner_id=101,
        control_chat_id=101,
    )
    preview = controller.prepare(
        direct.run_id,
        TrustedReference("managed_chat", "opaque-chat"),
        "Block this sender",
        preview_message_id=30,
    )
    assert interpreter.calls == ["Block this sender"]
    assert not gate.subject_blocked("subject-a")

    confirm_run = ledger.begin(
        RunTrigger(RunSource.TELEGRAM, 101, 101, 11, 21, fresh=True),
        owner_id=101,
        control_chat_id=101,
    )
    assert (
        controller.confirm(confirm_run.run_id, preview.intent_id, 30).outcome
        == "applied"
    )
    assert gate.subject_blocked("subject-a")
    assert interpreter.calls == ["Block this sender"]
    ledger.close()
    gate_store.close()


def test_confirmation_run_must_be_created_after_preview_preparation(
    tmp_path: Path,
) -> None:
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    gate = PolicyGateService(gate_store, MockExecutor())
    gate.register_subject("subject-a", {"managed_chat": "opaque-chat"})
    ledger = RunOriginLedger(tmp_path / "private.db", ORIGIN_KEY)
    controller = PrivateControllerService(
        gate, ledger, Interpreter(), owner_id=101, control_chat_id=101
    )
    prepared_run = ledger.begin(
        RunTrigger(RunSource.TELEGRAM, 101, 101, 10, 20, fresh=True),
        owner_id=101,
        control_chat_id=101,
    )
    precreated_confirmation = ledger.begin(
        RunTrigger(RunSource.TELEGRAM, 101, 101, 11, 21, fresh=True),
        owner_id=101,
        control_chat_id=101,
    )
    preview = controller.prepare(
        prepared_run.run_id,
        TrustedReference("managed_chat", "opaque-chat"),
        "Block this sender",
        preview_message_id=30,
    )

    with pytest.raises(PermissionError, match="after the preview"):
        controller.confirm(precreated_confirmation.run_id, preview.intent_id, 30)
    assert not gate.subject_blocked("subject-a")
    ledger.close()
    gate_store.close()


@pytest.mark.parametrize(
    "trigger",
    [
        RunTrigger(RunSource.WEBHOOK, 101, 101, 1, 1, fresh=True),
        RunTrigger(RunSource.SCHEDULED, 101, 101, 1, 1, fresh=True),
        RunTrigger(RunSource.TELEGRAM, 101, 101, 1, 1, fresh=True, forwarded=True),
        RunTrigger(
            RunSource.CONTEXT_ONLY, 101, 101, 1, 1, fresh=False, context_only=True
        ),
    ],
)
def test_non_owner_origins_cannot_create_confirmable_intents(
    tmp_path: Path, trigger: RunTrigger
) -> None:
    gate_store = GateStore(tmp_path / "gate.db", "g" * 40)
    gate = PolicyGateService(gate_store, MockExecutor())
    gate.register_subject("subject-a", {"managed_chat": "opaque-chat"})
    ledger = RunOriginLedger(tmp_path / "private.db", ORIGIN_KEY)
    interpreter = Interpreter()
    controller = PrivateControllerService(gate, ledger, interpreter, 101, 101)
    run = ledger.begin(trigger, owner_id=101, control_chat_id=101)
    with pytest.raises(PermissionError):
        controller.prepare(
            run.run_id,
            TrustedReference("managed_chat", "opaque-chat"),
            "Block this sender",
            preview_message_id=3,
        )
    assert interpreter.calls == []
    assert gate_store.pending_intent_count() == 0
    ledger.close()
    gate_store.close()
