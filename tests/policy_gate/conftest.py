from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import Operation

GATE_KEY = "gate-key-" + "g" * 40


@dataclass
class Clock:
    value: int = 1_788_177_600

    def now(self) -> float:
        return float(self.value)

    def advance(self, seconds: int) -> None:
        self.value += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def gate(
    tmp_path: Path, clock: Clock
) -> tuple[PolicyGateService, GateStore, MockExecutor]:
    store = GateStore(tmp_path / "gate.db", GATE_KEY, clock=clock.now)
    executor = MockExecutor()
    policy = PolicyConfig(
        enabled_operations=frozenset(Operation),
        allowed_durations=(30, 60),
        max_option_candidates=3,
        per_subject_daily_options=8,
        global_daily_options=20,
        per_subject_daily_meetings=3,
        per_subject_daily_tasks=5,
        global_daily_writes=20,
        attempts_per_subject_minute=10,
        attempts_global_minute=30,
    )
    service = PolicyGateService(store, executor, policy=policy, clock=clock.now)
    service.register_subject(
        "subject-a",
        {
            "managed_chat": "chat-ref-a",
            "request": "REQ-OPAQUE-A",
            "action": "ACT-OPAQUE-A",
        },
    )
    service.activate_receipt(
        "subject-a",
        version="integration-v2",
        revision=2,
        processor_purposes={
            "Google Calendar": ("meeting options", "meeting scheduling"),
            "Todoist": ("external task creation",),
        },
    )
    yield service, store, executor
    store.close()
