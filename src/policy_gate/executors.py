"""Mock-only executor contract for Unit 3."""

from __future__ import annotations

import threading
from collections import deque
from enum import Enum

from src.policy_gate.types import ActionBinding


class ExecutionOutcome(str, Enum):
    VERIFIED_SUCCESS = "verified_success"
    DEFINITE_FAILURE = "definite_failure"
    UNCERTAIN = "uncertain"


class ReconcileOutcome(str, Enum):
    VERIFIED_SUCCESS = "verified_success"
    VERIFIED_ABSENT = "verified_absent"
    UNRESOLVED = "unresolved"


class MockExecutor:
    """Deterministic fake; it imports no provider SDK and performs no I/O."""

    is_mock = True

    def __init__(self) -> None:
        self.calls: list[ActionBinding] = []
        self.reconcile_calls: list[ActionBinding] = []
        self._outcomes: deque[ExecutionOutcome | BaseException] = deque()
        self._reconcile_outcomes: deque[ReconcileOutcome] = deque()
        self._lock = threading.Lock()

    def queue(self, *outcomes: ExecutionOutcome | BaseException) -> None:
        with self._lock:
            self._outcomes.extend(outcomes)

    def queue_reconcile(self, *outcomes: ReconcileOutcome) -> None:
        with self._lock:
            self._reconcile_outcomes.extend(outcomes)

    def execute(self, binding: ActionBinding) -> ExecutionOutcome:
        with self._lock:
            self.calls.append(binding)
            outcome = (
                self._outcomes.popleft()
                if self._outcomes
                else ExecutionOutcome.VERIFIED_SUCCESS
            )
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def reconcile(self, binding: ActionBinding) -> ReconcileOutcome:
        with self._lock:
            self.reconcile_calls.append(binding)
            return (
                self._reconcile_outcomes.popleft()
                if self._reconcile_outcomes
                else ReconcileOutcome.UNRESOLVED
            )
