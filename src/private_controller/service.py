"""One-shot drafting plus model-free confirmation for owner administration."""

from __future__ import annotations

from typing import Protocol

from src.policy_gate.types import (
    AdminDraft,
    AdminResult,
    PreparedIntent,
    TrustedReference,
)
from src.private_controller.origin import RunOrigin, RunOriginLedger


class IntentInterpreter(Protocol):
    """No-tools one-shot interpreter supplied by the private controller."""

    def draft(self, instruction: str) -> AdminDraft: ...


class ControllerGateClient(Protocol):
    """Administration-only Gate client; it exposes no Gate storage surface."""

    def prepare_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent: ...

    def confirm_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
    ) -> AdminResult: ...


class PrivateControllerService:
    """Resolve identity locally; the interpreter can propose scope only."""

    def __init__(
        self,
        gate: ControllerGateClient,
        runs: RunOriginLedger,
        interpreter: IntentInterpreter,
        owner_id: int,
        control_chat_id: int,
    ) -> None:
        if owner_id <= 0 or control_chat_id <= 0:
            raise ValueError("one explicit owner and control chat are required")
        self.gate = gate
        self.runs = runs
        self.interpreter = interpreter
        self.owner_id = owner_id
        self.control_chat_id = control_chat_id

    def prepare(
        self,
        run_id: str,
        reference: TrustedReference,
        instruction: str,
        *,
        preview_message_id: int,
    ) -> PreparedIntent:
        run = self.runs.require(run_id)
        if (
            run.origin is not RunOrigin.DIRECT_OWNER
            or not run.fresh
            or run.forwarded
            or run.context_only
            or run.actor_id != self.owner_id
            or run.chat_id != self.control_chat_id
        ):
            raise PermissionError(
                "only a fresh direct-owner run may draft administration"
            )
        if not instruction.strip():
            raise ValueError("owner instruction is empty")
        draft = self.interpreter.draft(instruction)
        prepared = self.gate.prepare_admin(
            reference,
            draft,
            owner_id=self.owner_id,
            control_chat_id=self.control_chat_id,
            preview_message_id=preview_message_id,
        )
        self.runs.link_intent(prepared.intent_id, run_id)
        return prepared

    def confirm(
        self, run_id: str, intent_id: str, preview_message_id: int
    ) -> AdminResult:
        self.runs.require_second_fresh_control(intent_id, run_id)
        return self.gate.confirm_admin(
            intent_id,
            owner_id=self.owner_id,
            control_chat_id=self.control_chat_id,
            preview_message_id=preview_message_id,
        )
