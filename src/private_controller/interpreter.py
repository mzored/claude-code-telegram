"""Deterministic operational-fallback interpreter for owner administration."""

from __future__ import annotations

import re

from src.policy_gate.types import AdminDraft, AdminKind, Operation, Scope

_USES = re.compile(
    r"^(?:allow|grant) (?P<operation>task creation|meeting scheduling) "
    r"for (?P<uses>[1-9][0-9]?) uses?$"
)
_STANDING = re.compile(
    r"^(?:allow|grant) (?P<operation>task creation|meeting scheduling) "
    r"(?:from now on|permanently|standing)$"
)
_REVOKE = re.compile(
    r"^revoke (?P<operation>task creation|meeting scheduling)(?: delegation)?$"
)

_OPERATIONS = {
    "task creation": Operation.TASK_CREATE,
    "meeting scheduling": Operation.MEETING_SCHEDULE,
}


class DeterministicIntentInterpreter:
    """Interpret a deliberately small English grammar without model or tools."""

    def draft(self, instruction: str) -> AdminDraft:
        normalized = " ".join(instruction.casefold().split()).strip(".!?")
        if normalized in {"block", "block this sender", "block this person"}:
            return AdminDraft(AdminKind.BLOCK)
        if normalized in {"unblock", "unblock this sender", "unblock this person"}:
            return AdminDraft(AdminKind.UNBLOCK)
        if normalized in {
            "approve exact action",
            "allow exact action",
            "grant exact action",
        }:
            return AdminDraft(AdminKind.GRANT, scope=Scope.EXACT)
        revoke = _REVOKE.fullmatch(normalized)
        if revoke is not None:
            return AdminDraft(
                AdminKind.REVOKE,
                operation=_OPERATIONS[revoke.group("operation")],
            )
        bounded = _USES.fullmatch(normalized)
        if bounded is not None:
            return AdminDraft(
                AdminKind.GRANT,
                operation=_OPERATIONS[bounded.group("operation")],
                scope=Scope.BOUNDED,
                remaining_uses=int(bounded.group("uses")),
            )
        standing = _STANDING.fullmatch(normalized)
        if standing is not None:
            return AdminDraft(
                AdminKind.GRANT,
                operation=_OPERATIONS[standing.group("operation")],
                scope=Scope.STANDING,
            )
        raise ValueError("owner instruction is outside the safe administration grammar")
