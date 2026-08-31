"""Atomic public-candidate exact-owner acceptance for Unit 6."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from src.external_read import (
    ExternalInspection,
    ExternalRecordRef,
    ExternalSource,
    ExternalSourceMetadata,
    PublicTaskCandidateEnvelope,
    external_link_identity,
)
from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.todoist import TodoistAddResult, TodoistItemAdd, TodoistPolicy
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    AdminDraft,
    AdminKind,
    AdminResult,
    ExternalActionLink,
    Operation,
    PreparedIntent,
    Scope,
    TrustedReference,
    digest,
)
from src.private_controller.origin import RunOriginLedger, RunSource, RunTrigger
from src.private_controller.service import PrivateControllerService

ORIGIN_KEY = "origin-key-" + "o" * 40


@dataclass
class Clock:
    value: int = 1_788_177_600

    def now(self) -> float:
        return float(self.value)

    def advance(self, seconds: int) -> None:
        self.value += seconds


@dataclass
class FakeTodoist:
    calls: list[TodoistItemAdd]
    result: TodoistAddResult | None = None

    def item_add(self, command: TodoistItemAdd) -> TodoistAddResult:
        self.calls.append(command)
        return self.result or TodoistAddResult.verified("provider-task")

    def reconcile(self, command: TodoistItemAdd) -> TodoistAddResult:
        return TodoistAddResult.verified("provider-task")


@dataclass
class CandidateReads:
    candidate: PublicTaskCandidateEnvelope

    def inspect(self, reference: ExternalRecordRef) -> ExternalInspection:
        del reference
        raise AssertionError("public candidate path inspected source content")

    def validate_for_prepare(
        self, reference: ExternalRecordRef
    ) -> ExternalSourceMetadata:
        del reference
        raise AssertionError("public candidate path used owner-authored validation")

    def public_task_candidate(
        self, reference: ExternalRecordRef
    ) -> PublicTaskCandidateEnvelope:
        assert reference == self.candidate.metadata.reference
        return self.candidate


class RaisingInterpreter:
    def draft(self, instruction: str) -> AdminDraft:
        del instruction
        raise AssertionError("public candidate path invoked the private model")


def _binding(*, title: str = "Send agenda") -> ActionBinding:
    return ActionBinding.create(
        subject_id="subject-a",
        connection_id="connection-a",
        conversation_id=202002,
        update_id=51,
        request_id="REQ-PUBLIC-TASK-51",
        operation=Operation.TASK_CREATE,
        arguments={"title": title, "due_date": None},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
        origin=ActionOrigin.PUBLIC_SENDER,
    )


def _link(
    binding: ActionBinding, *, reference: str | None = None
) -> ExternalActionLink:
    value = binding.request_id if reference is None else reference
    record = ExternalRecordRef(ExternalSource.INBOX, value)
    return ExternalActionLink(
        external_link_identity(record.reference_hash(), binding.payload_digest),
        binding.payload_digest,
    )


def _candidate(binding: ActionBinding) -> PublicTaskCandidateEnvelope:
    title = binding.arguments["title"]
    due_date = binding.arguments["due_date"]
    assert isinstance(title, str)
    assert due_date is None or isinstance(due_date, str)
    arguments: dict[str, str | None] = {"title": title, "due_date": due_date}
    payload_digest = digest(arguments)
    reference = ExternalRecordRef(ExternalSource.INBOX, binding.request_id)
    return PublicTaskCandidateEnvelope(
        "PTC-PUBLIC-TASK-51",
        ExternalSourceMetadata(
            reference,
            binding.subject_id,
            binding.connection_id,
            binding.conversation_id,
            binding.update_id,
            binding.request_id,
            binding.processing_authorization_version,
            binding.processing_authorization_revision,
            payload_digest,
        ),
        arguments,
        payload_digest,
    )


def _direct_run(ledger: RunOriginLedger, sequence: int) -> str:
    return ledger.begin(
        RunTrigger(
            RunSource.TELEGRAM,
            101,
            101,
            sequence,
            sequence + 100,
            fresh=True,
        ),
        owner_id=101,
        control_chat_id=101,
    ).run_id


def _service(
    tmp_path: Path,
) -> tuple[PolicyGateService, GateStore, FakeTodoist, Clock]:
    clock = Clock()
    store = GateStore(tmp_path / "gate.db", "gate-" + "g" * 40, clock=clock.now)
    provider = FakeTodoist([])
    service = PolicyGateService(
        store,
        MockExecutor(),
        policy=PolicyConfig(
            enabled_operations=frozenset({Operation.TASK_CREATE}),
            per_subject_daily_tasks=1,
            todoist=TodoistPolicy(
                enabled=True, external_requests_project_id="external-project"
            ),
        ),
        todoist_api=provider,
        clock=clock.now,
    )
    assert service.activate_receipt(
        "subject-a",
        "integration-v2",
        2,
        {"Todoist": ("external task creation",)},
    )
    return service, store, provider, clock


def _prepare(
    service: PolicyGateService,
    binding: ActionBinding,
    link: ExternalActionLink,
    *,
    preview_message_id: int = 71,
) -> PreparedIntent:
    return service.prepare_public_task_exact(
        TrustedReference("request", binding.request_id),
        binding,
        link,
        101,
        101,
        preview_message_id,
    )


def _confirm(
    service: PolicyGateService,
    intent_id: str,
    binding: ActionBinding,
    link: ExternalActionLink,
    *,
    preview_message_id: int = 71,
    crash_hook: Callable[[str], None] | None = None,
) -> AdminResult:
    return service.confirm_public_task_exact(
        intent_id,
        101,
        101,
        preview_message_id,
        binding,
        link,
        crash_hook=crash_hook,
    )


def test_prepare_and_confirm_atomically_bind_one_candidate_authority_and_journal(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    binding = _binding()
    link = _link(binding)
    prepared = _prepare(service, binding, link)

    candidate = store.database.execute(
        """SELECT public_candidate_identity, public_candidate_digest
           FROM candidate_actions WHERE action_id=?""",
        (binding.action_id,),
    ).fetchone()
    assert tuple(candidate) == (link.link_identity, binding.payload_digest)
    assert prepared.preview["exact_binding"] == binding.as_dict()
    assert (
        store.database.execute("SELECT count(*) FROM subject_references").fetchone()[0]
        == 2
    )
    assert (
        store.database.execute("SELECT count(*) FROM action_journal").fetchone()[0] == 0
    )

    result = _confirm(service, prepared.intent_id, binding, link)
    assert result.outcome == "executed"
    assert result.action_result is not None
    assert result.action_result.outcome == "verified_success"
    journal = store.database.execute(
        """SELECT state, authority_id, binding_json FROM action_journal
           WHERE action_id=?""",
        (binding.action_id,),
    ).fetchone()
    authority = store.database.execute(
        """SELECT status, remaining_uses, exact_action_id
           FROM delegations WHERE delegation_id=?""",
        (journal["authority_id"],),
    ).fetchone()
    assert tuple(authority) == ("consumed", 0, binding.action_id)
    assert journal["state"] == "succeeded"
    assert len(provider.calls) == 1

    replay = _confirm(service, prepared.intent_id, binding, link)
    assert replay.outcome == "replayed"
    assert replay.action_result is not None
    assert replay.action_result.outcome == "replayed_success"
    assert len(provider.calls) == 1
    store.close()


def test_public_exact_claim_does_not_spend_existing_standing_authority(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    service.register_subject("subject-a", {"request": "REQ-STANDING-GRANT"})
    standing = service.prepare_admin(
        TrustedReference("request", "REQ-STANDING-GRANT"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.TASK_CREATE,
            scope=Scope.STANDING,
        ),
        101,
        101,
        70,
    )
    assert service.confirm_admin(standing.intent_id, 101, 101, 70).outcome == "applied"
    standing_id = store.database.execute(
        "SELECT delegation_id FROM delegations WHERE scope='standing'"
    ).fetchone()[0]

    binding = _binding()
    link = _link(binding)
    prepared = _prepare(service, binding, link)
    assert _confirm(service, prepared.intent_id, binding, link).outcome == "executed"
    standing_row = store.database.execute(
        "SELECT status, remaining_uses FROM delegations WHERE delegation_id=?",
        (standing_id,),
    ).fetchone()
    exact_row = store.database.execute(
        """SELECT status, remaining_uses FROM delegations
           WHERE exact_action_id=?""",
        (binding.action_id,),
    ).fetchone()
    assert tuple(standing_row) == ("active", None)
    assert tuple(exact_row) == ("consumed", 0)
    assert len(provider.calls) == 1
    store.close()


def test_definite_failure_replays_same_terminal_journal_without_provider_retry(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    provider.result = TodoistAddResult.failed()
    binding = _binding()
    link = _link(binding)
    prepared = _prepare(service, binding, link)

    failed = _confirm(service, prepared.intent_id, binding, link)
    assert failed.outcome == "executed"
    assert failed.action_result is not None
    assert failed.action_result.outcome == "definite_failure"
    replay = _confirm(service, prepared.intent_id, binding, link)
    assert replay.outcome == "replayed"
    assert replay.action_result is not None
    assert replay.action_result.outcome == "definite_failure"
    assert len(provider.calls) == 1
    assert (
        store.database.execute(
            "SELECT state FROM action_journal WHERE action_id=?", (binding.action_id,)
        ).fetchone()[0]
        == "definite_failure"
    )
    store.close()


def test_controller_requires_second_newer_control_and_same_candidate_digest(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    ledger = RunOriginLedger(tmp_path / "controller.db", ORIGIN_KEY)
    binding = _binding()
    candidate = _candidate(binding)
    reads = CandidateReads(candidate)
    controller = PrivateControllerService(
        service,
        ledger,
        RaisingInterpreter(),
        owner_id=101,
        control_chat_id=101,
        external_reads=reads,
    )
    try:
        prepare_run = _direct_run(ledger, 1)
        prepared = controller.prepare_public_task(
            prepare_run,
            candidate.metadata.reference,
            preview_message_id=71,
        )
        durable_link = ledger.external_intent_link(prepared.intent_id)
        assert durable_link.source_digest == candidate.payload_digest
        candidate_title = candidate.arguments["title"]
        assert isinstance(candidate_title, str)
        assert candidate_title not in str(durable_link)

        with pytest.raises(PermissionError, match="fresh owner control"):
            controller.confirm_public_task(
                prepare_run,
                prepared.intent_id,
                candidate.metadata.reference,
                preview_message_id=71,
            )
        result = controller.confirm_public_task(
            _direct_run(ledger, 2),
            prepared.intent_id,
            candidate.metadata.reference,
            preview_message_id=71,
        )
        assert result.outcome == "executed"
        assert len(provider.calls) == 1
    finally:
        ledger.close()
        store.close()


def test_prepare_rollback_leaves_no_candidate_reference_or_preview(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    binding = _binding()
    link = _link(binding)

    def crash(phase: str) -> None:
        assert phase == "after_public_task_candidate_staged"
        raise RuntimeError("prepare crash")

    with pytest.raises(RuntimeError, match="prepare crash"):
        service.prepare_public_task_exact(
            TrustedReference("request", binding.request_id),
            binding,
            link,
            101,
            101,
            71,
            crash_hook=crash,
        )
    for table in (
        "subject_references",
        "candidate_actions",
        "administration_intents",
        "action_journal",
    ):
        assert (
            store.database.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        )
    assert provider.calls == []
    store.close()


@pytest.mark.parametrize("case", ("wrong_link", "altered", "stale", "revoked"))
def test_confirm_rejects_changed_or_no_longer_current_candidate(
    tmp_path: Path, case: str
) -> None:
    service, store, provider, _ = _service(tmp_path)
    binding = _binding()
    link = _link(binding)
    prepared = _prepare(service, binding, link)
    confirmation_binding = binding
    confirmation_link = link
    if case == "wrong_link":
        confirmation_link = _link(binding, reference="REQ-PUBLIC-TASK-OTHER")
    elif case == "altered":
        confirmation_binding = _binding(title="Altered title")
    elif case == "stale":
        with store.database.transaction() as connection:
            connection.execute(
                "UPDATE subjects SET revision=revision+1 WHERE subject_id='subject-a'"
            )
    else:
        assert service.revoke_receipt("subject-a", 3)

    result = _confirm(
        service,
        prepared.intent_id,
        confirmation_binding,
        confirmation_link,
    )
    assert result.outcome in {"denied", "stale"}
    assert provider.calls == []
    assert (
        store.database.execute("SELECT count(*) FROM action_journal").fetchone()[0] == 0
    )
    assert store.database.execute("SELECT count(*) FROM delegations").fetchone()[0] == 0
    store.close()


def test_expired_or_erased_candidate_cannot_create_authority_or_claim(
    tmp_path: Path,
) -> None:
    service, store, provider, clock = _service(tmp_path)
    binding = _binding()
    link = _link(binding)
    expired = _prepare(service, binding, link)
    clock.advance(301)
    assert _confirm(service, expired.intent_id, binding, link).outcome == "expired"
    assert provider.calls == []
    assert (
        store.database.execute("SELECT count(*) FROM action_journal").fetchone()[0] == 0
    )
    store.close()

    service, store, provider, _ = _service(tmp_path / "erased")
    binding = _binding()
    link = _link(binding)
    erased = _prepare(service, binding, link)
    assert service.erase_subject(binding.subject_id) == "erased"
    assert _confirm(service, erased.intent_id, binding, link).outcome == "denied"
    assert provider.calls == []
    assert (
        store.database.execute("SELECT count(*) FROM action_journal").fetchone()[0] == 0
    )
    store.close()


def test_concurrent_confirmations_share_one_claim_and_provider_effect(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    binding = _binding()
    link = _link(binding)
    prepared = _prepare(service, binding, link)
    results = []

    def confirm() -> None:
        results.append(_confirm(service, prepared.intent_id, binding, link))

    threads = [threading.Thread(target=confirm) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(result.outcome for result in results) == ["executed", "replayed"]
    assert len(provider.calls) == 1
    assert (
        store.database.execute(
            "SELECT count(*) FROM action_journal WHERE action_id=?",
            (binding.action_id,),
        ).fetchone()[0]
        == 1
    )
    assert (
        store.database.execute(
            "SELECT count(*) FROM delegations WHERE exact_action_id=?",
            (binding.action_id,),
        ).fetchone()[0]
        == 1
    )
    store.close()


def test_post_commit_crash_resumes_same_claim_mapping_and_command(
    tmp_path: Path,
) -> None:
    service, store, provider, _ = _service(tmp_path)
    binding = _binding()
    link = _link(binding)
    prepared = _prepare(service, binding, link)

    def crash(phase: str) -> None:
        if phase == "after_public_task_exact_committed":
            raise RuntimeError("confirm crash")

    with pytest.raises(RuntimeError, match="confirm crash"):
        _confirm(
            service,
            prepared.intent_id,
            binding,
            link,
            crash_hook=crash,
        )
    journal = store.database.execute(
        "SELECT state, authority_id, claim_token FROM action_journal WHERE action_id=?",
        (binding.action_id,),
    ).fetchone()
    mapping = store.database.execute(
        """SELECT command_uuid, temp_id, state FROM todoist_task_mappings
           WHERE action_id=?""",
        (binding.action_id,),
    ).fetchone()
    assert journal["state"] == "claimed"
    assert mapping["state"] == "claimed"
    assert (
        store.database.execute(
            "SELECT remaining_uses FROM delegations WHERE delegation_id=?",
            (journal["authority_id"],),
        ).fetchone()[0]
        == 0
    )
    assert provider.calls == []
    assert service.revoke_receipt(binding.subject_id, 3)

    resumed = _confirm(service, prepared.intent_id, binding, link)
    assert resumed.outcome == "executed"
    assert resumed.action_result is not None
    assert resumed.action_result.outcome == "verified_success"
    assert len(provider.calls) == 1
    command = provider.calls[0]
    assert command.command_uuid == mapping["command_uuid"]
    assert command.temp_id == mapping["temp_id"]
    store.close()
