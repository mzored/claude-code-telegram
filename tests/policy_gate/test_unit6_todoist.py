"""Unit 6 Todoist add-only public-sender acceptance coverage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qs

from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.todoist import TodoistAddResult, TodoistItemAdd, TodoistPolicy
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    AdminDraft,
    AdminKind,
    Operation,
    Scope,
    TrustedReference,
)


@dataclass
class FakeTodoist:
    calls: list[TodoistItemAdd]
    outcome: TodoistAddResult = TodoistAddResult.verified("TASK-1")

    def item_add(self, command: TodoistItemAdd) -> TodoistAddResult:
        self.calls.append(command)
        return self.outcome

    def reconcile(self, command: TodoistItemAdd) -> TodoistAddResult:
        return self.outcome


@dataclass
class FakeTodoistDelete:
    calls: list[str]
    outcome: bool | None = True

    def delete_mapped_task(self, provider_task_id: str) -> bool | None:
        self.calls.append(provider_task_id)
        return self.outcome


def _binding(update_id: int = 51) -> ActionBinding:
    return ActionBinding.create(
        subject_id="subject-a",
        connection_id="telegram",
        conversation_id=202002,
        update_id=update_id,
        request_id=f"REQ-TASK-{update_id}",
        operation=Operation.TASK_CREATE,
        arguments={"title": "Send agenda", "due_date": "2026-09-01"},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
        origin=ActionOrigin.PUBLIC_SENDER,
    )


def _grant(
    service: PolicyGateService, binding: ActionBinding, scope: Scope = Scope.EXACT
) -> None:
    service.register_subject(binding.subject_id, {"action": binding.action_id})
    assert service.stage_action(binding)
    prepared = service.prepare_admin(
        TrustedReference("action", binding.action_id),
        AdminDraft(AdminKind.GRANT, scope=scope),
        101,
        101,
        1,
    )
    result = service.confirm_admin(prepared.intent_id, 101, 101, 1)
    assert result.outcome == ("executed" if scope is Scope.EXACT else "applied")


def test_todoist_is_disabled_by_default_and_decoupled_from_calendar(gate) -> None:
    service, store, executor = gate
    binding = _binding()
    assert service.submit_action(binding).outcome == "denied"
    assert executor.calls == []
    store.close()


def test_todoist_exact_public_sender_adds_once_and_maps_before_success(gate) -> None:
    _, store, executor = gate
    fake = FakeTodoist([])
    service = PolicyGateService(
        store,
        executor,
        policy=PolicyConfig(
            enabled_operations=frozenset({Operation.TASK_CREATE}),
            todoist=TodoistPolicy(enabled=True, external_requests_project_id="project"),
        ),
        todoist_api=fake,
    )
    binding = _binding()
    _grant(service, binding)
    result = service.submit_action(binding)
    assert result.outcome == "replayed_success"
    assert len(fake.calls) == 1
    assert fake.calls[0].project_id == "project"
    assert fake.calls[0].content == "[External request] Send agenda"
    assert fake.calls[0].description == "Provenance: external_untrusted"
    assert binding.action_id not in repr(fake.calls[0])
    row = store.database.execute(
        "SELECT provider_task_id, state FROM todoist_task_mappings WHERE action_id=?",
        (binding.action_id,),
    ).fetchone()
    assert tuple(row) == ("TASK-1", "succeeded")
    assert service.submit_action(binding).outcome == "replayed_success"
    assert len(fake.calls) == 1
    store.close()


def test_sync_wire_uses_form_encoded_commands_without_local_ids() -> None:
    from src.policy_gate.todoist import TodoistSyncApi, item_add_command

    sent: dict[str, object] = {}

    def post(url: str, headers: dict[str, str], payload: bytes) -> bytes:
        sent.update(url=url, headers=headers, payload=payload)
        command = json.loads(parse_qs(payload.decode())["commands"][0])[0]
        return json.dumps(
            {
                "sync_status": {command["uuid"]: "ok"},
                "temp_id_mapping": {command["temp_id"]: "TASK-1"},
            }
        ).encode()

    api = TodoistSyncApi("x" * 20, post=post)
    result = api.item_add(
        item_add_command(
            TodoistPolicy(enabled=True, external_requests_project_id="project"),
            "secret-action",
            "Title",
            None,
        )
    )
    assert result.provider_task_id == "TASK-1"
    assert sent["headers"] == {
        "Authorization": "Bearer " + "x" * 20,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    assert b"commands=" in sent["payload"]
    assert b"secret-action" not in sent["payload"]


def test_erasure_keeps_mapped_id_until_separate_admin_delete_succeeds(gate) -> None:
    _, store, executor = gate
    deleted = FakeTodoistDelete([])
    service = PolicyGateService(
        store,
        executor,
        policy=PolicyConfig(
            enabled_operations=frozenset({Operation.TASK_CREATE}),
            todoist=TodoistPolicy(enabled=True, external_requests_project_id="project"),
        ),
        todoist_api=FakeTodoist([]),
        todoist_erasure_api=deleted,
    )
    binding = _binding()
    _grant(service, binding)
    assert service.erase_subject(binding.subject_id) == "erased"
    assert deleted.calls == ["TASK-1"]
    assert (
        store.database.execute("SELECT * FROM todoist_task_mappings").fetchall() == []
    )
    assert (
        store.database.execute(
            "SELECT count(*) FROM todoist_erasure_tombstones"
        ).fetchone()[0]
        == 1
    )


def test_todoist_rejects_extra_fields_and_keeps_an_uncertain_lost_response_unmapped(
    gate,
) -> None:
    _, store, executor = gate
    fake = FakeTodoist([], TodoistAddResult.uncertain())
    service = PolicyGateService(
        store,
        executor,
        policy=PolicyConfig(
            enabled_operations=frozenset({Operation.TASK_CREATE}),
            todoist=TodoistPolicy(enabled=True, external_requests_project_id="project"),
        ),
        todoist_api=fake,
    )
    binding = _binding()
    _grant(service, binding)
    assert service.submit_action(binding).outcome == "uncertain"
    assert service.reconcile_action(binding.action_id).outcome == "uncertain"
    bad = ActionBinding.create(
        subject_id="subject-a",
        connection_id="telegram",
        conversation_id=202002,
        update_id=52,
        request_id="REQ-BAD",
        operation=Operation.TASK_CREATE,
        arguments={"title": "No selectors", "due_date": None, "project_id": "other"},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
    )
    assert not service.stage_action(bad)
    assert fake.calls == [fake.calls[0]]
    store.close()
