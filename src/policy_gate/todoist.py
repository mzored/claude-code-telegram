"""Narrow add-only Todoist boundary for the disabled-by-default Unit 6 path."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, cast
from urllib.request import Request, urlopen

TODOIST_COMMAND_NAMESPACE = uuid.UUID("1c9bc1ca-21a4-4d9e-8b04-0b8b3e4c3943")
TODOIST_TEMP_ID_NAMESPACE = uuid.UUID("f1be8d48-7f2f-43c3-8bdc-6f7e5309cc84")
TODOIST_DESCRIPTION_PREFIX = "Created by Assist AI public sender; action="
TODOIST_CONTENT_PREFIX = "[Public request] "


@dataclass(frozen=True)
class TodoistPolicy:
    """Deployment-owned configuration; no project selector crosses the model boundary."""

    enabled: bool = False
    external_requests_project_id: str = ""
    credential_file: Path | None = None
    optional_read_scope_enabled: bool = False

    def __post_init__(self) -> None:
        if self.enabled and not self.external_requests_project_id.strip():
            raise ValueError("enabled Todoist requires the External Requests project")
        if self.optional_read_scope_enabled:
            # Lost-response recovery has not been demonstrated against a sandbox.
            raise ValueError("Todoist optional read scope is not enabled")


@dataclass(frozen=True)
class TodoistAddResult:
    """Provider result deliberately distinguishes a confirmed ID from uncertainty."""

    provider_task_id: str | None = None
    definite_failure: bool = False

    @classmethod
    def verified(cls, provider_task_id: str) -> "TodoistAddResult":
        if not provider_task_id:
            raise ValueError("Todoist task ID is required for success")
        return cls(provider_task_id)

    @classmethod
    def uncertain(cls) -> "TodoistAddResult":
        return cls()

    @classmethod
    def failed(cls) -> "TodoistAddResult":
        return cls(None, True)


@dataclass(frozen=True)
class TodoistItemAdd:
    """The complete fixed Sync command, constructed only inside Policy Gate."""

    command_uuid: str
    temp_id: str
    project_id: str
    content: str
    description: str
    due_date: str | None


class TodoistApi(Protocol):
    """Exactly one write command and optional same-command reconciliation seam."""

    def item_add(self, command: TodoistItemAdd) -> TodoistAddResult: ...

    def reconcile(self, command: TodoistItemAdd) -> TodoistAddResult: ...


HttpPost = Callable[[str, dict[str, str], bytes], bytes]


def _post(url: str, headers: dict[str, str], payload: bytes) -> bytes:
    with urlopen(
        Request(url, data=payload, headers=headers, method="POST"), timeout=10
    ) as response:
        return cast(bytes, response.read())


class TodoistSyncApi:
    """One-command Sync API adapter; network transport is injectable for tests."""

    def __init__(self, token: str, *, post: HttpPost = _post) -> None:
        if not token:
            raise ValueError("Todoist token is required")
        self._token = token
        self._post = post

    @staticmethod
    def _payload(command: TodoistItemAdd) -> bytes:
        args: dict[str, object] = {
            "content": command.content,
            "project_id": command.project_id,
            "description": command.description,
        }
        if command.due_date is not None:
            args["due"] = {"date": command.due_date}
        return json.dumps(
            {
                "commands": [
                    {
                        "type": "item_add",
                        "uuid": command.command_uuid,
                        "temp_id": command.temp_id,
                        "args": args,
                    }
                ]
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def item_add(self, command: TodoistItemAdd) -> TodoistAddResult:
        try:
            raw = self._post(
                "https://api.todoist.com/api/v1/sync",
                {
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                self._payload(command),
            )
            value = json.loads(raw)
            status = value.get("sync_status", {}).get(command.command_uuid)
            task_id = value.get("temp_id_mapping", {}).get(command.temp_id)
            if status == "ok" and isinstance(task_id, str) and task_id:
                return TodoistAddResult.verified(task_id)
            if isinstance(status, dict) and status.get("error"):
                return TodoistAddResult.failed()
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return TodoistAddResult.uncertain()

    def reconcile(self, command: TodoistItemAdd) -> TodoistAddResult:
        # Same command identity and payload only; no optional provider read scope.
        return self.item_add(command)


def command_identity(action_id: str) -> tuple[str, str]:
    """Derive stable provider identifiers only from the immutable action binding."""

    return (
        str(uuid.uuid5(TODOIST_COMMAND_NAMESPACE, action_id)),
        str(uuid.uuid5(TODOIST_TEMP_ID_NAMESPACE, action_id)),
    )


def item_add_command(
    policy: TodoistPolicy, action_id: str, title: str, due_date: str | None
) -> TodoistItemAdd:
    """Make the sole allowed provider payload with no caller-controlled selector."""

    command_uuid, temp_id = command_identity(action_id)
    return TodoistItemAdd(
        command_uuid=command_uuid,
        temp_id=temp_id,
        project_id=policy.external_requests_project_id,
        content=TODOIST_CONTENT_PREFIX + title,
        description=TODOIST_DESCRIPTION_PREFIX + action_id,
        due_date=due_date,
    )


__all__ = [
    "TODOIST_DESCRIPTION_PREFIX",
    "TodoistAddResult",
    "TodoistApi",
    "TodoistItemAdd",
    "TodoistPolicy",
    "TodoistSyncApi",
    "command_identity",
    "item_add_command",
]
