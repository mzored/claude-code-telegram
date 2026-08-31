"""Fail-closed ordinary Todoist reads for externally sourced task records."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Mapping, Protocol

from src.external_read import ExternalRecord, ExternalRecordRef, ExternalSource

_EXTERNAL_MARKER = "Provenance: external_untrusted"
_SAFE_EXTERNAL_TITLE = "External untrusted task"


@dataclass(frozen=True)
class TodoistTask:
    """Raw backend task shape. It never reaches the ordinary private agent."""

    opaque_ref: str
    title: str = field(repr=False)
    description: str | None = field(repr=False)
    due_date: str | None = field(repr=False)
    comments: tuple[str, ...] = field(repr=False)
    external_untrusted: bool

    def __post_init__(self) -> None:
        ExternalRecordRef(ExternalSource.TODOIST, self.opaque_ref)
        if (
            not isinstance(self.title, str)
            or not isinstance(self.comments, tuple)
            or any(not isinstance(comment, str) for comment in self.comments)
            or not isinstance(self.external_untrusted, bool)
        ):
            raise ValueError("Todoist task shape is invalid")
        if self.description is not None and not isinstance(self.description, str):
            raise ValueError("Todoist task shape is invalid")
        if self.due_date is not None and not isinstance(self.due_date, str):
            raise ValueError("Todoist task shape is invalid")

    @property
    def marked_external(self) -> bool:
        return self.external_untrusted or (
            self.description is not None
            and _EXTERNAL_MARKER.casefold() in self.description.casefold()
        )


@dataclass(frozen=True)
class TodoistReadView:
    """Ordinary-read view. A source body is absent for external task records."""

    opaque_ref: str
    title: str
    description: str | None
    due_date: str | None
    comments: tuple[str, ...]


class TodoistReadBackend(Protocol):
    """Provider access stays behind this adapter and remains fake in Unit 4."""

    def list_tasks(self) -> tuple[TodoistTask, ...]: ...

    def search_tasks(self, query: str) -> tuple[TodoistTask, ...]: ...

    def get_task(self, opaque_ref: str) -> TodoistTask | None: ...


class FilteredTodoistReadAdapter:
    """The only ordinary private-agent Todoist read boundary."""

    def __init__(self, backend: TodoistReadBackend) -> None:
        self._backend = backend

    @staticmethod
    def _external_view(task: TodoistTask) -> TodoistReadView:
        return TodoistReadView(
            opaque_ref="todoist:" + task.opaque_ref,
            title=_SAFE_EXTERNAL_TITLE,
            description=None,
            due_date=None,
            comments=(),
        )

    @staticmethod
    def _view(task: TodoistTask) -> TodoistReadView:
        if task.marked_external:
            return FilteredTodoistReadAdapter._external_view(task)
        return TodoistReadView(
            opaque_ref="todoist:" + task.opaque_ref,
            title=task.title,
            description=task.description,
            due_date=task.due_date,
            comments=task.comments,
        )

    @staticmethod
    def _tasks(value: object) -> tuple[TodoistTask, ...]:
        if not isinstance(value, tuple) or any(
            not isinstance(task, TodoistTask) for task in value
        ):
            raise ValueError("Todoist adapter rejected an unclassified response")
        return value

    def list_tasks(self) -> tuple[TodoistReadView, ...]:
        try:
            tasks = self._tasks(self._backend.list_tasks())
        except Exception:
            raise ValueError("Todoist adapter could not safely list tasks") from None
        return tuple(self._view(task) for task in tasks)

    def search_tasks(self, query: str) -> tuple[TodoistReadView, ...]:
        if not isinstance(query, str):
            raise ValueError("Todoist search is invalid")
        try:
            tasks = self._tasks(self._backend.search_tasks(query))
        except Exception:
            raise ValueError("Todoist adapter could not safely search tasks") from None
        return tuple(self._view(task) for task in tasks)

    def get_task(self, opaque_ref: str) -> TodoistReadView | None:
        try:
            reference = ExternalRecordRef.parse(opaque_ref)
        except ValueError:
            return None
        if reference.source is not ExternalSource.TODOIST:
            return None
        try:
            task = self._backend.get_task(reference.value)
        except Exception:
            raise ValueError("Todoist adapter could not safely read a task") from None
        if task is None:
            return None
        if not isinstance(task, TodoistTask) or task.opaque_ref != reference.value:
            raise ValueError("Todoist adapter rejected an unclassified response")
        return self._view(task)


@dataclass(frozen=True)
class TodoistExternalSource:
    """Synthetic raw source descriptor used before Unit 6 adds a provider backend."""

    task: TodoistTask
    subject_id: str
    connection_id: str
    conversation_id: int
    update_id: int
    request_id: str
    processing_authorization_version: str
    processing_authorization_revision: int


class InMemoryTodoistExternalResolver:
    """Test-only resolver that gives raw marked tasks to the isolated broker only."""

    def __init__(self, sources: Mapping[str, TodoistExternalSource]) -> None:
        self._sources = dict(sources)

    def resolve(self, reference: ExternalRecordRef) -> ExternalRecord | None:
        if reference.source is not ExternalSource.TODOIST:
            return None
        source = self._sources.get(reference.value)
        if source is None or not source.task.marked_external:
            return None
        return ExternalRecord.create(
            reference,
            subject_id=source.subject_id,
            connection_id=source.connection_id,
            conversation_id=source.conversation_id,
            update_id=source.update_id,
            request_id=source.request_id,
            processing_authorization_version=source.processing_authorization_version,
            processing_authorization_revision=source.processing_authorization_revision,
            # Canonical field labels make the digest change if any raw task
            # field changes, including a due date that no owner action may use.
            content=json.dumps(
                {
                    "comments": list(source.task.comments),
                    "description": source.task.description,
                    "due_date": source.task.due_date,
                    "title": source.task.title,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


__all__ = [
    "FilteredTodoistReadAdapter",
    "InMemoryTodoistExternalResolver",
    "TodoistExternalSource",
    "TodoistReadBackend",
    "TodoistReadView",
    "TodoistTask",
]
