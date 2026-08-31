"""Public Assistant-owned, PID-authenticated Unit 4 external-read broker."""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path
from typing import Mapping, Protocol, cast

from src.external_read import (
    EXTERNAL_SUMMARY_PREFIX,
    ExternalInspection,
    ExternalReadClient,
    ExternalReadError,
    ExternalReadUnavailable,
    ExternalRecord,
    ExternalRecordRef,
    ExternalSource,
    ExternalSourceMetadata,
    PublicTaskCandidateEnvelope,
)
from src.policy_gate.rpc import MAX_FRAME_BYTES
from src.policy_gate.transport import (
    bind_unix_listener,
    peer_credentials,
    remove_bound_socket,
    validate_socket_path,
)
from src.policy_gate.types import canonical_json

PROTOCOL_VERSION = 1
_OPERATIONS = frozenset({"inspect", "validate_for_prepare", "public_task_candidate"})
_MAX_SUMMARY_BYTES = 1_200


class ExternalRecordResolver(Protocol):
    """The broker may resolve one record by a typed opaque reference only."""

    def resolve(self, reference: ExternalRecordRef) -> ExternalRecord | None: ...


class OneShotExternalAnalyzer(Protocol):
    """The broker's analyzer owns no tools, session, or action capability."""

    def summarize(self, record: ExternalRecord) -> str: ...


class ModelExternalAnalyzer:
    """Expose only one summary method from the dedicated Public Assistant model."""

    def __init__(self, model: object) -> None:
        self._model = model

    def summarize(self, record: ExternalRecord) -> str:
        method = getattr(self._model, "summarize_external", None)
        if not callable(method):
            raise ExternalReadUnavailable("external inspection is unavailable")
        result = method(record)
        if not isinstance(result, str):
            raise ExternalReadUnavailable("external inspection is unavailable")
        return result


class MappingExternalRecordResolver:
    """In-memory resolver used only by Unit 4 tests and synthetic fixtures."""

    def __init__(self, records: Mapping[ExternalRecordRef, ExternalRecord]) -> None:
        self._records = dict(records)

    def resolve(self, reference: ExternalRecordRef) -> ExternalRecord | None:
        return self._records.get(reference)


class InboxExternalRecordResolver:
    """Read exact Inbox rows inside the Public Assistant process only."""

    def __init__(self, store: object) -> None:
        self._store = store

    def resolve(self, reference: ExternalRecordRef) -> ExternalRecord | None:
        if reference.source is not ExternalSource.INBOX:
            return None
        method = getattr(self._store, "resolve_external_inbox", None)
        if not callable(method):
            return None
        record = method(reference)
        return record if isinstance(record, ExternalRecord) else None

    def resolve_public_task_candidate(
        self, reference: ExternalRecordRef
    ) -> PublicTaskCandidateEnvelope | None:
        method = getattr(self._store, "resolve_public_task_candidate", None)
        if not callable(method):
            return None
        candidate = method(reference)
        return candidate if isinstance(candidate, PublicTaskCandidateEnvelope) else None


class MultiplexedExternalRecordResolver:
    """Keep source-specific raw retrieval behind a fixed source discriminator."""

    def __init__(
        self, resolvers: Mapping[ExternalSource, ExternalRecordResolver]
    ) -> None:
        self._resolvers = dict(resolvers)

    def resolve(self, reference: ExternalRecordRef) -> ExternalRecord | None:
        resolver = self._resolvers.get(reference.source)
        return None if resolver is None else resolver.resolve(reference)

    def resolve_public_task_candidate(
        self, reference: ExternalRecordRef
    ) -> PublicTaskCandidateEnvelope | None:
        resolver = self._resolvers.get(reference.source)
        method = (
            None
            if resolver is None
            else getattr(resolver, "resolve_public_task_candidate", None)
        )
        return None if not callable(method) else method(reference)


class ExternalReadBroker:
    """One-shot inspection service. It never returns raw source content."""

    def __init__(
        self,
        resolver: ExternalRecordResolver,
        analyzer: OneShotExternalAnalyzer,
        *,
        processor_authorized: bool = False,
    ) -> None:
        if not isinstance(processor_authorized, bool):
            raise ValueError("external processor authorization is invalid")
        self._resolver = resolver
        self._analyzer = analyzer
        self._processor_authorized = processor_authorized

    def _record(self, reference: ExternalRecordRef) -> ExternalRecord:
        try:
            record = self._resolver.resolve(reference)
        except Exception:
            # Resolver implementations may have handled raw source fields. Keep
            # their diagnostics out of controller errors and any caller logging.
            raise ExternalReadError("external record is unavailable") from None
        if (
            not isinstance(record, ExternalRecord)
            or record.metadata.reference != reference
        ):
            raise ExternalReadError("external record reference is invalid")
        return record

    def validate_for_prepare(
        self, reference: ExternalRecordRef
    ) -> ExternalSourceMetadata:
        return self._record(reference).metadata

    def public_task_candidate(
        self, reference: ExternalRecordRef
    ) -> PublicTaskCandidateEnvelope:
        """Resolve a typed candidate without exposing source content or summaries."""

        resolver = getattr(self._resolver, "resolve_public_task_candidate", None)
        try:
            candidate = None if not callable(resolver) else resolver(reference)
        except Exception:
            candidate = None
        if (
            not isinstance(candidate, PublicTaskCandidateEnvelope)
            or candidate.metadata.reference != reference
        ):
            raise ExternalReadError("public task candidate is unavailable")
        return candidate

    def inspect(self, reference: ExternalRecordRef) -> ExternalInspection:
        if not self._processor_authorized:
            raise ExternalReadUnavailable("external inspection is unavailable")
        record = self._record(reference)
        try:
            summary = self._analyzer.summarize(record)
            if not isinstance(summary, str):
                raise ValueError("external analyzer returned invalid output")
            summary = summary.strip()
            if not summary or len(summary.encode("utf-8")) > _MAX_SUMMARY_BYTES:
                raise ValueError("external analyzer summary is invalid")
        except Exception:
            raise ExternalReadUnavailable(
                "external inspection is unavailable"
            ) from None
        return ExternalInspection(
            record.metadata,
            EXTERNAL_SUMMARY_PREFIX + summary,
        )


class ExternalReadPeerAuthorizer:
    """Authorize only the preconfigured private-controller process."""

    def __init__(self, controller_uid: int, controller_pid: int) -> None:
        if (
            not isinstance(controller_uid, int)
            or isinstance(controller_uid, bool)
            or controller_uid < 0
            or not isinstance(controller_pid, int)
            or isinstance(controller_pid, bool)
            or controller_pid <= 0
        ):
            raise ValueError("external read peer identifiers are invalid")
        self.controller_uid = controller_uid
        self.controller_pid = controller_pid

    def require(self, uid: int, pid: int, operation: str) -> None:
        if (
            uid != self.controller_uid
            or pid != self.controller_pid
            or operation not in _OPERATIONS
        ):
            raise PermissionError("external read peer is unauthorized")


def _read_frame(connection: socket.socket) -> dict[str, object]:
    buffer = bytearray()
    while True:
        chunk = connection.recv(min(4096, MAX_FRAME_BYTES + 2 - len(buffer)))
        if not chunk:
            raise ValueError("external read frame ended before its newline")
        buffer.extend(chunk)
        line, separator, trailing = bytes(buffer).partition(b"\n")
        if separator:
            if trailing or not line or len(line) > MAX_FRAME_BYTES:
                raise ValueError("external read frame is invalid")
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("external read frame is invalid") from exc
            if (
                not isinstance(value, dict)
                or canonical_json(value).encode("utf-8") != line
            ):
                raise ValueError("external read frame is not canonical")
            return cast(dict[str, object], value)
        if len(buffer) > MAX_FRAME_BYTES:
            raise ValueError("external read frame is too large")


def _write_frame(connection: socket.socket, payload: Mapping[str, object]) -> None:
    wire = canonical_json(dict(payload)).encode("utf-8")
    if len(wire) > MAX_FRAME_BYTES:
        raise ValueError("external read response is too large")
    connection.sendall(wire + b"\n")


def _reference_from_wire(value: object) -> ExternalRecordRef:
    if not isinstance(value, dict) or set(value) != {"source", "value"}:
        raise ValueError("external read reference is invalid")
    source = value["source"]
    opaque = value["value"]
    if not isinstance(source, str) or not isinstance(opaque, str):
        raise ValueError("external read reference is invalid")
    return ExternalRecordRef(ExternalSource(source), opaque)


def _reference_to_wire(reference: ExternalRecordRef) -> dict[str, object]:
    return {"source": reference.source.value, "value": reference.value}


def _metadata_to_wire(metadata: ExternalSourceMetadata) -> dict[str, object]:
    return {
        "reference": _reference_to_wire(metadata.reference),
        "subject_id": metadata.subject_id,
        "connection_id": metadata.connection_id,
        "conversation_id": metadata.conversation_id,
        "update_id": metadata.update_id,
        "request_id": metadata.request_id,
        "processing_authorization_version": metadata.processing_authorization_version,
        "processing_authorization_revision": metadata.processing_authorization_revision,
        "source_digest": metadata.source_digest,
    }


def _public_task_candidate_to_wire(
    candidate: PublicTaskCandidateEnvelope,
) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "metadata": _metadata_to_wire(candidate.metadata),
        "arguments": dict(candidate.arguments),
        "payload_digest": candidate.payload_digest,
    }


def _public_task_candidate_from_wire(value: object) -> PublicTaskCandidateEnvelope:
    if not isinstance(value, dict) or set(value) != {
        "candidate_id",
        "metadata",
        "arguments",
        "payload_digest",
    }:
        raise ValueError("public task candidate response is invalid")
    if (
        not isinstance(value["candidate_id"], str)
        or not isinstance(value["arguments"], dict)
        or not isinstance(value["payload_digest"], str)
    ):
        raise ValueError("public task candidate response is invalid")
    arguments = value["arguments"]
    if set(arguments) != {"title", "due_date"}:
        raise ValueError("public task candidate response is invalid")
    return PublicTaskCandidateEnvelope(
        value["candidate_id"],
        _metadata_from_wire(value["metadata"]),
        cast(dict[str, str | None], arguments),
        value["payload_digest"],
    )


def _metadata_from_wire(value: object) -> ExternalSourceMetadata:
    expected = {
        "reference",
        "subject_id",
        "connection_id",
        "conversation_id",
        "update_id",
        "request_id",
        "processing_authorization_version",
        "processing_authorization_revision",
        "source_digest",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("external read metadata is invalid")
    strings = (
        "subject_id",
        "connection_id",
        "request_id",
        "processing_authorization_version",
        "source_digest",
    )
    integers = (
        "conversation_id",
        "update_id",
        "processing_authorization_revision",
    )
    if any(not isinstance(value[key], str) for key in strings) or any(
        not isinstance(value[key], int) or isinstance(value[key], bool)
        for key in integers
    ):
        raise ValueError("external read metadata is invalid")
    return ExternalSourceMetadata(
        reference=_reference_from_wire(value["reference"]),
        subject_id=cast(str, value["subject_id"]),
        connection_id=cast(str, value["connection_id"]),
        conversation_id=cast(int, value["conversation_id"]),
        update_id=cast(int, value["update_id"]),
        request_id=cast(str, value["request_id"]),
        processing_authorization_version=cast(
            str, value["processing_authorization_version"]
        ),
        processing_authorization_revision=cast(
            int, value["processing_authorization_revision"]
        ),
        source_digest=cast(str, value["source_digest"]),
    )


class ExternalReadBrokerServer:
    """Single-operation AF_UNIX server owned by Public Assistant."""

    def __init__(
        self,
        broker: ExternalReadBroker,
        socket_path: Path,
        *,
        controller_uid: int,
        controller_pid: int,
        client_gid: int,
    ) -> None:
        self.broker = broker
        self.socket_path = validate_socket_path(socket_path)
        self.authorizer = ExternalReadPeerAuthorizer(controller_uid, controller_pid)
        self.listener = bind_unix_listener(self.socket_path, client_gid)
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.listener.close()
        remove_bound_socket(self.socket_path)

    def _reply(self, connection: socket.socket, request: dict[str, object]) -> None:
        expected = {"version", "operation", "reference"}
        version = request.get("version")
        if (
            set(request) != expected
            or not isinstance(version, int)
            or isinstance(version, bool)
            or version != PROTOCOL_VERSION
        ):
            raise ValueError("external read request is invalid")
        operation = request.get("operation")
        if not isinstance(operation, str):
            raise ValueError("external read request is invalid")
        credentials = peer_credentials(connection)
        self.authorizer.require(credentials.uid, credentials.pid, operation)
        reference = _reference_from_wire(request.get("reference"))
        if operation == "inspect":
            inspection = self.broker.inspect(reference)
            _write_frame(
                connection,
                {
                    "ok": True,
                    "result": {
                        "metadata": _metadata_to_wire(inspection.metadata),
                        "summary": inspection.summary,
                    },
                },
            )
            return
        if operation == "validate_for_prepare":
            _write_frame(
                connection,
                {
                    "ok": True,
                    "result": {
                        "metadata": _metadata_to_wire(
                            self.broker.validate_for_prepare(reference)
                        )
                    },
                },
            )
            return
        if operation == "public_task_candidate":
            _write_frame(
                connection,
                {
                    "ok": True,
                    "result": _public_task_candidate_to_wire(
                        self.broker.public_task_candidate(reference)
                    ),
                },
            )
            return
        raise ValueError("external read request is invalid")

    def serve_once(self) -> None:
        connection, _ = self.listener.accept()
        connection.settimeout(3.0)
        try:
            try:
                self._reply(connection, _read_frame(connection))
            except ExternalReadUnavailable:
                _write_frame(connection, {"ok": False, "error": "unavailable"})
            except (ExternalReadError, PermissionError, ValueError, OSError):
                _write_frame(connection, {"ok": False, "error": "rejected"})
        except OSError:
            return
        finally:
            connection.close()

    def serve_forever(self, stop_signal: object, *, poll_interval: float = 0.2) -> None:
        if poll_interval <= 0 or poll_interval > 1:
            raise ValueError("external read poll interval is invalid")
        is_set = getattr(stop_signal, "is_set", None)
        if not callable(is_set):
            raise ValueError("external read stop signal is invalid")
        self.listener.settimeout(poll_interval)
        try:
            while not is_set():
                try:
                    self.serve_once()
                except socket.timeout:
                    continue
                except OSError:
                    if is_set():
                        break
                    raise
        finally:
            self.close()


class ExternalReadRpcClient(ExternalReadClient):
    """PID-pinned client available only to the private controller process."""

    def __init__(self, socket_path: Path, *, timeout: float = 3.0) -> None:
        self.socket_path = validate_socket_path(socket_path)
        if timeout <= 0 or timeout > 10:
            raise ValueError("external read client timeout is invalid")
        self.timeout = timeout
        self.opened_by_pid = os.getpid()
        self._lock = threading.RLock()

    def _call(self, operation: str, reference: ExternalRecordRef) -> dict[str, object]:
        if os.getpid() != self.opened_by_pid:
            raise PermissionError(
                "external read client cannot be used by a forked process"
            )
        with self._lock:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.set_inheritable(False)
            connection.settimeout(self.timeout)
            try:
                connection.connect(str(self.socket_path))
                _write_frame(
                    connection,
                    {
                        "version": PROTOCOL_VERSION,
                        "operation": operation,
                        "reference": _reference_to_wire(reference),
                    },
                )
                connection.shutdown(socket.SHUT_WR)
                response = _read_frame(connection)
            except (OSError, ValueError) as exc:
                raise ExternalReadError("external read broker is unavailable") from exc
            finally:
                connection.close()
        if set(response) != {"ok", "result"} and set(response) != {"ok", "error"}:
            raise ExternalReadError("external read broker response is invalid")
        if response.get("ok") is True:
            result = response.get("result")
            if not isinstance(result, dict):
                raise ExternalReadError("external read broker response is invalid")
            return result
        if response.get("ok") is False and response.get("error") == "unavailable":
            raise ExternalReadUnavailable("external inspection is unavailable")
        raise ExternalReadError("external read request was rejected")

    def inspect(self, reference: ExternalRecordRef) -> ExternalInspection:
        result = self._call("inspect", reference)
        if set(result) != {"metadata", "summary"} or not isinstance(
            result["summary"], str
        ):
            raise ExternalReadError("external inspection response is invalid")
        try:
            return ExternalInspection(
                _metadata_from_wire(result["metadata"]), result["summary"]
            )
        except ValueError as exc:
            raise ExternalReadError("external inspection response is invalid") from exc

    def validate_for_prepare(
        self, reference: ExternalRecordRef
    ) -> ExternalSourceMetadata:
        result = self._call("validate_for_prepare", reference)
        if set(result) != {"metadata"}:
            raise ExternalReadError("external validation response is invalid")
        try:
            return _metadata_from_wire(result["metadata"])
        except ValueError as exc:
            raise ExternalReadError("external validation response is invalid") from exc

    def public_task_candidate(
        self, reference: ExternalRecordRef
    ) -> PublicTaskCandidateEnvelope:
        try:
            return _public_task_candidate_from_wire(
                self._call("public_task_candidate", reference)
            )
        except ValueError as exc:
            raise ExternalReadError(
                "public task candidate response is invalid"
            ) from exc


__all__ = [
    "ExternalReadBroker",
    "ExternalReadBrokerServer",
    "ExternalReadPeerAuthorizer",
    "ExternalReadRpcClient",
    "InboxExternalRecordResolver",
    "MappingExternalRecordResolver",
    "ModelExternalAnalyzer",
    "MultiplexedExternalRecordResolver",
    "OneShotExternalAnalyzer",
]
