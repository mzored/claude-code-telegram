"""Bounded local RPC for Policy Gate clients."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence, cast

from src.policy_gate.service import PolicyGateService
from src.policy_gate.transport import (
    GatePeerAuthorizer,
    peer_credentials,
    validate_socket_path,
)
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    ActionResult,
    AdminDraft,
    AdminKind,
    AdminResult,
    ExternalActionConfirmation,
    ExternalActionLink,
    MeetingOptionsResult,
    Operation,
    PreparedIntent,
    Scope,
    TrustedReference,
    canonical_json,
)

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 32 * 1024
MAX_STRING_BYTES = 4096
MIN_SIGNED_64 = -(2**63)
MAX_SIGNED_64 = 2**63 - 1


class GateRpcError(RuntimeError):
    """Base failure for the local Policy Gate protocol."""


class GateRpcProtocolError(GateRpcError):
    """The peer did not speak the fixed canonical protocol."""


class GateRpcAuthorizationError(GateRpcError):
    """Kernel credentials do not authorize the claimed role and operation."""


class GateRpcRejectedError(GateRpcError):
    """Policy Gate rejected an otherwise valid administration request."""


class StopSignal(Protocol):
    def is_set(self) -> bool: ...


@dataclass(frozen=True)
class _Request:
    role: str
    operation: str
    payload: dict[str, object]


def _reject_constant(_: str) -> object:
    raise GateRpcProtocolError("non-finite JSON numbers are forbidden")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GateRpcProtocolError("duplicate JSON object key")
        result[key] = value
    return result


def _decode_canonical_json(wire: bytes) -> object:
    try:
        text = wire.decode("utf-8")
        value = cast(
            object,
            json.loads(
                text,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            ),
        )
        if canonical_json(value).encode("utf-8") != wire:
            raise GateRpcProtocolError("RPC frame is not canonical JSON")
        return value
    except GateRpcProtocolError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise GateRpcProtocolError("RPC frame is invalid") from exc


def _read_frame(connection: socket.socket) -> object:
    buffer = bytearray()
    while True:
        chunk = connection.recv(min(4096, MAX_FRAME_BYTES + 2 - len(buffer)))
        if not chunk:
            raise GateRpcProtocolError("RPC frame ended before its newline")
        buffer.extend(chunk)
        line, separator, trailing = bytes(buffer).partition(b"\n")
        if separator:
            if trailing:
                raise GateRpcProtocolError("one connection accepts one RPC frame")
            if not line or len(line) > MAX_FRAME_BYTES:
                raise GateRpcProtocolError("RPC frame size is invalid")
            return _decode_canonical_json(line)
        if len(buffer) > MAX_FRAME_BYTES:
            raise GateRpcProtocolError("RPC frame is too large")


def _write_frame(connection: socket.socket, value: object) -> None:
    try:
        wire = canonical_json(value).encode("utf-8")
    except (RecursionError, ValueError) as exc:
        raise GateRpcProtocolError("RPC response is not canonical JSON") from exc
    if not wire or len(wire) > MAX_FRAME_BYTES:
        raise GateRpcProtocolError("RPC frame is too large")
    connection.sendall(wire + b"\n")


def _object(value: object, keys: frozenset[str] | None = None) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise GateRpcProtocolError("RPC value must be an object")
    result = cast(dict[str, object], value)
    if keys is not None and set(result) != keys:
        raise GateRpcProtocolError("RPC object fields do not match the DTO")
    return result


def _text(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise GateRpcProtocolError("RPC value must be text")
    if not allow_empty and not value:
        raise GateRpcProtocolError("RPC text value is empty")
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise GateRpcProtocolError("RPC text value is too large")
    return value


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise GateRpcProtocolError("RPC value must be an integer")
    if value < MIN_SIGNED_64 or value > MAX_SIGNED_64:
        raise GateRpcProtocolError("RPC integer exceeds the signed 64-bit range")
    return value


def _optional_integer(value: object) -> int | None:
    return None if value is None else _integer(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise GateRpcProtocolError("RPC value must be a boolean")
    return value


_REFERENCE_KEYS = frozenset({"kind", "value"})
_ACTION_KEYS = frozenset(
    {
        "action_id",
        "subject_id",
        "connection_id",
        "conversation_id",
        "update_id",
        "request_id",
        "operation",
        "arguments",
        "processing_authorization_version",
        "processing_authorization_revision",
        "processor_purpose",
        "origin",
    }
)
_LEGACY_PUBLIC_ACTION_KEYS = _ACTION_KEYS - frozenset({"origin"})
_ACTION_RESULT_KEYS = frozenset({"outcome", "action_id"})
_MEETING_OPTIONS_RESULT_KEYS = frozenset({"outcome", "action_id", "slots", "timezone"})
_EXTERNAL_LINK_KEYS = frozenset({"link_identity", "source_digest"})
_EXTERNAL_CONFIRMATION_KEYS = frozenset({"link", "confirmation_sequence"})
_DRAFT_KEYS = frozenset(
    {
        "kind",
        "operation",
        "scope",
        "constraints",
        "expires_at",
        "remaining_uses",
        "exact_binding",
    }
)


def _reference_to_wire(reference: TrustedReference) -> dict[str, object]:
    return {"kind": reference.kind, "value": reference.value}


def _reference_from_wire(value: object) -> TrustedReference:
    fields = _object(value, _REFERENCE_KEYS)
    return TrustedReference(_text(fields["kind"]), _text(fields["value"]))


def _action_to_wire(binding: ActionBinding) -> dict[str, object]:
    return binding.as_dict()


def _action_from_wire(
    value: object, *, allow_legacy_public: bool = False
) -> ActionBinding:
    fields = _object(value)
    legacy_public = set(fields) == _LEGACY_PUBLIC_ACTION_KEYS
    if set(fields) != _ACTION_KEYS and not (allow_legacy_public and legacy_public):
        raise GateRpcProtocolError("RPC object fields do not match the DTO")
    arguments = _object(fields["arguments"])
    try:
        operation = Operation(_text(fields["operation"]))
    except ValueError as exc:
        raise GateRpcProtocolError("RPC action operation is invalid") from exc
    normalized: dict[str, object] = {
        "action_id": _text(fields["action_id"]),
        "subject_id": _text(fields["subject_id"]),
        "connection_id": _text(fields["connection_id"]),
        "conversation_id": _integer(fields["conversation_id"]),
        "update_id": _integer(fields["update_id"]),
        "request_id": _text(fields["request_id"]),
        "operation": operation.value,
        "arguments": arguments,
        "processing_authorization_version": _text(
            fields["processing_authorization_version"]
        ),
        "processing_authorization_revision": _integer(
            fields["processing_authorization_revision"]
        ),
        "processor_purpose": _text(fields["processor_purpose"]),
    }
    try:
        if legacy_public:
            return ActionBinding.from_legacy_public_dict(normalized)
        normalized["origin"] = ActionOrigin(_text(fields["origin"])).value
        return ActionBinding.from_dict(normalized)
    except ValueError as exc:
        raise GateRpcProtocolError("RPC action binding is invalid") from exc


def _action_result_to_wire(result: ActionResult) -> dict[str, object]:
    return {"outcome": result.outcome, "action_id": result.action_id}


def _action_result_from_wire(value: object) -> ActionResult:
    fields = _object(value, _ACTION_RESULT_KEYS)
    return ActionResult(
        outcome=_text(fields["outcome"]),
        action_id=_text(fields["action_id"], allow_empty=True),
    )


def _meeting_options_result_to_wire(result: MeetingOptionsResult) -> dict[str, object]:
    return {
        "outcome": result.outcome,
        "action_id": result.action_id,
        "slots": [list(slot) for slot in result.slots],
        "timezone": result.timezone,
    }


def _meeting_options_result_from_wire(value: object) -> MeetingOptionsResult:
    fields = _object(value, _MEETING_OPTIONS_RESULT_KEYS)
    slots_value = fields["slots"]
    if not isinstance(slots_value, list):
        raise GateRpcProtocolError("meeting options response is invalid")
    slots: list[tuple[str, int, int, int]] = []
    for item in slots_value:
        if not isinstance(item, list) or len(item) != 4:
            raise GateRpcProtocolError("meeting options response is invalid")
        slots.append(
            (_text(item[0]), _integer(item[1]), _integer(item[2]), _integer(item[3]))
        )
    return MeetingOptionsResult(
        _text(fields["outcome"]),
        _text(fields["action_id"], allow_empty=True),
        tuple(slots),
        _text(fields["timezone"]),
    )


def _external_link_to_wire(link: ExternalActionLink) -> dict[str, object]:
    return {
        "link_identity": link.link_identity,
        "source_digest": link.source_digest,
    }


def _external_link_from_wire(value: object) -> ExternalActionLink:
    fields = _object(value, _EXTERNAL_LINK_KEYS)
    try:
        return ExternalActionLink(
            _text(fields["link_identity"]), _text(fields["source_digest"])
        )
    except ValueError as exc:
        raise GateRpcProtocolError("external action link is invalid") from exc


def _external_confirmation_to_wire(
    confirmation: ExternalActionConfirmation,
) -> dict[str, object]:
    return {
        "link": _external_link_to_wire(confirmation.link),
        "confirmation_sequence": confirmation.confirmation_sequence,
    }


def _external_confirmation_from_wire(value: object) -> ExternalActionConfirmation:
    fields = _object(value, _EXTERNAL_CONFIRMATION_KEYS)
    try:
        return ExternalActionConfirmation(
            _external_link_from_wire(fields["link"]),
            _integer(fields["confirmation_sequence"]),
        )
    except ValueError as exc:
        raise GateRpcProtocolError("external confirmation is invalid") from exc


def _draft_to_wire(draft: AdminDraft) -> dict[str, object]:
    return {
        "kind": draft.kind.value,
        "operation": None if draft.operation is None else draft.operation.value,
        "scope": None if draft.scope is None else draft.scope.value,
        "constraints": (None if draft.constraints is None else dict(draft.constraints)),
        "expires_at": draft.expires_at,
        "remaining_uses": draft.remaining_uses,
        "exact_binding": (
            None
            if draft.exact_binding is None
            else _action_to_wire(draft.exact_binding)
        ),
    }


def _draft_from_wire(value: object) -> AdminDraft:
    fields = _object(value, _DRAFT_KEYS)
    operation_value = fields["operation"]
    scope_value = fields["scope"]
    constraints_value = fields["constraints"]
    exact_value = fields["exact_binding"]
    try:
        kind = AdminKind(_text(fields["kind"]))
        operation = (
            None if operation_value is None else Operation(_text(operation_value))
        )
        scope = None if scope_value is None else Scope(_text(scope_value))
    except ValueError as exc:
        raise GateRpcProtocolError("RPC administration enum is invalid") from exc
    constraints = None if constraints_value is None else _object(constraints_value)
    exact_binding = None if exact_value is None else _action_from_wire(exact_value)
    return AdminDraft(
        kind=kind,
        operation=operation,
        scope=scope,
        constraints=constraints,
        expires_at=_optional_integer(fields["expires_at"]),
        remaining_uses=_optional_integer(fields["remaining_uses"]),
        exact_binding=exact_binding,
    )


def _prepared_to_wire(prepared: PreparedIntent) -> dict[str, object]:
    return {
        "intent_id": prepared.intent_id,
        "preview": dict(prepared.preview),
        "expires_at": prepared.expires_at,
    }


def _prepared_from_wire(value: object) -> PreparedIntent:
    fields = _object(value, frozenset({"intent_id", "preview", "expires_at"}))
    return PreparedIntent(
        intent_id=_text(fields["intent_id"]),
        preview=_object(fields["preview"]),
        expires_at=_integer(fields["expires_at"]),
    )


def _admin_result_to_wire(result: AdminResult) -> dict[str, object]:
    return {
        "outcome": result.outcome,
        "action_result": (
            None
            if result.action_result is None
            else _action_result_to_wire(result.action_result)
        ),
    }


def _admin_result_from_wire(value: object) -> AdminResult:
    fields = _object(value, frozenset({"outcome", "action_result"}))
    action_value = fields["action_result"]
    return AdminResult(
        outcome=_text(fields["outcome"]),
        action_result=(
            None if action_value is None else _action_result_from_wire(action_value)
        ),
    )


def _processor_purposes(value: object) -> dict[str, tuple[str, ...]]:
    fields = _object(value)
    result: dict[str, tuple[str, ...]] = {}
    for processor, purposes_value in fields.items():
        _text(processor)
        if not isinstance(purposes_value, list):
            raise GateRpcProtocolError("processor purposes must be an array")
        purposes = tuple(_text(purpose) for purpose in purposes_value)
        if not purposes or len(set(purposes)) != len(purposes):
            raise GateRpcProtocolError("processor purposes are invalid")
        result[processor] = purposes
    if not result:
        raise GateRpcProtocolError("processor purposes are empty")
    return result


def _request_from_wire(value: object) -> _Request:
    fields = _object(value, frozenset({"version", "role", "operation", "payload"}))
    if _integer(fields["version"]) != PROTOCOL_VERSION:
        raise GateRpcProtocolError("RPC protocol version is unsupported")
    return _Request(
        role=_text(fields["role"]),
        operation=_text(fields["operation"]),
        payload=_object(fields["payload"]),
    )


class GateRpcDispatcher:
    """Map fixed wire operations to explicit Policy Gate service methods."""

    def __init__(self, service: PolicyGateService) -> None:
        self.service = service

    def dispatch(self, request: _Request) -> object:
        payload = request.payload
        operation = request.operation
        if request.role == "public":
            if operation == "register_subject":
                fields = _object(payload, frozenset({"subject_id", "references"}))
                references = _object(fields["references"])
                self.service.register_subject(
                    _text(fields["subject_id"]),
                    {
                        _text(kind): _text(reference)
                        for kind, reference in references.items()
                    },
                )
                return None
            if operation == "allowed_actions":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "subject_id",
                            "processing_authorization_version",
                            "processing_authorization_revision",
                        }
                    ),
                )
                return [
                    item.value
                    for item in self.service.allowed_actions(
                        _text(fields["subject_id"]),
                        _text(fields["processing_authorization_version"]),
                        _integer(fields["processing_authorization_revision"]),
                    )
                ]
            if operation == "stage_action":
                fields = _object(payload, frozenset({"binding"}))
                return self.service.stage_action(
                    _action_from_wire(fields["binding"], allow_legacy_public=True)
                )
            if operation == "submit_action":
                fields = _object(payload, frozenset({"binding"}))
                return _action_result_to_wire(
                    self.service.submit_action(
                        _action_from_wire(fields["binding"], allow_legacy_public=True)
                    )
                )
            if operation == "meeting_options":
                fields = _object(payload, frozenset({"binding"}))
                return _meeting_options_result_to_wire(
                    self.service.meeting_options(
                        _action_from_wire(fields["binding"], allow_legacy_public=True)
                    )
                )
            if operation == "activate_receipt":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "subject_id",
                            "version",
                            "revision",
                            "processor_purposes",
                        }
                    ),
                )
                return self.service.activate_receipt(
                    _text(fields["subject_id"]),
                    _text(fields["version"]),
                    _integer(fields["revision"]),
                    _processor_purposes(fields["processor_purposes"]),
                )
            if operation == "revoke_receipt":
                fields = _object(payload, frozenset({"subject_id", "revision"}))
                return self.service.revoke_receipt(
                    _text(fields["subject_id"]), _integer(fields["revision"])
                )
            if operation == "erase_subject":
                fields = _object(payload, frozenset({"subject_id"}))
                return self.service.erase_subject(_text(fields["subject_id"]))
        elif request.role == "controller":
            if operation == "stage_owner_exact_action":
                fields = _object(
                    payload,
                    frozenset({"request_reference", "binding", "external_link"}),
                )
                return self.service.stage_owner_exact_action(
                    _reference_from_wire(fields["request_reference"]),
                    _action_from_wire(fields["binding"]),
                    _external_link_from_wire(fields["external_link"]),
                )
            if operation == "external_intent_execution_started":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "intent_id",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                            "external_link",
                        }
                    ),
                )
                return self.service.external_intent_execution_started(
                    _text(fields["intent_id"]),
                    owner_id=_integer(fields["owner_id"]),
                    control_chat_id=_integer(fields["control_chat_id"]),
                    preview_message_id=_integer(fields["preview_message_id"]),
                    external_link=_external_link_from_wire(fields["external_link"]),
                )
            if operation == "prepare_external_admin":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "reference",
                            "draft",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                            "external_link",
                            "minimum_confirmation_sequence",
                            "ttl_seconds",
                        }
                    ),
                )
                return _prepared_to_wire(
                    self.service.prepare_external_admin(
                        _reference_from_wire(fields["reference"]),
                        _draft_from_wire(fields["draft"]),
                        owner_id=_integer(fields["owner_id"]),
                        control_chat_id=_integer(fields["control_chat_id"]),
                        preview_message_id=_integer(fields["preview_message_id"]),
                        external_link=_external_link_from_wire(fields["external_link"]),
                        minimum_confirmation_sequence=_integer(
                            fields["minimum_confirmation_sequence"]
                        ),
                        ttl_seconds=_integer(fields["ttl_seconds"]),
                    )
                )
            if operation == "prepare_public_task_exact":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "request_reference",
                            "binding",
                            "candidate_link",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                            "ttl_seconds",
                        }
                    ),
                )
                return _prepared_to_wire(
                    self.service.prepare_public_task_exact(
                        _reference_from_wire(fields["request_reference"]),
                        _action_from_wire(fields["binding"]),
                        _external_link_from_wire(fields["candidate_link"]),
                        owner_id=_integer(fields["owner_id"]),
                        control_chat_id=_integer(fields["control_chat_id"]),
                        preview_message_id=_integer(fields["preview_message_id"]),
                        ttl_seconds=_integer(fields["ttl_seconds"]),
                    )
                )
            if operation == "prepare_admin":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "reference",
                            "draft",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                            "ttl_seconds",
                        }
                    ),
                )
                return _prepared_to_wire(
                    self.service.prepare_admin(
                        _reference_from_wire(fields["reference"]),
                        _draft_from_wire(fields["draft"]),
                        owner_id=_integer(fields["owner_id"]),
                        control_chat_id=_integer(fields["control_chat_id"]),
                        preview_message_id=_integer(fields["preview_message_id"]),
                        ttl_seconds=_integer(fields["ttl_seconds"]),
                    )
                )
            if operation == "confirm_admin":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "intent_id",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                        }
                    ),
                )
                return _admin_result_to_wire(
                    self.service.confirm_admin(
                        _text(fields["intent_id"]),
                        owner_id=_integer(fields["owner_id"]),
                        control_chat_id=_integer(fields["control_chat_id"]),
                        preview_message_id=_integer(fields["preview_message_id"]),
                    )
                )
            if operation == "confirm_external_admin":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "intent_id",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                            "external_confirmation",
                        }
                    ),
                )
                return _admin_result_to_wire(
                    self.service.confirm_external_admin(
                        _text(fields["intent_id"]),
                        owner_id=_integer(fields["owner_id"]),
                        control_chat_id=_integer(fields["control_chat_id"]),
                        preview_message_id=_integer(fields["preview_message_id"]),
                        external_confirmation=_external_confirmation_from_wire(
                            fields["external_confirmation"]
                        ),
                    )
                )
            if operation == "confirm_public_task_exact":
                fields = _object(
                    payload,
                    frozenset(
                        {
                            "intent_id",
                            "owner_id",
                            "control_chat_id",
                            "preview_message_id",
                            "binding",
                            "candidate_link",
                        }
                    ),
                )
                return _admin_result_to_wire(
                    self.service.confirm_public_task_exact(
                        _text(fields["intent_id"]),
                        owner_id=_integer(fields["owner_id"]),
                        control_chat_id=_integer(fields["control_chat_id"]),
                        preview_message_id=_integer(fields["preview_message_id"]),
                        binding=_action_from_wire(fields["binding"]),
                        candidate_link=_external_link_from_wire(
                            fields["candidate_link"]
                        ),
                    )
                )
            if operation == "set_breaker":
                fields = _object(payload, frozenset({"name", "is_open"}))
                self.service.set_breaker(
                    _text(fields["name"]), _boolean(fields["is_open"])
                )
                return None
        raise GateRpcProtocolError("RPC operation is unsupported")


def _send_error(connection: socket.socket, code: str) -> None:
    try:
        _write_frame(connection, {"ok": False, "error": code})
    except (GateRpcProtocolError, OSError):
        return


class PolicyGateRpcServer:
    """Serve one-shot public calls and one pre-model controller channel."""

    def __init__(
        self,
        service: PolicyGateService,
        listener: socket.socket,
        authorizer: GatePeerAuthorizer,
        *,
        connection_timeout: float = 3.0,
    ) -> None:
        if listener.family != socket.AF_UNIX:
            raise ValueError("Policy Gate RPC requires an AF_UNIX listener")
        if connection_timeout <= 0 or connection_timeout > 10:
            raise ValueError("Policy Gate connection timeout is invalid")
        self.listener = listener
        self.service = service
        self.authorizer = authorizer
        self.dispatcher = GateRpcDispatcher(service)
        self.connection_timeout = connection_timeout
        self._controller_lock = threading.Lock()
        self._controller_session_claimed = False
        self._worker_capacity = threading.BoundedSemaphore(32)
        self._workers_lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()

    def _claim_controller_session(self) -> bool:
        with self._controller_lock:
            if self._controller_session_claimed:
                return False
            self._controller_session_claimed = True
            return True

    def _serve_connection(
        self, connection: socket.socket, stop_signal: StopSignal | None = None
    ) -> None:
        """Authenticate once and keep only the first controller channel alive."""

        with connection:
            connection.settimeout(self.connection_timeout)
            try:
                credentials = peer_credentials(connection)
            except OSError:
                _send_error(connection, "unauthorized")
                return
            controller_session = False
            while stop_signal is None or not stop_signal.is_set():
                try:
                    request = _request_from_wire(_read_frame(connection))
                except socket.timeout:
                    if controller_session:
                        continue
                    _send_error(connection, "invalid_request")
                    return
                except (GateRpcProtocolError, OSError):
                    if not controller_session:
                        _send_error(connection, "invalid_request")
                    return
                if controller_session and request.role != "controller":
                    _send_error(connection, "unauthorized")
                    return
                if not controller_session and request.role == "controller":
                    if request.operation != "open_controller_session":
                        _send_error(connection, "unauthorized")
                        return
                    try:
                        self.authorizer.require(
                            credentials.uid,
                            credentials.pid,
                            request.role,
                            request.operation,
                        )
                    except ValueError:
                        _send_error(connection, "unauthorized")
                        return
                    if not self._claim_controller_session():
                        _send_error(connection, "unauthorized")
                        return
                    try:
                        _object(request.payload, frozenset())
                        _write_frame(connection, {"ok": True, "result": None})
                    except (GateRpcProtocolError, OSError):
                        return
                    controller_session = True
                    connection.settimeout(min(self.connection_timeout, 0.5))
                    continue
                if request.operation == "open_controller_session":
                    _send_error(connection, "unauthorized")
                    return
                try:
                    self.authorizer.require(
                        credentials.uid,
                        credentials.pid,
                        request.role,
                        request.operation,
                    )
                except ValueError:
                    _send_error(connection, "unauthorized")
                    return
                try:
                    result = self.dispatcher.dispatch(request)
                    _write_frame(connection, {"ok": True, "result": result})
                except GateRpcProtocolError:
                    _send_error(connection, "invalid_request")
                    return
                except (PermissionError, ValueError):
                    _send_error(connection, "rejected")
                except Exception:
                    _send_error(connection, "internal_error")
                if not controller_session:
                    return

    def _worker(self, connection: socket.socket, stop_signal: StopSignal) -> None:
        try:
            self._serve_connection(connection, stop_signal)
        finally:
            with self._workers_lock:
                self._connections.discard(connection)
                self._workers.discard(threading.current_thread())
            self._worker_capacity.release()

    def serve_once(self) -> None:
        connection, _ = self.listener.accept()
        self._serve_connection(connection)

    def serve_forever(
        self,
        stop_signal: StopSignal,
        *,
        poll_interval: float = 0.2,
        recovery_interval: float = 1.0,
    ) -> None:
        if poll_interval <= 0 or poll_interval > 1:
            raise ValueError("Policy Gate poll interval is invalid")
        if recovery_interval <= 0 or recovery_interval > 60:
            raise ValueError("Policy Gate recovery interval is invalid")
        self.listener.settimeout(poll_interval)
        self.service.recover_claimed_actions()
        next_recovery = time.monotonic() + recovery_interval
        try:
            while not stop_signal.is_set():
                if time.monotonic() >= next_recovery:
                    self.service.recover_claimed_actions()
                    next_recovery = time.monotonic() + recovery_interval
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                if not self._worker_capacity.acquire(blocking=False):
                    connection.close()
                    continue
                worker = threading.Thread(
                    target=self._worker,
                    args=(connection, stop_signal),
                    daemon=True,
                )
                with self._workers_lock:
                    self._connections.add(connection)
                    self._workers.add(worker)
                worker.start()
        finally:
            with self._workers_lock:
                connections = tuple(self._connections)
                workers = tuple(self._workers)
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            for worker in workers:
                worker.join(timeout=1)


class _GateRpcClient:
    def __init__(
        self,
        socket_path: Path,
        role: str,
        *,
        timeout: float = 3.0,
    ) -> None:
        self.socket_path = validate_socket_path(socket_path)
        if timeout <= 0 or timeout > 10:
            raise ValueError("Policy Gate client timeout is invalid")
        self.role = role
        self.timeout = timeout

    @staticmethod
    def _result(response: dict[str, object]) -> object:
        ok_value = response.get("ok")
        ok = _boolean(ok_value)
        if ok:
            response = _object(response, frozenset({"ok", "result"}))
            return response["result"]
        response = _object(response, frozenset({"ok", "error"}))
        error = _text(response["error"])
        if error == "unauthorized":
            raise GateRpcAuthorizationError("Policy Gate peer is unauthorized")
        if error == "rejected":
            raise GateRpcRejectedError("Policy Gate rejected the request")
        if error == "invalid_request":
            raise GateRpcProtocolError("Policy Gate rejected the RPC frame")
        raise GateRpcError("Policy Gate failed the request")

    def _request(self, operation: str, payload: Mapping[str, object]) -> object:
        return {
            "version": PROTOCOL_VERSION,
            "role": self.role,
            "operation": operation,
            "payload": dict(payload),
        }

    def _call(self, operation: str, payload: Mapping[str, object]) -> object:
        request = self._request(operation, payload)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.set_inheritable(False)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            _write_frame(connection, request)
            connection.shutdown(socket.SHUT_WR)
            response = _object(_read_frame(connection))
        except GateRpcProtocolError:
            raise
        except OSError as exc:
            raise GateRpcError("Policy Gate is unavailable") from exc
        finally:
            connection.close()
        return self._result(response)


class PublicGateRpcClient(_GateRpcClient):
    """Strict client available to the public assistant process."""

    def __init__(self, socket_path: Path, *, timeout: float = 3.0) -> None:
        super().__init__(socket_path, "public", timeout=timeout)

    def allowed_actions(
        self,
        subject_id: str,
        processing_authorization_version: str,
        processing_authorization_revision: int,
    ) -> tuple[Operation, ...]:
        value = self._call(
            "allowed_actions",
            {
                "subject_id": subject_id,
                "processing_authorization_version": processing_authorization_version,
                "processing_authorization_revision": processing_authorization_revision,
            },
        )
        if not isinstance(value, list):
            raise GateRpcProtocolError("allowed actions response is invalid")
        try:
            operations = tuple(Operation(_text(item)) for item in value)
        except ValueError as exc:
            raise GateRpcProtocolError("allowed actions response is invalid") from exc
        if len(set(operations)) != len(operations):
            raise GateRpcProtocolError("allowed actions response has duplicates")
        return operations

    def register_subject(self, subject_id: str, references: Mapping[str, str]) -> None:
        value = self._call(
            "register_subject",
            {"subject_id": subject_id, "references": dict(references)},
        )
        if value is not None:
            raise GateRpcProtocolError("register subject response is invalid")

    def submit_action(self, binding: ActionBinding) -> ActionResult:
        return _action_result_from_wire(
            self._call("submit_action", {"binding": _action_to_wire(binding)})
        )

    def meeting_options(self, binding: ActionBinding) -> MeetingOptionsResult:
        return _meeting_options_result_from_wire(
            self._call("meeting_options", {"binding": _action_to_wire(binding)})
        )

    def stage_action(self, binding: ActionBinding) -> bool:
        return _boolean(
            self._call("stage_action", {"binding": _action_to_wire(binding)})
        )

    def activate_receipt(
        self,
        subject_id: str,
        version: str,
        revision: int,
        processor_purposes: Mapping[str, Sequence[str]],
    ) -> bool:
        value = self._call(
            "activate_receipt",
            {
                "subject_id": subject_id,
                "version": version,
                "revision": revision,
                "processor_purposes": {
                    processor: list(purposes)
                    for processor, purposes in processor_purposes.items()
                },
            },
        )
        return _boolean(value)

    def revoke_receipt(self, subject_id: str, revision: int) -> bool:
        return _boolean(
            self._call(
                "revoke_receipt",
                {"subject_id": subject_id, "revision": revision},
            )
        )

    def erase_subject(self, subject_id: str) -> str:
        return _text(self._call("erase_subject", {"subject_id": subject_id}))


class ControllerGateRpcClient(_GateRpcClient):
    """Strict PID-pinned administration client for the private controller."""

    def __init__(self, socket_path: Path, *, timeout: float = 3.0) -> None:
        super().__init__(socket_path, "controller", timeout=timeout)
        self.opened_by_pid = os.getpid()
        self._lock = threading.RLock()
        self._connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._connection.set_inheritable(False)
        self._connection.settimeout(self.timeout)
        try:
            self._connection.connect(str(self.socket_path))
            result = self._call("open_controller_session", {})
            if result is not None:
                raise GateRpcProtocolError(
                    "open controller session response is invalid"
                )
        except BaseException:
            self._connection.close()
            raise

    def _call(self, operation: str, payload: Mapping[str, object]) -> object:
        if os.getpid() != self.opened_by_pid:
            raise GateRpcAuthorizationError(
                "controller channel cannot be used by a forked process"
            )
        with self._lock:
            try:
                _write_frame(self._connection, self._request(operation, payload))
                response = _object(_read_frame(self._connection))
            except GateRpcProtocolError:
                raise
            except OSError as exc:
                raise GateRpcError(
                    "Policy Gate controller channel is unavailable"
                ) from exc
        return self._result(response)

    def fileno(self) -> int:
        return self._connection.fileno()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def prepare_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent:
        return _prepared_from_wire(
            self._call(
                "prepare_admin",
                {
                    "reference": _reference_to_wire(reference),
                    "draft": _draft_to_wire(draft),
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                    "ttl_seconds": ttl_seconds,
                },
            )
        )

    def stage_owner_exact_action(
        self,
        request_reference: TrustedReference,
        binding: ActionBinding,
        external_link: ExternalActionLink,
    ) -> bool:
        """Stage the one exact Unit 4 action the controller may prepare."""

        if not isinstance(external_link, ExternalActionLink):
            raise ValueError("external action link is invalid")
        return _boolean(
            self._call(
                "stage_owner_exact_action",
                {
                    "request_reference": _reference_to_wire(request_reference),
                    "binding": _action_to_wire(binding),
                    "external_link": _external_link_to_wire(external_link),
                },
            )
        )

    def prepare_external_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_link: ExternalActionLink,
        minimum_confirmation_sequence: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent:
        if not isinstance(external_link, ExternalActionLink):
            raise ValueError("external action link is invalid")
        return _prepared_from_wire(
            self._call(
                "prepare_external_admin",
                {
                    "reference": _reference_to_wire(reference),
                    "draft": _draft_to_wire(draft),
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                    "external_link": _external_link_to_wire(external_link),
                    "minimum_confirmation_sequence": minimum_confirmation_sequence,
                    "ttl_seconds": ttl_seconds,
                },
            )
        )

    def prepare_public_task_exact(
        self,
        request_reference: TrustedReference,
        binding: ActionBinding,
        candidate_link: ExternalActionLink,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent:
        return _prepared_from_wire(
            self._call(
                "prepare_public_task_exact",
                {
                    "request_reference": _reference_to_wire(request_reference),
                    "binding": _action_to_wire(binding),
                    "candidate_link": _external_link_to_wire(candidate_link),
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                    "ttl_seconds": ttl_seconds,
                },
            )
        )

    def external_intent_execution_started(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_link: ExternalActionLink,
    ) -> bool:
        """Check recovery state without exposing an intent payload."""

        if not isinstance(external_link, ExternalActionLink):
            raise ValueError("external action link is invalid")
        return _boolean(
            self._call(
                "external_intent_execution_started",
                {
                    "intent_id": intent_id,
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                    "external_link": _external_link_to_wire(external_link),
                },
            )
        )

    def confirm_external_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_confirmation: ExternalActionConfirmation,
    ) -> AdminResult:
        if not isinstance(external_confirmation, ExternalActionConfirmation):
            raise ValueError("external confirmation is invalid")
        return _admin_result_from_wire(
            self._call(
                "confirm_external_admin",
                {
                    "intent_id": intent_id,
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                    "external_confirmation": _external_confirmation_to_wire(
                        external_confirmation
                    ),
                },
            )
        )

    def confirm_public_task_exact(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        binding: ActionBinding,
        candidate_link: ExternalActionLink,
    ) -> AdminResult:
        return _admin_result_from_wire(
            self._call(
                "confirm_public_task_exact",
                {
                    "intent_id": intent_id,
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                    "binding": _action_to_wire(binding),
                    "candidate_link": _external_link_to_wire(candidate_link),
                },
            )
        )

    def confirm_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
    ) -> AdminResult:
        return _admin_result_from_wire(
            self._call(
                "confirm_admin",
                {
                    "intent_id": intent_id,
                    "owner_id": owner_id,
                    "control_chat_id": control_chat_id,
                    "preview_message_id": preview_message_id,
                },
            )
        )

    def set_breaker(self, name: str, is_open: bool) -> None:
        value = self._call("set_breaker", {"name": name, "is_open": is_open})
        if value is not None:
            raise GateRpcProtocolError("set breaker response is invalid")
