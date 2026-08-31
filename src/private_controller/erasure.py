"""Write-only controller ledger erasure endpoint for Unit 4 links."""

from __future__ import annotations

import json
import os
import re
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, cast

from src.policy_gate.rpc import MAX_FRAME_BYTES
from src.policy_gate.transport import (
    bind_unix_listener,
    peer_credentials,
    remove_bound_socket,
    validate_socket_path,
)
from src.policy_gate.types import canonical_json
from src.private_controller.origin import RunOriginLedger

PROTOCOL_VERSION = 1
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class ExternalIntentLinkErasureError(RuntimeError):
    """The fixed controller erasure sink is unavailable or rejected a request."""


@dataclass(frozen=True)
class ExternalIntentLinkEraseRequest:
    """One opaque deletion target; no link lookup or status capability exists."""

    subject_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.subject_hash, str) or not _SHA256_HEX.fullmatch(
            self.subject_hash
        ):
            raise ValueError("external intent-link subject hash is invalid")


class ExternalIntentLinkEraser(Protocol):
    """Minimal public-side dependency: fixed deletion only, never a ledger read."""

    def erase_external_links(self, request: ExternalIntentLinkEraseRequest) -> None: ...


class ExternalIntentLinkErasePeerAuthorizer:
    """Pin this write-only endpoint to one Public Assistant process."""

    def __init__(self, public_uid: int, public_pid: int) -> None:
        if (
            not isinstance(public_uid, int)
            or isinstance(public_uid, bool)
            or public_uid < 0
            or not isinstance(public_pid, int)
            or isinstance(public_pid, bool)
            or public_pid <= 0
        ):
            raise ValueError("external erasure peer identifiers are invalid")
        self.public_uid = public_uid
        self.public_pid = public_pid

    def require(self, uid: int, pid: int) -> None:
        if uid != self.public_uid or pid != self.public_pid:
            raise PermissionError("external erasure peer is unauthorized")


def _read_frame(connection: socket.socket) -> dict[str, object]:
    buffer = bytearray()
    while True:
        chunk = connection.recv(min(4096, MAX_FRAME_BYTES + 2 - len(buffer)))
        if not chunk:
            raise ValueError("external erasure frame ended before its newline")
        buffer.extend(chunk)
        line, separator, trailing = bytes(buffer).partition(b"\n")
        if separator:
            if trailing or not line or len(line) > MAX_FRAME_BYTES:
                raise ValueError("external erasure frame is invalid")
            try:
                value = json.loads(line.decode("utf-8"))
                canonical = canonical_json(value).encode("utf-8")
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                RecursionError,
                ValueError,
            ):
                raise ValueError("external erasure frame is invalid") from None
            if not isinstance(value, dict) or canonical != line:
                raise ValueError("external erasure frame is not canonical")
            return cast(dict[str, object], value)
        if len(buffer) > MAX_FRAME_BYTES:
            raise ValueError("external erasure frame is too large")


def _write_frame(connection: socket.socket, payload: Mapping[str, object]) -> None:
    try:
        wire = canonical_json(dict(payload)).encode("utf-8")
    except (RecursionError, ValueError) as exc:
        raise ValueError("external erasure response is invalid") from exc
    if not wire or len(wire) > MAX_FRAME_BYTES:
        raise ValueError("external erasure response is too large")
    connection.sendall(wire + b"\n")


class ControllerExternalErasureRpcServer:
    """Controller-owned AF_UNIX sink with exactly one idempotent operation."""

    def __init__(
        self,
        ledger: RunOriginLedger,
        socket_path: Path,
        *,
        public_uid: int,
        public_pid: int,
        client_gid: int,
    ) -> None:
        self.ledger = ledger
        self.socket_path = validate_socket_path(socket_path)
        self.authorizer = ExternalIntentLinkErasePeerAuthorizer(public_uid, public_pid)
        self.listener = bind_unix_listener(self.socket_path, client_gid)
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.listener.close()
        remove_bound_socket(self.socket_path)

    def _reply(self, connection: socket.socket, request: dict[str, object]) -> None:
        if set(request) != {"version", "subject_hash"}:
            raise ValueError("external erasure request is invalid")
        version = request["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != PROTOCOL_VERSION
        ):
            raise ValueError("external erasure request is invalid")
        credentials = peer_credentials(connection)
        self.authorizer.require(credentials.uid, credentials.pid)
        subject_hash = request["subject_hash"]
        if not isinstance(subject_hash, str):
            raise ValueError("external erasure request is invalid")
        request_dto = ExternalIntentLinkEraseRequest(subject_hash)
        self.ledger.erase_external_subject_hash(request_dto.subject_hash)
        _write_frame(connection, {"ok": True, "result": None})

    def serve_once(self) -> None:
        connection, _ = self.listener.accept()
        connection.settimeout(3.0)
        try:
            try:
                self._reply(connection, _read_frame(connection))
            except (PermissionError, ValueError, OSError):
                _write_frame(connection, {"ok": False, "error": "rejected"})
        except OSError:
            return
        finally:
            connection.close()

    def serve_forever(self, stop_signal: object, *, poll_interval: float = 0.2) -> None:
        if poll_interval <= 0 or poll_interval > 1:
            raise ValueError("external erasure poll interval is invalid")
        is_set = getattr(stop_signal, "is_set", None)
        if not callable(is_set):
            raise ValueError("external erasure stop signal is invalid")
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


class ControllerExternalErasureRpcClient(ExternalIntentLinkEraser):
    """Public-side client that can send one opaque erase request and nothing else."""

    def __init__(self, socket_path: Path, *, timeout: float = 3.0) -> None:
        self.socket_path = validate_socket_path(socket_path)
        if timeout <= 0 or timeout > 10:
            raise ValueError("external erasure client timeout is invalid")
        self.timeout = timeout
        self.opened_by_pid = os.getpid()
        self._lock = threading.RLock()

    def erase_external_links(self, request: ExternalIntentLinkEraseRequest) -> None:
        if not isinstance(request, ExternalIntentLinkEraseRequest):
            raise ValueError("external erasure request is invalid")
        if os.getpid() != self.opened_by_pid:
            raise PermissionError(
                "external erasure client cannot be used by a forked process"
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
                        "subject_hash": request.subject_hash,
                    },
                )
                response = _read_frame(connection)
            except (OSError, ValueError) as exc:
                raise ExternalIntentLinkErasureError(
                    "private external-link erasure is unavailable"
                ) from exc
            finally:
                connection.close()
        if set(response) == {"ok", "result"} and response.get("ok") is True:
            if response.get("result") is None:
                return
        if set(response) == {"ok", "error"} and response.get("ok") is False:
            raise ExternalIntentLinkErasureError(
                "private external-link erasure was rejected"
            )
        raise ExternalIntentLinkErasureError(
            "private external-link erasure response is invalid"
        )


__all__ = [
    "ControllerExternalErasureRpcClient",
    "ControllerExternalErasureRpcServer",
    "ExternalIntentLinkErasePeerAuthorizer",
    "ExternalIntentLinkEraseRequest",
    "ExternalIntentLinkEraser",
    "ExternalIntentLinkErasureError",
]
