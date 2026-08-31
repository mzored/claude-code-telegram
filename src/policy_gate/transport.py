"""Unix-socket peer authorization for the fixed Gate protocol."""

from __future__ import annotations

import ctypes
import errno
import os
import socket
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MAX_UNIX_SOCKET_PATH_BYTES = 103
RUN_DIRECTORY_MODE = 0o710
SOCKET_MODE = 0o660

PUBLIC_OPERATIONS = frozenset(
    {
        "register_subject",
        "stage_action",
        "allowed_actions",
        "submit_action",
        "meeting_options",
        "activate_receipt",
        "revoke_receipt",
        "erase_subject",
    }
)
CONTROLLER_OPERATIONS = frozenset(
    {
        "open_controller_session",
        "stage_owner_exact_action",
        "external_intent_execution_started",
        "prepare_external_admin",
        "prepare_admin",
        "confirm_external_admin",
        "confirm_admin",
        "set_breaker",
    }
)

OwnershipSetter = Callable[[Path, int, int], None]


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def validate_socket_path(path: Path) -> Path:
    """Reject paths that cannot be represented by every supported Unix socket."""

    if not path.is_absolute():
        raise ValueError("gate socket path must be absolute")
    if path.resolve(strict=False) != path:
        raise ValueError("gate socket path must be resolved")
    encoded = os.fsencode(path)
    if b"\x00" in encoded:
        raise ValueError("gate socket path contains a null byte")
    if len(encoded) > MAX_UNIX_SOCKET_PATH_BYTES:
        raise ValueError("gate socket path is too long")
    return path


def prepare_socket_path(
    path: Path,
    client_gid: int,
    *,
    ownership_setter: OwnershipSetter = os.chown,
) -> Path:
    """Create a Gate-owned run directory traversable by the client group."""

    validate_socket_path(path)
    if (
        not isinstance(client_gid, int)
        or isinstance(client_gid, bool)
        or client_gid < 0
    ):
        raise ValueError("gate client GID is invalid")
    path.parent.mkdir(parents=True, exist_ok=True, mode=RUN_DIRECTORY_MODE)
    ownership_setter(path.parent, -1, client_gid)
    os.chmod(path.parent, RUN_DIRECTORY_MODE)
    directory = path.parent.stat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.geteuid()
        or directory.st_gid != client_gid
        or stat.S_IMODE(directory.st_mode) != RUN_DIRECTORY_MODE
    ):
        raise PermissionError("gate run directory ownership is unsafe")
    if os.path.lexists(path):
        socket_metadata = path.lstat()
        if not stat.S_ISSOCK(socket_metadata.st_mode):
            raise ValueError("gate socket path already exists")
        if (
            socket_metadata.st_uid != os.geteuid()
            or socket_metadata.st_gid != client_gid
            or stat.S_IMODE(socket_metadata.st_mode) != SOCKET_MODE
        ):
            raise PermissionError("existing gate socket ownership is unsafe")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.2)
            result = probe.connect_ex(str(path))
        finally:
            probe.close()
        if result == 0:
            raise ValueError("gate socket path belongs to an active listener")
        if result not in {errno.ECONNREFUSED, errno.ENOENT}:
            raise ValueError("gate socket liveness could not be established")
        path.unlink()
    return path


def remove_bound_socket(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(mode):
        path.unlink()


def bind_unix_listener(
    path: Path,
    client_gid: int,
    backlog: int = 16,
    *,
    ownership_setter: OwnershipSetter = os.chown,
) -> socket.socket:
    """Bind AF_UNIX and grant connect access only to the configured client group."""

    if backlog <= 0 or backlog > 128:
        raise ValueError("gate listener backlog is invalid")
    prepared = prepare_socket_path(path, client_gid, ownership_setter=ownership_setter)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(prepared))
        ownership_setter(prepared, -1, client_gid)
        os.chmod(prepared, SOCKET_MODE)
        socket_metadata = prepared.stat()
        if (
            not stat.S_ISSOCK(socket_metadata.st_mode)
            or socket_metadata.st_uid != os.geteuid()
            or socket_metadata.st_gid != client_gid
            or stat.S_IMODE(socket_metadata.st_mode) != SOCKET_MODE
        ):
            raise PermissionError("gate socket ownership is unsafe")
        listener.listen(backlog)
    except BaseException:
        listener.close()
        remove_bound_socket(prepared)
        raise
    return listener


def peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Read credentials captured by the kernel for one AF_UNIX connection."""

    if connection.family != socket.AF_UNIX:
        raise OSError(errno.EPROTOTYPE, "Policy Gate accepts AF_UNIX peers only")
    if sys.platform.startswith("linux"):
        option = getattr(socket, "SO_PEERCRED", 17)
        raw = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("=iII"))
        pid, uid, gid = struct.unpack("=iII", raw)
    elif sys.platform == "darwin":
        peer_uid = ctypes.c_uint32()
        peer_gid = ctypes.c_uint32()
        libc = ctypes.CDLL(None, use_errno=True)
        getpeereid = libc.getpeereid
        getpeereid.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        getpeereid.restype = ctypes.c_int
        if getpeereid(
            connection.fileno(), ctypes.byref(peer_uid), ctypes.byref(peer_gid)
        ):
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        raw_pid = connection.getsockopt(0, 0x002, struct.calcsize("=i"))
        pid = struct.unpack("=i", raw_pid)[0]
        uid = int(peer_uid.value)
        gid = int(peer_gid.value)
    else:
        raise OSError(errno.ENOTSUP, "kernel peer credentials are unavailable")
    if pid <= 0 or uid < 0 or gid < 0:
        raise OSError(errno.EACCES, "kernel returned invalid peer credentials")
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


class GatePeerAuthorizer:
    """Bind administration to the controller connection's pre-model PID."""

    def __init__(
        self, public_uid: int, controller_uid: int, controller_pid: int
    ) -> None:
        identifiers = (public_uid, controller_uid, controller_pid)
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in identifiers
        ):
            raise ValueError("gate peer identifiers must be integers")
        if public_uid < 0 or controller_uid < 0 or controller_pid <= 0:
            raise ValueError("gate peer identifiers are invalid")
        self.public_uid = public_uid
        self.controller_uid = controller_uid
        self.controller_pid = controller_pid

    def authorize(self, uid: int, pid: int, role: str, operation: str) -> bool:
        if role == "public":
            return uid == self.public_uid and operation in PUBLIC_OPERATIONS
        if role == "controller":
            return (
                uid == self.controller_uid
                and pid == self.controller_pid
                and operation in CONTROLLER_OPERATIONS
            )
        return False

    def require(self, uid: int, pid: int, role: str, operation: str) -> None:
        if not self.authorize(uid, pid, role, operation):
            raise ValueError("gate peer is not authorized for this operation")
