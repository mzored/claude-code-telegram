from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

from src.policy_gate.transport import (
    MAX_UNIX_SOCKET_PATH_BYTES,
    GatePeerAuthorizer,
    bind_unix_listener,
    peer_credentials,
    prepare_socket_path,
)


@pytest.fixture
def short_run_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(
        prefix="pg-", dir=str(Path("/tmp").resolve())
    ) as directory:
        yield Path(directory)


def test_socket_group_and_roles_have_fixed_operations(short_run_dir: Path) -> None:
    socket_path = prepare_socket_path(short_run_dir / "gate.sock", os.getgid())
    parent = os.stat(socket_path.parent)
    assert parent.st_mode & 0o777 == 0o710
    assert parent.st_gid == os.getgid()
    authorizer = GatePeerAuthorizer(
        public_uid=501,
        controller_uid=502,
        controller_pid=9001,
    )
    assert authorizer.authorize(501, 7001, "public", "allowed_actions")
    assert authorizer.authorize(501, 7001, "public", "submit_action")
    assert not authorizer.authorize(501, 7001, "public", "prepare_admin")
    assert not authorizer.authorize(501, 7001, "public", "prepare_external_admin")
    assert authorizer.authorize(502, 9001, "controller", "prepare_admin")
    assert authorizer.authorize(502, 9001, "controller", "prepare_external_admin")
    assert authorizer.authorize(502, 9001, "controller", "confirm_external_admin")
    assert not authorizer.authorize(
        502, 9001, "controller", "_submit_owner_external_action"
    )
    assert not authorizer.authorize(502, 9002, "controller", "prepare_admin")
    assert not authorizer.authorize(999, 9001, "controller", "confirm_admin")


def test_unknown_role_or_operation_is_rejected() -> None:
    authorizer = GatePeerAuthorizer(501, 502, 9001)
    with pytest.raises(ValueError):
        authorizer.require(501, 1, "model", "submit_action")
    with pytest.raises(ValueError):
        authorizer.require(501, 1, "public", "arbitrary.execute")
    with pytest.raises(ValueError, match="identifiers"):
        GatePeerAuthorizer(501, 502, 0)


def test_bound_socket_has_no_public_listener_and_group_mode(
    short_run_dir: Path,
) -> None:
    path = short_run_dir / "run" / "gate.sock"
    listener = bind_unix_listener(path, os.getgid())
    try:
        assert listener.family.name == "AF_UNIX"
        socket_stat = os.stat(path)
        assert socket_stat.st_mode & 0o777 == 0o660
        assert socket_stat.st_gid == os.getgid()
    finally:
        listener.close()


def test_kernel_reports_unix_peer_credentials() -> None:
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        credentials = peer_credentials(server)
    finally:
        server.close()
        client.close()
    assert credentials.uid == os.getuid()
    assert credentials.gid == os.getgid()
    assert credentials.pid == os.getpid()


def test_socket_path_limit_is_checked_before_filesystem_changes(
    tmp_path: Path,
) -> None:
    too_long = tmp_path / ("g" * (MAX_UNIX_SOCKET_PATH_BYTES + 1))
    with pytest.raises(ValueError, match="too long"):
        prepare_socket_path(too_long, os.getgid())


def test_socket_ownership_failure_leaves_no_listener(
    short_run_dir: Path,
) -> None:
    path = short_run_dir / "run" / "gate.sock"

    def fail_for_socket(target: Path, uid: int, gid: int) -> None:
        if target == path:
            raise PermissionError("simulated group assignment failure")
        os.chown(target, uid, gid)

    with pytest.raises(PermissionError, match="simulated"):
        bind_unix_listener(path, os.getgid(), ownership_setter=fail_for_socket)
    assert not path.exists()


def test_gate_restart_removes_only_a_stale_owned_socket(short_run_dir: Path) -> None:
    path = short_run_dir / "run" / "gate.sock"
    crashed = bind_unix_listener(path, os.getgid())
    crashed.close()
    assert path.exists()

    restarted = bind_unix_listener(path, os.getgid())
    try:
        assert restarted.family == socket.AF_UNIX
    finally:
        restarted.close()


def test_gate_restart_refuses_to_replace_an_active_socket(short_run_dir: Path) -> None:
    path = short_run_dir / "run" / "gate.sock"
    active = bind_unix_listener(path, os.getgid())
    try:
        with pytest.raises(ValueError, match="active"):
            bind_unix_listener(path, os.getgid())
    finally:
        active.close()
