"""Fail-closed filesystem and identity configuration for Policy Gate."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class GateConfigurationError(ValueError):
    """Policy Gate cannot start with an unsafe local boundary."""


def _absolute(environment: Mapping[str, str], name: str) -> Path:
    raw = environment.get(name, "").strip()
    if not raw:
        raise GateConfigurationError(f"{name} is required")
    path = Path(raw)
    if not path.is_absolute():
        raise GateConfigurationError(f"{name} must be absolute")
    return path


def _uid(environment: Mapping[str, str], name: str) -> int:
    try:
        value = int(environment.get(name, ""))
    except ValueError as exc:
        raise GateConfigurationError(f"{name} must be numeric") from exc
    if value <= 0:
        raise GateConfigurationError(f"{name} must be positive")
    return value


def _read_owner_file(path: Path, label: str, minimum_bytes: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GateConfigurationError(f"cannot read {label} file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise GateConfigurationError(f"{label} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise GateConfigurationError(f"{label} file must have mode 0600")
        if metadata.st_uid != os.geteuid():
            raise GateConfigurationError(f"{label} file must be process-owned")
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            descriptor = -1
            value = stream.read().strip()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value.encode("utf-8")) < minimum_bytes:
        raise GateConfigurationError(f"{label} is missing or too short")
    return value


@dataclass(frozen=True)
class GateConfig:
    data_dir: Path
    database_key_file: Path
    socket_path: Path
    public_uid: int
    controller_uid: int
    client_gid: int

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "GateConfig":
        env = os.environ if environment is None else environment
        if env.get("POLICY_GATE_DATABASE_KEY", "").strip():
            raise GateConfigurationError(
                "inline Policy Gate database keys are forbidden; use an owner-only file"
            )
        data_dir = _absolute(env, "POLICY_GATE_DATA_DIR").resolve()
        key_file = _absolute(env, "POLICY_GATE_DATABASE_KEY_FILE").resolve()
        socket_path = _absolute(env, "POLICY_GATE_SOCKET_PATH").resolve()
        repository = Path(__file__).resolve().parents[2]
        if key_file == data_dir or key_file.is_relative_to(data_dir):
            raise GateConfigurationError(
                "Policy Gate key must stay outside its data directory"
            )
        if key_file == repository or key_file.is_relative_to(repository):
            raise GateConfigurationError(
                "Policy Gate key must stay outside the repository"
            )
        if socket_path == data_dir or socket_path.is_relative_to(data_dir):
            raise GateConfigurationError(
                "Policy Gate socket must stay outside its data directory"
            )
        public_uid = _uid(env, "POLICY_GATE_PUBLIC_UID")
        controller_uid = _uid(env, "POLICY_GATE_CONTROLLER_UID")
        client_gid = _uid(env, "POLICY_GATE_CLIENT_GID")
        if public_uid == controller_uid:
            raise GateConfigurationError(
                "public and controller processes need separate UIDs"
            )
        return cls(
            data_dir,
            key_file,
            socket_path,
            public_uid,
            controller_uid,
            client_gid,
        )

    def read_database_key(self) -> str:
        return _read_owner_file(self.database_key_file, "Policy Gate database key", 32)
