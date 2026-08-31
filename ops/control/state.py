from __future__ import annotations

import fcntl
import json
import os
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

SCHEMA = 1
VALID_SLOTS = frozenset({"legacy", "slot-a", "slot-b"})
VALID_STATES = frozenset({"committed", "pending", "rollback-pending"})


class StateError(RuntimeError):
    """The durable deployment state violates its schema or transition rules."""


@dataclass(frozen=True)
class DeploymentPaths:
    home: Path
    control_root: Path
    releases_root: Path
    state_root: Path
    legacy_root: Path
    env_file: Path
    data_root: Path
    unit_root: Path

    @classmethod
    def for_home(cls, home: Path) -> "DeploymentPaths":
        resolved = home.resolve()
        legacy = resolved / "projects/assist-ai/bot"
        unit_root = Path(
            os.environ.get(
                "ASSIST_AI_SYSTEMD_UNIT_ROOT",
                str(resolved / ".config/systemd/user"),
            )
        )
        if not unit_root.is_absolute():
            raise StateError("systemd unit root must be an absolute path")
        return cls(
            home=resolved,
            control_root=resolved / ".local/lib/assist-ai/control/v1",
            releases_root=resolved / ".local/lib/assist-ai/releases",
            state_root=resolved / ".local/state/assist-ai",
            legacy_root=legacy,
            env_file=legacy / ".env",
            data_root=legacy / "data",
            unit_root=unit_root,
        )

    @property
    def state_file(self) -> Path:
        return self.state_root / "active.json"

    @property
    def request_file(self) -> Path:
        return self.state_root / "activation-request.json"

    @property
    def receipts_root(self) -> Path:
        return self.state_root / "receipts"

    @property
    def lock_file(self) -> Path:
        return self.state_root / "activation.lock"

    def slot_path(self, slot: str) -> Path:
        if slot not in {"slot-a", "slot-b"}:
            raise StateError(f"invalid physical release slot: {slot}")
        return self.releases_root / slot

    def release_path(self, release: "ReleaseRef") -> Path:
        if release.slot == "legacy":
            return self.legacy_root
        return self.slot_path(release.slot)

    def ensure_directories(self) -> None:
        for path, mode in (
            (self.control_root.parent, 0o700),
            (self.releases_root, 0o700),
            (self.state_root, 0o700),
            (self.receipts_root, 0o700),
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)


@dataclass(frozen=True)
class ReleaseRef:
    slot: str
    sha: str
    manifest_sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> "ReleaseRef":
        if not isinstance(value, dict):
            raise StateError("release reference must be an object")
        release = cls(
            slot=value.get("slot", ""),
            sha=value.get("sha", ""),
            manifest_sha256=value.get("manifest_sha256", ""),
        )
        release.validate()
        return release

    def validate(self) -> None:
        if self.slot not in VALID_SLOTS:
            raise StateError(f"invalid release slot: {self.slot}")
        if (
            not isinstance(self.sha, str)
            or len(self.sha) != 40
            or any(char not in "0123456789abcdef" for char in self.sha)
        ):
            raise StateError("release SHA must be 40 lowercase hexadecimal characters")
        if self.slot == "legacy":
            if self.manifest_sha256 != "legacy":
                raise StateError("legacy release must use the legacy manifest marker")
        elif (
            not isinstance(self.manifest_sha256, str)
            or len(self.manifest_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.manifest_sha256)
        ):
            raise StateError("release manifest digest must be lowercase SHA-256")


@dataclass(frozen=True)
class ActivationState:
    generation: int
    status: str
    current: ReleaseRef
    previous: ReleaseRef | None
    transaction: str | None = None
    failed: ReleaseRef | None = None
    last_transaction: str | None = None
    last_result: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> "ActivationState":
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise StateError("unsupported activation state schema")
        generation = value.get("generation")
        if not isinstance(generation, int):
            raise StateError("activation generation must be an integer")
        state = cls(
            generation=generation,
            status=value.get("status", ""),
            current=ReleaseRef.from_dict(value.get("current")),
            previous=(
                ReleaseRef.from_dict(value["previous"])
                if value.get("previous") is not None
                else None
            ),
            transaction=value.get("transaction"),
            failed=(
                ReleaseRef.from_dict(value["failed"])
                if value.get("failed") is not None
                else None
            ),
            last_transaction=value.get("last_transaction"),
            last_result=value.get("last_result"),
        )
        state.validate()
        return state

    def validate(self) -> None:
        if (
            not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 0
        ):
            raise StateError("activation generation must be a nonnegative integer")
        if self.status not in VALID_STATES:
            raise StateError(f"invalid activation status: {self.status}")
        if self.previous == self.current:
            raise StateError("current and previous releases must differ")
        if self.status == "committed":
            if self.transaction is not None or self.failed is not None:
                raise StateError("committed state cannot contain an active transaction")
        elif not self.transaction:
            raise StateError("transitional state must name its transaction")
        if self.transaction is not None:
            try:
                uuid.UUID(self.transaction)
            except (ValueError, TypeError) as error:
                raise StateError("activation transaction must be a UUID") from error
        if self.status == "pending" and self.previous is None:
            raise StateError("pending state must retain the previous release")
        if self.status == "pending" and self.failed is not None:
            raise StateError("pending activation cannot name a failed release")
        if self.status == "rollback-pending" and self.failed is None:
            raise StateError("rollback state must retain the failed release")
        if self.status == "rollback-pending" and self.previous is not None:
            raise StateError("rollback state cannot retain another previous release")
        if (self.last_transaction is None) != (self.last_result is None):
            raise StateError("last transaction and result must appear together")
        if self.last_transaction is not None:
            try:
                uuid.UUID(self.last_transaction)
            except (ValueError, TypeError) as error:
                raise StateError("last transaction must be a UUID") from error
            if self.last_result not in {"deployed", "rolled-back"}:
                raise StateError("last transaction result is invalid")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema"] = SCHEMA
        return value


@dataclass(frozen=True)
class ActivationRequest:
    transaction: str
    action: str
    expected_generation: int
    expected_current: ReleaseRef
    candidate: ReleaseRef

    @classmethod
    def from_dict(cls, value: Any) -> "ActivationRequest":
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise StateError("unsupported activation request schema")
        expected_generation = value.get("expected_generation")
        if not isinstance(expected_generation, int):
            raise StateError("expected generation must be an integer")
        request = cls(
            transaction=value.get("transaction", ""),
            action=value.get("action", ""),
            expected_generation=expected_generation,
            expected_current=ReleaseRef.from_dict(value.get("expected_current")),
            candidate=ReleaseRef.from_dict(value.get("candidate")),
        )
        request.validate()
        return request

    def validate(self) -> None:
        try:
            uuid.UUID(self.transaction)
        except (ValueError, TypeError) as error:
            raise StateError("activation transaction must be a UUID") from error
        if self.action not in {"deploy", "rollback"}:
            raise StateError(f"invalid activation action: {self.action}")
        if (
            not isinstance(self.expected_generation, int)
            or isinstance(self.expected_generation, bool)
            or self.expected_generation < 0
        ):
            raise StateError("expected generation must be a nonnegative integer")
        self.expected_current.validate()
        self.candidate.validate()
        if self.expected_current == self.candidate:
            raise StateError("candidate must differ from the current release")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema"] = SCHEMA
        return value


def atomic_write_bytes(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def atomic_write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    atomic_write_bytes(path, content, mode)


def durable_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class StateStore:
    def __init__(self, paths: DeploymentPaths) -> None:
        self.paths = paths

    @contextmanager
    def locked(self) -> Iterator[None]:
        self.paths.state_root.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.paths.lock_file, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def initialize(self, release: ReleaseRef) -> ActivationState:
        release.validate()
        if self.paths.state_file.exists():
            existing = self.load_state()
            if existing.current != release:
                raise StateError("activation state already selects a different release")
            return existing
        state = ActivationState(0, "committed", release, None)
        atomic_write_json(self.paths.state_file, state.to_dict())
        return state

    def load_state(self) -> ActivationState:
        try:
            value = json.loads(self.paths.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise StateError("activation state is missing or invalid") from error
        return ActivationState.from_dict(value)

    def load_request(self) -> ActivationRequest:
        try:
            value = json.loads(self.paths.request_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise StateError("activation request is missing or invalid") from error
        return ActivationRequest.from_dict(value)

    def create_request(self, action: str, candidate: ReleaseRef) -> ActivationRequest:
        if self.paths.request_file.exists():
            raise StateError("another activation request is pending")
        state = self.load_state()
        if state.status != "committed":
            raise StateError("cannot request activation from a transitional state")
        request = ActivationRequest(
            transaction=str(uuid.uuid4()),
            action=action,
            expected_generation=state.generation,
            expected_current=state.current,
            candidate=candidate,
        )
        request.validate()
        atomic_write_json(self.paths.request_file, request.to_dict())
        return request

    def retire_previous_for_build(self, slot: str) -> ActivationState:
        state = self.load_state()
        if state.status != "committed":
            raise StateError("cannot retire a rollback during activation")
        if state.previous is None or state.previous.slot != slot:
            return state
        updated = ActivationState(
            state.generation + 1,
            "committed",
            state.current,
            None,
            last_transaction=state.last_transaction,
            last_result=state.last_result,
        )
        atomic_write_json(self.paths.state_file, updated.to_dict())
        return updated

    def begin_activation(self, request: ActivationRequest) -> ActivationState:
        state = self.load_state()
        if state.status == "pending" and state.transaction == request.transaction:
            return state
        if state.status != "committed":
            raise StateError("another activation transition is in progress")
        if state.generation != request.expected_generation:
            raise StateError("activation request generation is stale")
        if state.current != request.expected_current:
            raise StateError("activation request current release is stale")
        updated = ActivationState(
            state.generation + 1,
            "pending",
            request.candidate,
            state.current,
            transaction=request.transaction,
        )
        atomic_write_json(self.paths.state_file, updated.to_dict())
        return updated

    def commit_candidate(self, request: ActivationRequest) -> ActivationState:
        state = self.load_state()
        if state.status != "pending" or state.transaction != request.transaction:
            raise StateError("candidate commit does not match pending activation")
        updated = ActivationState(
            state.generation + 1,
            "committed",
            state.current,
            state.previous,
            last_transaction=request.transaction,
            last_result="deployed",
        )
        atomic_write_json(self.paths.state_file, updated.to_dict())
        return updated

    def begin_rollback(self, request: ActivationRequest) -> ActivationState:
        state = self.load_state()
        if (
            state.status == "rollback-pending"
            and state.transaction == request.transaction
        ):
            return state
        if state.status != "pending" or state.transaction != request.transaction:
            raise StateError("rollback does not match pending activation")
        if state.previous is None:
            raise StateError("pending activation has no rollback release")
        updated = ActivationState(
            state.generation + 1,
            "rollback-pending",
            state.previous,
            None,
            transaction=request.transaction,
            failed=state.current,
        )
        atomic_write_json(self.paths.state_file, updated.to_dict())
        return updated

    def commit_rollback(self, request: ActivationRequest) -> ActivationState:
        state = self.load_state()
        if (
            state.status != "rollback-pending"
            or state.transaction != request.transaction
        ):
            raise StateError("rollback commit does not match pending rollback")
        updated = ActivationState(
            state.generation + 1,
            "committed",
            state.current,
            None,
            last_transaction=request.transaction,
            last_result="rolled-back",
        )
        atomic_write_json(self.paths.state_file, updated.to_dict())
        return updated

    def write_receipt(self, request: ActivationRequest, **result: Any) -> Path:
        receipt = {
            "schema": SCHEMA,
            "transaction": request.transaction,
            "action": request.action,
            **result,
        }
        path = self.paths.receipts_root / f"{request.transaction}.json"
        atomic_write_json(path, receipt)
        receipts = sorted(
            self.paths.receipts_root.glob("*.json"),
            key=lambda candidate: candidate.stat().st_mtime_ns,
            reverse=True,
        )
        for stale in receipts[20:]:
            durable_unlink(stale)
        return path

    def load_latest_receipt(self) -> dict[str, Any]:
        paths = sorted(
            self.paths.receipts_root.glob("*.json"),
            key=lambda path: path.stat().st_mtime_ns,
        )
        if not paths:
            raise StateError("no activation receipt exists")
        value = json.loads(paths[-1].read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise StateError("activation receipt must be an object")
        return dict(value)

    def finish_request(self) -> None:
        durable_unlink(self.paths.request_file)

    def clear_previous(self, expected: ReleaseRef) -> ActivationState:
        state = self.load_state()
        if state.status != "committed" or state.previous != expected:
            raise StateError("legacy retirement does not match the committed rollback")
        updated = ActivationState(
            state.generation + 1,
            "committed",
            state.current,
            None,
            last_transaction=state.last_transaction,
            last_result=state.last_result,
        )
        atomic_write_json(self.paths.state_file, updated.to_dict())
        return updated
