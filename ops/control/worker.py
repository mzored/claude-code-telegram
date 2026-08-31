from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import posixpath
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, Protocol

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ops.control.integrity import ControlIntegrityError, verify_control_plane
    from ops.control.manifest import (  # type: ignore[no-redef]
        ManifestError,
        create_ready_manifest,
        verify_ready_release,
    )
    from ops.control.state import (  # type: ignore[no-redef]
        ActivationRequest,
        DeploymentPaths,
        ReleaseRef,
        StateError,
        StateStore,
        atomic_write_json,
        durable_unlink,
    )
else:
    from .integrity import ControlIntegrityError, verify_control_plane
    from .manifest import ManifestError, create_ready_manifest, verify_ready_release
    from .state import (
        ActivationRequest,
        DeploymentPaths,
        ReleaseRef,
        StateError,
        StateStore,
        atomic_write_json,
        durable_unlink,
    )


POETRY_VERSION = "2.4.1"
DEFAULT_RESERVE_BYTES = 512 * 1024 * 1024
BOT_UNIT = "assist-ai-bot.service"
ACTIVATION_UNIT = "assist-ai-activation.service"


class ActivationError(RuntimeError):
    """A candidate could not be staged or made healthy."""


def systemd_user_scope() -> bool:
    scope = os.environ.get("ASSIST_AI_SYSTEMD_SCOPE", "user")
    if scope == "user":
        return True
    if scope == "system":
        return False
    raise ActivationError("systemd scope must be user or system")


class Systemd(Protocol):
    def restart_bot(self) -> None: ...

    def assert_running(self, release: ReleaseRef) -> int: ...


class HashingReader(io.RawIOBase):
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        self.digest.update(data)
        return data

    def drain(self) -> None:
        while self.read(1024 * 1024):
            pass

    def hexdigest(self) -> str:
        return self.digest.hexdigest()


def available_bytes(path: Path) -> int:
    usage = os.statvfs(path)
    return usage.f_bavail * usage.f_frsize


def make_tree_writable(root: Path) -> None:
    if not root.exists():
        return
    for directory, names, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IWUSR)
        for name in names:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IWUSR)
        Path(directory).chmod(
            stat.S_IMODE(Path(directory).stat().st_mode) | stat.S_IWUSR
        )


def _protected_archive_path(path: PurePosixPath) -> bool:
    if path.parts and path.parts[0] in {
        ".git",
        ".venv",
        "data",
        ".assist-ai-release.json",
        ".assist-ai-ready",
    }:
        return True
    for part in path.parts:
        lower = part.lower()
        if lower == ".env" or lower == "credentials.json":
            return True
        if lower.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")):
            return True
        if lower.startswith(("id_rsa", "id_ed25519")):
            return True
    return False


def _member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ActivationError(f"archive contains unsafe path: {name}")
    if _protected_archive_path(path):
        raise ActivationError(f"archive contains protected path: {name}")
    return path


def _safe_symlink(path: PurePosixPath, target: str) -> None:
    if not target or target.startswith("/"):
        raise ActivationError(f"archive contains unsafe symlink: {path}")
    resolved = posixpath.normpath(posixpath.join(str(path.parent), target))
    if resolved == ".." or resolved.startswith("../"):
        raise ActivationError(f"archive contains unsafe symlink: {path}")


def extract_archive(source: BinaryIO, destination: Path, expected_sha256: str) -> None:
    reader = HashingReader(source)
    seen: set[PurePosixPath] = set()
    destination.mkdir(parents=True, mode=0o700)
    try:
        with tarfile.open(fileobj=reader, mode="r|*") as archive:
            for member in archive:
                path = _member_path(member.name.rstrip("/"))
                if path in seen:
                    raise ActivationError(f"archive repeats path: {path}")
                seen.add(path)
                target = destination.joinpath(*path.parts)
                for parent in target.parents:
                    if parent == destination.parent:
                        break
                    if parent.is_symlink():
                        raise ActivationError(f"archive writes through symlink: {path}")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False)
                    target.chmod(member.mode & 0o777)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ActivationError(f"archive member has no data: {path}")
                    with target.open("xb") as handle:
                        shutil.copyfileobj(extracted, handle)
                    target.chmod(member.mode & 0o777)
                elif member.issym():
                    _safe_symlink(path, member.linkname)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(member.linkname)
                else:
                    raise ActivationError(
                        f"archive contains unsupported member: {path}"
                    )
        reader.drain()
    except (tarfile.TarError, OSError) as error:
        raise ActivationError(
            f"could not extract candidate archive: {error}"
        ) from error
    if reader.hexdigest() != expected_sha256:
        raise ActivationError("candidate archive digest does not match the controller")


def default_builder(release: Path, paths: DeploymentPaths) -> tuple[str, str]:
    if sys.version_info[:2] not in {(3, 11), (3, 12)}:
        raise ActivationError(
            f"production control plane requires Python 3.11 or 3.12, found {sys.version_info.major}.{sys.version_info.minor}"
        )
    tool = paths.control_root / "poetry"
    poetry = tool / "bin/poetry"
    if not poetry.is_file():
        subprocess.run([sys.executable, "-m", "venv", str(tool)], check=True)
        subprocess.run(
            [
                str(tool / "bin/python"),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                f"poetry=={POETRY_VERSION}",
            ],
            env={**os.environ, "PIP_NO_CACHE_DIR": "1"},
            check=True,
        )
    with tempfile.TemporaryDirectory(
        prefix="build-cache.", dir=paths.state_root
    ) as cache:
        environment = os.environ.copy()
        environment.update(
            {
                "POETRY_VIRTUALENVS_CREATE": "true",
                "POETRY_VIRTUALENVS_IN_PROJECT": "true",
                "POETRY_CONFIG_DIR": str(Path(cache) / "config"),
                "POETRY_CACHE_DIR": str(Path(cache) / "cache"),
                "POETRY_DATA_DIR": str(Path(cache) / "data"),
            }
        )
        subprocess.run(
            [str(poetry), "env", "use", sys.executable],
            cwd=release,
            env=environment,
            check=True,
        )
        subprocess.run(
            [str(poetry), "sync", "--only", "main", "--no-root"],
            cwd=release,
            env=environment,
            check=True,
        )
    python = release / ".venv/bin/python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ActivationError(
            "Poetry did not create the final-path release environment"
        )
    identity = subprocess.check_output(
        [
            str(python),
            "-c",
            "import sys; print(f'{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}')",
        ],
        text=True,
    ).strip()
    return identity, f"stable-control-v1-poetry-{POETRY_VERSION}"


class ReleaseManager:
    def __init__(
        self,
        paths: DeploymentPaths,
        store: StateStore,
        *,
        builder: Callable[[Path], tuple[str, str]] | None = None,
        reserve_bytes: int = DEFAULT_RESERVE_BYTES,
        available_bytes: Callable[[Path], int] = available_bytes,
    ) -> None:
        self.paths = paths
        self.store = store
        self.builder = builder or (lambda release: default_builder(release, paths))
        self.reserve_bytes = reserve_bytes
        self.available_bytes = available_bytes

    def inactive_slot(self) -> str:
        current = self.store.load_state().current.slot
        if current in {"legacy", "slot-b"}:
            return "slot-a"
        return "slot-b"

    def stage_archive(
        self,
        source: BinaryIO,
        *,
        sha: str,
        tree: str,
        archive_sha256: str,
    ) -> ReleaseRef:
        slot = self.inactive_slot()
        state = self.store.load_state()
        if state.current.slot == slot:
            raise ActivationError("refusing to modify the active release slot")
        self.store.retire_previous_for_build(slot)
        release = self.paths.slot_path(slot)
        if release.exists():
            make_tree_writable(release)
            shutil.rmtree(release)
        try:
            extract_archive(source, release, archive_sha256)
            if (
                not (release / "pyproject.toml").is_file()
                or not (release / "poetry.lock").is_file()
            ):
                raise ActivationError("candidate lacks pyproject.toml or poetry.lock")
            python_identity, builder = self.builder(release)
            if self.available_bytes(release) < self.reserve_bytes:
                raise ActivationError(
                    "measured free space after the candidate build is below the reserve"
                )
            manifest_digest = create_ready_manifest(
                release,
                sha=sha,
                tree=tree,
                archive_sha256=archive_sha256,
                python_identity=python_identity,
                builder=builder,
            )
            if self.available_bytes(release) < self.reserve_bytes:
                raise ActivationError(
                    "measured free space after ready metadata is below the reserve"
                )
            candidate = ReleaseRef(slot, sha, manifest_digest)
            verify_ready_release(release, candidate)
            return candidate
        except Exception:
            if release.exists():
                make_tree_writable(release)
                shutil.rmtree(release)
            raise


class RealSystemd:
    def __init__(
        self,
        paths: DeploymentPaths,
        *,
        stabilization_seconds: int = 10,
        user_scope: bool = True,
    ) -> None:
        self.paths = paths
        self.stabilization_seconds = stabilization_seconds
        self.command = ["systemctl"] + (["--user"] if user_scope else [])
        self.expected_restarts: int | None = None

    def _run(
        self, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.command, *arguments],
            check=check,
            text=True,
            capture_output=True,
        )

    def restart_bot(self) -> None:
        before = self._properties()
        self.expected_restarts = int(before.get("NRestarts", "-1"))
        self._run("restart", BOT_UNIT)

    def _properties(self) -> dict[str, str]:
        result = self._run(
            "show",
            BOT_UNIT,
            "--property=ActiveState,SubState,MainPID,NRestarts,FragmentPath,NeedDaemonReload",
        )
        return dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )

    def assert_running(self, release: ReleaseRef) -> int:
        first = self._properties()
        initial_restarts = int(first.get("NRestarts", "-1"))
        if (
            self.expected_restarts is not None
            and initial_restarts != self.expected_restarts
        ):
            raise ActivationError("service restarted before stabilization began")
        deadline = time.monotonic() + self.stabilization_seconds
        runtime_error = "bot MainPID did not reach the selected release"
        while True:
            properties = self._properties()
            if (
                properties.get("ActiveState") != "active"
                or properties.get("SubState") != "running"
            ):
                raise ActivationError("service stopped during stabilization")
            if properties.get("NeedDaemonReload") != "no":
                raise ActivationError("loaded unit differs from its stable fragment")
            expected_fragment = str(self.paths.unit_root / BOT_UNIT)
            if Path(properties.get("FragmentPath", "")) != Path(expected_fragment):
                raise ActivationError("systemd loaded an unexpected bot unit fragment")
            pid_text = properties.get("MainPID", "0")
            if not pid_text.isdigit() or int(pid_text) <= 0:
                raise ActivationError("systemd did not report a live bot MainPID")
            pid = int(pid_text)
            release_path = self.paths.release_path(release).resolve()
            try:
                cwd = Path(f"/proc/{pid}/cwd").resolve()
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            except OSError as error:
                runtime_error = f"could not inspect the bot MainPID: {error}"
            else:
                if cwd != release_path:
                    runtime_error = (
                        "bot MainPID working directory is not the selected release"
                    )
                else:
                    expected_python = str(release_path / ".venv/bin/python").encode()
                    if expected_python not in cmdline:
                        runtime_error = (
                            "bot MainPID command does not use the selected interpreter"
                        )
                    else:
                        runtime_error = ""
            if time.monotonic() >= deadline:
                final_restarts = int(properties.get("NRestarts", "-1"))
                if final_restarts != initial_restarts:
                    raise ActivationError("service restarted during stabilization")
                if runtime_error:
                    raise ActivationError(runtime_error)
                return final_restarts
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))


class ActivationEngine:
    def __init__(
        self,
        store: StateStore,
        paths: DeploymentPaths,
        systemd: Systemd,
        *,
        stabilization_seconds: int = 10,
        fault_boundary: str | None = None,
    ) -> None:
        self.store = store
        self.paths = paths
        self.systemd = systemd
        self.stabilization_seconds = stabilization_seconds
        self.fault_boundary = fault_boundary

    def _fault(self, boundary: str) -> None:
        if self.fault_boundary == boundary:
            os.kill(os.getpid(), signal.SIGKILL)

    def _verify_release(self, release: ReleaseRef) -> None:
        if release.slot == "legacy":
            python = self.paths.legacy_root / ".venv/bin/python"
            if not python.is_file() or not os.access(python, os.X_OK):
                raise ActivationError("legacy rollback environment is unavailable")
            return
        try:
            verify_ready_release(self.paths.release_path(release), release)
        except ManifestError as error:
            raise ActivationError(str(error)) from error

    def _finish_deployed(self, request: ActivationRequest) -> None:
        self.store.write_receipt(
            request,
            result="deployed",
            sha=request.candidate.sha,
            slot=request.candidate.slot,
        )
        self._fault("after-success-receipt")
        self.store.finish_request()

    def _finish_rollback(self, request: ActivationRequest, message: str) -> None:
        self.store.write_receipt(
            request,
            result="rolled-back",
            sha=request.expected_current.sha,
            failed_sha=request.candidate.sha,
            error=message,
        )
        self._fault("after-failure-receipt")
        self.store.finish_request()

    def _resume_rollback(self, request: ActivationRequest, message: str) -> None:
        state = self.store.load_state()
        if state.status == "pending":
            state = self.store.begin_rollback(request)
            self._fault("after-rollback-state")
        if state.status != "rollback-pending":
            raise ActivationError(
                "cannot resume rollback from current activation state"
            )
        self._verify_release(state.current)
        self.systemd.restart_bot()
        self._fault("after-rollback-restart")
        self.systemd.assert_running(state.current)
        self._fault("after-rollback-health")
        self.store.commit_rollback(request)
        self._fault("after-rollback-committed-state")
        self._finish_rollback(request, message)

    def activate(self) -> None:
        with self.store.locked():
            request = self.store.load_request()
            state = self.store.load_state()
            if (
                state.status == "committed"
                and state.last_transaction == request.transaction
            ):
                if state.last_result == "deployed":
                    self._finish_deployed(request)
                    return
                if state.last_result == "rolled-back":
                    self._finish_rollback(
                        request, "candidate failed before worker restart"
                    )
                    raise ActivationError("candidate activation rolled back")
            if state.status == "rollback-pending":
                self._resume_rollback(request, "candidate did not stabilize")
                raise ActivationError("candidate activation rolled back")
            try:
                self._verify_release(request.candidate)
            except ActivationError as error:
                if state.status == "pending":
                    self._resume_rollback(request, str(error))
                else:
                    self.store.write_receipt(
                        request,
                        result="rejected",
                        sha=state.current.sha,
                        failed_sha=request.candidate.sha,
                        error=str(error),
                    )
                    self.store.finish_request()
                raise
            if state.status == "committed":
                state = self.store.begin_activation(request)
                self._fault("after-pending-state")
            if state.status != "pending" or state.transaction != request.transaction:
                raise ActivationError(
                    "activation state does not match the durable request"
                )
            try:
                self.systemd.restart_bot()
                self._fault("after-candidate-restart")
                self.systemd.assert_running(request.candidate)
                self._fault("after-candidate-health")
            except (ActivationError, subprocess.CalledProcessError) as error:
                message = str(error)
                self._resume_rollback(request, message)
                raise ActivationError(message) from error
            self.store.commit_candidate(request)
            self._fault("after-committed-state")
            self._finish_deployed(request)

    def recover_for_boot(self) -> None:
        if not self.paths.request_file.exists():
            return
        with self.store.locked():
            request = self.store.load_request()
            state = self.store.load_state()
            if (
                state.status == "committed"
                and state.last_transaction == request.transaction
            ):
                if state.last_result == "deployed":
                    self._finish_deployed(request)
                else:
                    self._finish_rollback(request, "boot finalized prior rollback")
                return
            if (
                state.status == "committed"
                and state.generation == request.expected_generation
                and state.current == request.expected_current
            ):
                self._verify_release(state.current)
                self._finish_rollback(
                    request,
                    "boot discarded an activation that had not selected its candidate",
                )
                return
            if state.status == "pending":
                state = self.store.begin_rollback(request)
            if state.status == "rollback-pending":
                self._verify_release(state.current)
                self.store.commit_rollback(request)
                self._finish_rollback(
                    request, "boot recovered an interrupted activation"
                )
                return
            raise ActivationError("boot recovery found an unrelated activation request")


def _legacy_retire_request(paths: DeploymentPaths, sha: str) -> tuple[Path, list[str]]:
    request = paths.state_root / "legacy-retire.json"
    if request.exists():
        value = json.loads(request.read_text(encoding="utf-8"))
        if value.get("sha") != sha or not isinstance(value.get("tracked"), list):
            raise ActivationError(
                "legacy retirement request does not match the requested SHA"
            )
        return request, [str(path) for path in value["tracked"]]
    result = subprocess.run(
        ["git", "-C", str(paths.legacy_root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    tracked = [path.decode() for path in result.stdout.split(b"\0") if path]
    for relative in tracked:
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or _protected_archive_path(path):
            raise ActivationError(
                f"legacy tracked path is unsafe to retire: {relative}"
            )
    atomic_write_json(request, {"schema": 1, "sha": sha, "tracked": tracked})
    return request, tracked


def _retirement_complete(paths: DeploymentPaths, sha: str) -> bool:
    marker = paths.state_root / "legacy-retired.json"
    request = paths.state_root / "legacy-retire.json"
    if not marker.exists() or request.exists():
        return False
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ActivationError("legacy retirement marker is invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or value.get("sha") != sha
        or value.get("current") != sha
    ):
        raise ActivationError("legacy retirement marker does not match current SHA")
    return True


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def retire_legacy(
    sha: str,
    *,
    paths: DeploymentPaths | None = None,
    systemd: Systemd | None = None,
    fault_boundary: str | None = None,
) -> None:
    paths = paths or _home_paths()
    systemd = systemd or RealSystemd(
        paths,
        stabilization_seconds=10,
        user_scope=systemd_user_scope(),
    )

    def fault(boundary: str) -> None:
        if fault_boundary == boundary:
            os.kill(os.getpid(), signal.SIGKILL)

    store = StateStore(paths)
    with store.locked():
        state = store.load_state()
        legacy = ReleaseRef("legacy", sha, "legacy")
        if state.current.slot not in {"slot-a", "slot-b"} or state.current.sha != sha:
            raise ActivationError("same-SHA fixed-slot release is not current")
        if state.previous not in {legacy, None}:
            raise ActivationError("legacy checkout is not the immediate rollback")
        systemd.assert_running(state.current)
        if _retirement_complete(paths, sha):
            return
        request, tracked = _legacy_retire_request(paths, sha)
        fault("after-retirement-request")
        if state.previous == legacy:
            store.clear_previous(legacy)
        fault("after-previous-cleared")
        for relative in tracked:
            target = paths.legacy_root.joinpath(*PurePosixPath(relative).parts)
            if target.is_symlink() or target.is_file():
                durable_unlink(target)
        fault("after-tracked-files")
        for removable in (".venv", ".git", ".cache"):
            target = paths.legacy_root / removable
            if target.exists():
                make_tree_writable(target)
                shutil.rmtree(target)
                _fsync_directory(paths.legacy_root)
        fault("after-legacy-runtime")
        for directory, _names, _files in os.walk(paths.legacy_root, topdown=False):
            path = Path(directory)
            if path != paths.legacy_root:
                try:
                    path.rmdir()
                except OSError:
                    pass
        _fsync_directory(paths.legacy_root)

        atomic_write_json(
            paths.state_root / "legacy-retired.json",
            {"schema": 1, "sha": sha, "current": state.current.sha},
        )
        fault("after-retired-marker")
        durable_unlink(request)
        fault("after-retirement-finished")


def _home_paths() -> DeploymentPaths:
    return DeploymentPaths.for_home(Path.home())


def receive(arguments: argparse.Namespace) -> int:
    paths = _home_paths()
    paths.ensure_directories()
    store = StateStore(paths)
    with store.locked():
        candidate = ReleaseManager(paths, store).stage_archive(
            sys.stdin.buffer,
            sha=arguments.sha,
            tree=arguments.tree,
            archive_sha256=arguments.archive_sha256,
        )
        request = store.create_request(arguments.action, candidate)
    command = ["systemctl", "--user"]
    subprocess.run([*command, "reset-failed", ACTIVATION_UNIT], check=False)
    subprocess.run([*command, "start", "--no-block", ACTIVATION_UNIT], check=True)
    receipt = paths.receipts_root / f"{request.transaction}.json"
    deadline = time.monotonic() + arguments.timeout
    while time.monotonic() < deadline:
        if receipt.exists():
            result = json.loads(receipt.read_text(encoding="utf-8"))
            if (
                result.get("result") == "deployed"
                and result.get("sha") == arguments.sha
            ):
                print(f"DEPLOYED_SHA={arguments.sha}")
                return 0
            raise ActivationError(
                "candidate failed and the previous release was restored"
            )
        time.sleep(0.25)
    raise ActivationError(
        "activation receipt timed out; durable recovery remains pending"
    )


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="assist-ai stable deployment worker")
    subparsers = parser.add_subparsers(dest="command", required=True)
    receive_parser = subparsers.add_parser("receive")
    receive_parser.add_argument("action", choices=("deploy", "rollback"))
    receive_parser.add_argument("sha")
    receive_parser.add_argument("tree")
    receive_parser.add_argument("archive_sha256")
    receive_parser.add_argument("--timeout", type=int, default=120)
    subparsers.add_parser("activate")
    subparsers.add_parser("recover")
    retire_parser = subparsers.add_parser("retire-legacy")
    retire_parser.add_argument("sha")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv or sys.argv[1:])
    try:
        paths = _home_paths()
        verify_control_plane(paths)
        if arguments.command == "receive":
            return receive(arguments)
        if arguments.command == "retire-legacy":
            retire_legacy(arguments.sha)
            print(f"RETIRED_LEGACY_SHA={arguments.sha}")
            return 0
        engine = ActivationEngine(
            StateStore(paths),
            paths,
            RealSystemd(paths, user_scope=systemd_user_scope()),
        )
        if arguments.command == "activate":
            engine.activate()
        else:
            engine.recover_for_boot()
        return 0
    except (
        ActivationError,
        ControlIntegrityError,
        StateError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        if arguments.command == "activate" and not _home_paths().request_file.exists():
            return 0
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
