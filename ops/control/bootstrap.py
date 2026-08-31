from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ops.control.integrity import (  # type: ignore[no-redef]
        CONTROL_MANIFEST,
        CONTROL_UNITS,
        ControlIntegrityError,
        expected_control_manifest,
        verify_control_plane,
        verify_installed_control,
    )
    from ops.control.state import (  # type: ignore[no-redef]
        DeploymentPaths,
        ReleaseRef,
        StateError,
        StateStore,
        atomic_write_bytes,
        atomic_write_json,
        durable_unlink,
    )
    from ops.control.worker import (  # type: ignore[no-redef]
        BOT_UNIT,
        RealSystemd,
    )
else:
    from .integrity import (
        CONTROL_MANIFEST,
        CONTROL_UNITS,
        ControlIntegrityError,
        expected_control_manifest,
        verify_control_plane,
        verify_installed_control,
    )
    from .state import (
        DeploymentPaths,
        ReleaseRef,
        StateError,
        StateStore,
        atomic_write_bytes,
        atomic_write_json,
        durable_unlink,
    )
    from .worker import BOT_UNIT, RealSystemd


CANONICAL_ORIGIN = "https://github.com/mzored/claude-code-telegram.git"


class BootstrapError(RuntimeError):
    """The legacy host cannot be migrated without risking the live bot."""


class BootstrapSystemd(Protocol):
    def daemon_reload(self) -> None: ...


class RealBootstrapSystemd:
    def _run(
        self, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["systemctl", "--user", *arguments],
            check=check,
            text=True,
            capture_output=True,
        )

    def daemon_reload(self) -> None:
        self._run("daemon-reload")

    def bot_enabled(self) -> bool:
        return self._run("is-enabled", "--quiet", BOT_UNIT, check=False).returncode == 0

    def bot_active(self) -> bool:
        return self._run("is-active", "--quiet", BOT_UNIT, check=False).returncode == 0

    def bot_fragment(self) -> Path:
        result = self._run("show", BOT_UNIT, "--property=FragmentPath", "--value")
        return Path(result.stdout.strip())

    def activation_path_enabled(self) -> bool:
        return (
            self._run(
                "is-enabled",
                "--quiet",
                "assist-ai-activation.path",
                check=False,
            ).returncode
            == 0
        )

    def enable_activation_path(self) -> None:
        self._run("enable", "--now", "assist-ai-activation.path")

    def disable_activation_path(self) -> None:
        self._run("disable", "--now", "assist-ai-activation.path", check=False)

    def enable_bot(self) -> None:
        self._run("enable", BOT_UNIT)

    def disable_bot(self) -> None:
        self._run("disable", BOT_UNIT, check=False)

    def restart_bot(self) -> None:
        self._run("restart", BOT_UNIT)

    def start_bot(self) -> None:
        self._run("start", BOT_UNIT)

    def stop_bot(self) -> None:
        self._run("stop", BOT_UNIT)


@dataclass(frozen=True)
class FileSnapshot:
    content: bytes | None
    mode: int | None


@dataclass(frozen=True)
class CutoverPlan:
    sha: str
    action: str


def snapshot_unit_files(target: Path) -> dict[str, FileSnapshot]:
    snapshots: dict[str, FileSnapshot] = {}
    for name in CONTROL_UNITS:
        path = target / name
        if path.is_file():
            snapshots[name] = FileSnapshot(
                path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            )
        else:
            snapshots[name] = FileSnapshot(None, None)
    return snapshots


def restore_unit_files(
    target: Path,
    snapshots: dict[str, FileSnapshot],
    systemd: BootstrapSystemd,
) -> None:
    for name in CONTROL_UNITS:
        snapshot = snapshots[name]
        path = target / name
        if snapshot.content is None:
            durable_unlink(path)
        else:
            atomic_write_bytes(path, snapshot.content, snapshot.mode or 0o644)
    systemd.daemon_reload()


def snapshot_modes(root: Path) -> dict[Path, int]:
    result: dict[Path, int] = {}
    for directory, names, files in os.walk(root):
        path = Path(directory)
        result[path] = stat.S_IMODE(path.stat().st_mode)
        for name in [*names, *files]:
            child = path / name
            if not child.is_symlink():
                result[child] = stat.S_IMODE(child.stat().st_mode)
    return result


def restore_modes(modes: dict[Path, int]) -> None:
    for path, mode in modes.items():
        if path.exists() and not path.is_symlink():
            path.chmod(mode)


def install_unit_files(
    source: Path,
    target: Path,
    systemd: BootstrapSystemd,
    *,
    fault: Callable[[str], None] = lambda _point: None,
) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for name in CONTROL_UNITS:
        if not (source / name).is_file():
            raise BootstrapError(f"control bundle is missing {name}")
    for name in CONTROL_UNITS[:-1]:
        atomic_write_bytes(target / name, (source / name).read_bytes(), 0o644)
    fault("after-support-units")
    atomic_write_bytes(
        target / "assist-ai-bot.service",
        (source / "assist-ai-bot.service").read_bytes(),
        0o644,
    )
    fault("after-bot-unit")
    systemd.daemon_reload()
    fault("after-daemon-reload")


def install_control_bundle(source: Path, units: Path, destination: Path) -> None:
    expected = expected_control_manifest(source, units)
    if destination.exists():
        try:
            verify_installed_control(destination, expected)
            return
        except ControlIntegrityError as error:
            raise BootstrapError(
                "installed control/v1 differs from the reviewed bundle"
            ) from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".control-v1.", dir=destination.parent))
    try:
        package = temporary / "ops/control"
        package.mkdir(parents=True)
        atomic_write_bytes(
            temporary / "ops/__init__.py",
            (source.parent / "__init__.py").read_bytes(),
            0o400,
        )
        for path in sorted(source.glob("*.py")):
            shutil.copyfile(path, package / path.name)
            (package / path.name).chmod(0o500)
        atomic_write_json(temporary / CONTROL_MANIFEST, expected, 0o400)
        package.chmod(0o500)
        (temporary / "ops").chmod(0o500)
        directory = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        os.replace(temporary, destination)
        parent = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _git(repo: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *arguments],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError as error:
        raise BootstrapError(
            f"legacy checkout failed git {' '.join(arguments)}"
        ) from error


def inspect_legacy(paths: DeploymentPaths) -> str:
    if sys.platform != "linux":
        raise BootstrapError("host bootstrap is Linux-only")
    if not (paths.legacy_root / ".git").exists():
        raise BootstrapError("canonical legacy checkout is missing")
    if _git(paths.legacy_root, "remote", "get-url", "origin") != CANONICAL_ORIGIN:
        raise BootstrapError(f"legacy origin must be {CANONICAL_ORIGIN}")
    if _git(paths.legacy_root, "status", "--porcelain", "--untracked-files=normal"):
        raise BootstrapError("legacy checkout must be clean before migration")
    sha = _git(paths.legacy_root, "rev-parse", "HEAD")
    if subprocess.run(
        [
            "git",
            "-C",
            str(paths.legacy_root),
            "merge-base",
            "--is-ancestor",
            sha,
            "origin/main",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        raise BootstrapError("legacy commit is not on the existing origin/main ref")
    if not paths.env_file.is_file():
        raise BootstrapError("server-owned production .env is missing")
    python = paths.legacy_root / ".venv/bin/python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise BootstrapError("legacy service environment is missing")
    if not paths.data_root.is_dir():
        raise BootstrapError("server-owned data directory is missing")
    return sha


def normalize_server_state(paths: DeploymentPaths) -> None:
    content = paths.env_file.read_bytes()
    relative = b"DATABASE_URL=sqlite:///data/bot.db"
    absolute = f"DATABASE_URL=sqlite:///{paths.data_root}/bot.db".encode()
    if relative in content:
        content = content.replace(relative, absolute)
        atomic_write_bytes(paths.env_file, content, 0o600)
    elif absolute not in content:
        raise BootstrapError("production DATABASE_URL must name the stable database")
    paths.env_file.chmod(0o600)
    for directory, names, files in os.walk(paths.data_root):
        Path(directory).chmod(0o700)
        for name in [*names, *files]:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o077)


def validate_server_state(paths: DeploymentPaths, *, normalized: bool = False) -> None:
    if not paths.env_file.is_file() or not paths.data_root.is_dir():
        raise BootstrapError("server-owned credentials or data are missing")
    content = paths.env_file.read_bytes()
    relative = b"DATABASE_URL=sqlite:///data/bot.db"
    absolute = f"DATABASE_URL=sqlite:///{paths.data_root}/bot.db".encode()
    if absolute not in content and (normalized or relative not in content):
        raise BootstrapError("production DATABASE_URL must name the stable database")
    if normalized and stat.S_IMODE(paths.env_file.stat().st_mode) != 0o600:
        raise BootstrapError("server-owned production .env mode changed")
    for directory, names, files in os.walk(paths.data_root):
        directory_path = Path(directory)
        directory_path.stat()
        if normalized and stat.S_IMODE(directory_path.stat().st_mode) != 0o700:
            raise BootstrapError("server-owned data directory mode changed")
        for name in [*names, *files]:
            path = directory_path / name
            path.lstat()
            if (
                normalized
                and not path.is_symlink()
                and stat.S_IMODE(path.stat().st_mode) & 0o077
            ):
                raise BootstrapError("server-owned data permissions changed")


def _marker_sha(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BootstrapError(
            f"legacy cutover marker is invalid: {path.name}"
        ) from error
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise BootstrapError(f"legacy cutover marker is invalid: {path.name}")
    sha = value.get("sha")
    if not isinstance(sha, str):
        raise BootstrapError(f"legacy cutover marker is invalid: {path.name}")
    try:
        ReleaseRef("legacy", sha, "legacy").validate()
    except StateError as error:
        raise BootstrapError(
            f"legacy cutover marker is invalid: {path.name}"
        ) from error
    return sha


def _interrupted_legacy_sha(paths: DeploymentPaths) -> str:
    retirement = _marker_sha(paths.state_root / "legacy-retire.json")
    retired = _marker_sha(paths.state_root / "legacy-retired.json")
    if retirement and retired and retirement != retired:
        raise BootstrapError("legacy cutover markers name different commits")
    sha = retirement or retired
    if sha is None:
        raise BootstrapError(
            "legacy checkout is missing without a durable retirement marker"
        )
    return sha


def classify_cutover(paths: DeploymentPaths, sha: str) -> CutoverPlan:
    store = StateStore(paths)
    state = store.load_state()
    if state.status != "committed":
        raise BootstrapError("an activation transition is still pending recovery")
    if paths.request_file.exists():
        raise BootstrapError("an activation request is still pending recovery")
    legacy = ReleaseRef("legacy", sha, "legacy")
    if state.current == legacy and state.previous is None:
        return CutoverPlan(sha, "deploy")
    if state.current.slot not in {"slot-a", "slot-b"} or state.current.sha != sha:
        raise BootstrapError("activation state does not match the legacy cutover")
    if state.previous == legacy:
        return CutoverPlan(sha, "retire")
    if state.previous is not None:
        raise BootstrapError("legacy checkout is not the selected rollback release")
    retirement = _marker_sha(paths.state_root / "legacy-retire.json")
    retired = _marker_sha(paths.state_root / "legacy-retired.json")
    if retirement is not None:
        if retirement != sha:
            raise BootstrapError("legacy retirement marker names another commit")
        return CutoverPlan(sha, "retire")
    if retired == sha:
        return CutoverPlan(sha, "complete")
    raise BootstrapError("legacy rollback disappeared without a retirement marker")


def prepare_legacy_cutover() -> CutoverPlan:
    paths = DeploymentPaths.for_home(Path.home())
    if sys.platform != "linux":
        raise BootstrapError("host bootstrap is Linux-only")
    has_legacy_git = (paths.legacy_root / ".git").exists()
    legacy_sha = (
        inspect_legacy(paths) if has_legacy_git else _interrupted_legacy_sha(paths)
    )
    source = Path(__file__).resolve().parent
    systemd = RealBootstrapSystemd()
    expected_fragment = paths.unit_root / BOT_UNIT
    if systemd.bot_fragment().resolve() != expected_fragment.resolve():
        raise BootstrapError("systemd loaded the bot from an unexpected unit fragment")
    for name in CONTROL_UNITS:
        if not (source.parent / "systemd" / name).is_file():
            raise BootstrapError(f"control bundle is missing {name}")
    expected_control = expected_control_manifest(source, source.parent / "systemd")
    existing_state = None
    if paths.state_file.exists():
        existing_state = StateStore(paths).load_state()
    if existing_state is not None and existing_state.current.slot != "legacy":
        validate_server_state(paths, normalized=True)
        if not paths.control_root.exists():
            raise BootstrapError(
                "migrated activation state has no stable control plane"
            )
        verify_installed_control(paths.control_root, expected_control)
        verify_control_plane(paths)
        plan = classify_cutover(paths, legacy_sha)
        if plan.action == "complete":
            RealSystemd(paths, stabilization_seconds=10).assert_running(
                existing_state.current
            )
        return plan
    validate_server_state(paths)
    if not has_legacy_git:
        raise BootstrapError("legacy checkout disappeared before fixed-slot activation")
    if paths.control_root.exists():
        try:
            verify_installed_control(paths.control_root, expected_control)
        except ControlIntegrityError as error:
            raise BootstrapError(
                "installed control/v1 differs from the reviewed bundle"
            ) from error
    store = StateStore(paths)
    if existing_state is not None:
        plan = classify_cutover(paths, legacy_sha)
        if plan.action != "deploy":
            raise BootstrapError("legacy activation state is not ready for deployment")
    was_enabled = systemd.bot_enabled()
    was_active = systemd.bot_active()
    was_activation_path_enabled = systemd.activation_path_enabled()
    unit_snapshots = snapshot_unit_files(paths.unit_root)
    env_snapshot = FileSnapshot(
        paths.env_file.read_bytes(), stat.S_IMODE(paths.env_file.stat().st_mode)
    )
    data_modes = snapshot_modes(paths.data_root)

    try:
        paths.ensure_directories()
        install_control_bundle(source, source.parent / "systemd", paths.control_root)
        normalize_server_state(paths)
        if existing_state is None:
            store.initialize(ReleaseRef("legacy", legacy_sha, "legacy"))
        install_unit_files(source.parent / "systemd", paths.unit_root, systemd)
        verify_control_plane(paths)
        systemd.enable_activation_path()
        if was_active:
            systemd.restart_bot()
        else:
            systemd.start_bot()
        RealSystemd(paths, stabilization_seconds=10).assert_running(
            ReleaseRef("legacy", legacy_sha, "legacy")
        )
        if not was_enabled:
            systemd.disable_bot()
        if not was_active:
            systemd.stop_bot()
    except Exception as error:
        try:
            restore_unit_files(paths.unit_root, unit_snapshots, systemd)
            atomic_write_bytes(
                paths.env_file,
                env_snapshot.content or b"",
                env_snapshot.mode or 0o600,
            )
            restore_modes(data_modes)
            if was_activation_path_enabled:
                systemd.enable_activation_path()
            else:
                systemd.disable_activation_path()
            if was_enabled:
                systemd.enable_bot()
            else:
                systemd.disable_bot()
            if was_active:
                systemd.restart_bot()
            else:
                systemd.stop_bot()
        except Exception as rollback_error:
            raise BootstrapError(
                f"control-plane migration failed and unit restoration also failed: {rollback_error}"
            ) from error
        raise
    return CutoverPlan(legacy_sha, "deploy")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="install the stable assist-ai control plane"
    )
    parser.add_argument("command", choices=("prepare-legacy",))
    parser.parse_args(argv or sys.argv[1:])
    try:
        plan = prepare_legacy_cutover()
    except (
        BootstrapError,
        ControlIntegrityError,
        StateError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"LEGACY_SHA={plan.sha}")
    print(f"CUTOVER_ACTION={plan.action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
