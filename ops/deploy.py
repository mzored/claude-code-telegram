"""Foreground deployment primitives for immutable assist-ai releases.

This module is deliberately not installed as a server control plane.  The local
controller invokes it for one deploy or recovery operation; the selected release is
only the ``current`` symlink.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol

CANONICAL_ORIGIN = "https://github.com/mzored/claude-code-telegram.git"
DEPLOY_HOST = "mybots"
BOT_UNIT = "assist-ai-bot.service"
READY_FILE = ".assist-ai-ready"
MANIFEST_FILE = ".assist-ai-release.json"
DEFAULT_RESERVE_BYTES = 512 * 1024 * 1024
SENSITIVE_ARCHIVE_COMPONENTS = frozenset(
    {".git", ".env", "data", ".ssh", ".aws", ".gnupg"}
)
SENSITIVE_ARCHIVE_FILENAMES = frozenset(
    {
        ".netrc",
        "authorized_keys",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
        "private.pem",
    }
)
SENSITIVE_ARCHIVE_SUFFIXES = frozenset(
    {".cer", ".crt", ".der", ".key", ".p12", ".pem", ".pfx"}
)
DIRECT_UNIT = """[Unit]
Description=assist-ai-bot (claude-code-telegram)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
EnvironmentFile=%h/projects/assist-ai/bot/.env
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=%h/.local/lib/assist-ai/current
ExecStart=%h/.local/lib/assist-ai/current/.venv/bin/claude-telegram-bot
Restart=on-failure
RestartSec=10
MemoryHigh=300M
MemoryMax=400M
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""


class DeployError(RuntimeError):
    """The requested deploy cannot safely change the selected release."""


@dataclass(frozen=True)
class Paths:
    home: Path
    legacy_root: Path
    env_file: Path
    data_root: Path
    unit_root: Path

    @classmethod
    def for_home(cls, home: Path) -> "Paths":
        return cls(
            home=home,
            legacy_root=home / "projects/assist-ai/bot",
            env_file=home / "projects/assist-ai/bot/.env",
            data_root=home / "projects/assist-ai/bot/data",
            unit_root=home / ".config/systemd/user",
        )

    @property
    def root(self) -> Path:
        return self.home / ".local/lib/assist-ai"

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def current(self) -> Path:
        return self.root / "current"

    @property
    def lock_file(self) -> Path:
        return self.root / "deploy.lock"

    @property
    def unit_file(self) -> Path:
        return self.unit_root / BOT_UNIT


def require_sha(value: str) -> str:
    if len(value) != 40 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise DeployError("commit must be a full lowercase 40-character SHA")
    return value


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_symlink(path: Path, target: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}"
    relative_target = os.path.relpath(target, path.parent)
    os.symlink(relative_target, temporary)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def selected_path(paths: Paths) -> Path:
    if not paths.current.is_symlink():
        raise DeployError("current selector is missing")
    selected = paths.current.resolve(strict=True)
    if selected != paths.legacy_root.resolve() and selected.parent != paths.releases:
        raise DeployError("current selector points outside the legacy root or releases")
    return selected


@contextmanager
def deploy_lock(paths: Paths) -> Iterator[None]:
    import fcntl

    paths.root.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(paths.lock_file, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DeployError(
                "another foreground deployment is already running"
            ) from error
        yield
    finally:
        os.close(descriptor)


def _member_is_safe(member: tarfile.TarInfo) -> bool:
    parts = Path(member.name).parts
    if not member.name or member.name.startswith("/") or ".." in parts:
        return False
    if member.isreg() or member.isdir():
        return True
    if member.issym():
        target = Path(member.linkname)
        return not target.is_absolute() and ".." not in target.parts
    return False


def _forbidden_member(name: str) -> bool:
    path = Path(name)
    parts = {part.lower() for part in path.parts}
    filename = path.name.lower()
    return (
        bool(SENSITIVE_ARCHIVE_COMPONENTS.intersection(parts))
        or filename in SENSITIVE_ARCHIVE_FILENAMES
        or path.stem.lower() in {"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
        or path.suffix.lower() in SENSITIVE_ARCHIVE_SUFFIXES
    )


def extract_archive(archive: BinaryIO, destination: Path) -> str:
    payload = archive.read()
    digest = hashlib.sha256(payload).hexdigest()
    try:
        opened = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
    except tarfile.TarError as error:
        raise DeployError("delivery is not a valid tar archive") from error
    with opened:
        members = opened.getmembers()
        for member in members:
            if (
                not _member_is_safe(member)
                or _forbidden_member(member.name)
                or (member.issym() and _forbidden_member(member.linkname))
            ):
                raise DeployError(f"unsafe archive member: {member.name}")
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode & 0o755)
            elif member.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = opened.extractfile(member)
                if source is None:
                    raise DeployError(f"archive member has no payload: {member.name}")
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o755)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, target)
    return digest


def _manifest_entries(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative in {READY_FILE, MANIFEST_FILE}:
            continue
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            entries.append(
                {
                    "path": relative,
                    "kind": "symlink",
                    "mode": mode,
                    "target": os.readlink(path),
                }
            )
        elif path.is_file():
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": mode,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        elif path.is_dir():
            entries.append({"path": relative, "kind": "dir", "mode": mode})
        else:
            raise DeployError(f"release has unsupported file type: {relative}")
    return entries


def tree_digest(root: Path) -> str:
    encoded = json.dumps(
        _manifest_entries(root), sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def write_manifest(
    release: Path, sha: str, archive_digest: str, source_tree_digest: str
) -> dict[str, object]:
    for path in sorted(release.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(
                0o500 if path.is_dir() else stat.S_IMODE(path.stat().st_mode) & 0o555
            )
    manifest: dict[str, object] = {
        "schema": 1,
        "sha": require_sha(sha),
        "archive_sha256": archive_digest,
        "source_tree_sha256": source_tree_digest,
        "entries": _manifest_entries(release),
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (release / MANIFEST_FILE).write_bytes(encoded + b"\n")
    (release / MANIFEST_FILE).chmod(0o400)
    digest = hashlib.sha256(encoded).hexdigest()
    (release / READY_FILE).write_text(digest + "\n", encoding="ascii")
    (release / READY_FILE).chmod(0o400)
    release.chmod(0o500)
    return manifest


def verify_release(release: Path, sha: str | None = None) -> dict[str, object]:
    manifest_path = release / MANIFEST_FILE
    ready_path = release / READY_FILE
    try:
        encoded = manifest_path.read_bytes().rstrip(b"\n")
        manifest = json.loads(encoded)
        ready = ready_path.read_text(encoding="ascii").strip()
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise DeployError(f"release is not ready: {release}") from error
    if hashlib.sha256(encoded).hexdigest() != ready:
        raise DeployError(f"release manifest digest changed: {release}")
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise DeployError(f"release manifest is invalid: {release}")
    for field in ("archive_sha256", "source_tree_sha256"):
        digest = manifest.get(field)
        if not isinstance(digest, str) or len(digest) != 64:
            raise DeployError(f"release manifest has no valid {field}: {release}")
    release_sha = manifest.get("sha")
    if not isinstance(release_sha, str) or require_sha(release_sha) != release.name:
        raise DeployError(f"release SHA does not match its final path: {release}")
    if sha is not None and release_sha != require_sha(sha):
        raise DeployError(f"release SHA does not match requested recovery: {sha}")
    if manifest.get("entries") != _manifest_entries(release):
        raise DeployError(f"release contents changed: {release}")
    python = release / ".venv/bin/python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise DeployError(f"release has no production interpreter: {release}")
    return manifest


def available_bytes(path: Path) -> int:
    usage = shutil.disk_usage(path)
    return usage.free


class Builder(Protocol):
    def build(self, release: Path) -> None: ...


class PipBuilder:
    def build(self, release: Path) -> None:
        subprocess.run([sys.executable, "-m", "venv", ".venv"], cwd=release, check=True)
        python = release / ".venv/bin/python"
        requirements = release / ".assist-ai-requirements.txt"
        if not requirements.is_file():
            raise DeployError(
                "local controller did not provide locked production requirements"
            )
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                str(requirements),
            ],
            cwd=release,
            check=True,
        )
        wheels = sorted((release / ".assist-ai-package").glob("*.whl"))
        if len(wheels) != 1:
            raise DeployError("local controller did not provide one application wheel")
        subprocess.run(
            [str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])],
            cwd=release,
            check=True,
        )


def prepare_release(
    paths: Paths,
    sha: str,
    archive: BinaryIO,
    *,
    builder: Builder,
    reserve_bytes: int = DEFAULT_RESERVE_BYTES,
) -> Path:
    sha = require_sha(sha)
    paths.releases.mkdir(parents=True, exist_ok=True)
    final = paths.releases / sha
    payload = archive.read()
    if available_bytes(paths.releases) < len(payload) + reserve_bytes:
        raise DeployError("insufficient free disk before candidate build")
    temporary = Path(tempfile.mkdtemp(prefix=f".{sha}.", dir=paths.releases))
    published = False
    try:
        archive_digest = extract_archive(io.BytesIO(payload), temporary)
        incoming_tree_digest = tree_digest(temporary)
        if final.exists():
            manifest = verify_release(final, sha)
            if (
                manifest["archive_sha256"] != archive_digest
                or manifest["source_tree_sha256"] != incoming_tree_digest
            ):
                raise DeployError(
                    "incoming archive does not match the existing SHA release"
                )
            return final
        os.replace(temporary, final)
        published = True
        # Console scripts contain an absolute interpreter shebang.  Build only after
        # the source tree is at its immutable final path; never move that venv later.
        builder.build(final)
        if available_bytes(paths.releases) < reserve_bytes:
            raise DeployError("candidate build left insufficient free disk")
        write_manifest(final, sha, archive_digest, incoming_tree_digest)
        fsync_directory(paths.releases)
        return final
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        if published:
            shutil.rmtree(final, ignore_errors=True)
        raise


class Systemd(Protocol):
    def restart(self) -> None: ...
    def health(self, expected: Path) -> None: ...


@dataclass(frozen=True)
class FileSnapshot:
    content: bytes
    mode: int


@dataclass(frozen=True)
class SelectorSnapshot:
    target: str | None


@dataclass(frozen=True)
class CutoverSnapshot:
    environment: FileSnapshot
    selector: SelectorSnapshot
    unit: FileSnapshot
    loaded_unit: dict[str, str]


class UserSystemd:
    def __init__(self, paths: Paths, *, timeout_seconds: float = 10.0) -> None:
        self.paths = paths
        self.timeout_seconds = timeout_seconds

    def restart(self) -> None:
        subprocess.run(["systemctl", "--user", "restart", BOT_UNIT], check=True)

    def health(self, expected: Path) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        before: int | None = None
        while time.monotonic() < deadline:
            output = subprocess.check_output(
                [
                    "systemctl",
                    "--user",
                    "show",
                    BOT_UNIT,
                    "--property=ActiveState,SubState,MainPID,NRestarts,FragmentPath,NeedDaemonReload",
                ],
                text=True,
            )
            values = dict(
                line.split("=", 1) for line in output.splitlines() if "=" in line
            )
            restarts = int(values.get("NRestarts", "0"))
            before = restarts if before is None else before
            pid = values.get("MainPID", "0")
            if (
                values.get("ActiveState") == "active"
                and values.get("SubState") == "running"
                and values.get("NeedDaemonReload") == "no"
                and Path(values.get("FragmentPath", "")).resolve()
                == self.paths.unit_file.resolve()
                and pid.isdigit()
                and int(pid) > 0
                and Path(f"/proc/{pid}/cwd").resolve() == expected.resolve()
                and restarts == before
            ):
                command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                if str(expected / ".venv/bin/python").encode() in command:
                    return
            time.sleep(0.25)
        raise DeployError("bot did not pass bounded runtime health check")


def select_and_health(paths: Paths, candidate: Path, systemd: Systemd) -> None:
    previous = selected_path(paths)
    atomic_symlink(paths.current, candidate)
    try:
        systemd.restart()
        systemd.health(candidate)
    except Exception as error:
        atomic_symlink(paths.current, previous)
        try:
            systemd.restart()
            systemd.health(previous)
        except Exception as rollback_error:
            raise DeployError(
                f"candidate failed and prior release did not recover: {rollback_error}"
            ) from error
        raise DeployError(f"candidate failed; restored {previous}") from error


def recover(paths: Paths, sha: str, systemd: Systemd) -> None:
    release = paths.releases / require_sha(sha)
    verify_release(release, sha)
    atomic_symlink(paths.current, release)
    systemd.restart()
    systemd.health(release)


def verify_legacy(paths: Paths) -> str:
    if not (paths.legacy_root / ".git").is_dir():
        raise DeployError("legacy checkout is missing")
    if not paths.env_file.is_file() or not paths.data_root.is_dir():
        raise DeployError("legacy server-owned environment or data is missing")
    result = subprocess.run(
        [
            "git",
            "-C",
            str(paths.legacy_root),
            "status",
            "--porcelain",
            "--untracked-files=normal",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout:
        raise DeployError("legacy checkout must be clean for cutover")
    origin = subprocess.check_output(
        ["git", "-C", str(paths.legacy_root), "remote", "get-url", "origin"], text=True
    ).strip()
    if origin != CANONICAL_ORIGIN:
        raise DeployError("legacy checkout origin is not the canonical fork")
    sha = subprocess.check_output(
        ["git", "-C", str(paths.legacy_root), "rev-parse", "HEAD"], text=True
    ).strip()
    return require_sha(sha)


def _regular_file_snapshot(path: Path, description: str) -> FileSnapshot:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise DeployError(f"{description} must be a regular file")
        return FileSnapshot(path.read_bytes(), stat.S_IMODE(info.st_mode))
    except OSError as error:
        raise DeployError(f"{description} is missing") from error


def _restore_file(path: Path, snapshot: FileSnapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    temporary.write_bytes(snapshot.content)
    temporary.chmod(snapshot.mode)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def _selector_snapshot(paths: Paths) -> SelectorSnapshot:
    if not os.path.lexists(paths.current):
        return SelectorSnapshot(None)
    if not paths.current.is_symlink():
        raise DeployError("existing current selector is not a symlink")
    return SelectorSnapshot(os.readlink(paths.current))


def _restore_selector(paths: Paths, snapshot: SelectorSnapshot) -> None:
    if snapshot.target is None:
        if os.path.lexists(paths.current):
            paths.current.unlink()
            fsync_directory(paths.current.parent)
        return
    paths.current.parent.mkdir(parents=True, exist_ok=True)
    temporary = paths.current.parent / f".{paths.current.name}.{uuid.uuid4().hex}"
    os.symlink(snapshot.target, temporary)
    os.replace(temporary, paths.current)
    fsync_directory(paths.current.parent)


def loaded_unit_state(paths: Paths) -> dict[str, str]:
    output = subprocess.check_output(
        [
            "systemctl",
            "--user",
            "show",
            BOT_UNIT,
            "--property=LoadState,ActiveState,SubState,FragmentPath,ExecStart",
        ],
        text=True,
    )
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if values.get("LoadState") != "loaded":
        raise DeployError("current bot unit is not loaded")
    fragment = Path(values.get("FragmentPath", ""))
    if fragment.resolve() != paths.unit_file.resolve():
        raise DeployError("current bot unit does not use the stable unit path")
    return values


def normalize_server_environment(paths: Paths) -> None:
    content = paths.env_file.read_bytes()
    legacy_url = b"DATABASE_URL=sqlite:///data/bot.db"
    stable_url = f"DATABASE_URL=sqlite:///{paths.data_root}/bot.db".encode()
    if legacy_url in content:
        temporary = paths.env_file.with_name(
            f".{paths.env_file.name}.{uuid.uuid4().hex}"
        )
        temporary.write_bytes(content.replace(legacy_url, stable_url))
        temporary.chmod(0o600)
        os.replace(temporary, paths.env_file)
        fsync_directory(paths.env_file.parent)
    elif stable_url not in content:
        raise DeployError("production DATABASE_URL must use the stable data path")
    paths.env_file.chmod(0o600)
    paths.data_root.chmod(0o700)


def preflight_legacy_runtime(paths: Paths) -> None:
    _regular_file_snapshot(paths.env_file, "legacy production .env")
    _regular_file_snapshot(paths.unit_file, "current bot unit")
    if stat.S_IMODE(paths.env_file.stat().st_mode) & 0o077:
        raise DeployError("legacy production .env permissions are too broad")
    entrypoint = paths.legacy_root / ".venv/bin/claude-telegram-bot"
    if not entrypoint.is_file() or not os.access(entrypoint, os.X_OK):
        raise DeployError("legacy direct entrypoint is missing or not executable")
    database = paths.data_root / "bot.db"
    if database.is_symlink() or not database.is_file():
        raise DeployError("legacy production database is missing or unsafe")
    for directory, _names, files in os.walk(paths.data_root):
        current = Path(directory)
        if current.is_symlink() or stat.S_IMODE(current.stat().st_mode) & 0o077:
            raise DeployError("legacy data directory permissions are too broad")
        for name in files:
            candidate = current / name
            if candidate.is_symlink() or stat.S_IMODE(candidate.stat().st_mode) & 0o077:
                raise DeployError("legacy data file permissions are too broad")
    values = loaded_unit_state(paths)
    if values.get("ActiveState") != "active" or values.get("SubState") != "running":
        raise DeployError("legacy bot is not healthy before cutover")
    if str(entrypoint) not in values.get("ExecStart", ""):
        raise DeployError(
            "current bot unit does not start the legacy direct entrypoint"
        )
    selector = _selector_snapshot(paths)
    if (
        selector.target is not None
        and selected_path(paths) != paths.legacy_root.resolve()
    ):
        raise DeployError("existing current selector does not retain the legacy root")


def capture_cutover_snapshot(paths: Paths) -> CutoverSnapshot:
    return CutoverSnapshot(
        environment=_regular_file_snapshot(paths.env_file, "legacy production .env"),
        selector=_selector_snapshot(paths),
        unit=_regular_file_snapshot(paths.unit_file, "current bot unit"),
        loaded_unit=loaded_unit_state(paths),
    )


def restore_cutover_snapshot(
    paths: Paths, snapshot: CutoverSnapshot, systemd: Systemd
) -> None:
    _restore_file(paths.env_file, snapshot.environment)
    _restore_selector(paths, snapshot.selector)
    _restore_file(paths.unit_file, snapshot.unit)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    restored = loaded_unit_state(paths)
    for property in (
        "LoadState",
        "ActiveState",
        "SubState",
        "FragmentPath",
        "ExecStart",
    ):
        if restored.get(property) != snapshot.loaded_unit.get(property):
            raise DeployError(f"cutover restore did not recover unit {property}")
    systemd.restart()
    systemd.health(paths.legacy_root)


def install_direct_unit_content(paths: Paths) -> None:
    paths.unit_root.mkdir(parents=True, exist_ok=True)
    temporary = paths.unit_root / f".{BOT_UNIT}.{uuid.uuid4().hex}"
    temporary.write_text(DIRECT_UNIT, encoding="utf-8")
    temporary.chmod(0o644)
    os.replace(temporary, paths.unit_file)
    fsync_directory(paths.unit_root)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)


def verify_direct_unit(paths: Paths) -> None:
    try:
        actual = paths.unit_file.read_text(encoding="utf-8")
    except OSError as error:
        raise DeployError("stable direct unit is missing") from error
    if actual != DIRECT_UNIT:
        raise DeployError("stable direct unit differs from the reviewed unit")


def cutover(paths: Paths, systemd: Systemd) -> str:
    """Install the direct unit after a safe legacy selector prefix.

    The legacy checkout stays in place.  If this process dies, current still selects
    it and no later process attempts to infer or repair the cutover.
    """
    with deploy_lock(paths):
        legacy_sha = verify_legacy(paths)
        preflight_legacy_runtime(paths)
        if available_bytes(paths.home) < DEFAULT_RESERVE_BYTES:
            raise DeployError("insufficient free disk before legacy cutover")
        snapshot = capture_cutover_snapshot(paths)
        try:
            normalize_server_environment(paths)
            atomic_symlink(paths.current, paths.legacy_root)
            install_direct_unit_content(paths)
            systemd.restart()
            systemd.health(paths.legacy_root)
        except Exception as error:
            try:
                restore_cutover_snapshot(paths, snapshot, systemd)
            except Exception as restore_error:
                raise DeployError(
                    f"cutover failed and could not restore the legacy state: {restore_error}"
                ) from error
            raise DeployError(
                "cutover failed; restored the exact legacy state"
            ) from error
        return legacy_sha


def local_identity(repo: Path, sha: str) -> None:
    if subprocess.check_output(
        ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=normal"],
        text=True,
    ):
        raise DeployError("local checkout must be clean")
    origin = subprocess.check_output(
        ["git", "-C", str(repo), "remote", "get-url", "origin"], text=True
    ).strip()
    if origin != CANONICAL_ORIGIN:
        raise DeployError("local origin is not the canonical fork")
    sha = require_sha(sha)
    with tempfile.TemporaryDirectory(prefix="assist-ai-origin-main-") as directory:
        subprocess.run(
            ["git", "init", "--bare", directory], check=True, stdout=subprocess.DEVNULL
        )
        subprocess.run(
            ["git", "-C", directory, "fetch", "--quiet", origin, "main"], check=True
        )
        if subprocess.run(
            ["git", "-C", directory, "merge-base", "--is-ancestor", sha, "FETCH_HEAD"],
            check=False,
        ).returncode:
            raise DeployError(
                "commit is not reachable from freshly fetched origin/main"
            )


def local_archive(repo: Path, sha: str) -> bytes:
    local_identity(repo, sha)
    with tempfile.TemporaryDirectory(prefix="assist-ai-export-") as directory:
        root = Path(directory) / "release"
        root.mkdir()
        archive = subprocess.check_output(["git", "-C", str(repo), "archive", sha])
        extract_archive(io.BytesIO(archive), root)
        (root / ".assist-ai-requirements.txt").write_text(
            locked_requirements(root / "poetry.lock"), encoding="utf-8"
        )
        wheelhouse = root / ".assist-ai-package"
        wheelhouse.mkdir()
        subprocess.run(
            [
                "poetry",
                "build",
                "--format",
                "wheel",
                "--output",
                str(wheelhouse),
            ],
            cwd=root,
            check=True,
        )
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            for path in sorted(root.rglob("*")):
                tar.add(
                    path, arcname=path.relative_to(root).as_posix(), recursive=False
                )
        return output.getvalue()


def locked_requirements(lock_file: Path) -> str:
    """Render the committed main dependency set without a Poetry plugin on the host."""
    try:
        from packaging.markers import Marker, default_environment
    except ImportError as error:
        raise DeployError("local dependency export requires packaging") from error
    try:
        lock = tomllib.loads(lock_file.read_text(encoding="utf-8"))
        packages = lock["package"]
    except (OSError, tomllib.TOMLDecodeError, KeyError) as error:
        raise DeployError(
            "committed Poetry lock cannot produce production requirements"
        ) from error
    target_environment = default_environment()
    target_environment.update(
        {
            "os_name": "posix",
            "sys_platform": "linux",
            "platform_system": "Linux",
        }
    )
    lines: list[str] = []
    for package in packages:
        if "main" not in package.get("groups", []) or package.get("optional", False):
            continue
        marker = package.get("markers")
        if marker is not None:
            if not isinstance(marker, str):
                raise DeployError("committed Poetry lock has an invalid marker")
            try:
                if not Marker(marker).evaluate(target_environment):
                    continue
            except (SyntaxError, ValueError) as error:
                raise DeployError(
                    "committed Poetry lock has an invalid marker"
                ) from error
        name = package.get("name")
        version = package.get("version")
        files = package.get("files")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(files, list)
        ):
            raise DeployError("committed Poetry lock has an invalid package entry")
        hashes = [entry.get("hash") for entry in files if isinstance(entry, dict)]
        if not hashes or not all(isinstance(value, str) for value in hashes):
            raise DeployError(f"committed Poetry lock has no hashes for {name}")
        lines.append(
            f"{name}=={version}" + "".join(f" --hash={value}" for value in hashes)
        )
    return "\n".join(sorted(lines)) + "\n"


def remote_command(command: str, sha: str, payload: bytes | None = None) -> None:
    require_sha(sha)
    source = Path(__file__).read_text(encoding="utf-8")
    process = subprocess.Popen(
        ["ssh", DEPLOY_HOST, "python3", "-c", source, command, sha],
        stdin=subprocess.PIPE if payload is not None else None,
    )
    if payload is not None:
        assert process.stdin is not None
        process.stdin.write(payload)
        process.stdin.close()
    if process.wait() != 0:
        raise DeployError(f"{command} failed on {DEPLOY_HOST}")


def receive_deploy(sha: str, home: Path) -> None:
    paths = Paths.for_home(home)
    with deploy_lock(paths):
        verify_direct_unit(paths)
        candidate = prepare_release(paths, sha, sys.stdin.buffer, builder=PipBuilder())
        select_and_health(paths, candidate, UserSystemd(paths))


def receive_recover(sha: str, home: Path) -> None:
    paths = Paths.for_home(home)
    with deploy_lock(paths):
        verify_direct_unit(paths)
        recover(paths, sha, UserSystemd(paths))


def receive_cutover(sha: str, home: Path) -> None:
    paths = Paths.for_home(home)
    legacy_sha = cutover(paths, UserSystemd(paths))
    if legacy_sha != require_sha(sha):
        raise DeployError("legacy SHA differs from the requested cutover SHA")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="deploy an immutable assist-ai release"
    )
    parser.add_argument(
        "command",
        choices=(
            "deploy",
            "recover",
            "cutover",
            "verify-local",
            "receive-deploy",
            "receive-recover",
            "receive-cutover",
        ),
    )
    parser.add_argument("sha")
    parser.add_argument("--home", type=Path, default=Path.home())
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "verify-local":
            local_identity(Path(__file__).resolve().parents[1], arguments.sha)
            print(f"VERIFIED_SHA={arguments.sha}")
        elif arguments.command == "deploy":
            repo = Path(__file__).resolve().parents[1]
            remote_command(
                "receive-deploy", arguments.sha, local_archive(repo, arguments.sha)
            )
            print(f"DEPLOYED_SHA={arguments.sha}")
        elif arguments.command == "recover":
            remote_command("receive-recover", arguments.sha)
            print(f"RECOVERED_SHA={arguments.sha}")
        elif arguments.command == "cutover":
            repo = Path(__file__).resolve().parents[1]
            local_identity(repo, arguments.sha)
            remote_command("receive-cutover", arguments.sha)
            print(f"CUTOVER_SHA={arguments.sha}")
        elif arguments.command == "receive-deploy":
            paths = Paths.for_home(arguments.home)
            receive_deploy(arguments.sha, paths.home)
            print(f"DEPLOYED_SHA={arguments.sha}")
        elif arguments.command == "receive-recover":
            paths = Paths.for_home(arguments.home)
            receive_recover(arguments.sha, paths.home)
            print(f"RECOVERED_SHA={arguments.sha}")
        else:
            paths = Paths.for_home(arguments.home)
            receive_cutover(arguments.sha, paths.home)
            print(f"CUTOVER_SHA={arguments.sha}")
    except (DeployError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
