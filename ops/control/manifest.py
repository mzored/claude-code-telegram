from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Iterator

from .state import ReleaseRef, atomic_write_bytes, atomic_write_json

MANIFEST_NAME = ".assist-ai-release.json"
READY_NAME = ".assist-ai-ready"
EXCLUDED_NAMES = frozenset({MANIFEST_NAME, READY_NAME})


class ManifestError(RuntimeError):
    """A release does not match its durable ready manifest."""


def _entries(root: Path) -> Iterator[Path]:
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        names[:] = sorted(names)
        for name in names:
            yield current / name
        for name in sorted(files):
            if current == root and name in EXCLUDED_NAMES:
                continue
            yield current / name


def release_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in _entries(root):
        relative = path.relative_to(root).as_posix().encode()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            kind = b"link"
            payload = os.readlink(path).encode()
        elif path.is_dir():
            kind = b"dir"
            payload = b""
        elif path.is_file():
            kind = b"file"
            payload = hashlib.sha256(path.read_bytes()).digest()
        else:
            raise ManifestError(
                f"release contains unsupported file type: {relative.decode()}"
            )
        for part in (kind, relative, f"{mode:o}".encode(), payload):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    return digest.hexdigest()


def release_allocated_bytes(root: Path) -> int:
    total = 0
    for path in _entries(root):
        total += path.lstat().st_blocks * 512
    return total


def _make_read_only(root: Path) -> None:
    entries = list(_entries(root))
    for path in reversed(entries):
        if path.is_symlink():
            continue
        current = stat.S_IMODE(path.stat().st_mode)
        path.chmod(current & ~0o222)


def create_ready_manifest(
    root: Path,
    *,
    sha: str,
    tree: str,
    archive_sha256: str,
    python_identity: str,
    builder: str,
) -> str:
    if not root.is_dir():
        raise ManifestError("release root is missing")
    root.chmod(0o700)
    _make_read_only(root)
    manifest: dict[str, Any] = {
        "schema": 1,
        "sha": sha,
        "tree": tree,
        "archive_sha256": archive_sha256,
        "python_identity": python_identity,
        "builder": builder,
        "release_sha256": release_digest(root),
        "allocated_bytes": release_allocated_bytes(root),
    }
    manifest_path = root / MANIFEST_NAME
    atomic_write_json(manifest_path, manifest, 0o400)
    manifest_bytes = manifest_path.read_bytes()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    atomic_write_bytes(root / READY_NAME, f"{manifest_digest}\n".encode(), 0o400)
    root.chmod(0o500)
    directory = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return manifest_digest


def verify_ready_release(
    root: Path, expected: ReleaseRef | None = None
) -> dict[str, Any]:
    manifest_path = root / MANIFEST_NAME
    ready_path = root / READY_NAME
    try:
        manifest_bytes = manifest_path.read_bytes()
        ready_digest = ready_path.read_text(encoding="utf-8").strip()
        value = json.loads(manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError("release ready metadata is missing or invalid") from error
    if not isinstance(value, dict):
        raise ManifestError("release manifest must be an object")
    manifest: dict[str, Any] = dict(value)
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if ready_digest != manifest_digest:
        raise ManifestError("ready marker does not match the release manifest")
    if expected is not None:
        if expected.slot != root.name:
            raise ManifestError("release path does not match the selected slot")
        if expected.sha != manifest.get("sha"):
            raise ManifestError("release SHA does not match activation state")
        if expected.manifest_sha256 != manifest_digest:
            raise ManifestError("manifest digest does not match activation state")
    if manifest.get("schema") != 1:
        raise ManifestError("unsupported release manifest schema")
    for field, length in (
        ("sha", 40),
        ("tree", 40),
        ("archive_sha256", 64),
        ("release_sha256", 64),
    ):
        content = manifest.get(field)
        if (
            not isinstance(content, str)
            or len(content) != length
            or any(character not in "0123456789abcdef" for character in content)
        ):
            raise ManifestError(f"release manifest has invalid {field}")
    if not isinstance(manifest.get("python_identity"), str) or not manifest.get(
        "python_identity"
    ):
        raise ManifestError("release manifest has invalid Python identity")
    if not isinstance(manifest.get("builder"), str) or not manifest.get("builder"):
        raise ManifestError("release manifest has invalid builder identity")
    allocated = manifest.get("allocated_bytes")
    if not isinstance(allocated, int) or isinstance(allocated, bool) or allocated < 0:
        raise ManifestError("release manifest has invalid allocated size")
    if manifest.get("release_sha256") != release_digest(root):
        raise ManifestError("release content, mode, or symlink target changed")
    if manifest.get("allocated_bytes") != release_allocated_bytes(root):
        raise ManifestError("release allocated size changed")
    if stat.S_IMODE(root.stat().st_mode) != 0o500:
        raise ManifestError("ready release root must be read-only")
    if stat.S_IMODE(manifest_path.stat().st_mode) != 0o400:
        raise ManifestError("release manifest must be read-only")
    if stat.S_IMODE(ready_path.stat().st_mode) != 0o400:
        raise ManifestError("release ready marker must be read-only")
    return manifest
