from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

from .state import DeploymentPaths, atomic_write_json

CONTROL_ABI = 1
CONTROL_MANIFEST = "CONTROL_MANIFEST.json"
CONTROL_UNITS = (
    "assist-ai-recover.service",
    "assist-ai-activation.service",
    "assist-ai-activation.path",
    "assist-ai-bot.service",
)


class ControlIntegrityError(RuntimeError):
    """The installed stable controller or unit bundle changed."""


def _require_plain_path(path: Path, description: str) -> None:
    if path.is_symlink():
        raise ControlIntegrityError(f"{description} must not be a symlink")


def control_digest(package: Path) -> str:
    digest = hashlib.sha256()
    package_init = package.parent / "__init__.py"
    files = [package_init, *sorted(package.glob("*.py"))]
    _require_plain_path(package.parent, "stable operations package")
    _require_plain_path(package, "stable control package")
    if not package_init.is_file() or len(files) == 1:
        raise ControlIntegrityError("stable control package is empty")
    for path in files:
        _require_plain_path(path, f"stable control file {path.name}")
        name = str(path.relative_to(package.parent.parent)).encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def expected_control_manifest(package: Path, unit_root: Path) -> dict[str, Any]:
    units: dict[str, str] = {}
    for name in CONTROL_UNITS:
        path = unit_root / name
        _require_plain_path(path, f"stable unit {name}")
        if not path.is_file():
            raise ControlIntegrityError(f"stable unit is missing: {name}")
        units[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "schema": 1,
        "control_abi": CONTROL_ABI,
        "control_sha256": control_digest(package),
        "units": units,
    }


def install_control_manifest(
    package: Path, unit_root: Path, control_root: Path
) -> None:
    atomic_write_json(
        control_root / CONTROL_MANIFEST,
        expected_control_manifest(package, unit_root),
        0o400,
    )


def load_control_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ControlIntegrityError(
            "stable control manifest is missing or invalid"
        ) from error
    if not isinstance(value, dict):
        raise ControlIntegrityError("stable control manifest must be an object")
    return dict(value)


def verify_control_plane(paths: DeploymentPaths) -> None:
    package = paths.control_root / "ops/control"
    expected = expected_control_manifest(package, paths.unit_root)
    verify_installed_control(paths.control_root, expected)
    manifest = load_control_manifest(paths.control_root / CONTROL_MANIFEST)
    if manifest != expected:
        raise ControlIntegrityError("stable controller or unit bundle digest changed")
    verify_unit_modes(paths)


def verify_installed_control(control_root: Path, expected: dict[str, Any]) -> None:
    package = control_root / "ops/control"
    manifest_path = control_root / CONTROL_MANIFEST
    _require_plain_path(control_root, "stable control root")
    _require_plain_path(manifest_path, "stable control manifest")
    manifest = load_control_manifest(manifest_path)
    if manifest != expected or control_digest(package) != expected["control_sha256"]:
        raise ControlIntegrityError("installed stable controller digest changed")
    if stat.S_IMODE(manifest_path.stat().st_mode) != 0o400:
        raise ControlIntegrityError("stable control manifest must be read-only")
    if stat.S_IMODE((control_root / "ops").stat().st_mode) != 0o500:
        raise ControlIntegrityError("stable operations package must be read-only")
    if stat.S_IMODE(package.stat().st_mode) != 0o500:
        raise ControlIntegrityError("stable control package must be read-only")
    package_init = control_root / "ops/__init__.py"
    if stat.S_IMODE(package_init.stat().st_mode) != 0o400:
        raise ControlIntegrityError("stable operations initializer must be read-only")
    for path in package.glob("*.py"):
        _require_plain_path(path, f"stable control file {path.name}")
        if stat.S_IMODE(path.stat().st_mode) != 0o500:
            raise ControlIntegrityError(
                f"stable control file mode changed: {path.name}"
            )


def verify_unit_modes(paths: DeploymentPaths) -> None:
    for name in CONTROL_UNITS:
        path = paths.unit_root / name
        _require_plain_path(path, f"stable unit {name}")
        if stat.S_IMODE(path.stat().st_mode) != 0o644:
            raise ControlIntegrityError(f"stable unit mode changed: {name}")
