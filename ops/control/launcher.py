from __future__ import annotations

import os
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ops.control.integrity import ControlIntegrityError, verify_control_plane
    from ops.control.manifest import ManifestError, verify_ready_release
    from ops.control.state import DeploymentPaths, StateError, StateStore
else:
    from .integrity import ControlIntegrityError, verify_control_plane
    from .manifest import ManifestError, verify_ready_release
    from .state import DeploymentPaths, StateError, StateStore


class LauncherError(RuntimeError):
    """The selected release is not safe to execute."""


def selected_command(paths: DeploymentPaths) -> tuple[Path, list[str]]:
    state = StateStore(paths).load_state()
    release = state.current
    root = paths.release_path(release)
    if release.slot == "legacy":
        if root.resolve() != paths.legacy_root.resolve():
            raise LauncherError("legacy release path is not canonical")
    else:
        try:
            verify_ready_release(root, release)
        except ManifestError as error:
            raise LauncherError(str(error)) from error
    python = root / ".venv/bin/python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise LauncherError("selected release has no executable Python interpreter")
    return root, [str(python), "-m", "src.main"]


def main() -> int:
    paths = DeploymentPaths.for_home(Path.home())
    try:
        verify_control_plane(paths)
        root, command = selected_command(paths)
    except (ControlIntegrityError, LauncherError, StateError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    os.chdir(root)
    os.execv(command[0], command)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
