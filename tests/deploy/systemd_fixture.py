from __future__ import annotations

import argparse
import hashlib
from dataclasses import replace
from pathlib import Path

from ops.control.integrity import install_control_manifest
from ops.control.manifest import create_ready_manifest
from ops.control.state import DeploymentPaths, ReleaseRef, StateStore
from ops.control.worker import ActivationEngine, ActivationError, RealSystemd

SHA_A = "a" * 40
SHA_B = "b" * 40
TREE_A = "1" * 40
TREE_B = "2" * 40


def paths_for(home: Path) -> DeploymentPaths:
    return replace(
        DeploymentPaths.for_home(home),
        unit_root=Path("/etc/systemd/system"),
    )


def make_release(
    paths: DeploymentPaths, slot: str, sha: str, tree: str, failing: bool
) -> ReleaseRef:
    release = paths.slot_path(slot)
    (release / ".venv/bin").mkdir(parents=True)
    (release / "src").mkdir()
    (release / "src/__init__.py").write_text("", encoding="utf-8")
    source = "raise SystemExit(1)\n" if failing else "import time\ntime.sleep(300)\n"
    (release / "src/main.py").write_text(source, encoding="utf-8")
    (release / "pyproject.toml").write_text(
        "[project]\nname='fixture'\n", encoding="utf-8"
    )
    (release / "poetry.lock").write_text("fixture\n", encoding="utf-8")
    (release / ".venv/bin/python").symlink_to("/usr/bin/python3")
    digest = create_ready_manifest(
        release,
        sha=sha,
        tree=tree,
        archive_sha256=hashlib.sha256(sha.encode()).hexdigest(),
        python_identity="cpython-3.12",
        builder="systemd-integration-v1",
    )
    return ReleaseRef(slot, sha, digest)


def setup(home: Path) -> None:
    paths = paths_for(home)
    paths.ensure_directories()
    package = paths.control_root / "ops/control"
    for control_file in package.glob("*.py"):
        control_file.chmod(0o500)
    (paths.control_root / "ops/__init__.py").chmod(0o400)
    package.chmod(0o500)
    (paths.control_root / "ops").chmod(0o500)
    install_control_manifest(package, paths.unit_root, paths.control_root)
    paths.env_file.parent.mkdir(parents=True)
    paths.env_file.write_text(
        "ENVIRONMENT=production\n"
        "TELEGRAM_BOT_TOKEN=integration-placeholder\n"
        f"DATABASE_URL=sqlite:///{paths.data_root}/bot.db\n",
        encoding="utf-8",
    )
    paths.env_file.chmod(0o600)
    paths.data_root.mkdir()
    paths.data_root.chmod(0o700)
    current = make_release(paths, "slot-a", SHA_A, TREE_A, False)
    StateStore(paths).initialize(current)


def exercise(home: Path) -> None:
    paths = paths_for(home)
    store = StateStore(paths)
    systemd = RealSystemd(paths, stabilization_seconds=2, user_scope=False)
    current = store.load_state().current
    systemd.assert_running(current)
    candidate = make_release(paths, "slot-b", SHA_B, TREE_B, True)
    store.create_request("deploy", candidate)
    try:
        ActivationEngine(
            store,
            paths,
            systemd,
            stabilization_seconds=2,
        ).activate()
    except ActivationError:
        pass
    else:
        raise AssertionError("failing candidate unexpectedly committed")
    state = store.load_state()
    if (
        state.status != "committed"
        or state.current != current
        or state.previous is not None
    ):
        raise AssertionError(
            "real systemd activation did not restore the prior release"
        )
    if paths.request_file.exists():
        raise AssertionError("completed rollback left its activation request")
    receipt = store.load_latest_receipt()
    if receipt.get("result") != "rolled-back" or receipt.get("failed_sha") != SHA_B:
        raise AssertionError("real systemd rollback receipt is incomplete")
    properties = subprocess_properties()
    pid = int(properties["MainPID"])
    if Path(f"/proc/{pid}/cwd").resolve() != paths.slot_path("slot-a").resolve():
        raise AssertionError("restored MainPID does not run from slot-a")


def subprocess_properties() -> dict[str, str]:
    import subprocess

    output = subprocess.check_output(
        [
            "systemctl",
            "show",
            "assist-ai-bot.service",
            "--property=ActiveState,SubState,MainPID,NRestarts,FragmentPath,NeedDaemonReload",
        ],
        text=True,
    )
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("setup", "exercise"))
    parser.add_argument("home", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "setup":
        setup(arguments.home)
    else:
        exercise(arguments.home)


if __name__ == "__main__":
    main()
