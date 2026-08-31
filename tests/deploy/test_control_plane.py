from __future__ import annotations

import hashlib
import io
import json
import multiprocessing
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from ops.control.controller import (
    DEPLOY_HOST,
    CheckoutIdentity,
    ControllerError,
    deploy,
    prepare_artifact,
)
from ops.control.launcher import selected_command
from ops.control.manifest import (
    ManifestError,
    create_ready_manifest,
    release_allocated_bytes,
    verify_ready_release,
)
from ops.control.state import DeploymentPaths, ReleaseRef, StateError, StateStore
from ops.control.worker import (
    ActivationEngine,
    ActivationError,
    ReleaseManager,
    retire_legacy,
    systemd_user_scope,
)

SHA_A = "a" * 40
SHA_B = "b" * 40
TREE_A = "1" * 40
TREE_B = "2" * 40


def test_systemd_scope_and_unit_root_default_to_user_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASSIST_AI_SYSTEMD_SCOPE", raising=False)
    monkeypatch.delenv("ASSIST_AI_SYSTEMD_UNIT_ROOT", raising=False)
    assert systemd_user_scope()
    assert DeploymentPaths.for_home(tmp_path).unit_root == (
        tmp_path / ".config/systemd/user"
    )

    monkeypatch.setenv("ASSIST_AI_SYSTEMD_SCOPE", "system")
    monkeypatch.setenv("ASSIST_AI_SYSTEMD_UNIT_ROOT", "/etc/systemd/system")
    assert not systemd_user_scope()
    assert DeploymentPaths.for_home(tmp_path).unit_root == Path("/etc/systemd/system")

    monkeypatch.setenv("ASSIST_AI_SYSTEMD_SCOPE", "other")
    with pytest.raises(ActivationError, match="scope"):
        systemd_user_scope()
    monkeypatch.setenv("ASSIST_AI_SYSTEMD_UNIT_ROOT", "relative")
    with pytest.raises(StateError, match="absolute"):
        DeploymentPaths.for_home(tmp_path)


def make_release(path: Path, sha: str, tree: str) -> ReleaseRef:
    (path / ".venv/bin").mkdir(parents=True)
    (path / "src").mkdir()
    (path / "src/main.py").write_text("value = 1\n", encoding="utf-8")
    python = path / ".venv/bin/python"
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o755)
    manifest_digest = create_ready_manifest(
        path,
        sha=sha,
        tree=tree,
        archive_sha256=hashlib.sha256(sha.encode()).hexdigest(),
        python_identity="cpython-3.11",
        builder="test-builder-v1",
    )
    return ReleaseRef(
        slot=path.name,
        sha=sha,
        manifest_sha256=manifest_digest,
    )


class FileSystemd:
    """Persistent fake for state-machine tests, not runtime acceptance."""

    def __init__(
        self,
        paths: DeploymentPaths,
        *,
        fail_slot: str | None = None,
    ) -> None:
        self.paths = paths
        self.fail_slot = fail_slot
        self.runtime_file = paths.state_root / "test-runtime.json"

    def restart_bot(self) -> None:
        state = StateStore(self.paths).load_state()
        payload = {
            "slot": state.current.slot,
            "sha": state.current.sha,
            "restarts": self.snapshot()["restarts"] + 1,
            "active": state.current.slot != self.fail_slot,
        }
        self.runtime_file.write_text(json.dumps(payload), encoding="utf-8")

    def snapshot(self) -> dict[str, object]:
        if not self.runtime_file.exists():
            return {"slot": None, "sha": None, "restarts": 0, "active": False}
        return json.loads(self.runtime_file.read_text(encoding="utf-8"))

    def assert_running(self, release: ReleaseRef) -> int:
        snapshot = self.snapshot()
        if not snapshot["active"] or snapshot["slot"] != release.slot:
            raise ActivationError(f"{release.slot} did not stabilize")
        return int(snapshot["restarts"])


def initialize_activation(
    tmp_path: Path,
    *,
    fail_slot: str | None = None,
) -> tuple[DeploymentPaths, StateStore, FileSystemd, ReleaseRef, ReleaseRef]:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    old = make_release(paths.slot_path("slot-a"), SHA_A, TREE_A)
    candidate = make_release(paths.slot_path("slot-b"), SHA_B, TREE_B)
    store = StateStore(paths)
    store.initialize(old)
    store.create_request("deploy", candidate)
    systemd = FileSystemd(paths, fail_slot=fail_slot)
    systemd.restart_bot()
    return paths, store, systemd, old, candidate


def run_killed_activation(home: str, boundary: str, fail_slot: str | None) -> None:
    paths = DeploymentPaths.for_home(Path(home))
    engine = ActivationEngine(
        StateStore(paths),
        paths,
        FileSystemd(paths, fail_slot=fail_slot),
        stabilization_seconds=0,
        fault_boundary=boundary,
    )
    engine.activate()


def run_activation(home: str, fail_slot: str | None) -> None:
    paths = DeploymentPaths.for_home(Path(home))
    engine = ActivationEngine(
        StateStore(paths),
        paths,
        FileSystemd(paths, fail_slot=fail_slot),
        stabilization_seconds=0,
    )
    try:
        engine.activate()
    except ActivationError:
        pass


def run_killed_retirement(home: str, boundary: str) -> None:
    paths = DeploymentPaths.for_home(Path(home))
    retire_legacy(
        SHA_A,
        paths=paths,
        systemd=FileSystemd(paths),
        fault_boundary=boundary,
    )


def tar_bytes(files: dict[str, bytes], modes: dict[str, int] | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = (modes or {}).get(name, 0o644)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def fake_builder(release: Path) -> tuple[str, str]:
    python = release / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o755)
    return "cpython-3.11", "test-builder-v1"


def test_manifest_rejects_content_mode_symlink_and_ready_tampering(
    tmp_path: Path,
) -> None:
    release = tmp_path / "slot-a"
    ref = make_release(release, SHA_A, TREE_A)
    verify_ready_release(release, ref)

    cases = ["content", "mode", "symlink", "ready", "metadata-mode"]
    for case in cases:
        root = tmp_path / case
        root.mkdir()
        copied = root / "slot-a"
        subprocess.run(["cp", "-a", str(release), str(copied)], check=True)
        copied.chmod(0o700)
        target = copied / "src/main.py"
        if case == "content":
            target.chmod(0o600)
            target.write_text("value = 2\n", encoding="utf-8")
        elif case == "mode":
            target.chmod(0o755)
        elif case == "symlink":
            target.parent.chmod(0o700)
            target.unlink()
            target.symlink_to("../poetry.lock")
        elif case == "ready":
            ready = copied / ".assist-ai-ready"
            ready.chmod(0o600)
            ready.write_text("0" * 64 + "\n", encoding="utf-8")
        else:
            (copied / ".assist-ai-release.json").chmod(0o600)
        target.parent.chmod(0o555)
        copied.chmod(0o500)
        with pytest.raises(ManifestError):
            verify_ready_release(copied, ref)


def test_activation_commits_candidate_and_keeps_old_as_rollback(tmp_path: Path) -> None:
    paths, store, systemd, old, candidate = initialize_activation(tmp_path)
    ActivationEngine(store, paths, systemd, stabilization_seconds=0).activate()

    state = store.load_state()
    assert state.status == "committed"
    assert state.current == candidate
    assert state.previous == old
    assert not paths.request_file.exists()
    receipt = store.load_latest_receipt()
    assert receipt["result"] == "deployed"
    assert receipt["sha"] == SHA_B


def test_activation_rolls_back_failed_candidate(tmp_path: Path) -> None:
    paths, store, systemd, old, candidate = initialize_activation(
        tmp_path, fail_slot="slot-b"
    )
    with pytest.raises(ActivationError, match="did not stabilize"):
        ActivationEngine(store, paths, systemd, stabilization_seconds=0).activate()

    state = store.load_state()
    assert state.status == "committed"
    assert state.current == old
    assert state.previous is None
    assert not paths.request_file.exists()
    receipt = store.load_latest_receipt()
    assert receipt["result"] == "rolled-back"
    assert receipt["failed_sha"] == candidate.sha


@pytest.mark.parametrize(
    "boundary",
    [
        "after-pending-state",
        "after-candidate-restart",
        "after-candidate-health",
        "after-committed-state",
        "after-success-receipt",
    ],
)
def test_sigkill_resume_commits_or_finalizes_candidate(
    tmp_path: Path, boundary: str
) -> None:
    paths, store, _systemd, old, candidate = initialize_activation(tmp_path)
    process = multiprocessing.Process(
        target=run_killed_activation,
        args=(str(tmp_path), boundary, None),
    )
    process.start()
    process.join(10)
    assert process.exitcode == -9

    run_activation(str(tmp_path), None)
    state = store.load_state()
    assert state.status == "committed"
    assert state.current == candidate
    assert state.previous == old
    assert not paths.request_file.exists()


@pytest.mark.parametrize(
    "boundary",
    [
        "after-rollback-state",
        "after-rollback-restart",
        "after-rollback-health",
        "after-rollback-committed-state",
        "after-failure-receipt",
    ],
)
def test_sigkill_resume_finishes_failed_candidate_rollback(
    tmp_path: Path, boundary: str
) -> None:
    paths, store, _systemd, old, _candidate = initialize_activation(
        tmp_path, fail_slot="slot-b"
    )
    process = multiprocessing.Process(
        target=run_killed_activation,
        args=(str(tmp_path), boundary, "slot-b"),
    )
    process.start()
    process.join(10)
    assert process.exitcode == -9

    run_activation(str(tmp_path), "slot-b")
    state = store.load_state()
    assert state.status == "committed"
    assert state.current == old
    assert state.previous is None
    assert not paths.request_file.exists()


def test_boot_recovery_conservatively_restores_previous(tmp_path: Path) -> None:
    paths, store, systemd, old, candidate = initialize_activation(tmp_path)
    store.begin_activation(store.load_request())
    assert store.load_state().current == candidate

    ActivationEngine(store, paths, systemd, stabilization_seconds=0).recover_for_boot()
    state = store.load_state()
    assert state.status == "committed"
    assert state.current == old
    assert state.previous is None


def test_boot_recovery_discards_request_before_candidate_selection(
    tmp_path: Path,
) -> None:
    paths, store, systemd, old, _candidate = initialize_activation(tmp_path)

    ActivationEngine(store, paths, systemd, stabilization_seconds=0).recover_for_boot()
    state = store.load_state()
    assert state.status == "committed"
    assert state.current == old
    assert state.previous is None
    assert not paths.request_file.exists()
    assert store.load_latest_receipt()["result"] == "rolled-back"


@pytest.mark.parametrize(
    "boundary",
    [
        "after-retirement-request",
        "after-previous-cleared",
        "after-tracked-files",
        "after-legacy-runtime",
        "after-retired-marker",
        "after-retirement-finished",
    ],
)
def test_sigkill_resume_finishes_legacy_retirement_without_touching_server_state(
    tmp_path: Path, boundary: str
) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    paths.legacy_root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(paths.legacy_root)], check=True)
    tracked = paths.legacy_root / "src/old.py"
    tracked.parent.mkdir()
    tracked.write_text("old release\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(paths.legacy_root), "add", "src/old.py"], check=True
    )
    (paths.legacy_root / ".venv/bin").mkdir(parents=True)
    legacy_python = paths.legacy_root / ".venv/bin/python"
    legacy_python.write_text("#!/bin/sh\n", encoding="utf-8")
    legacy_python.chmod(0o755)
    paths.env_file.write_bytes(b"TOKEN=server-owned\n")
    paths.env_file.chmod(0o600)
    paths.data_root.mkdir()
    database = paths.data_root / "bot.db"
    database.write_bytes(b"database")
    database.chmod(0o600)
    local_config = paths.legacy_root / "local-config.toml"
    local_config.write_bytes(b"untracked=true\n")
    local_config.chmod(0o600)
    preserved = {
        path: (path.read_bytes(), path.stat().st_ino, stat.S_IMODE(path.stat().st_mode))
        for path in (paths.env_file, database, local_config)
    }

    legacy = ReleaseRef("legacy", SHA_A, "legacy")
    store = StateStore(paths)
    store.initialize(legacy)
    candidate = make_release(paths.slot_path("slot-a"), SHA_A, TREE_A)
    request = store.create_request("deploy", candidate)
    store.begin_activation(request)
    systemd = FileSystemd(paths)
    systemd.restart_bot()
    store.commit_candidate(request)
    store.finish_request()

    process = multiprocessing.Process(
        target=run_killed_retirement,
        args=(str(tmp_path), boundary),
    )
    process.start()
    process.join(10)
    assert process.exitcode == -9

    retire_legacy(SHA_A, paths=paths, systemd=FileSystemd(paths))
    state = store.load_state()
    assert state.current == candidate
    assert state.previous is None
    assert not (paths.legacy_root / ".git").exists()
    assert not (paths.legacy_root / ".venv").exists()
    assert not tracked.exists()
    assert not (paths.state_root / "legacy-retire.json").exists()
    assert (paths.state_root / "legacy-retired.json").is_file()
    for path, expected in preserved.items():
        assert (
            path.read_bytes(),
            path.stat().st_ino,
            stat.S_IMODE(path.stat().st_mode),
        ) == expected


def test_release_manager_uses_fixed_slots_and_preserves_credentials(
    tmp_path: Path,
) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    paths.env_file.parent.mkdir(parents=True, exist_ok=True)
    paths.env_file.write_bytes(b"TOKEN=server-owned\n")
    paths.env_file.chmod(0o600)
    paths.data_root.mkdir()
    database = paths.data_root / "bot.db"
    database.write_bytes(b"database")
    database.chmod(0o600)
    before = {
        path: (path.read_bytes(), path.stat().st_ino, stat.S_IMODE(path.stat().st_mode))
        for path in (paths.env_file, database)
    }
    store = StateStore(paths)
    store.initialize(make_release(paths.slot_path("slot-a"), SHA_A, TREE_A))
    archive = tar_bytes(
        {
            "pyproject.toml": b"[project]\nname='fixture'\n",
            "poetry.lock": b"lock",
            "src/main.py": b"value = 2\n",
        }
    )
    manager = ReleaseManager(
        paths,
        store,
        builder=fake_builder,
        reserve_bytes=0,
    )
    candidate = manager.stage_archive(
        io.BytesIO(archive),
        sha=SHA_B,
        tree=TREE_B,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
    )

    assert candidate.slot == "slot-b"
    assert {path.name for path in paths.releases_root.iterdir()} == {
        "slot-a",
        "slot-b",
    }
    verify_ready_release(paths.slot_path("slot-b"), candidate)
    for path, expected in before.items():
        assert (
            path.read_bytes(),
            path.stat().st_ino,
            stat.S_IMODE(path.stat().st_mode),
        ) == expected


def test_release_manager_checks_measured_postbuild_reserve(tmp_path: Path) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    store = StateStore(paths)
    store.initialize(make_release(paths.slot_path("slot-a"), SHA_A, TREE_A))
    archive = tar_bytes(
        {
            "pyproject.toml": b"[project]\nname='fixture'\n",
            "poetry.lock": b"lock",
            "payload": b"x" * 8192,
        }
    )
    reserve = 16384

    failing = ReleaseManager(
        paths,
        store,
        builder=fake_builder,
        reserve_bytes=reserve,
        available_bytes=lambda _path: reserve - 1,
    )
    with pytest.raises(ActivationError, match="measured free space"):
        failing.stage_archive(
            io.BytesIO(archive),
            sha=SHA_B,
            tree=TREE_B,
            archive_sha256=hashlib.sha256(archive).hexdigest(),
        )
    assert not paths.slot_path("slot-b").exists()

    passing = ReleaseManager(
        paths,
        store,
        builder=fake_builder,
        reserve_bytes=reserve,
        available_bytes=lambda _path: reserve,
    )
    ref = passing.stage_archive(
        io.BytesIO(archive),
        sha=SHA_B,
        tree=TREE_B,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
    )
    manifest = verify_ready_release(paths.slot_path("slot-b"), ref)
    assert manifest["allocated_bytes"] == release_allocated_bytes(
        paths.slot_path("slot-b")
    )


def test_release_manager_rejects_credential_and_escaping_symlink_members(
    tmp_path: Path,
) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    store = StateStore(paths)
    store.initialize(make_release(paths.slot_path("slot-a"), SHA_A, TREE_A))
    manager = ReleaseManager(paths, store, builder=fake_builder, reserve_bytes=0)

    credential = tar_bytes({".env": b"TOKEN=tracked"})
    with pytest.raises(ActivationError, match="protected path"):
        manager.stage_archive(
            io.BytesIO(credential),
            sha=SHA_B,
            tree=TREE_B,
            archive_sha256=hashlib.sha256(credential).hexdigest(),
        )

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("src/escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../.env"
        archive.addfile(info)
    symlink_archive = output.getvalue()
    with pytest.raises(ActivationError, match="unsafe symlink"):
        manager.stage_archive(
            io.BytesIO(symlink_archive),
            sha=SHA_B,
            tree=TREE_B,
            archive_sha256=hashlib.sha256(symlink_archive).hexdigest(),
        )


def test_release_manager_never_executes_target_deployment_helper(
    tmp_path: Path,
) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    store = StateStore(paths)
    store.initialize(make_release(paths.slot_path("slot-a"), SHA_A, TREE_A))
    marker = tmp_path / "target-helper-ran"
    archive = tar_bytes(
        {
            "pyproject.toml": b"[project]\nname='fixture'\n",
            "poetry.lock": b"lock",
            "src/main.py": b"value = 2\n",
            "ops/remote-deploy.sh": (f"#!/bin/sh\ntouch {marker}\nexit 99\n".encode()),
        },
        modes={"ops/remote-deploy.sh": 0o755},
    )
    manager = ReleaseManager(paths, store, builder=fake_builder, reserve_bytes=0)
    manager.stage_archive(
        io.BytesIO(archive),
        sha=SHA_B,
        tree=TREE_B,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
    )
    assert not marker.exists()


def test_launcher_selects_pending_candidate_without_a_current_symlink(
    tmp_path: Path,
) -> None:
    paths, store, _systemd, _old, candidate = initialize_activation(tmp_path)
    store.begin_activation(store.load_request())

    root, command = selected_command(paths)
    assert root == paths.slot_path(candidate.slot)
    assert command == [str(root / ".venv/bin/python"), "-m", "src.main"]
    assert not (paths.legacy_root / "current").exists()


def init_origin(tmp_path: Path) -> tuple[Path, Path, str]:
    origin = tmp_path / "origin.git"
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "--bare", "-q", str(origin)], check=True)
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "deploy-test"],
        check=True,
    )
    (checkout / "tracked").write_text("content\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "tracked"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "initial"], check=True)
    subprocess.run(["git", "-C", str(checkout), "branch", "-M", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "remote", "add", "origin", str(origin)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "push", "-qu", "origin", "main"], check=True
    )
    sha = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    return origin, checkout, sha


def test_controller_exports_exact_origin_main_sha_without_touching_checkout(
    tmp_path: Path,
) -> None:
    origin, checkout, sha = init_origin(tmp_path)
    before = CheckoutIdentity.capture(checkout)
    artifact = prepare_artifact(checkout, sha, origin_url=str(origin))
    try:
        assert artifact.sha == sha
        assert len(artifact.tree) == 40
        assert (
            hashlib.sha256(artifact.archive.read_bytes()).hexdigest() == artifact.sha256
        )
        assert CheckoutIdentity.capture(checkout) == before
    finally:
        artifact.cleanup()


def test_controller_rejects_noncanonical_sha_and_dirty_checkout(tmp_path: Path) -> None:
    origin, checkout, sha = init_origin(tmp_path)
    with pytest.raises(ControllerError, match="full lowercase"):
        prepare_artifact(checkout, sha.upper(), origin_url=str(origin))
    (checkout / "untracked").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ControllerError, match="clean checkout"):
        prepare_artifact(checkout, sha, origin_url=str(origin))


def test_controller_rejects_clean_local_only_control_commit(tmp_path: Path) -> None:
    origin, checkout, target_sha = init_origin(tmp_path)
    (checkout / "local-only").write_text("not pushed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "local-only"], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "commit", "-qm", "local-only"], check=True
    )

    with pytest.raises(ControllerError, match="commits not on origin/main"):
        prepare_artifact(checkout, target_sha, origin_url=str(origin))


def test_controller_uses_fixed_worker_protocol_and_preserves_checkout(
    tmp_path: Path,
) -> None:
    origin, checkout, sha = init_origin(tmp_path)
    arguments = tmp_path / "ssh-arguments"
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "cat >/dev/null\n"
        f"printf '%s\\n' \"$@\" >'{arguments}'\n"
        'printf "DEPLOYED_SHA=%s\\n" "$6"\n',
        encoding="utf-8",
    )
    fake_ssh.chmod(0o755)
    before = CheckoutIdentity.capture(checkout)

    output = deploy(
        checkout,
        "rollback",
        sha,
        str(fake_ssh),
        origin_url=str(origin),
    )

    assert output.splitlines() == [f"DEPLOYED_SHA={sha}"]
    assert CheckoutIdentity.capture(checkout) == before
    sent = arguments.read_text(encoding="utf-8").splitlines()
    assert sent[0] == "mybots"
    assert sent[1:5] == [
        "/usr/bin/python3",
        "/home/mzored/.local/lib/assist-ai/control/v1/ops/control/worker.py",
        "receive",
        "rollback",
    ]
    assert sent[5] == sha


def test_controller_failure_preserves_checkout_identity(tmp_path: Path) -> None:
    origin, checkout, sha = init_origin(tmp_path)
    fake_ssh = tmp_path / "ssh-failure"
    fake_ssh.write_text(
        "#!/bin/sh\ncat >/dev/null\necho activation-failed >&2\nexit 1\n",
        encoding="utf-8",
    )
    fake_ssh.chmod(0o755)
    before = CheckoutIdentity.capture(checkout)

    with pytest.raises(ControllerError, match="activation-failed"):
        deploy(
            checkout,
            "deploy",
            sha,
            str(fake_ssh),
            origin_url=str(origin),
        )
    assert CheckoutIdentity.capture(checkout) == before


def test_deploy_shell_has_fixed_host_and_no_target_script_pipe() -> None:
    script = Path(__file__).parents[2] / "ops/deploy.sh"
    text = script.read_text(encoding="utf-8")
    assert DEPLOY_HOST == "mybots"
    assert "remote-deploy.sh" not in text
    assert "DEPLOY_HOST" not in text
