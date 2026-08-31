from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest

from ops.control.bootstrap import (
    CONTROL_UNITS,
    BootstrapError,
    classify_cutover,
    install_control_bundle,
    install_unit_files,
    prepare_legacy_cutover,
    restore_unit_files,
    snapshot_unit_files,
)
from ops.control.integrity import ControlIntegrityError, verify_control_plane
from ops.control.state import (
    DeploymentPaths,
    ReleaseRef,
    StateStore,
    atomic_write_json,
    durable_unlink,
)
from ops.control.worker import retire_legacy

SHA_A = "a" * 40
SHA_B = "b" * 40


class RecordingSystemd:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def daemon_reload(self) -> None:
        self.calls.append("daemon-reload")


class CutoverSystemd:
    def __init__(self, fragment: Path) -> None:
        self.fragment = fragment

    def bot_fragment(self) -> Path:
        return self.fragment


class LegacyRetirementSystemd:
    def assert_running(self, _release: ReleaseRef) -> int:
        return 0


def kill_during_git_retirement(home: str) -> None:
    paths = DeploymentPaths.for_home(Path(home))
    retire_legacy(
        SHA_A,
        paths=paths,
        systemd=LegacyRetirementSystemd(),
        fault_boundary="after-legacy-runtime",
    )


@pytest.mark.parametrize(
    "boundary",
    [
        "after-support-units",
        "after-bot-unit",
        "after-daemon-reload",
    ],
)
def test_unit_install_is_prefix_safe(tmp_path: Path, boundary: str) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    for name in CONTROL_UNITS:
        (source / name).write_text(f"new {name}\n", encoding="utf-8")
    bot = target / "assist-ai-bot.service"
    bot.write_text("old bot unit\n", encoding="utf-8")
    systemd = RecordingSystemd()

    def fault(point: str) -> None:
        if point == boundary:
            raise RuntimeError(point)

    with pytest.raises(RuntimeError, match=boundary):
        install_unit_files(source, target, systemd, fault=fault)

    support = [name for name in CONTROL_UNITS if name != "assist-ai-bot.service"]
    if boundary == "after-support-units":
        assert bot.read_text(encoding="utf-8") == "old bot unit\n"
    else:
        assert bot.read_text(encoding="utf-8") == "new assist-ai-bot.service\n"
    for name in support:
        assert (target / name).read_text(encoding="utf-8") == f"new {name}\n"
    assert systemd.calls == (
        [] if boundary != "after-daemon-reload" else ["daemon-reload"]
    )


def test_bot_unit_is_installed_last(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    for name in CONTROL_UNITS:
        (source / name).write_text(name, encoding="utf-8")
    observed: list[str] = []

    def fault(point: str) -> None:
        observed.append(point)

    install_unit_files(source, target, RecordingSystemd(), fault=fault)
    assert observed == [
        "after-support-units",
        "after-bot-unit",
        "after-daemon-reload",
    ]


def test_failed_unit_migration_restores_exact_prior_fragments(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    bot = target / "assist-ai-bot.service"
    bot.write_bytes(b"old bot unit\n")
    bot.chmod(0o664)
    snapshots = snapshot_unit_files(target)
    for name in CONTROL_UNITS:
        (source / name).write_text(f"new {name}\n", encoding="utf-8")
    systemd = RecordingSystemd()

    install_unit_files(source, target, systemd)
    restore_unit_files(target, snapshots, systemd)

    assert bot.read_bytes() == b"old bot unit\n"
    assert bot.stat().st_mode & 0o777 == 0o664
    for name in CONTROL_UNITS[:-1]:
        assert not (target / name).exists()
    assert systemd.calls == ["daemon-reload", "daemon-reload"]


@pytest.mark.parametrize(
    "tamper",
    [
        "control-content",
        "control-link",
        "control-mode",
        "ops-init",
        "unit-content",
        "unit-link",
        "unit-mode",
    ],
)
def test_stable_control_plane_rejects_code_unit_and_mode_tampering(
    tmp_path: Path, tamper: str
) -> None:
    repo = Path(__file__).resolve().parents[2]
    source = repo / "ops/control"
    unit_source = repo / "ops/systemd"
    paths = DeploymentPaths.for_home(tmp_path)
    install_control_bundle(source, unit_source, paths.control_root)
    install_unit_files(unit_source, paths.unit_root, RecordingSystemd())
    verify_control_plane(paths)

    if tamper.startswith("control"):
        target = paths.control_root / "ops/control/launcher.py"
        if tamper == "control-content":
            target.chmod(0o700)
            target.write_bytes(target.read_bytes() + b"# tampered\n")
        elif tamper == "control-link":
            target.chmod(0o700)
            replacement = tmp_path / "outside-launcher.py"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o500)
            target.parent.chmod(0o700)
            target.unlink()
            target.symlink_to(replacement)
            target.parent.chmod(0o500)
        else:
            target.chmod(0o700)
    elif tamper == "ops-init":
        target = paths.control_root / "ops/__init__.py"
        target.chmod(0o600)
        target.write_bytes(b"# tampered\n")
    else:
        target = paths.unit_root / "assist-ai-bot.service"
        if tamper == "unit-content":
            target.write_bytes(target.read_bytes() + b"# tampered\n")
        elif tamper == "unit-link":
            replacement = tmp_path / "outside-bot.service"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o644)
            target.unlink()
            target.symlink_to(replacement)
        else:
            target.chmod(0o600)

    with pytest.raises(ControlIntegrityError):
        verify_control_plane(paths)


def test_cutover_actions_are_derived_only_from_durable_state(tmp_path: Path) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    store = StateStore(paths)
    legacy = ReleaseRef("legacy", SHA_A, "legacy")
    store.initialize(legacy)
    assert classify_cutover(paths, SHA_A).action == "deploy"

    candidate = ReleaseRef("slot-a", SHA_A, "1" * 64)
    request = store.create_request("deploy", candidate)
    store.begin_activation(request)
    store.commit_candidate(request)
    store.finish_request()
    assert classify_cutover(paths, SHA_A).action == "retire"

    atomic_write_json(
        paths.state_root / "legacy-retire.json",
        {"schema": 1, "sha": SHA_A, "tracked": []},
    )
    store.clear_previous(legacy)
    assert classify_cutover(paths, SHA_A).action == "retire"

    atomic_write_json(
        paths.state_root / "legacy-retired.json",
        {"schema": 1, "sha": SHA_A, "current": SHA_A},
    )
    durable_unlink(paths.state_root / "legacy-retire.json")
    assert classify_cutover(paths, SHA_A).action == "complete"


def test_cutover_refuses_transitional_or_unmarked_state(tmp_path: Path) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    store = StateStore(paths)
    legacy = ReleaseRef("legacy", SHA_A, "legacy")
    store.initialize(legacy)
    request = store.create_request("deploy", ReleaseRef("slot-a", SHA_B, "2" * 64))
    store.begin_activation(request)

    with pytest.raises(BootstrapError, match="pending recovery"):
        classify_cutover(paths, SHA_A)


def test_prepare_cutover_reenters_after_sigkill_during_git_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = DeploymentPaths.for_home(tmp_path)
    paths.ensure_directories()
    paths.env_file.parent.mkdir(parents=True)
    paths.env_file.write_text(
        f"DATABASE_URL=sqlite:///{paths.data_root}/bot.db\n", encoding="utf-8"
    )
    paths.env_file.chmod(0o600)
    paths.data_root.mkdir()
    paths.data_root.chmod(0o700)
    legacy = ReleaseRef("legacy", SHA_A, "legacy")
    candidate = ReleaseRef("slot-a", SHA_A, "1" * 64)
    store = StateStore(paths)
    store.initialize(legacy)
    request = store.create_request("deploy", candidate)
    store.begin_activation(request)
    store.commit_candidate(request)
    store.finish_request()
    atomic_write_json(
        paths.state_root / "legacy-retire.json",
        {"schema": 1, "sha": SHA_A, "tracked": []},
    )
    (paths.legacy_root / ".git").mkdir(parents=True)

    process = multiprocessing.Process(
        target=kill_during_git_retirement, args=(str(tmp_path),)
    )
    process.start()
    process.join(10)
    assert process.exitcode == -9
    assert not (paths.legacy_root / ".git").exists()
    assert (paths.state_root / "legacy-retire.json").is_file()

    repo = Path(__file__).resolve().parents[2]
    install_control_bundle(
        repo / "ops/control", repo / "ops/systemd", paths.control_root
    )
    install_unit_files(repo / "ops/systemd", paths.unit_root, RecordingSystemd())

    import ops.control.bootstrap as bootstrap

    monkeypatch.setattr(bootstrap.sys, "platform", "linux")
    monkeypatch.setattr(bootstrap.Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setattr(
        bootstrap,
        "RealBootstrapSystemd",
        lambda: CutoverSystemd(paths.unit_root / "assist-ai-bot.service"),
    )

    assert prepare_legacy_cutover() == bootstrap.CutoverPlan(SHA_A, "retire")
