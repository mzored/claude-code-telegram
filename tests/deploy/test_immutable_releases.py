from __future__ import annotations

import io
import multiprocessing
import os
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

from ops.deploy import (
    DEFAULT_RESERVE_BYTES,
    DIRECT_UNIT,
    DeployError,
    Paths,
    PipBuilder,
    atomic_symlink,
    cutover,
    deploy_lock,
    extract_archive,
    locked_requirements,
    prepare_release,
    recover,
    select_and_health,
    selected_path,
    verify_release,
)

SHA_A = "a" * 40
SHA_B = "b" * 40


def archive_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def console_wheel() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as wheel:
        wheel.writestr(
            "fixture_app.py",
            "import sys\n\n\ndef main():\n    print('permanent console entrypoint')\n    print(sys.executable)\n",
        )
        wheel.writestr(
            "fixture_app-0.0.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: fixture-app\nVersion: 0.0.0\n",
        )
        wheel.writestr(
            "fixture_app-0.0.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        wheel.writestr(
            "fixture_app-0.0.0.dist-info/entry_points.txt",
            "[console_scripts]\nfixture-console = fixture_app:main\n",
        )
        wheel.writestr(
            "fixture_app-0.0.0.dist-info/RECORD",
            "fixture_app.py,,\n"
            "fixture_app-0.0.0.dist-info/METADATA,,\n"
            "fixture_app-0.0.0.dist-info/WHEEL,,\n"
            "fixture_app-0.0.0.dist-info/entry_points.txt,,\n"
            "fixture_app-0.0.0.dist-info/RECORD,,\n",
        )
    return output.getvalue()


def linux_marker_lock() -> str:
    return """
[[package]]
name = "pywin32"
version = "311"
groups = ["main"]
markers = "sys_platform == 'win32'"
files = [{file = "pywin32-311.whl", hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"}]
"""


class FixtureBuilder:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def build(self, release: Path) -> None:
        if self.fail:
            raise DeployError("fixture build failed")
        python = release / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        python.chmod(0o755)


class FixtureSystemd:
    def __init__(self, paths: Paths, *, fail: bool = False) -> None:
        self.paths = paths
        self.fail = fail
        self.running: Path | None = None
        self.restarts = 0

    def restart(self) -> None:
        self.restarts += 1
        self.running = selected_path(self.paths)

    def health(self, expected: Path) -> None:
        if self.fail and expected.name == SHA_B:
            raise DeployError("candidate did not stabilize")
        assert self.running == expected


class SubprocessBuilder:
    def build(self, release: Path) -> None:
        python = release / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        command = release / ".venv/bin/claude-telegram-bot"
        command.write_text(
            "#!/bin/sh\n"
            'exec "$(dirname "$0")/python" -c \''
            "import os, time; "
            "from pathlib import Path; "
            'Path(os.environ["ASSIST_AI_HEALTH_FILE"]).write_text(os.getcwd()); '
            "time.sleep(30)'\n",
            encoding="utf-8",
        )
        command.chmod(0o755)


class SubprocessSystemd:
    def __init__(self, paths: Paths, health_file: Path) -> None:
        self.paths = paths
        self.health_file = health_file
        self.process: subprocess.Popen[str] | None = None

    def restart(self) -> None:
        self.close()
        self.health_file.unlink(missing_ok=True)
        environment = {**os.environ, "ASSIST_AI_HEALTH_FILE": str(self.health_file)}
        self.process = subprocess.Popen(
            [str(self.paths.current / ".venv/bin/claude-telegram-bot")],
            cwd=self.paths.current,
            env=environment,
            text=True,
        )

    def health(self, expected: Path) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            observed = (
                self.health_file.read_text(encoding="utf-8")
                if self.health_file.exists()
                else ""
            )
            if (
                self.process is not None
                and self.process.poll() is None
                and observed == str(expected.resolve())
            ):
                return
            time.sleep(0.01)
        raise DeployError("fixture direct-current subprocess did not become healthy")

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=2)


class CutoverFaultSystemd:
    def __init__(self, paths: Paths, previous_unit: bytes) -> None:
        self.paths = paths
        self.previous_unit = previous_unit
        self.restarts = 0

    def restart(self) -> None:
        self.restarts += 1

    def health(self, expected: Path) -> None:
        if self.paths.unit_file.read_bytes() != self.previous_unit:
            raise DeployError("direct unit did not pass the cutover health check")
        assert expected == self.paths.legacy_root


def legacy_cutover_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    missing: str | None = None,
) -> tuple[Paths, bytes, str]:
    paths = Paths.for_home(tmp_path / "home")
    entrypoint = paths.legacy_root / ".venv/bin/claude-telegram-bot"
    entrypoint.parent.mkdir(parents=True)
    if missing != "entrypoint":
        entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        entrypoint.chmod(0o755)
    paths.env_file.write_text("DATABASE_URL=sqlite:///data/bot.db\n", encoding="utf-8")
    paths.env_file.chmod(0o600)
    paths.data_root.mkdir()
    paths.data_root.chmod(0o700)
    if missing != "database":
        database = paths.data_root / "bot.db"
        database.write_bytes(b"legacy data")
        database.chmod(0o600)

    subprocess.run(["git", "init", str(paths.legacy_root)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(paths.legacy_root),
            "config",
            "user.email",
            "test@example.test",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(paths.legacy_root), "config", "user.name", "Deployment test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(paths.legacy_root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(paths.legacy_root), "commit", "-m", "fixture"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(paths.legacy_root),
            "remote",
            "add",
            "origin",
            "https://github.com/mzored/claude-code-telegram.git",
        ],
        check=True,
    )

    previous_unit = f"[Service]\nExecStart={entrypoint}\n".encode()
    if missing != "unit":
        paths.unit_root.mkdir(parents=True)
        paths.unit_file.write_bytes(previous_unit)
        paths.unit_file.chmod(0o600)
    atomic_symlink(paths.current, paths.legacy_root)
    selector = os.readlink(paths.current)

    command_dir = tmp_path / "bin"
    command_dir.mkdir()
    log = tmp_path / "systemctl.log"
    systemctl = command_dir / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        'case "$2" in\n'
        "  show)\n"
        '    printf \'LoadState=loaded\\nActiveState=active\\nSubState=running\\nFragmentPath=%s\\nExecStart=%s\\n\' "$FAKE_FRAGMENT" "$FAKE_ENTRYPOINT"\n'
        "    ;;\n"
        "  daemon-reload) printf 'reload\\n' >>\"$FAKE_SYSTEMCTL_LOG\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    monkeypatch.setenv("PATH", f"{command_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_ENTRYPOINT", str(entrypoint))
    monkeypatch.setenv("FAKE_FRAGMENT", str(paths.unit_file))
    monkeypatch.setenv("FAKE_SYSTEMCTL_LOG", str(log))
    monkeypatch.setattr("ops.deploy.available_bytes", lambda _path: 10**12)
    return paths, previous_unit, selector


def prepared(paths: Paths, sha: str) -> Path:
    return prepare_release(
        paths,
        sha,
        io.BytesIO(archive_bytes({"pyproject.toml": b"[project]\nname='fixture'\n"})),
        builder=FixtureBuilder(),
        reserve_bytes=0,
    )


def test_final_sha_release_is_immutable_and_existing_release_is_verified(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    release = prepared(paths, SHA_A)
    assert release == paths.releases / SHA_A
    assert verify_release(release, SHA_A)["sha"] == SHA_A

    assert prepared(paths, SHA_A) == release
    release.chmod(0o700)
    (release / "pyproject.toml").chmod(0o600)
    (release / "pyproject.toml").write_text("changed\n", encoding="utf-8")
    with pytest.raises(DeployError, match="contents changed"):
        prepared(paths, SHA_A)


def test_same_sha_rejects_an_incoming_archive_with_different_identity(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    prepared(paths, SHA_A)
    with pytest.raises(DeployError, match="does not match"):
        prepare_release(
            paths,
            SHA_A,
            io.BytesIO(archive_bytes({"pyproject.toml": b"different source\n"})),
            builder=FixtureBuilder(),
            reserve_bytes=0,
        )


def test_archive_attacks_are_rejected_without_running_target_helpers(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "candidate"
    destination.mkdir()
    for bad_name in (
        "../escape",
        ".env",
        "data/bot.db",
        ".git/config",
        "credentials.json",
        "private.pem",
        ".ssh/id_ed25519",
        "id_ed25519.pub",
        "config/service.key",
        "certificates/production.crt",
    ):
        with pytest.raises(DeployError, match="unsafe archive member"):
            extract_archive(io.BytesIO(archive_bytes({bad_name: b"x"})), destination)
    assert list(destination.iterdir()) == []

    source_examples = archive_bytes(
        {
            "config/env.production.example": b"TOKEN=replace-me\n",
            "docs/certificates.md": b"Document certificate rotation here.\n",
            "src/security/key_parser.py": b"def parse(): pass\n",
        }
    )
    extract_archive(io.BytesIO(source_examples), destination)
    assert (destination / "config/env.production.example").is_file()


def test_low_space_and_build_failure_leave_current_service_and_releases_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = Paths.for_home(tmp_path)
    old = prepared(paths, SHA_A)
    atomic_symlink(paths.current, old)
    systemd = FixtureSystemd(paths)
    systemd.restart()
    before = (selected_path(paths), systemd.running, sorted(paths.releases.iterdir()))

    monkeypatch.setattr("ops.deploy.available_bytes", lambda _path: 0)
    with pytest.raises(DeployError, match="insufficient free disk"):
        prepare_release(
            paths,
            SHA_B,
            io.BytesIO(archive_bytes({"pyproject.toml": b"x"})),
            builder=FixtureBuilder(),
            reserve_bytes=DEFAULT_RESERVE_BYTES,
        )
    assert (
        selected_path(paths),
        systemd.running,
        sorted(paths.releases.iterdir()),
    ) == before

    monkeypatch.setattr("ops.deploy.available_bytes", lambda _path: 10**12)
    with pytest.raises(DeployError, match="fixture build failed"):
        prepare_release(
            paths,
            SHA_B,
            io.BytesIO(archive_bytes({"pyproject.toml": b"x"})),
            builder=FixtureBuilder(fail=True),
            reserve_bytes=0,
        )
    assert selected_path(paths) == old
    assert not (paths.releases / SHA_B).exists()


def test_failed_start_restores_only_the_prior_in_memory_selector(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    old = prepared(paths, SHA_A)
    candidate = prepared(paths, SHA_B)
    atomic_symlink(paths.current, old)
    systemd = FixtureSystemd(paths, fail=True)
    with pytest.raises(DeployError, match="restored"):
        select_and_health(paths, candidate, systemd)
    assert selected_path(paths) == old
    assert systemd.running == old
    assert systemd.restarts == 2


def test_direct_current_subprocess_passes_bounded_health_check(tmp_path: Path) -> None:
    paths = Paths.for_home(tmp_path)
    archive = io.BytesIO(
        archive_bytes({"pyproject.toml": b"[project]\nname='fixture'\n"})
    )
    old = prepare_release(
        paths, SHA_A, archive, builder=SubprocessBuilder(), reserve_bytes=0
    )
    candidate = prepare_release(
        paths,
        SHA_B,
        io.BytesIO(archive_bytes({"pyproject.toml": b"[project]\nname='fixture'\n"})),
        builder=SubprocessBuilder(),
        reserve_bytes=0,
    )
    atomic_symlink(paths.current, old)
    systemd = SubprocessSystemd(paths, tmp_path / "health.txt")
    try:
        select_and_health(paths, candidate, systemd)
        assert selected_path(paths) == candidate
        assert systemd.health_file.read_text(encoding="utf-8") == str(candidate)
    finally:
        systemd.close()


def test_selection_never_mutates_server_owned_environment_or_data(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    paths.legacy_root.mkdir(parents=True)
    paths.env_file.write_text(
        "DATABASE_URL=sqlite:////stable/data/bot.db\n", encoding="utf-8"
    )
    paths.env_file.chmod(0o600)
    paths.data_root.mkdir()
    database = paths.data_root / "bot.db"
    database.write_bytes(b"persistent data")
    database.chmod(0o600)
    old = prepared(paths, SHA_A)
    candidate = prepared(paths, SHA_B)
    atomic_symlink(paths.current, old)
    before = (
        paths.env_file.read_bytes(),
        database.read_bytes(),
        database.stat().st_ino,
    )

    systemd = FixtureSystemd(paths)
    select_and_health(paths, candidate, systemd)

    assert (
        paths.env_file.read_bytes(),
        database.read_bytes(),
        database.stat().st_ino,
    ) == before


def test_direct_unit_has_no_recovery_or_launcher_dependency() -> None:
    unit = (
        Path(__file__).resolve().parents[2] / "ops/systemd/assist-ai-bot.service"
    ).read_text(encoding="utf-8")
    assert "WorkingDirectory=%h/.local/lib/assist-ai/current" in unit
    assert (
        "ExecStart=%h/.local/lib/assist-ai/current/.venv/bin/claude-telegram-bot"
        in unit
    )
    assert "recover" not in unit
    assert "activation" not in unit
    assert "launcher" not in unit
    assert unit == DIRECT_UNIT


def test_locked_requirements_come_from_the_committed_main_lock() -> None:
    lock = Path(__file__).resolve().parents[2] / "poetry.lock"
    requirements = locked_requirements(lock)
    assert "aiofiles==24.1.0" in requirements
    assert (
        "--hash=sha256:b4ec55f4195e3eb5d7abd1bf7e061763e864dd4954231fb8539a0ef8bb8260e5"
        in requirements
    )
    assert "black==" not in requirements
    assert "pywin32==" not in requirements


def test_real_builder_uses_a_permanent_venv_and_linux_marker_export(
    tmp_path: Path,
) -> None:
    marker_lock = tmp_path / "marker.lock"
    marker_lock.write_text(linux_marker_lock(), encoding="utf-8")
    requirements = locked_requirements(marker_lock)
    assert requirements.strip() == ""

    paths = Paths.for_home(tmp_path)
    release = prepare_release(
        paths,
        SHA_A,
        io.BytesIO(
            archive_bytes(
                {
                    "pyproject.toml": b"[project]\nname='fixture'\n",
                    ".assist-ai-requirements.txt": requirements.encode(),
                    ".assist-ai-package/fixture_app-0.0.0-py3-none-any.whl": console_wheel(),
                }
            )
        ),
        builder=PipBuilder(),
        reserve_bytes=0,
    )
    command = release / ".venv/bin/fixture-console"
    result = subprocess.run([str(command)], check=True, capture_output=True, text=True)
    assert (
        result.stdout == f"permanent console entrypoint\n{release}/.venv/bin/python\n"
    )


def _select_then_kill(home: str, sha: str) -> None:
    paths = Paths.for_home(Path(home))
    atomic_symlink(paths.current, paths.releases / sha)
    os.kill(os.getpid(), 9)


def test_sigkill_boundaries_leave_a_plain_selector_for_manual_recovery(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    old = prepared(paths, SHA_A)
    candidate = prepared(paths, SHA_B)
    atomic_symlink(paths.current, old)

    before = multiprocessing.Process(
        target=_select_then_kill, args=(str(tmp_path), SHA_A)
    )
    before.start()
    before.join()
    assert before.exitcode == -9
    assert selected_path(paths) == old

    after = multiprocessing.Process(
        target=_select_then_kill, args=(str(tmp_path), SHA_B)
    )
    after.start()
    after.join()
    assert after.exitcode == -9
    assert selected_path(paths) == candidate

    systemd = FixtureSystemd(paths)
    recover(paths, SHA_A, systemd)
    assert selected_path(paths) == old
    assert systemd.running == old


def test_concurrent_deploy_is_rejected_without_a_request_or_queue(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    with deploy_lock(paths):
        with pytest.raises(DeployError, match="foreground deployment"):
            with deploy_lock(paths):
                pass
    assert not list(paths.root.glob("*request*"))
    assert not list(paths.root.glob("*receipt*"))


def test_legacy_prefix_can_be_selected_without_retiring_legacy_root(
    tmp_path: Path,
) -> None:
    paths = Paths.for_home(tmp_path)
    paths.legacy_root.mkdir(parents=True)
    paths.env_file.write_text(
        "DATABASE_URL=sqlite:////stable/data/bot.db\n", encoding="utf-8"
    )
    paths.data_root.mkdir()
    original = paths.env_file.read_bytes()
    atomic_symlink(paths.current, paths.legacy_root)
    assert selected_path(paths) == paths.legacy_root
    assert paths.legacy_root.exists()
    assert paths.env_file.read_bytes() == original


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("entrypoint", "direct entrypoint"),
        ("database", "database"),
        ("unit", "current bot unit"),
    ],
)
def test_real_cutover_preflight_rejects_missing_legacy_runtime_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str, message: str
) -> None:
    paths, previous_unit, selector = legacy_cutover_paths(
        tmp_path, monkeypatch, missing=missing
    )
    environment = paths.env_file.read_bytes()
    with pytest.raises(DeployError, match=message):
        cutover(paths, CutoverFaultSystemd(paths, previous_unit))
    assert paths.env_file.read_bytes() == environment
    assert os.readlink(paths.current) == selector


def test_real_cutover_fault_restores_exact_legacy_files_and_loaded_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous_unit, selector = legacy_cutover_paths(tmp_path, monkeypatch)
    environment = paths.env_file.read_bytes()
    environment_mode = paths.env_file.stat().st_mode & 0o777
    unit_mode = paths.unit_file.stat().st_mode & 0o777
    systemd = CutoverFaultSystemd(paths, previous_unit)

    with pytest.raises(DeployError, match="restored the exact legacy state"):
        cutover(paths, systemd)

    assert paths.env_file.read_bytes() == environment
    assert paths.env_file.stat().st_mode & 0o777 == environment_mode
    assert os.readlink(paths.current) == selector
    assert paths.unit_file.read_bytes() == previous_unit
    assert paths.unit_file.stat().st_mode & 0o777 == unit_mode
    assert (tmp_path / "systemctl.log").read_text(
        encoding="utf-8"
    ) == "reload\nreload\n"
    assert systemd.restarts == 2
