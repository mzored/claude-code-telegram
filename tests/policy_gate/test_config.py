from __future__ import annotations

from pathlib import Path

import pytest

from src.policy_gate.config import GateConfig, GateConfigurationError


def credential(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(0o600)
    return path


def environment(tmp_path: Path, key_file: Path) -> dict[str, str]:
    return {
        "POLICY_GATE_DATA_DIR": str(tmp_path / "data"),
        "POLICY_GATE_DATABASE_KEY_FILE": str(key_file),
        "POLICY_GATE_SOCKET_PATH": str(tmp_path / "run" / "gate.sock"),
        "POLICY_GATE_PUBLIC_UID": "501",
        "POLICY_GATE_CONTROLLER_UID": "502",
        "POLICY_GATE_CLIENT_GID": "503",
    }


def test_gate_key_is_file_only_distinct_and_owner_mode(tmp_path: Path) -> None:
    key = credential(tmp_path / "secrets" / "gate-key", "g" * 40)
    config = GateConfig.from_environment(environment(tmp_path, key))
    assert config.read_database_key() == "g" * 40
    assert config.public_uid != config.controller_uid
    assert config.client_gid == 503

    inline = {**environment(tmp_path, key), "POLICY_GATE_DATABASE_KEY": "secret"}
    with pytest.raises(GateConfigurationError, match="inline"):
        GateConfig.from_environment(inline)
    key.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        config.read_database_key()


def test_gate_rejects_shared_identity_and_key_inside_data(tmp_path: Path) -> None:
    key = credential(tmp_path / "data" / "gate-key", "g" * 40)
    with pytest.raises(GateConfigurationError, match="outside its data"):
        GateConfig.from_environment(environment(tmp_path, key))
    outside = credential(tmp_path / "secrets" / "gate-key", "g" * 40)
    same_uid = {**environment(tmp_path, outside), "POLICY_GATE_CONTROLLER_UID": "501"}
    with pytest.raises(GateConfigurationError, match="separate UIDs"):
        GateConfig.from_environment(same_uid)

    missing_group = environment(tmp_path, outside)
    del missing_group["POLICY_GATE_CLIENT_GID"]
    with pytest.raises(GateConfigurationError, match="CLIENT_GID"):
        GateConfig.from_environment(missing_group)
