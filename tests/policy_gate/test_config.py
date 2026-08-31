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


def test_enabled_calendar_requires_complete_distinct_configuration_and_fixed_scopes(
    tmp_path: Path,
) -> None:
    key = credential(tmp_path / "secrets" / "gate-key", "g" * 40)
    calendar = credential(
        tmp_path / "secrets" / "calendar.json",
        """{
        "client_id":"calendar-client",
        "client_secret":"calendar-secret",
        "refresh_token":"calendar-refresh-token",
        "token_uri":"https://oauth2.googleapis.com/token",
        "scopes":[
          "https://www.googleapis.com/auth/calendar.events.owned",
          "https://www.googleapis.com/auth/calendar.events.freebusy"
        ]
        }""",
    )
    env = {
        **environment(tmp_path, key),
        "POLICY_GATE_CALENDAR_ENABLED": "1",
        "POLICY_GATE_CALENDAR_BOOKING_ID": "booking",
        "POLICY_GATE_CALENDAR_AVAILABILITY_IDS": "booking,availability",
        "POLICY_GATE_CALENDAR_TIMEZONE": "America/New_York",
        "POLICY_GATE_CALENDAR_WORKING_DAYS": "0,1,2,3,4",
        "POLICY_GATE_CALENDAR_WORK_START_HOUR": "9",
        "POLICY_GATE_CALENDAR_WORK_END_HOUR": "18",
        "POLICY_GATE_CALENDAR_GRID_MINUTES": "30",
        "POLICY_GATE_CALENDAR_BEFORE_BUFFER_MINUTES": "10",
        "POLICY_GATE_CALENDAR_AFTER_BUFFER_MINUTES": "10",
        "POLICY_GATE_CALENDAR_OFFER_TTL_SECONDS": "900",
        "POLICY_GATE_CALENDAR_CREDENTIAL_FILE": str(calendar),
    }
    config = GateConfig.from_environment(env)
    assert config.calendar.enabled
    assert config.read_calendar_credentials().scopes == (
        "https://www.googleapis.com/auth/calendar.events.owned",
        "https://www.googleapis.com/auth/calendar.events.freebusy",
    )

    duplicate_day = {**env, "POLICY_GATE_CALENDAR_WORKING_DAYS": "0,0"}
    with pytest.raises(GateConfigurationError, match="working days"):
        GateConfig.from_environment(duplicate_day)
    inside_data = {
        **env,
        "POLICY_GATE_CALENDAR_CREDENTIAL_FILE": str(tmp_path / "data" / "calendar"),
    }
    with pytest.raises(GateConfigurationError, match="Calendar credential"):
        GateConfig.from_environment(inside_data)


def test_todoist_enablement_is_independent_of_calendar(tmp_path: Path) -> None:
    key = credential(tmp_path / "secrets" / "gate-key", "g" * 40)
    token = credential(
        tmp_path / "secrets" / "todoist-token",
        '{"token":"'
        + "t" * 32
        + '","scopes":["task:add"],"external_requests_project_id":"external-requests"}',
    )
    erasure = credential(
        tmp_path / "secrets" / "todoist-erasure-token",
        '{"token":"'
        + "e" * 32
        + '","scopes":["data:delete"],"external_requests_project_id":"external-requests"}',
    )
    base = environment(tmp_path, key)
    disabled = GateConfig.from_environment(base)
    assert not disabled.calendar.enabled and not disabled.todoist.enabled

    todoist = GateConfig.from_environment(
        {
            **base,
            "POLICY_GATE_TODOIST_ENABLED": "1",
            "POLICY_GATE_TODOIST_CREDENTIAL_FILE": str(token),
            "POLICY_GATE_TODOIST_ERASURE_CREDENTIAL_FILE": str(erasure),
            "POLICY_GATE_TODOIST_EXTERNAL_REQUESTS_PROJECT_ID": "external-requests",
        }
    )
    assert not todoist.calendar.enabled and todoist.todoist.enabled
    assert todoist.read_todoist_credentials().token == "t" * 32
    assert todoist.read_todoist_erasure_credentials().token == "e" * 32

    with pytest.raises(GateConfigurationError, match="TODOIST_CREDENTIAL_FILE"):
        GateConfig.from_environment({**base, "POLICY_GATE_TODOIST_ENABLED": "1"})


def test_todoist_credential_document_requires_exact_scopes_and_project(
    tmp_path: Path,
) -> None:
    key = credential(tmp_path / "secrets" / "gate-key", "g" * 40)
    token = credential(
        tmp_path / "secrets" / "todoist-token",
        '{"token":"'
        + "t" * 32
        + '","scopes":["task:add","data:read"],"external_requests_project_id":"external-requests"}',
    )
    erasure = credential(
        tmp_path / "secrets" / "todoist-erasure-token",
        '{"token":"'
        + "e" * 32
        + '","scopes":["data:delete"],"external_requests_project_id":"external-requests"}',
    )
    enabled = {
        **environment(tmp_path, key),
        "POLICY_GATE_TODOIST_ENABLED": "1",
        "POLICY_GATE_TODOIST_CREDENTIAL_FILE": str(token),
        "POLICY_GATE_TODOIST_ERASURE_CREDENTIAL_FILE": str(erasure),
        "POLICY_GATE_TODOIST_EXTERNAL_REQUESTS_PROJECT_ID": "external-requests",
    }
    without_explicit_read = GateConfig.from_environment(enabled)
    with pytest.raises(GateConfigurationError, match="scope or project"):
        without_explicit_read.read_todoist_credentials()
    with_read = GateConfig.from_environment(
        {**enabled, "POLICY_GATE_TODOIST_OPTIONAL_READ_SCOPE_ENABLED": "1"}
    )
    assert with_read.read_todoist_credentials().scopes == {"task:add", "data:read"}

    token.write_text(
        '{"token":"'
        + "t" * 32
        + '","scopes":["task:add","data:read_write"],"external_requests_project_id":"external-requests"}'
    )
    with pytest.raises(GateConfigurationError, match="scope or project"):
        with_read.read_todoist_credentials()
    token.write_text(
        '{"token":"'
        + "t" * 32
        + '","scopes":["task:add"],"external_requests_project_id":"other-project"}'
    )
    with pytest.raises(GateConfigurationError, match="scope or project"):
        with_read.read_todoist_credentials()
    erasure.write_text(
        '{"token":"'
        + "e" * 32
        + '","scopes":["data:delete","task:add"],"external_requests_project_id":"external-requests"}'
    )
    with pytest.raises(GateConfigurationError, match="erasure credential scope"):
        with_read.read_todoist_erasure_credentials()
