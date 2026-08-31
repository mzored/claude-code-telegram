from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from src.encrypted_sqlite import EncryptedStoreError
from src.private_controller.origin import (
    RunOrigin,
    RunOriginLedger,
    RunSource,
    RunTrigger,
)

ORIGIN_KEY = "origin-key-" + "o" * 40


@pytest.mark.parametrize(
    (
        "source",
        "actor",
        "chat",
        "fresh",
        "forwarded",
        "context_only",
        "resumed",
        "expected",
    ),
    [
        (
            RunSource.TELEGRAM,
            101,
            101,
            True,
            False,
            False,
            False,
            RunOrigin.DIRECT_OWNER,
        ),
        (
            RunSource.TELEGRAM,
            101,
            101,
            True,
            False,
            False,
            True,
            RunOrigin.DIRECT_OWNER,
        ),
        (
            RunSource.TELEGRAM,
            101,
            101,
            True,
            True,
            False,
            False,
            RunOrigin.PUBLIC_SENDER,
        ),
        (
            RunSource.TELEGRAM,
            202,
            202,
            True,
            False,
            False,
            False,
            RunOrigin.PUBLIC_SENDER,
        ),
        (
            RunSource.TELEGRAM,
            101,
            999,
            True,
            False,
            False,
            False,
            RunOrigin.PUBLIC_SENDER,
        ),
        (
            RunSource.WEBHOOK,
            101,
            101,
            True,
            False,
            False,
            True,
            RunOrigin.EXTERNAL_EVENT,
        ),
        (
            RunSource.EXTERNAL_HANDLER,
            101,
            101,
            True,
            False,
            False,
            True,
            RunOrigin.EXTERNAL_EVENT,
        ),
        (RunSource.SCHEDULED, 101, 101, True, False, False, True, RunOrigin.SCHEDULED),
        (
            RunSource.CONTEXT_ONLY,
            101,
            101,
            False,
            False,
            True,
            True,
            RunOrigin.EXTERNAL_EVENT,
        ),
    ],
)
def test_run_origin_matrix_is_assigned_before_execution(
    tmp_path: Path,
    source: RunSource,
    actor: int,
    chat: int,
    fresh: bool,
    forwarded: bool,
    context_only: bool,
    resumed: bool,
    expected: RunOrigin,
) -> None:
    ledger = RunOriginLedger(tmp_path / "private.db", ORIGIN_KEY)
    run = ledger.begin(
        RunTrigger(
            source=source,
            actor_id=actor,
            chat_id=chat,
            update_id=55,
            message_id=66,
            fresh=fresh,
            forwarded=forwarded,
            context_only=context_only,
            resumed_session=resumed,
        ),
        owner_id=101,
        control_chat_id=101,
    )
    assert run.origin is expected
    assert ledger.require(run.run_id) == run
    ledger.close()


def test_numeric_owner_identity_cannot_upgrade_non_owner_sources(
    tmp_path: Path,
) -> None:
    ledger = RunOriginLedger(tmp_path / "private.db", ORIGIN_KEY)
    for source in (RunSource.WEBHOOK, RunSource.SCHEDULED, RunSource.EXTERNAL_HANDLER):
        run = ledger.begin(
            RunTrigger(source, 101, 101, 1, 1, fresh=True),
            owner_id=101,
            control_chat_id=101,
        )
        assert run.origin is not RunOrigin.DIRECT_OWNER
    ledger.close()


def test_run_origin_ledger_is_sqlcipher_encrypted_and_owner_only(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.db"
    ledger = RunOriginLedger(path, ORIGIN_KEY)
    run = ledger.begin(
        RunTrigger(RunSource.TELEGRAM, 101, 101, 123456, 654321, fresh=True),
        owner_id=101,
        control_chat_id=101,
    )
    ledger.close()
    payload = path.read_bytes()
    assert not payload.startswith(b"SQLite format 3")
    assert b"123456" not in payload
    assert os.stat(path).st_mode & 0o777 == 0o600
    reopened = RunOriginLedger(path, ORIGIN_KEY)
    assert reopened.require(run.run_id).origin is RunOrigin.DIRECT_OWNER
    reopened.close()
    with pytest.raises(EncryptedStoreError):
        RunOriginLedger(path, "wrong-origin-key-" + "x" * 40)


def test_every_production_private_model_entry_supplies_origin_provenance() -> None:
    root = Path(__file__).resolve().parents[2]
    files = (
        root / "src/bot/orchestrator.py",
        root / "src/bot/handlers/message.py",
        root / "src/bot/handlers/command.py",
        root / "src/bot/handlers/callback.py",
        root / "src/events/handlers.py",
    )
    seen = 0
    for path in files:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                not isinstance(node.func, ast.Attribute)
                or node.func.attr != "run_command"
            ):
                continue
            seen += 1
            assert "run_trigger" in {keyword.arg for keyword in node.keywords}, path
    assert seen == 12

    for path in (files[2], files[3]):
        tree = ast.parse(path.read_text())
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "continue_session"
        ]
        assert len(calls) == 1
        assert "run_trigger" in {keyword.arg for keyword in calls[0].keywords}


def test_fresh_telegram_continue_preserves_direct_owner_origin(tmp_path: Path) -> None:
    ledger = RunOriginLedger(tmp_path / "private.db", ORIGIN_KEY)
    run = ledger.begin(
        RunTrigger(
            RunSource.TELEGRAM,
            101,
            101,
            77,
            88,
            fresh=True,
            resumed_session=True,
        ),
        owner_id=101,
        control_chat_id=101,
    )
    assert run.origin is RunOrigin.DIRECT_OWNER
    ledger.close()
