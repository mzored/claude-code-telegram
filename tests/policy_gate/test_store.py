from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from src.encrypted_sqlite import SqlCipherDatabase
from src.policy_gate.executors import MockExecutor, ReconcileOutcome
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GATE_SCHEMA_VERSION, GateStore
from src.policy_gate.types import ActionOrigin, Operation, canonical_json, digest
from src.public_assistant.sqlcipher import EncryptedStoreError

from .conftest import GATE_KEY


def test_gate_database_is_encrypted_owner_only_and_reopens(tmp_path: Path) -> None:
    path = tmp_path / "gate.db"
    store = GateStore(path, GATE_KEY)
    store.close()
    assert path.read_bytes()[:16] != b"SQLite format 3\x00"
    assert os.stat(path).st_mode & 0o777 == 0o600
    GateStore(path, GATE_KEY).close()
    with pytest.raises(EncryptedStoreError):
        GateStore(path, "wrong-" + "x" * 40)


def test_plaintext_and_newer_schema_are_refused(tmp_path: Path) -> None:
    plain = tmp_path / "plain.db"
    plain.write_bytes(b"SQLite format 3\x00" + b"\x00" * 128)
    plain.chmod(0o600)
    with pytest.raises(EncryptedStoreError):
        GateStore(plain, GATE_KEY)

    path = tmp_path / "future.db"
    store = GateStore(path, GATE_KEY)
    store.database.execute(
        "UPDATE gate_schema_meta SET version=?", (GATE_SCHEMA_VERSION + 1,)
    )
    store.close()
    with pytest.raises(EncryptedStoreError, match="newer"):
        GateStore(path, GATE_KEY)


def test_v1_gate_migration_discards_unclassified_candidates_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-gate.db"
    legacy_fields: dict[str, object] = {
        "subject_id": "subject-a",
        "connection_id": "connection-a",
        "conversation_id": 202002,
        "update_id": 31,
        "request_id": "REQ-LEGACY-A",
        "operation": Operation.TASK_CREATE.value,
        "arguments": {"title": "Legacy recovery", "due_date": None},
        "processing_authorization_version": "integration-v2",
        "processing_authorization_revision": 2,
        "processor_purpose": "external task creation",
    }
    legacy_action_id = digest(legacy_fields)
    legacy_binding = {"action_id": legacy_action_id, **legacy_fields}
    legacy = SqlCipherDatabase(
        path,
        GATE_KEY,
        """
        CREATE TABLE gate_schema_meta (version INTEGER NOT NULL);
        INSERT INTO gate_schema_meta VALUES (1);
        CREATE TABLE subjects (
            subject_id TEXT PRIMARY KEY,
            blocked INTEGER NOT NULL,
            revision INTEGER NOT NULL,
            changed_at INTEGER NOT NULL
        );
        INSERT INTO subjects VALUES ('subject-a', 0, 0, 1);
        CREATE TABLE candidate_actions (
            action_id TEXT PRIMARY KEY,
            binding_digest TEXT NOT NULL,
            binding_json TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        INSERT INTO candidate_actions VALUES ('action-a', 'digest-a', '{}', 'subject-a', 1);
        CREATE TABLE administration_intents (
            intent_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            old_state_json TEXT NOT NULL,
            new_state_json TEXT NOT NULL,
            base_subject_revision INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            control_chat_id INTEGER NOT NULL,
            preview_message_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL,
            consumed_at INTEGER
        );
        INSERT INTO administration_intents VALUES
            ('intent-a', 'subject-a', 'grant', '{}', '{}', '{}', 0, 1, 1, 1, 1, 2, 'prepared', NULL);
        CREATE TABLE action_journal (
            action_id TEXT PRIMARY KEY,
            binding_digest TEXT NOT NULL,
            binding_json TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            state TEXT NOT NULL,
            authority_id TEXT,
            claim_token TEXT,
            outcome TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        """,
    )
    legacy.execute(
        """INSERT INTO action_journal VALUES
           (?, ?, ?, 'subject-a', 'task.create', 'uncertain', NULL, NULL,
            'uncertain', 1, 1)""",
        (legacy_action_id, legacy_action_id, canonical_json(legacy_binding)),
    )
    legacy.close()

    store = GateStore(path, GATE_KEY)
    try:
        assert (
            store.database.execute("SELECT version FROM gate_schema_meta").fetchone()[0]
            == GATE_SCHEMA_VERSION
        )
        assert (
            store.database.execute("SELECT count(*) FROM candidate_actions").fetchone()[
                0
            ]
            == 0
        )
        assert (
            store.database.execute(
                "SELECT state FROM administration_intents WHERE intent_id='intent-a'"
            ).fetchone()[0]
            == "stale"
        )
        columns = {
            str(row["name"])
            for row in store.database.execute(
                "PRAGMA table_info(administration_intents)"
            ).fetchall()
        }
        assert {
            "provenance",
            "external_link_identity",
            "external_source_digest",
            "external_minimum_confirmation_sequence",
        }.issubset(columns)
        journal = store.database.execute(
            "SELECT origin FROM action_journal WHERE action_id=?", (legacy_action_id,)
        ).fetchone()
        assert journal is not None
        assert journal["origin"] == ActionOrigin.OWNER_EXTERNAL.value

        executor = MockExecutor()
        service = PolicyGateService(
            store,
            executor,
            policy=PolicyConfig(enabled_operations=frozenset({Operation.TASK_CREATE})),
        )
        # No generic API may reinterpret an unclassified pre-origin journal.
        assert service.reconcile_action(legacy_action_id).outcome == "denied"
        executor.queue_reconcile(ReconcileOutcome.VERIFIED_SUCCESS)
        # The internal erasure recovery path can only reconcile this existing
        # effect; it never resubmits it or promotes it to public authority.
        assert service.erase_subject("subject-a") == "erased"
        assert executor.calls == []
        assert len(executor.reconcile_calls) == 1
        assert executor.reconcile_calls[0].origin is ActionOrigin.OWNER_EXTERNAL
    finally:
        store.close()


def test_gate_and_mock_executor_import_no_provider_or_network_client() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "policy_gate"
    forbidden = ("anthropic", "google", "httpx", "openai", "requests", "todoist")
    imported: set[str] = set()
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
    assert all(
        not any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
        for name in imported
    )
