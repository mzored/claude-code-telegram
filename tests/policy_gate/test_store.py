from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from src.encrypted_sqlite import SqlCipherDatabase
from src.policy_gate.executors import MockExecutor, ReconcileOutcome
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GATE_SCHEMA, GATE_SCHEMA_VERSION, GateStore
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    AdminDraft,
    AdminKind,
    CandidateProvenance,
    ExternalActionConfirmation,
    ExternalActionLink,
    Operation,
    Scope,
    TrustedReference,
    canonical_json,
    digest,
)
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


def test_v4_to_v5_migration_creates_calendar_state_independently(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v4-calendar.db"
    database = SqlCipherDatabase(path, GATE_KEY, GATE_SCHEMA)
    try:
        with database.transaction() as connection:
            connection.execute("UPDATE gate_schema_meta SET version=4")
            connection.execute("DROP TABLE calendar_reservations")
            connection.execute("DROP TABLE calendar_offers")
    finally:
        database.close()

    store = GateStore(path, GATE_KEY)
    try:
        assert (
            store.database.execute("SELECT version FROM gate_schema_meta").fetchone()[0]
            == GATE_SCHEMA_VERSION
        )
        tables = {
            str(row["name"])
            for row in store.database.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"calendar_offers", "calendar_reservations"} <= tables
    finally:
        store.close()

    reopened = GateStore(path, GATE_KEY)
    try:
        assert (
            reopened.database.execute(
                "SELECT version FROM gate_schema_meta"
            ).fetchone()[0]
            == GATE_SCHEMA_VERSION
        )
    finally:
        reopened.close()


def test_v5_to_v6_migration_creates_todoist_recovery_state(tmp_path: Path) -> None:
    path = tmp_path / "v5-todoist.db"
    database = SqlCipherDatabase(path, GATE_KEY, GATE_SCHEMA)
    try:
        database.execute("UPDATE gate_schema_meta SET version=5")
        database.execute("DROP TABLE todoist_erasure_tombstones")
        database.execute("DROP TABLE todoist_task_mappings")
    finally:
        database.close()

    store = GateStore(path, GATE_KEY)
    try:
        assert (
            store.database.execute("SELECT version FROM gate_schema_meta").fetchone()[0]
            == 6
        )
        tables = {
            str(row["name"])
            for row in store.database.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"todoist_task_mappings", "todoist_erasure_tombstones"} <= tables
    finally:
        store.close()


def _legacy_binding(label: str, update_id: int) -> tuple[str, dict[str, object]]:
    fields: dict[str, object] = {
        "subject_id": "subject-a",
        "connection_id": "connection-a",
        "conversation_id": 202002,
        "update_id": update_id,
        "request_id": f"REQ-LEGACY-{label}",
        "operation": Operation.TASK_CREATE.value,
        "arguments": {"title": f"Legacy {label}", "due_date": None},
        "processing_authorization_version": "integration-v2",
        "processing_authorization_revision": 2,
        "processor_purpose": "external task creation",
    }
    action_id = digest(fields)
    return action_id, {"action_id": action_id, **fields}


_V1_SCHEMA = """
CREATE TABLE gate_schema_meta (version INTEGER NOT NULL);
INSERT INTO gate_schema_meta VALUES (1);
CREATE TABLE subjects (
    subject_id TEXT PRIMARY KEY,
    blocked INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    changed_at INTEGER NOT NULL
);
CREATE TABLE candidate_actions (
    action_id TEXT PRIMARY KEY,
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
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
"""


def _legacy_journals() -> dict[str, tuple[str, dict[str, object], str, str | None]]:
    journals: dict[str, tuple[str, dict[str, object], str, str | None]] = {}
    for offset, (label, state, outcome) in enumerate(
        (
            ("succeeded", "succeeded", "verified_success"),
            ("failure", "definite_failure", "definite_failure"),
            ("uncertain", "uncertain", "uncertain"),
            ("claimed", "claimed", None),
        ),
        start=40,
    ):
        action_id, binding = _legacy_binding(label, offset)
        journals[label] = (action_id, binding, state, outcome)
    return journals


def _insert_legacy_rows(
    database: SqlCipherDatabase,
    candidate: tuple[str, dict[str, object]],
    journals: dict[str, tuple[str, dict[str, object], str, str | None]],
    *,
    version: int,
) -> None:
    candidate_id, candidate_binding = candidate
    database.execute("INSERT INTO subjects VALUES ('subject-a', 0, 0, 1)")
    if version == 1:
        database.execute(
            "INSERT INTO candidate_actions VALUES (?, ?, ?, 'subject-a', 1)",
            (candidate_id, candidate_id, canonical_json(candidate_binding)),
        )
    else:
        database.execute(
            """INSERT INTO candidate_actions VALUES
               (?, ?, ?, 'subject-a', 1, 'ordinary_public', NULL, NULL)""",
            (candidate_id, candidate_id, canonical_json(candidate_binding)),
        )
    for action_id, binding, state, outcome in journals.values():
        database.execute(
            """INSERT INTO action_journal VALUES
               (?, ?, ?, 'subject-a', 'task.create', ?, NULL, NULL, ?, 1, 0)""",
            (action_id, action_id, canonical_json(binding), state, outcome),
        )


def _write_v1_database(
    path: Path,
    candidate: tuple[str, dict[str, object]],
    journals: dict[str, tuple[str, dict[str, object], str, str | None]],
) -> None:
    database = SqlCipherDatabase(path, GATE_KEY, _V1_SCHEMA)
    try:
        _insert_legacy_rows(database, candidate, journals, version=1)
    finally:
        database.close()


def _write_v2_database(
    path: Path,
    candidate: tuple[str, dict[str, object]],
    journals: dict[str, tuple[str, dict[str, object], str, str | None]],
) -> None:
    database = SqlCipherDatabase(path, GATE_KEY, GATE_SCHEMA)
    try:
        with database.transaction() as connection:
            connection.execute("UPDATE gate_schema_meta SET version=2")
            connection.execute("DROP INDEX idx_action_subject_state")
            connection.execute("DROP TABLE action_journal")
            connection.execute(
                """CREATE TABLE action_journal (
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
                   )"""
            )
        _insert_legacy_rows(database, candidate, journals, version=2)
    finally:
        database.close()


@pytest.mark.parametrize("version", (1, 2))
def test_preorigin_migration_preserves_public_identity_and_recovery(
    tmp_path: Path, version: int
) -> None:
    path = tmp_path / f"v{version}-gate.db"
    candidate = _legacy_binding("candidate", 31)
    journals = _legacy_journals()
    if version == 1:
        _write_v1_database(path, candidate, journals)
    else:
        _write_v2_database(path, candidate, journals)

    store = GateStore(path, GATE_KEY)
    try:
        assert (
            store.database.execute("SELECT version FROM gate_schema_meta").fetchone()[0]
            == GATE_SCHEMA_VERSION
        )
        candidate_row = store.database.execute(
            """SELECT action_id, binding_digest, binding_json, provenance,
                      external_link_identity, external_source_digest
               FROM candidate_actions WHERE action_id=?""",
            (candidate[0],),
        ).fetchone()
        assert candidate_row is not None
        assert tuple(candidate_row) == (
            candidate[0],
            candidate[0],
            canonical_json(candidate[1]),
            CandidateProvenance.ORDINARY_PUBLIC.value,
            None,
            None,
        )
        migrated = store.database.execute(
            """SELECT action_id, binding_digest, binding_json, state, outcome, origin
               FROM action_journal ORDER BY action_id"""
        ).fetchall()
        expected = sorted(
            (
                action_id,
                action_id,
                canonical_json(binding),
                state,
                outcome,
                ActionOrigin.PUBLIC_SENDER.value,
            )
            for action_id, binding, state, outcome in journals.values()
        )
        assert [tuple(row) for row in migrated] == expected
        assert not any(
            str(row["origin"]) == ActionOrigin.OWNER_EXTERNAL.value for row in migrated
        )

        executor = MockExecutor()
        service = PolicyGateService(
            store,
            executor,
            policy=PolicyConfig(enabled_operations=frozenset({Operation.TASK_CREATE})),
        )
        service.register_subject("subject-a", {"action": candidate[0]})
        assert service.activate_receipt(
            "subject-a",
            "integration-v2",
            2,
            {"Todoist": ("external task creation",)},
        )
        prepared = service.prepare_admin(
            TrustedReference("action", candidate[0]),
            AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
            owner_id=101,
            control_chat_id=101,
            preview_message_id=77,
        )
        confirmed = service.confirm_admin(
            prepared.intent_id,
            owner_id=101,
            control_chat_id=101,
            preview_message_id=77,
        )
        assert confirmed.action_result is not None
        assert confirmed.action_result.outcome == "verified_success"

        executor.queue_reconcile(
            ReconcileOutcome.VERIFIED_SUCCESS,
            ReconcileOutcome.VERIFIED_ABSENT,
        )
        assert service.reconcile_action(journals["uncertain"][0]).outcome == (
            "verified_success"
        )
        assert service.recover_claimed_actions() == 1
        assert service.reconcile_action(journals["claimed"][0]).outcome == (
            "definite_failure"
        )
        assert all(
            binding.origin is ActionOrigin.PUBLIC_SENDER
            for binding in executor.reconcile_calls
        )
        assert service.erase_subject("subject-a") == "erased"
        assert executor.calls[0].origin is ActionOrigin.PUBLIC_SENDER
    finally:
        store.close()


def test_v3_repair_reclassifies_only_valid_legacy_public_journals(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v3-repair.db"
    legacy_id, legacy_binding = _legacy_binding("repair", 71)
    external = ActionBinding.create(
        subject_id="subject-a",
        connection_id="connection-a",
        conversation_id=202002,
        update_id=72,
        request_id="REQ-EXTERNAL-REPAIR",
        operation=Operation.TASK_CREATE,
        arguments={"title": "External repair", "due_date": None},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
        origin=ActionOrigin.OWNER_EXTERNAL,
    )
    database = SqlCipherDatabase(path, GATE_KEY, GATE_SCHEMA)
    try:
        with database.transaction() as connection:
            connection.execute("UPDATE gate_schema_meta SET version=3")
            connection.execute("INSERT INTO subjects VALUES ('subject-a', 0, 0, 1)")
            connection.execute(
                """INSERT INTO action_journal VALUES
                   (?, ?, ?, 'subject-a', 'task.create', 'owner_external',
                    'uncertain', NULL, NULL, 'uncertain', 1, 1)""",
                (legacy_id, legacy_id, canonical_json(legacy_binding)),
            )
            connection.execute(
                """INSERT INTO action_journal VALUES
                   (?, ?, ?, 'subject-a', 'task.create', 'owner_external',
                    'uncertain', NULL, NULL, 'uncertain', 1, 1)""",
                (
                    external.action_id,
                    external.binding_digest,
                    canonical_json(external.as_dict()),
                ),
            )
            connection.execute(
                """INSERT INTO action_journal VALUES
                   ('corrupt', ?, '{}', 'subject-a', 'task.create', 'owner_external',
                    'uncertain', NULL, NULL, 'uncertain', 1, 1)""",
                ("f" * 64,),
            )
    finally:
        database.close()

    store = GateStore(path, GATE_KEY)
    try:
        rows = store.database.execute(
            "SELECT action_id, binding_json, origin FROM action_journal ORDER BY action_id"
        ).fetchall()
        by_id = {str(row["action_id"]): row for row in rows}
        assert by_id[legacy_id]["binding_json"] == canonical_json(legacy_binding)
        assert by_id[legacy_id]["origin"] == ActionOrigin.PUBLIC_SENDER.value
        assert by_id[external.action_id]["origin"] == ActionOrigin.OWNER_EXTERNAL.value
        assert by_id["corrupt"]["origin"] == ActionOrigin.OWNER_EXTERNAL.value
        service = PolicyGateService(store, MockExecutor())
        assert service.reconcile_action("corrupt").outcome == "denied"
    finally:
        store.close()


def test_origin_free_public_binding_requires_a_migrated_durable_record(
    tmp_path: Path,
) -> None:
    store = GateStore(tmp_path / "gate.db", GATE_KEY)
    executor = MockExecutor()
    service = PolicyGateService(
        store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset({Operation.TASK_CREATE})),
    )
    action_id, legacy_payload = _legacy_binding("unstored", 81)
    binding = ActionBinding.from_legacy_public_dict(legacy_payload)
    try:
        service.register_subject(
            "subject-a",
            {"managed_chat": "MCHAT-LEGACY-A", "action": action_id},
        )
        assert service.activate_receipt(
            "subject-a",
            "integration-v2",
            2,
            {"Todoist": ("external task creation",)},
        )
        prepared = service.prepare_admin(
            TrustedReference("managed_chat", "MCHAT-LEGACY-A"),
            AdminDraft(
                AdminKind.GRANT,
                operation=Operation.TASK_CREATE,
                scope=Scope.BOUNDED,
                remaining_uses=1,
            ),
            owner_id=101,
            control_chat_id=101,
            preview_message_id=77,
        )
        assert (
            service.confirm_admin(
                prepared.intent_id,
                owner_id=101,
                control_chat_id=101,
                preview_message_id=77,
            ).outcome
            == "applied"
        )
        assert not service.stage_action(binding)
        assert service.submit_action(binding).outcome == "denied"
        assert executor.calls == []
    finally:
        store.close()


def test_fresh_external_origin_requires_explicit_controller_stage(
    tmp_path: Path,
) -> None:
    store = GateStore(tmp_path / "gate.db", GATE_KEY)
    try:
        service = PolicyGateService(
            store,
            MockExecutor(),
            policy=PolicyConfig(enabled_operations=frozenset({Operation.TASK_CREATE})),
        )
        service.register_subject("subject-a", {"request": "REQ-EXTERNAL-NEW"})
        assert service.activate_receipt(
            "subject-a",
            "integration-v2",
            2,
            {"Todoist": ("external task creation",)},
        )
        external = ActionBinding.create(
            subject_id="subject-a",
            connection_id="connection-a",
            conversation_id=202002,
            update_id=91,
            request_id="REQ-EXTERNAL-NEW",
            operation=Operation.TASK_CREATE,
            arguments={"title": "Explicit external task", "due_date": None},
            processing_authorization_version="integration-v2",
            processing_authorization_revision=2,
            processor_purpose="external task creation",
            origin=ActionOrigin.OWNER_EXTERNAL,
        )
        link = ExternalActionLink("a" * 64, "b" * 64)
        assert not service.stage_action(external)
        assert service.stage_owner_exact_action(
            TrustedReference("request", "REQ-EXTERNAL-NEW"), external, link
        )
        prepared = service.prepare_external_admin(
            TrustedReference("action", external.action_id),
            AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
            owner_id=101,
            control_chat_id=101,
            preview_message_id=77,
            external_link=link,
            minimum_confirmation_sequence=1,
        )
        result = service.confirm_external_admin(
            prepared.intent_id,
            owner_id=101,
            control_chat_id=101,
            preview_message_id=77,
            external_confirmation=ExternalActionConfirmation(link, 2),
        )
        assert result.action_result is not None
        assert result.action_result.outcome == "verified_success"
        row = store.database.execute(
            "SELECT origin FROM action_journal WHERE action_id=?", (external.action_id,)
        ).fetchone()
        assert row is not None
        assert row["origin"] == ActionOrigin.OWNER_EXTERNAL.value
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
