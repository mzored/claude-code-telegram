"""Encrypted, content-free Policy Gate state."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable

from src.encrypted_sqlite import EncryptedStoreError, SqlCipherDatabase
from src.policy_gate.types import Operation

GATE_SCHEMA_VERSION = 1

GATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS gate_schema_meta (
    version INTEGER NOT NULL
);
INSERT INTO gate_schema_meta(version)
SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM gate_schema_meta);
CREATE TABLE IF NOT EXISTS subjects (
    subject_id TEXT PRIMARY KEY,
    blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 0,
    changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS subject_references (
    reference_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('managed_chat', 'request', 'action')),
    subject_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
);
CREATE TABLE IF NOT EXISTS processing_receipts (
    subject_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    revision INTEGER NOT NULL,
    grants_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
    changed_at INTEGER NOT NULL,
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
);
CREATE TABLE IF NOT EXISTS operation_policies (
    operation TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS breakers (
    name TEXT PRIMARY KEY CHECK(name IN ('reads', 'writes')),
    is_open INTEGER NOT NULL CHECK(is_open IN (0, 1)),
    changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS delegations (
    delegation_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('exact', 'bounded', 'standing')),
    constraints_json TEXT NOT NULL,
    expires_at INTEGER,
    remaining_uses INTEGER,
    exact_action_id TEXT,
    exact_payload_digest TEXT,
    exact_binding_json TEXT,
    status TEXT NOT NULL CHECK(status IN
        ('active', 'revoked', 'consumed', 'expired')),
    source_owner_command_ref TEXT NOT NULL,
    confirmed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
);
CREATE INDEX IF NOT EXISTS idx_delegations_active
    ON delegations(subject_id, operation, status);
CREATE TABLE IF NOT EXISTS administration_intents (
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
    state TEXT NOT NULL CHECK(state IN
        ('prepared', 'executing', 'applied', 'expired', 'stale')),
    consumed_at INTEGER,
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
);
CREATE TABLE IF NOT EXISTS administration_audit (
    audit_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    outcome TEXT NOT NULL,
    changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS candidate_actions (
    action_id TEXT PRIMARY KEY,
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
);
CREATE TABLE IF NOT EXISTS action_journal (
    action_id TEXT PRIMARY KEY,
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('claimed', 'succeeded', 'definite_failure', 'uncertain', 'cancelled')),
    authority_id TEXT,
    claim_token TEXT,
    outcome TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_subject_state
    ON action_journal(subject_id, state, created_at);
CREATE TABLE IF NOT EXISTS action_attempts (
    attempt_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    minute INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_subject_time
    ON action_attempts(subject_id, created_at);
CREATE INDEX IF NOT EXISTS idx_attempts_global_time
    ON action_attempts(created_at);
CREATE TABLE IF NOT EXISTS quota_events (
    action_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    day INTEGER NOT NULL,
    minute INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('reserved', 'succeeded', 'uncertain', 'released')),
    changed_at INTEGER NOT NULL
);
"""


class GateStore:
    """Own one SQLCipher database and expose test-safe aggregate inspection."""

    def __init__(
        self,
        path: Path,
        key: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self.database = SqlCipherDatabase(path, key, GATE_SCHEMA)
        version = int(
            self.database.execute("SELECT version FROM gate_schema_meta").fetchone()[0]
        )
        if version > GATE_SCHEMA_VERSION:
            self.database.close()
            raise EncryptedStoreError("gate database schema is newer than this binary")
        if version != GATE_SCHEMA_VERSION:
            self.database.close()
            raise EncryptedStoreError("gate database schema migration is incomplete")

    def now(self) -> int:
        return int(self._clock())

    @staticmethod
    def reference_hash(kind: str, value: str) -> str:
        return hashlib.sha256(f"{kind}\0{value}".encode("utf-8")).hexdigest()

    def close(self) -> None:
        self.database.close()

    def delegations(self, subject_id: str) -> tuple[tuple[str, str, int | None], ...]:
        rows = self.database.execute(
            """SELECT scope, status, remaining_uses FROM delegations
               WHERE subject_id=? ORDER BY confirmed_at, delegation_id""",
            (subject_id,),
        ).fetchall()
        return tuple((str(row[0]), str(row[1]), row[2]) for row in rows)

    def remaining_uses(self, subject_id: str, operation: Operation) -> int | None:
        row = self.database.execute(
            """SELECT remaining_uses FROM delegations WHERE subject_id=?
               AND operation=? ORDER BY confirmed_at DESC LIMIT 1""",
            (subject_id, operation.value),
        ).fetchone()
        return None if row is None or row[0] is None else int(row[0])

    def pending_intent_count(self) -> int:
        return int(
            self.database.execute(
                "SELECT count(*) FROM administration_intents WHERE state='prepared'"
            ).fetchone()[0]
        )

    def journal_count(self, action_id: str) -> int:
        return int(
            self.database.execute(
                "SELECT count(*) FROM action_journal WHERE action_id=?", (action_id,)
            ).fetchone()[0]
        )
