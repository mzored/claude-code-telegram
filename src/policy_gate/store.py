"""Encrypted, content-free Policy Gate state."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Callable

from src.encrypted_sqlite import EncryptedStoreError, SqlCipherDatabase
from src.policy_gate.types import ActionBinding, ActionOrigin, Operation

GATE_SCHEMA_VERSION = 4

GATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS gate_schema_meta (
    version INTEGER NOT NULL
);
INSERT INTO gate_schema_meta(version)
SELECT 4 WHERE NOT EXISTS (SELECT 1 FROM gate_schema_meta);
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
    provenance TEXT NOT NULL CHECK(provenance IN
        ('ordinary_public', 'external_untrusted')),
    external_link_identity TEXT,
    external_source_digest TEXT,
    external_minimum_confirmation_sequence INTEGER,
    state TEXT NOT NULL CHECK(state IN
        ('prepared', 'executing', 'applied', 'expired', 'stale')),
    consumed_at INTEGER,
    CHECK(
        (provenance = 'ordinary_public'
         AND external_link_identity IS NULL
         AND external_source_digest IS NULL
         AND external_minimum_confirmation_sequence IS NULL)
        OR
        (provenance = 'external_untrusted'
         AND typeof(external_link_identity) = 'text'
         AND length(external_link_identity) = 64
         AND external_link_identity NOT GLOB '*[^0-9a-f]*'
         AND typeof(external_source_digest) = 'text'
         AND length(external_source_digest) = 64
         AND external_source_digest NOT GLOB '*[^0-9a-f]*'
         AND typeof(external_minimum_confirmation_sequence) = 'integer'
         AND external_minimum_confirmation_sequence > 0)
    ),
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
    provenance TEXT NOT NULL CHECK(provenance IN
        ('ordinary_public', 'external_untrusted')),
    external_link_identity TEXT,
    external_source_digest TEXT,
    CHECK(
        (provenance = 'ordinary_public'
         AND external_link_identity IS NULL
         AND external_source_digest IS NULL)
        OR
        (provenance = 'external_untrusted'
         AND typeof(external_link_identity) = 'text'
         AND length(external_link_identity) = 64
         AND external_link_identity NOT GLOB '*[^0-9a-f]*'
         AND typeof(external_source_digest) = 'text'
         AND length(external_source_digest) = 64
         AND external_source_digest NOT GLOB '*[^0-9a-f]*')
    ),
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
);
CREATE TABLE IF NOT EXISTS action_journal (
    action_id TEXT PRIMARY KEY,
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    origin TEXT NOT NULL CHECK(origin IN ('public_sender', 'owner_external')),
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
        if version == 1:
            self._migrate_v1_to_v2()
            version = int(
                self.database.execute(
                    "SELECT version FROM gate_schema_meta"
                ).fetchone()[0]
            )
        if version == 2:
            self._migrate_v2_to_v3()
            version = int(
                self.database.execute(
                    "SELECT version FROM gate_schema_meta"
                ).fetchone()[0]
            )
        if version == 3:
            self._migrate_v3_to_v4()
            version = int(
                self.database.execute(
                    "SELECT version FROM gate_schema_meta"
                ).fetchone()[0]
            )
        if version != GATE_SCHEMA_VERSION:
            self.database.close()
            raise EncryptedStoreError("gate database schema migration is incomplete")

    def _migrate_v1_to_v2(self) -> None:
        """Classify pre-origin Unit 3 state as ordinary public without rewriting it."""

        with self.database.transaction() as connection:
            # Unit 3 predates the owner-external route.  Its candidate and
            # administration data are therefore ordinary public state, not
            # unknown hostile-data state.  Preserve canonical bytes and IDs so
            # an interrupted Unit 3 action can still recover idempotently.
            connection.execute(
                """CREATE TABLE candidate_actions_v2 (
                    action_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL,
                    binding_json TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    provenance TEXT NOT NULL CHECK(provenance IN
                        ('ordinary_public', 'external_untrusted')),
                    external_link_identity TEXT,
                    external_source_digest TEXT,
                    CHECK(
                        (provenance = 'ordinary_public'
                         AND external_link_identity IS NULL
                         AND external_source_digest IS NULL)
                        OR
                        (provenance = 'external_untrusted'
                         AND typeof(external_link_identity) = 'text'
                         AND length(external_link_identity) = 64
                         AND external_link_identity NOT GLOB '*[^0-9a-f]*'
                         AND typeof(external_source_digest) = 'text'
                         AND length(external_source_digest) = 64
                         AND external_source_digest NOT GLOB '*[^0-9a-f]*')
                    ),
                    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
                )"""
            )
            connection.execute(
                """INSERT INTO candidate_actions_v2(
                       action_id, binding_digest, binding_json, subject_id, created_at,
                       provenance, external_link_identity, external_source_digest
                   )
                   SELECT action_id, binding_digest, binding_json, subject_id, created_at,
                          'ordinary_public', NULL, NULL
                   FROM candidate_actions"""
            )
            connection.execute(
                """CREATE TABLE administration_intents_v2 (
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
                    provenance TEXT NOT NULL CHECK(provenance IN
                        ('ordinary_public', 'external_untrusted')),
                    external_link_identity TEXT,
                    external_source_digest TEXT,
                    external_minimum_confirmation_sequence INTEGER,
                    state TEXT NOT NULL CHECK(state IN
                        ('prepared', 'executing', 'applied', 'expired', 'stale')),
                    consumed_at INTEGER,
                    CHECK(
                        (provenance = 'ordinary_public'
                         AND external_link_identity IS NULL
                         AND external_source_digest IS NULL
                         AND external_minimum_confirmation_sequence IS NULL)
                        OR
                        (provenance = 'external_untrusted'
                         AND typeof(external_link_identity) = 'text'
                         AND length(external_link_identity) = 64
                         AND external_link_identity NOT GLOB '*[^0-9a-f]*'
                         AND typeof(external_source_digest) = 'text'
                         AND length(external_source_digest) = 64
                         AND external_source_digest NOT GLOB '*[^0-9a-f]*'
                         AND typeof(external_minimum_confirmation_sequence) = 'integer'
                         AND external_minimum_confirmation_sequence > 0)
                    ),
                    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
                )"""
            )
            connection.execute(
                """INSERT INTO administration_intents_v2(
                       intent_id, subject_id, kind, payload_json, old_state_json,
                       new_state_json, base_subject_revision, owner_id,
                       control_chat_id, preview_message_id, created_at, expires_at,
                       provenance, external_link_identity, external_source_digest,
                       external_minimum_confirmation_sequence, state, consumed_at
                   )
                   SELECT intent_id, subject_id, kind, payload_json, old_state_json,
                          new_state_json, base_subject_revision, owner_id,
                          control_chat_id, preview_message_id, created_at, expires_at,
                          'ordinary_public', NULL, NULL, NULL, state, consumed_at
                   FROM administration_intents"""
            )
            connection.execute("DROP TABLE candidate_actions")
            connection.execute(
                "ALTER TABLE candidate_actions_v2 RENAME TO candidate_actions"
            )
            connection.execute("DROP TABLE administration_intents")
            connection.execute(
                "ALTER TABLE administration_intents_v2 RENAME TO administration_intents"
            )
            connection.execute("UPDATE gate_schema_meta SET version=2")

    def _migrate_v2_to_v3(self) -> None:
        """Add public origin metadata without changing pre-origin identity bytes."""

        with self.database.transaction() as connection:
            # No Unit 4 external route existed in v2.  Normalize even malformed
            # synthetic metadata to ordinary-public rather than inferring an
            # owner-external provenance from historic bytes.
            connection.execute(
                """UPDATE candidate_actions SET provenance='ordinary_public',
                   external_link_identity=NULL, external_source_digest=NULL"""
            )
            connection.execute(
                """UPDATE administration_intents SET provenance='ordinary_public',
                   external_link_identity=NULL, external_source_digest=NULL,
                   external_minimum_confirmation_sequence=NULL"""
            )
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(action_journal)"
                ).fetchall()
            }
            if "origin" not in columns:
                connection.execute(
                    """ALTER TABLE action_journal
                       ADD COLUMN origin TEXT NOT NULL DEFAULT 'public_sender'
                       CHECK(origin IN ('public_sender', 'owner_external'))"""
                )
            else:
                connection.execute("UPDATE action_journal SET origin='public_sender'")
            connection.execute("UPDATE gate_schema_meta SET version=3")

    @staticmethod
    def _legacy_public_binding_matches(
        *,
        action_id: object,
        binding_digest: object,
        binding_json: object,
        subject_id: object,
        operation: object | None,
    ) -> bool:
        """Recognize only an intact Unit 3 public binding without changing it."""

        try:
            payload = json.loads(str(binding_json))
            if not isinstance(payload, dict):
                return False
            binding = ActionBinding.from_legacy_public_dict(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        return (
            binding.action_id == str(action_id)
            and binding.binding_digest == str(binding_digest)
            and binding.subject_id == str(subject_id)
            and (operation is None or binding.operation.value == str(operation))
        )

    def _migrate_v3_to_v4(self) -> None:
        """Repair only the temporary v3 default that mislabeled Unit 3 journals."""

        with self.database.transaction() as connection:
            journal_rows = connection.execute(
                """SELECT action_id, binding_digest, binding_json, subject_id, operation
                   FROM action_journal WHERE origin=?""",
                (ActionOrigin.OWNER_EXTERNAL.value,),
            ).fetchall()
            for row in journal_rows:
                if self._legacy_public_binding_matches(
                    action_id=row["action_id"],
                    binding_digest=row["binding_digest"],
                    binding_json=row["binding_json"],
                    subject_id=row["subject_id"],
                    operation=row["operation"],
                ):
                    connection.execute(
                        "UPDATE action_journal SET origin=? WHERE action_id=?",
                        (ActionOrigin.PUBLIC_SENDER.value, row["action_id"]),
                    )

            candidate_rows = connection.execute(
                """SELECT action_id, binding_digest, binding_json, subject_id
                   FROM candidate_actions"""
            ).fetchall()
            for row in candidate_rows:
                if self._legacy_public_binding_matches(
                    action_id=row["action_id"],
                    binding_digest=row["binding_digest"],
                    binding_json=row["binding_json"],
                    subject_id=row["subject_id"],
                    operation=None,
                ):
                    connection.execute(
                        """UPDATE candidate_actions SET provenance='ordinary_public',
                           external_link_identity=NULL, external_source_digest=NULL
                           WHERE action_id=?""",
                        (row["action_id"],),
                    )
            connection.execute("UPDATE gate_schema_meta SET version=4")

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
