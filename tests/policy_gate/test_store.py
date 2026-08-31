from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from src.policy_gate.store import GATE_SCHEMA_VERSION, GateStore
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
