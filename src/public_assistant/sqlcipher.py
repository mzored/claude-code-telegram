"""Narrow synchronous adapter for SQLCipher-backed SQLite stores."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, Iterator, Sequence

from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]


class EncryptedStoreError(RuntimeError):
    """Raised when a store cannot prove SQLCipher encryption and key access."""


def _key_pragma(key: str) -> str:
    return f'PRAGMA key = "x\'{key.encode("utf-8").hex()}\'"'


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class SqlCipherDatabase:
    """Own one SQLCipher connection and enforce safe filesystem defaults."""

    def __init__(self, path: Path, key: str, schema: str) -> None:
        self.path = path
        self._key = key
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        existed = self.path.exists()
        if not existed:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
        os.chmod(self.path, 0o600)
        try:
            self.connection = sqlcipher.connect(
                str(self.path), isolation_level=None, check_same_thread=False
            )
            self.connection.row_factory = sqlcipher.Row
            self.connection.execute(_key_pragma(key))
            cipher_row = self.connection.execute("PRAGMA cipher_version").fetchone()
            if cipher_row is None or not cipher_row[0]:
                raise EncryptedStoreError("SQLCipher support is unavailable")
            self.connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA secure_delete = ON")
            self.connection.execute("PRAGMA busy_timeout = 5000")
            mode = self.connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise EncryptedStoreError("encrypted store did not enter WAL mode")
            self.connection.execute("PRAGMA wal_autocheckpoint = 0")
            self.connection.executescript(schema)
            self._secure_files()
        except Exception as exc:
            try:
                self.connection.close()
            except Exception:
                pass
            if not existed and self.path.exists() and self.path.stat().st_size == 0:
                self.path.unlink()
            if isinstance(exc, EncryptedStoreError):
                raise
            raise EncryptedStoreError(
                f"cannot open encrypted store {self.path.name}"
            ) from exc

    def _secure_files(self) -> None:
        os.chmod(self.path.parent, 0o700)
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            if candidate.exists():
                os.chmod(candidate, 0o600)

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
            except BaseException:
                self.connection.execute("ROLLBACK")
                raise
            else:
                self.connection.execute("COMMIT")
                self._secure_files()

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> Any:
        with self._lock:
            return self.connection.execute(sql, parameters)

    def encrypted_backup(self, destination: Path, backup_key: str) -> None:
        """Export a transactionally consistent database under a distinct key."""

        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination.parent, 0o700)
        if destination.exists():
            raise EncryptedStoreError("backup destination already exists")
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        alias = "encrypted_backup"
        attach = (
            f"ATTACH DATABASE {_sql_string(str(destination))} AS {alias} "
            f"KEY \"x'{backup_key.encode('utf-8').hex()}'\""
        )
        try:
            with self._lock:
                self.connection.execute(attach)
                self.connection.execute(f"SELECT sqlcipher_export('{alias}')")
                self.connection.execute(f"DETACH DATABASE {alias}")
            os.chmod(destination, 0o600)
        except Exception as exc:
            try:
                self.connection.execute(f"DETACH DATABASE {alias}")
            except Exception:
                pass
            if destination.exists():
                destination.unlink()
            raise EncryptedStoreError("encrypted backup export failed") from exc

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def __enter__(self) -> "SqlCipherDatabase":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
