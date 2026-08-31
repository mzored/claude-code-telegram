"""Separate encrypted public-store export maintenance entry point."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from src.public_assistant.config import (
    BackupConfig,
    PublicAssistantConfigurationError,
    read_credential,
    validate_credential_paths,
)
from src.public_assistant.inbox import ERASURE_SCHEMA, erase_subject_from_public_store
from src.public_assistant.sqlcipher import SqlCipherDatabase


def export_public_backup(config: BackupConfig, destination: Path) -> None:
    """Export only public.db beneath the validated, disjoint backup root."""

    if destination.is_symlink():
        raise PublicAssistantConfigurationError(
            "backup destination cannot be a symlink"
        )
    resolved = destination.resolve()
    if not resolved.is_relative_to(config.backup_dir) or resolved == config.backup_dir:
        raise PublicAssistantConfigurationError(
            "backup destination must be a file beneath the configured backup root"
        )
    if resolved.name == "pending.db":
        raise PublicAssistantConfigurationError("pending.db cannot be exported")
    validate_credential_paths(
        (config.public_database_key_file, config.backup_database_key_file),
        config.data_dir,
        config.backup_dir,
    )
    public_key = read_credential(
        config.public_database_key_file, "public database key", minimum_bytes=32
    )
    backup_key = read_credential(
        config.backup_database_key_file, "backup database key", minimum_bytes=32
    )
    if public_key == backup_key:
        raise PublicAssistantConfigurationError(
            "public and backup database keys must be distinct"
        )
    source = config.data_dir / "public.db"
    if (
        not source.is_file()
        or source.is_symlink()
        or source.resolve().parent != config.data_dir.resolve()
        or source.stat().st_size == 0
    ):
        raise PublicAssistantConfigurationError("public backup source does not exist")
    database = SqlCipherDatabase(source, public_key, "", create=False)
    try:
        required = database.execute(
            """SELECT count(*) FROM sqlite_master WHERE type='table'
               AND name IN ('messages', 'privacy_state', 'poll_state')"""
        ).fetchone()[0]
        if int(required) != 3:
            raise PublicAssistantConfigurationError(
                "public backup source schema is invalid"
            )
        database.encrypted_backup(resolved, backup_key)
    finally:
        database.close()


def restore_public_backup(config: BackupConfig, source: Path) -> Path:
    """Restore into an empty live location and replay tombstones before return."""

    if source.is_symlink():
        raise PublicAssistantConfigurationError("restore source cannot be a symlink")
    resolved = source.resolve()
    if (
        not resolved.is_relative_to(config.backup_dir)
        or resolved.parent != config.backup_dir.resolve()
        or not resolved.is_file()
        or resolved.stat().st_mtime <= time.time() - config.backup_retention_seconds
    ):
        raise PublicAssistantConfigurationError(
            "restore source must be a regular file in the backup root"
        )
    destination = config.data_dir.resolve() / "public.db"
    live_paths = (
        destination,
        Path(f"{destination}-wal"),
        Path(f"{destination}-shm"),
    )
    if any(path.exists() or path.is_symlink() for path in live_paths):
        raise PublicAssistantConfigurationError(
            "restore requires an empty public database destination and journal"
        )
    erasure_ledger_path = config.data_dir.resolve() / "erasure.db"
    if not erasure_ledger_path.is_file() or erasure_ledger_path.is_symlink():
        raise PublicAssistantConfigurationError(
            "restore requires the current encrypted erasure ledger"
        )
    public_key = read_credential(
        config.public_database_key_file, "public database key", minimum_bytes=32
    )
    backup_key = read_credential(
        config.backup_database_key_file, "backup database key", minimum_bytes=32
    )
    if public_key == backup_key:
        raise PublicAssistantConfigurationError(
            "public and backup database keys must be distinct"
        )
    now = int(time.time())
    erasure_ledger: SqlCipherDatabase | None = None
    source_database: SqlCipherDatabase | None = None
    try:
        erasure_ledger = SqlCipherDatabase(
            erasure_ledger_path, public_key, ERASURE_SCHEMA, create=False
        )
        source_database = SqlCipherDatabase(resolved, backup_key, "", create=False)
        required = source_database.execute(
            """SELECT count(*) FROM sqlite_master WHERE type='table'
               AND name IN ('messages', 'privacy_state', 'poll_state',
                            'assistant_context', 'inbox_requests',
                            'notification_outbox', 'model_reservations',
                            'privacy_references', 'privacy_previews',
                            'privacy_attempts')"""
        ).fetchone()[0]
        if int(required) != 10:
            raise PublicAssistantConfigurationError(
                "Unit 2 backup source schema is invalid"
            )
        source_database.encrypted_backup(destination, public_key)
        tombstones = erasure_ledger.execute(
            "SELECT subject_ref FROM erasure_tombstones WHERE expires_at>?",
            (now,),
        ).fetchall()
        restored_database = SqlCipherDatabase(destination, public_key, "", create=False)
        try:
            for tombstone in tombstones:
                erase_subject_from_public_store(
                    restored_database, str(tombstone[0]), now
                )
        finally:
            restored_database.close()
    except BaseException:
        for partial in live_paths:
            partial.unlink(missing_ok=True)
        raise
    finally:
        if source_database is not None:
            source_database.close()
        if erasure_ledger is not None:
            erasure_ledger.close()
    return destination


def prune_expired_backups(
    backup_dir: Path,
    retention_seconds: int,
    *,
    now: float | None = None,
) -> int:
    """Remove expired encrypted snapshots from the configured flat backup set."""

    if retention_seconds <= 0:
        raise PublicAssistantConfigurationError("backup retention must be positive")
    root = backup_dir.resolve()
    cutoff = (time.time() if now is None else now) - retention_seconds
    removed = 0
    if not root.is_dir():
        return 0
    for candidate in root.iterdir():
        if (
            candidate.parent == root
            and candidate.suffix == ".db"
            and candidate.is_file()
            and not candidate.is_symlink()
            and candidate.stat().st_mtime <= cutoff
        ):
            candidate.unlink()
            removed += 1
    return removed


def run() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--restore", type=Path)
    parser.add_argument("--prune", action="store_true")
    arguments = parser.parse_args()
    config = BackupConfig.from_environment()
    prune_expired_backups(config.backup_dir, config.backup_retention_seconds)
    if arguments.restore is not None:
        if arguments.destination is not None or arguments.prune:
            parser.error("--restore cannot be combined with a destination or --prune")
        restore_public_backup(config, arguments.restore)
    elif arguments.prune:
        if arguments.destination is not None:
            parser.error("--prune cannot be combined with a destination")
    elif arguments.destination is not None:
        export_public_backup(config, arguments.destination)
    else:
        parser.error("provide a backup destination, --restore, or --prune")


if __name__ == "__main__":
    run()
