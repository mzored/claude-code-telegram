"""Separate encrypted public-store export maintenance entry point."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from src.public_assistant.config import (
    BackupConfig,
    PublicAssistantConfigurationError,
    read_credential,
    validate_credential_paths,
)
from src.public_assistant.sqlcipher import SqlCipherDatabase


def export_public_backup(config: BackupConfig, destination: Path) -> None:
    """Export only public.db beneath the validated, disjoint backup root."""

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


def run() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    export_public_backup(BackupConfig.from_environment(), arguments.destination)


if __name__ == "__main__":
    run()
