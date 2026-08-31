"""Durable integration evidence for public-assistant delivery unit 1."""

from __future__ import annotations

import ast
import asyncio
import io
import json
import logging
import os
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlcipher3 import dbapi2 as sqlcipher
from telegram import Bot, Update
from telegram.error import Conflict, NetworkError

from src.public_assistant.backup import export_public_backup
from src.public_assistant.config import (
    BackupConfig,
    PublicAssistantConfig,
    PublicAssistantConfigurationError,
)
from src.public_assistant.main import (
    CredentialRedactingFormatter,
    DependencyPrivacyFilter,
)
from src.public_assistant.service import (
    DefiniteDeliveryError,
    RetryableDeliveryError,
    SecretaryService,
)
from src.public_assistant.sqlcipher import EncryptedStoreError, SqlCipherDatabase
from src.public_assistant.storage import PUBLIC_SCHEMA, TransferInterrupted, Unit1Store
from src.public_assistant.telegram_adapter import (
    EXPLICIT_ALLOWED_UPDATES,
    DurablePollingRunner,
    TelegramBusinessAdapter,
    TransientConnectionError,
    build_application,
)
from src.public_assistant.types import (
    ConnectionObservation,
    DeleteNotice,
    DeliveryState,
    InboundMessage,
    OwnerMessage,
)

OWNER_ID = 101001
SENDER_ID = 202002
CONNECTION_ID = "business-connection-opaque"
BODY = "confidential sender body unique 9cc302"
PENDING_KEY = "pending-key-" + "p" * 32
PUBLIC_KEY = "public-key-" + "u" * 32
BACKUP_KEY = "backup-key-" + "b" * 32
PSEUDONYM_KEY = b"log-key-" + b"l" * 32
BOT_TOKEN = "123456:test-token-never-used"


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value

    def timestamp(self) -> float:
        return self.value.timestamp()

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


def credential(path: Path, value: str) -> Path:
    path.write_text(value)
    path.chmod(0o600)
    return path


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def config(tmp_path: Path) -> PublicAssistantConfig:
    secret_dir = tmp_path / "credentials"
    secret_dir.mkdir()
    return PublicAssistantConfig(
        bot_token_file=credential(secret_dir / "bot", BOT_TOKEN),
        pending_database_key_file=credential(secret_dir / "pending", PENDING_KEY),
        public_database_key_file=credential(secret_dir / "public", PUBLIC_KEY),
        pseudonym_key_file=credential(secret_dir / "pseudonym", PSEUDONYM_KEY.decode()),
        owner_id=OWNER_ID,
        selected_sender_ids=frozenset({SENDER_ID}),
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backups",
        privacy_url="https://example.test/privacy",
        privacy_policy_version="privacy-wording-1",
        processing_authorization_version="processing-scope-1",
    )


@pytest.fixture
def store(config: PublicAssistantConfig, clock: Clock) -> Any:
    value = Unit1Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    yield value
    value.close()


@pytest.fixture
def service(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> SecretaryService:
    value = SecretaryService(config, store, now=clock.now)
    value.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    return value


def inbound(
    clock: Clock,
    *,
    update_id: int = 1,
    message_id: int = 11,
    text: str = BODY,
    sender_id: int = SENDER_ID,
    edited: bool = False,
) -> InboundMessage:
    return InboundMessage(
        CONNECTION_ID,
        sender_id,
        sender_id,
        message_id,
        update_id,
        text,
        clock.now(),
        edited_at=clock.now() if edited else None,
    )


def callback(reply: Any, label: str) -> str:
    for row in json.loads(reply.keyboard_json):
        for item in row:
            if item["text"] == label:
                return str(item["callback_data"])
    raise AssertionError(label)


def sent_reply(store: Unit1Store, reply: Any, message_id: int = 9001) -> int:
    store.finalize_reply(reply.reply_id, DeliveryState.SENT, message_id)
    return message_id


def control(
    service: SecretaryService,
    store: Unit1Store,
    reply: Any,
    label: str,
    *,
    message_id: int = 9001,
    crash_hook: Any = None,
) -> str:
    sent_reply(store, reply, message_id)
    return service.handle_control(
        callback(reply, label),
        actor_id=SENDER_ID,
        conversation_id=SENDER_ID,
        connection_id=CONNECTION_ID,
        origin_message_id=message_id,
        crash_hook=crash_hook,
    )


def authorize(
    service: SecretaryService, store: Unit1Store, clock: Clock, update_id: int = 1
) -> InboundMessage:
    message = inbound(clock, update_id=update_id, message_id=update_id + 10)
    result = service.handle_message(message)
    assert result.reply is not None
    assert (
        control(service, store, result.reply, "Continue", message_id=9000 + update_id)
        == "accepted"
    )
    return message


def open_encrypted(path: Path, key: str) -> Any:
    connection = sqlcipher.connect(str(path))
    connection.execute(f"PRAGMA key = \"x'{key.encode().hex()}'\"")
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return connection


def connection_object(
    clock: Clock, *, enabled: bool = True, can_reply: bool = True
) -> Any:
    return SimpleNamespace(
        id=CONNECTION_ID,
        user=SimpleNamespace(id=OWNER_ID),
        date=clock.now() - timedelta(days=30),
        is_enabled=enabled,
        rights=SimpleNamespace(can_reply=can_reply),
    )


class BoundaryBot:
    def __init__(
        self, clock: Clock, *, enabled: bool = True, can_reply: bool = True
    ) -> None:
        self.clock = clock
        self.enabled = enabled
        self.can_reply = can_reply
        self.refreshes = 0
        self.sent: list[dict[str, Any]] = []

    async def get_business_connection(self, connection_id: str) -> Any:
        assert connection_id == CONNECTION_ID
        self.refreshes += 1
        return connection_object(
            self.clock, enabled=self.enabled, can_reply=self.can_reply
        )

    async def send_message(self, **kwargs: Any) -> Any:
        self.sent.append(kwargs)
        return SimpleNamespace(message_id=8000 + len(self.sent))


def telegram_message(
    clock: Clock,
    *,
    update_id: int = 100,
    message_id: int = 101,
    text: str | None = BODY,
    sender_id: int = SENDER_ID,
    sender_business_bot: bool = False,
    offline: bool = False,
) -> Update:
    message: dict[str, Any] = {
        "message_id": message_id,
        "date": int(clock.timestamp()),
        "chat": {"id": SENDER_ID, "type": "private", "first_name": "Pilot"},
        "from": {"id": sender_id, "is_bot": False, "first_name": "Actor"},
        "business_connection_id": CONNECTION_ID,
        "is_from_offline": offline,
    }
    if text is not None:
        message["text"] = text
    if sender_business_bot:
        message["sender_business_bot"] = {
            "id": 303003,
            "is_bot": True,
            "first_name": "Assistant",
        }
    return Update.de_json(
        {"update_id": update_id, "business_message": message}, Bot(BOT_TOKEN)
    )


def test_config_reads_only_0600_credential_files_and_redacts_repr(
    config: PublicAssistantConfig,
) -> None:
    loaded = config.load_runtime_credentials()
    assert loaded.bot_token == BOT_TOKEN
    assert BOT_TOKEN not in repr(loaded)
    assert BACKUP_KEY not in repr(config)
    config.bot_token_file.chmod(0o644)
    with pytest.raises(PublicAssistantConfigurationError, match="0600"):
        config.load_runtime_credentials()


def test_config_rejects_legacy_environment_secret_values(
    config: PublicAssistantConfig, tmp_path: Path
) -> None:
    env = {
        "PUBLIC_ASSISTANT_SELECTED_SENDERS": str(SENDER_ID),
        "PUBLIC_ASSISTANT_OWNER_ID": str(OWNER_ID),
        "PUBLIC_ASSISTANT_DATA_DIR": str(tmp_path / "data"),
        "PUBLIC_ASSISTANT_BACKUP_DIR": str(tmp_path / "backups"),
        "PUBLIC_ASSISTANT_BOT_TOKEN_FILE": str(config.bot_token_file),
        "PUBLIC_ASSISTANT_PENDING_DATABASE_KEY_FILE": str(
            config.pending_database_key_file
        ),
        "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY_FILE": str(
            config.public_database_key_file
        ),
        "PUBLIC_ASSISTANT_PSEUDONYM_KEY_FILE": str(config.pseudonym_key_file),
        "PUBLIC_ASSISTANT_PRIVACY_URL": config.privacy_url,
        "PUBLIC_ASSISTANT_PRIVACY_POLICY_VERSION": "1",
        "PUBLIC_ASSISTANT_PROCESSING_AUTHORIZATION_VERSION": "1",
        "PUBLIC_ASSISTANT_BOT_TOKEN": "forbidden-inline-secret",
    }
    with pytest.raises(PublicAssistantConfigurationError, match="forbidden"):
        PublicAssistantConfig.from_environment(env)


@pytest.mark.parametrize(
    ("data", "backup"),
    [("root", "root"), ("root", "root/backups"), ("root/data", "root")],
)
def test_config_rejects_equal_or_nested_roots(
    tmp_path: Path, config: PublicAssistantConfig, data: str, backup: str
) -> None:
    env = {
        "PUBLIC_ASSISTANT_SELECTED_SENDERS": str(SENDER_ID),
        "PUBLIC_ASSISTANT_OWNER_ID": str(OWNER_ID),
        "PUBLIC_ASSISTANT_DATA_DIR": str(tmp_path / data),
        "PUBLIC_ASSISTANT_BACKUP_DIR": str(tmp_path / backup),
        "PUBLIC_ASSISTANT_BOT_TOKEN_FILE": str(config.bot_token_file),
        "PUBLIC_ASSISTANT_PENDING_DATABASE_KEY_FILE": str(
            config.pending_database_key_file
        ),
        "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY_FILE": str(
            config.public_database_key_file
        ),
        "PUBLIC_ASSISTANT_PSEUDONYM_KEY_FILE": str(config.pseudonym_key_file),
        "PUBLIC_ASSISTANT_PRIVACY_URL": config.privacy_url,
        "PUBLIC_ASSISTANT_PRIVACY_POLICY_VERSION": "1",
        "PUBLIC_ASSISTANT_PROCESSING_AUTHORIZATION_VERSION": "1",
    }
    with pytest.raises(PublicAssistantConfigurationError, match="non-overlapping"):
        PublicAssistantConfig.from_environment(env)


def test_separate_backup_exports_only_public_store_inside_backup_root(
    config: PublicAssistantConfig,
    store: Unit1Store,
    service: SecretaryService,
    clock: Clock,
    tmp_path: Path,
) -> None:
    assert service.handle_message(inbound(clock)).outcome == "awaiting_consent"
    backup_key_file = credential(tmp_path / "backup-key", BACKUP_KEY)
    maintenance = BackupConfig(
        config.data_dir,
        config.backup_dir,
        config.public_database_key_file,
        backup_key_file,
    )
    destination = config.backup_dir / "public-20260831.db"
    export_public_backup(maintenance, destination)
    restored = open_encrypted(destination, BACKUP_KEY)
    assert (
        restored.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='pending_messages'"
        ).fetchone()[0]
        == 0
    )
    restored.close()
    with pytest.raises(sqlcipher.DatabaseError):
        wrong = open_encrypted(destination, PUBLIC_KEY)
        wrong.close()
    assert BODY.encode() not in destination.read_bytes()
    assert BODY.encode() not in (config.data_dir / "pending.db-wal").read_bytes()
    assert os.stat(destination).st_mode & 0o777 == 0o600
    with pytest.raises(PublicAssistantConfigurationError):
        export_public_backup(maintenance, tmp_path / "outside.db")
    assert not hasattr(store, "backup_key") and not hasattr(store, "backup_public")


def test_logs_expose_only_pseudonymous_references(caplog: Any) -> None:
    from src.public_assistant.privacy_log import PrivacyLog

    logger = logging.getLogger("unit1-redaction")
    privacy_log = PrivacyLog(PSEUDONYM_KEY, logger)
    with caplog.at_level(logging.INFO, logger="unit1-redaction"):
        privacy_log.event(
            "message_transition",
            connection_id=CONNECTION_ID,
            chat_id=SENDER_ID,
            sender_id=SENDER_ID,
            update_id=778899,
            state="pending",
        )
    rendered = " ".join(
        str(getattr(record, "public_fields", "")) for record in caplog.records
    )
    assert CONNECTION_ID not in rendered
    assert str(SENDER_ID) not in rendered
    assert "778899" not in rendered
    assert BODY not in rendered


def test_sqlcipher_rejects_wrong_key_and_plaintext(
    config: PublicAssistantConfig, store: Unit1Store, tmp_path: Path
) -> None:
    store.close()
    with pytest.raises(EncryptedStoreError):
        SqlCipherDatabase(config.data_dir / "public.db", "wrong" * 10, PUBLIC_SCHEMA)
    plain = tmp_path / "plain.db"
    connection = sqlite3.connect(plain)
    connection.execute("CREATE TABLE plaintext(value TEXT)")
    connection.commit()
    connection.close()
    with pytest.raises(EncryptedStoreError):
        SqlCipherDatabase(plain, PUBLIC_KEY, PUBLIC_SCHEMA)


@pytest.mark.asyncio
async def test_authoritative_refresh_uses_observation_time_on_admission_and_send(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    bot = BoundaryBot(clock)
    await adapter.on_business_message(telegram_message(clock), SimpleNamespace(bot=bot))
    await adapter.deliver_due_replies(bot)
    assert bot.refreshes == 2
    observed = store.public.execute(
        "SELECT observed_at FROM business_connections"
    ).fetchone()[0]
    assert observed == int(clock.timestamp())
    assert len(bot.sent) == 1


@pytest.mark.asyncio
async def test_connection_lookup_failure_fails_closed_without_storing_body(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)

    class FailingBot:
        async def get_business_connection(self, connection_id: str) -> Any:
            raise OSError(connection_id)

    with pytest.raises(TransientConnectionError):
        await adapter.on_business_message(
            telegram_message(clock), SimpleNamespace(bot=FailingBot())
        )
    assert store.counts()["pending"] == 0


@pytest.mark.asyncio
async def test_takeover_observes_non_text_without_rights_and_ignores_bot_and_offline(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    bot = BoundaryBot(clock, can_reply=False)
    await adapter.on_business_message(
        telegram_message(clock, sender_id=OWNER_ID, text=None),
        SimpleNamespace(bot=bot),
    )
    assert store.is_taken_over(CONNECTION_ID, SENDER_ID)

    other_dir = config.data_dir.parent / "other"
    other = Unit1Store(
        other_dir, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.timestamp
    )
    try:
        other_service = SecretaryService(config, other, now=clock.now)
        other_adapter = TelegramBusinessAdapter(
            config, other_service, other, now=clock.now
        )
        await other_adapter.on_business_message(
            telegram_message(clock, sender_id=OWNER_ID, sender_business_bot=True),
            SimpleNamespace(bot=bot),
        )
        await other_adapter.on_business_message(
            telegram_message(clock, update_id=102, sender_id=OWNER_ID, offline=True),
            SimpleNamespace(bot=bot),
        )
        assert not other.is_taken_over(CONNECTION_ID, SENDER_ID)
    finally:
        other.close()


def test_callbacks_require_actor_chat_connection_and_originating_bot_message(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    token = callback(result.reply, "Continue")
    sent_reply(store, result.reply, 777)
    base = dict(
        token=token,
        actor_id=SENDER_ID,
        conversation_id=SENDER_ID,
        connection_id=CONNECTION_ID,
        origin_message_id=777,
    )
    for wrong in (
        {"actor_id": SENDER_ID + 1},
        {"conversation_id": SENDER_ID + 1},
        {"connection_id": CONNECTION_ID + "-wrong"},
        {"origin_message_id": 778},
    ):
        assert service.handle_control(**(base | wrong)) == "neutral"
    assert service.handle_control(**base) == "accepted"


@pytest.mark.asyncio
async def test_callback_consent_lookup_failure_answers_neutrally_without_accepting(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    sent_reply(store, result.reply, 779)
    answers: list[str] = []

    class FailingBot:
        id = 303003

        async def get_business_connection(self, connection_id: str) -> Any:
            raise OSError(connection_id)

    async def answer(*, text: str) -> None:
        answers.append(text)

    query = SimpleNamespace(
        data=callback(result.reply, "Continue"),
        from_user=SimpleNamespace(id=SENDER_ID),
        message=SimpleNamespace(
            business_connection_id=CONNECTION_ID,
            sender_business_bot=SimpleNamespace(id=303003),
            chat=SimpleNamespace(id=SENDER_ID),
            message_id=779,
        ),
        answer=answer,
    )
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    with pytest.raises(TransientConnectionError):
        await adapter.on_callback_query(
            SimpleNamespace(callback_query=query), SimpleNamespace(bot=FailingBot())
        )
    assert answers == []
    assert store.counts()["pending"] == 1


def test_restrictive_control_survives_takeover_rights_loss_and_pilot_removal(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    privacy = service.handle_message(
        inbound(clock, update_id=2, message_id=12, text="privacy")
    )
    assert privacy.reply is not None
    sent_reply(store, privacy.reply, 778)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, False, False, clock.now())
    )
    store.record_takeover(CONNECTION_ID, SENDER_ID, SENDER_ID, 90, 900)
    removed = SecretaryService(
        replace(config, selected_sender_ids=frozenset({SENDER_ID + 1})),
        store,
        now=clock.now,
    )
    assert (
        removed.handle_control(
            callback(privacy.reply, "Delete data"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            connection_id=CONNECTION_ID,
            origin_message_id=778,
        )
        == "erased"
    )


@pytest.mark.parametrize(
    "stage", ["before_copy", "after_copy", "after_receipt", "before_pending_delete"]
)
def test_consent_transfer_recovers_each_crash_boundary(
    config: PublicAssistantConfig, clock: Clock, tmp_path: Path, stage: str
) -> None:
    data = tmp_path / stage
    first = Unit1Store(
        data, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.timestamp
    )
    service = SecretaryService(config, first, now=clock.now)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    sent_reply(first, result.reply, 700)

    def crash(current: str) -> None:
        if current == stage:
            raise TransferInterrupted(stage)

    with pytest.raises(TransferInterrupted):
        service.handle_control(
            callback(result.reply, "Continue"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            connection_id=CONNECTION_ID,
            origin_message_id=700,
            crash_hook=crash,
        )
    first.close()
    recovered = Unit1Store(
        data, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.timestamp
    )
    assert recovered.counts() == {"pending": 0, "messages": 1, "receipts": 1}
    assert recovered.public.execute("SELECT body FROM messages").fetchone()[0] == BODY
    recovered.close()


def test_decline_tombstone_recovers_and_never_strands_authorized_pending(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    sent_reply(store, result.reply, 701)

    def crash(stage: str) -> None:
        if stage == "after_tombstone":
            raise TransferInterrupted(stage)

    with pytest.raises(TransferInterrupted):
        service.handle_control(
            callback(result.reply, "Decline"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            connection_id=CONNECTION_ID,
            origin_message_id=701,
            crash_hook=crash,
        )
    store.close()
    recovered = Unit1Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    assert recovered.counts()["pending"] == 0
    assert recovered.counts()["messages"] == 0
    recovered.close()


def test_erasure_tombstone_prevents_orphan_authorized_body_resurrection(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    changed = SecretaryService(
        replace(config, processing_authorization_version="scope-2"),
        store,
        now=clock.now,
    )
    pending = changed.handle_message(
        inbound(clock, update_id=2, message_id=12, text="orphan")
    )
    assert pending.reply is not None
    store.pending.execute("UPDATE pending_messages SET state='authorized'")
    privacy = service.handle_message(
        inbound(clock, update_id=3, message_id=13, text="privacy")
    )
    assert privacy.reply is not None

    def crash(stage: str) -> None:
        if stage == "after_tombstone":
            raise TransferInterrupted(stage)

    with pytest.raises(TransferInterrupted):
        control(
            service,
            store,
            privacy.reply,
            "Delete data",
            message_id=703,
            crash_hook=crash,
        )
    store.close()
    recovered = Unit1Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    assert recovered.counts()["pending"] == 0
    assert recovered.counts()["messages"] == 0
    assert (
        recovered.public.execute("SELECT count(*) FROM privacy_state").fetchone()[0]
        == 1
    )
    recovered.close()


def test_ninety_day_expiry_removes_body_and_associated_personal_rows(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    authorize(service, store, clock)
    assert store.counts()["messages"] == 1
    clock.advance(days=89, hours=23)
    assert store.expire_public(90 * 24 * 60 * 60) == 0
    clock.advance(hours=1)
    assert store.expire_public(90 * 24 * 60 * 60) == 1
    for table in ("messages", "consents", "controls", "chat_state", "rate_admissions"):
        assert store.public.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_wording_change_keeps_consent_but_processing_change_requires_it(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    wording = SecretaryService(
        replace(config, privacy_policy_version="wording-2"), store, now=clock.now
    )
    assert (
        wording.handle_message(inbound(clock, update_id=2, message_id=12)).outcome
        == "stored_after_consent"
    )
    scope = SecretaryService(
        replace(config, processing_authorization_version="scope-2"),
        store,
        now=clock.now,
    )
    assert (
        scope.handle_message(inbound(clock, update_id=3, message_id=13)).outcome
        == "awaiting_consent"
    )


def test_revoked_text_is_not_stored_and_offers_deterministic_reconsent(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    authorize(service, store, clock)
    privacy = service.handle_message(
        inbound(clock, update_id=2, message_id=12, text="privacy")
    )
    assert privacy.reply is not None
    assert control(service, store, privacy.reply, "Revoke", message_id=704) == "revoked"
    secret = "ordinary revoked secret 7a3c"
    stopped = service.handle_message(
        inbound(clock, update_id=3, message_id=13, text=secret)
    )
    assert stopped.outcome == "privacy_stopped" and stopped.reply is not None
    assert secret.encode() not in (store.data_dir / "public.db-wal").read_bytes()
    row = store.public.execute(
        "SELECT content_digest FROM processed_updates WHERE update_id=3"
    ).fetchone()
    assert row[0] is None
    sent_reply(store, stopped.reply, 705)
    assert (
        service.handle_control(
            callback(stopped.reply, "Enable processing"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            connection_id=CONNECTION_ID,
            origin_message_id=705,
        )
        == "accepted"
    )


def test_erasure_leaves_only_minimal_pseudonymous_state(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    authorize(service, store, clock)
    privacy = service.handle_message(
        inbound(clock, update_id=2, message_id=12, text="privacy")
    )
    assert privacy.reply is not None
    assert (
        control(service, store, privacy.reply, "Delete data", message_id=706)
        == "erased"
    )
    for table in (
        "messages",
        "consents",
        "controls",
        "chat_state",
        "replies",
        "processed_updates",
        "rate_admissions",
        "transfer_receipts",
    ):
        assert store.public.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    columns = store.public.execute("SELECT * FROM privacy_state").fetchone()
    assert tuple(columns) == (
        store.subject_ref(CONNECTION_ID, SENDER_ID, SENDER_ID),
        "erased",
        int(clock.timestamp()),
    )


def test_edits_and_deletes_sync_after_rights_loss_takeover_and_pilot_removal(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, False, False, clock.now())
    )
    store.record_takeover(CONNECTION_ID, SENDER_ID, SENDER_ID, 80, 800)
    removed = SecretaryService(
        replace(config, selected_sender_ids=frozenset({999})), store, now=clock.now
    )
    edited = inbound(clock, update_id=2, message_id=11, text="final edit", edited=True)
    assert removed.handle_edit(edited).outcome == "consented_body_replaced"
    assert (
        store.public.execute("SELECT body FROM messages").fetchone()[0] == "final edit"
    )
    assert (
        removed.handle_delete(DeleteNotice(CONNECTION_ID, SENDER_ID, (11,), 3)).outcome
        == "deleted"
    )
    assert store.public.execute("SELECT body FROM messages").fetchone()[0] is None


@pytest.mark.asyncio
async def test_delivery_uses_inbound_sent_at_for_final_window_check(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    message = inbound(clock)
    result = service.handle_message(message)
    assert result.reply is not None
    clock.advance(hours=24)
    attempts = 0

    async def sender(reply: Any) -> int:
        nonlocal attempts
        attempts += 1
        return 1

    assert await service.deliver_reply(result.reply, sender) == DeliveryState.CANCELLED
    assert attempts == 0


@pytest.mark.asyncio
async def test_retry_after_reuses_identical_durable_reply_and_transport_is_uncertain(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    payloads: list[tuple[str, str]] = []

    async def retry(reply: Any) -> int:
        payloads.append((reply.text, reply.keyboard_json))
        raise RetryableDeliveryError(10)

    assert (
        await service.deliver_reply(result.reply, retry) == DeliveryState.RETRY_PENDING
    )
    assert store.due_replies() == []
    clock.advance(seconds=10)

    async def succeed(reply: Any) -> int:
        payloads.append((reply.text, reply.keyboard_json))
        return 99

    due = store.due_replies()[0]
    assert await service.deliver_reply(due, succeed) == DeliveryState.SENT
    assert payloads[0] == payloads[1]

    second = service.handle_message(inbound(clock, update_id=2, message_id=12))
    assert second.reply is not None

    async def ambiguous(reply: Any) -> int:
        raise TimeoutError(reply.reply_id)

    assert (
        await service.deliver_reply(second.reply, ambiguous)
        == DeliveryState.DELIVERY_UNCERTAIN
    )
    assert (
        await service.deliver_reply(second.reply, ambiguous)
        == DeliveryState.DELIVERY_UNCERTAIN
    )


@pytest.mark.asyncio
async def test_definite_delivery_failure_is_terminal(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None

    async def rejected(reply: Any) -> int:
        raise DefiniteDeliveryError(reply.reply_id)

    assert (
        await service.deliver_reply(result.reply, rejected)
        == DeliveryState.DEFINITE_FAILURE
    )
    assert store.due_replies() == []


class PollBot(BoundaryBot):
    def __init__(self, clock: Clock, updates: list[Update]) -> None:
        super().__init__(clock)
        self.updates = updates
        self.polls: list[dict[str, Any]] = []

    async def get_updates(self, **kwargs: Any) -> tuple[Update, ...]:
        self.polls.append(kwargs)
        offset = kwargs["offset"]
        candidates = [
            update
            for update in self.updates
            if offset is None or update.update_id >= offset
        ]
        return tuple(candidates[:1])


class FakeApplication:
    def __init__(self, bot: PollBot) -> None:
        self.bot = bot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage", ["after_fetch", "after_handler", "after_offset", "before_next_poll"]
)
async def test_polling_crash_boundaries_preserve_offset_and_replay_safely(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
    stage: str,
) -> None:
    update = telegram_message(clock, update_id=50, message_id=51)
    bot = PollBot(clock, [update])
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)

    def crash(current: str) -> None:
        if current == stage:
            raise TransferInterrupted(stage)

    runner = DurablePollingRunner(FakeApplication(bot), adapter, store, crash_hook=crash)  # type: ignore[arg-type]
    with pytest.raises(TransferInterrupted):
        await runner.run_once()
    if stage in {"after_offset", "before_next_poll"}:
        assert store.get_next_update_id() == 51
    else:
        assert store.get_next_update_id() is None
        replay = DurablePollingRunner(FakeApplication(bot), adapter, store)  # type: ignore[arg-type]
        assert await replay.run_once()
        assert store.get_next_update_id() == 51
    assert len(bot.sent) <= 1
    assert bot.polls[0]["limit"] == 1
    assert bot.polls[0]["allowed_updates"] == list(EXPLICIT_ALLOWED_UPDATES)


@pytest.mark.asyncio
async def test_handler_failure_never_advances_offset(
    store: Unit1Store, clock: Clock
) -> None:
    update = telegram_message(clock, update_id=60)
    bot = PollBot(clock, [update])

    class BrokenAdapter:
        config = SimpleNamespace(retention_seconds=90 * 24 * 60 * 60)

        async def deliver_due_replies(self, bot: Any) -> None:
            return None

        async def dispatch(self, update: Update, bot: Any) -> None:
            raise RuntimeError("handler/context failure")

    runner = DurablePollingRunner(FakeApplication(bot), BrokenAdapter(), store)  # type: ignore[arg-type, unused-ignore]
    with pytest.raises(RuntimeError, match="handler/context"):
        await runner.run_once()
    assert store.get_next_update_id() is None


def test_durable_pending_can_advance_offset_but_sending_cannot(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    result = service.handle_message(inbound(clock, update_id=70))
    assert result.reply is not None
    store.commit_update_offset(70)
    assert store.get_next_update_id() == 71
    sending = service.handle_message(inbound(clock, update_id=72, message_id=82))
    assert sending.reply is not None
    assert store.mark_reply_sending(sending.reply.reply_id)
    with pytest.raises(RuntimeError, match="unfinished reply"):
        store.commit_update_offset(72)
    store.finalize_reply(sending.reply.reply_id, DeliveryState.DELIVERY_UNCERTAIN)
    store.commit_update_offset(72)
    assert store.get_next_update_id() == 73


def test_replay_resumes_incomplete_ingress_ledger(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    message = inbound(clock, update_id=71)
    assert store.begin_update(message, "business_message", "received") == (True, None)
    resumed = service.handle_message(message)
    assert resumed.outcome == "awaiting_consent"
    assert resumed.reply is not None


@pytest.mark.asyncio
async def test_gap_update_ids_commit_exact_fetched_successor(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    update = telegram_message(clock, update_id=900, message_id=901)
    bot = PollBot(clock, [update])
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    runner = DurablePollingRunner(FakeApplication(bot), adapter, store)  # type: ignore[arg-type]
    assert await runner.run_once()
    assert store.get_next_update_id() == 901


def test_restart_marks_sending_uncertain_but_leaves_pending_for_dispatch(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    first = service.handle_message(inbound(clock))
    second = service.handle_message(inbound(clock, update_id=2, message_id=12))
    assert first.reply is not None and second.reply is not None
    assert store.mark_reply_sending(first.reply.reply_id)
    store.close()
    reopened = Unit1Store(
        config.data_dir, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.timestamp
    )
    assert (
        reopened.get_reply(first.reply.reply_id).state
        == DeliveryState.DELIVERY_UNCERTAIN
    )
    assert reopened.get_reply(second.reply.reply_id).state == DeliveryState.PENDING
    assert [reply.reply_id for reply in reopened.due_replies()] == [
        second.reply.reply_id
    ]
    reopened.close()


@pytest.mark.asyncio
async def test_custom_polling_lifecycle_dispatches_seeded_pending_before_fetch(
    service: SecretaryService,
    store: Unit1Store,
    config: PublicAssistantConfig,
    clock: Clock,
) -> None:
    result = service.handle_message(inbound(clock, update_id=72))
    assert result.reply is not None
    stopped = asyncio.Event()

    class LifecycleBot(PollBot):
        async def delete_webhook(self, **kwargs: Any) -> bool:
            self.polls.append(kwargs)
            return True

        async def get_updates(self, **kwargs: Any) -> tuple[Update, ...]:
            self.polls.append(kwargs)
            stopped.set()
            return ()

    class LifecycleApplication(FakeApplication):
        def __init__(self, bot: PollBot) -> None:
            super().__init__(bot)
            self.events: list[str] = []

        async def initialize(self) -> None:
            self.events.append("initialize")

        async def start(self) -> None:
            self.events.append("start")

        async def stop(self) -> None:
            self.events.append("stop")

        async def shutdown(self) -> None:
            self.events.append("shutdown")

    bot = LifecycleBot(clock, [])
    application = LifecycleApplication(bot)
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    runner = DurablePollingRunner(application, adapter, store)  # type: ignore[arg-type]
    await runner.run(stopped)
    assert application.events == ["initialize", "start", "stop", "shutdown"]
    assert bot.polls[0] == {"drop_pending_updates": False}
    assert len(bot.sent) == 1


def test_rate_limit_replay_is_idempotent(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    limited = SecretaryService(
        replace(config, rate_limit_count=1), store, now=clock.now
    )
    limited.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    first = inbound(clock)
    assert limited.handle_message(first).outcome == "awaiting_consent"
    assert limited.handle_message(first).outcome == "duplicate"
    assert (
        limited.handle_message(inbound(clock, update_id=2, message_id=12)).outcome
        == "rate_limited"
    )


def test_ptb_handler_surface_is_explicit_blocking_and_callback_limited(
    config: PublicAssistantConfig, service: SecretaryService, store: Unit1Store
) -> None:
    application, _ = build_application(config, service, store, BOT_TOKEN)
    handlers = [
        handler for values in application.handlers.values() for handler in values
    ]
    assert [type(handler).__name__ for handler in handlers] == [
        "BusinessConnectionHandler",
        "MessageHandler",
        "MessageHandler",
        "BusinessMessagesDeletedHandler",
        "CallbackQueryHandler",
    ]
    assert all(handler.block is True for handler in handlers)
    callback_handler = handlers[-1]
    assert callback_handler.pattern.pattern == "^pa:"
    assert "message" not in EXPLICIT_ALLOWED_UPDATES
    assert "pause" not in PUBLIC_SCHEMA.casefold()


def test_unit1_has_no_model_integration_or_private_agent_imports() -> None:
    forbidden = {
        "anthropic",
        "openai",
        "src.claude",
        "src.events",
        "src.api",
        "src.mcp",
        "src.notifications",
        "src.scheduler",
        "src.storage",
        "fastapi",
        "uvicorn",
    }
    imported: set[str] = set()
    for source_path in Path("src/public_assistant").glob("*.py"):
        tree = ast.parse(source_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
    assert all(
        not any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
        for name in imported
    )


def test_dependency_critical_logs_never_render_raw_update_payloads_or_ids() -> None:
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(DependencyPrivacyFilter())
    handler.setFormatter(CredentialRedactingFormatter("%(levelname)s %(message)s"))
    logger = logging.getLogger("telegram.ext.Application")
    prior_handlers, prior_propagate = logger.handlers, logger.propagate
    logger.handlers = [handler]
    logger.propagate = False
    try:
        try:
            raise ValueError(f"parse failed {BODY} update_id=998877")
        except ValueError:
            logger.critical(
                "Failed to parse raw payload %s sender=%s",
                BODY,
                SENDER_ID,
                exc_info=True,
            )
    finally:
        logger.handlers = prior_handlers
        logger.propagate = prior_propagate
    rendered = output.getvalue()
    assert "dependency diagnostic redacted" in rendered
    assert BODY not in rendered
    assert str(SENDER_ID) not in rendered
    assert "998877" not in rendered


@pytest.mark.asyncio
async def test_queued_takeover_is_drained_before_pending_outbox_delivery(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    sender_update = telegram_message(clock, update_id=200, message_id=201)
    takeover_update = telegram_message(
        clock, update_id=202, message_id=203, sender_id=OWNER_ID, text=None
    )
    bot = PollBot(clock, [sender_update, takeover_update])
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    runner = DurablePollingRunner(FakeApplication(bot), adapter, store)  # type: ignore[arg-type]
    assert await runner.run_once()
    assert store.get_next_update_id() == 203
    assert store.is_taken_over(CONNECTION_ID, SENDER_ID)
    assert bot.sent == []
    assert store.public.execute("SELECT state FROM replies").fetchone()[0] == (
        DeliveryState.CANCELLED.value
    )


@pytest.mark.asyncio
async def test_queued_edit_replaces_and_cancels_original_pending_reply_before_send(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    original = service.handle_message(
        inbound(clock, update_id=210, message_id=211, text="before edit")
    )
    assert original.reply is not None
    edited_update = Update.de_json(
        {
            "update_id": 212,
            "edited_business_message": {
                "message_id": 211,
                "date": int(clock.timestamp()),
                "edit_date": int(clock.timestamp()),
                "chat": {"id": SENDER_ID, "type": "private", "first_name": "Pilot"},
                "from": {"id": SENDER_ID, "is_bot": False, "first_name": "Pilot"},
                "business_connection_id": CONNECTION_ID,
                "text": "after edit",
            },
        },
        Bot(BOT_TOKEN),
    )
    bot = PollBot(clock, [edited_update])
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    runner = DurablePollingRunner(FakeApplication(bot), adapter, store)  # type: ignore[arg-type]
    assert await runner.run_once()
    assert store.get_reply(original.reply.reply_id).state == DeliveryState.CANCELLED
    assert len(bot.sent) == 1
    assert (
        store.public.execute(
            "SELECT body FROM messages WHERE message_id=211"
        ).fetchone()[0]
        == "after edit"
    )


@pytest.mark.asyncio
async def test_transient_connection_refresh_retries_without_ack_or_cancelling_reply(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    result = service.handle_message(inbound(clock, update_id=220, message_id=221))
    assert result.reply is not None
    sleeps: list[float] = []

    class TransientBot(BoundaryBot):
        async def get_business_connection(self, connection_id: str) -> Any:
            self.refreshes += 1
            raise NetworkError("temporary network failure")

    bot = TransientBot(clock)
    adapter = TelegramBusinessAdapter(
        config,
        service,
        store,
        now=clock.now,
        sleep=lambda seconds: _record_sleep(sleeps, seconds),
    )
    await adapter.deliver_due_replies(bot)
    assert bot.refreshes == 3
    assert sleeps == [1.0, 2.0]
    assert store.get_reply(result.reply.reply_id).state == DeliveryState.PENDING


async def _record_sleep(values: list[float], seconds: float) -> None:
    values.append(seconds)


def test_edit_under_new_processing_scope_stages_body_without_public_overwrite(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    changed = SecretaryService(
        replace(config, processing_authorization_version="scope-2"),
        store,
        now=clock.now,
    )
    edited = changed.handle_edit(
        inbound(clock, update_id=230, message_id=11, text="new scope body", edited=True)
    )
    assert edited.outcome == "awaiting_consent"
    assert (
        store.public.execute(
            "SELECT body FROM messages WHERE message_id=11"
        ).fetchone()[0]
        == BODY
    )
    pending = store.pending.execute(
        "SELECT body, processing_authorization_version FROM pending_messages"
    ).fetchone()
    assert tuple(pending) == ("new scope body", "scope-2")


def test_edit_preserves_source_binding_and_delete_cancels_reprocessed_reply(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    authorize(service, store, clock)
    original = service.handle_message(
        inbound(clock, update_id=240, message_id=241, text="original")
    )
    assert original.reply is not None
    edited = service.handle_edit(
        inbound(clock, update_id=242, message_id=241, text="edited", edited=True)
    )
    assert edited.reply is not None
    row = store.public.execute(
        """SELECT source_update_id, last_update_id FROM messages
           WHERE message_id=241"""
    ).fetchone()
    assert tuple(row) == (240, 242)
    assert store.get_reply(original.reply.reply_id).state == DeliveryState.CANCELLED
    assert (
        service.handle_delete(
            DeleteNotice(CONNECTION_ID, SENDER_ID, (241,), 243)
        ).outcome
        == "deleted"
    )
    assert store.get_reply(edited.reply.reply_id).state == DeliveryState.CANCELLED
    ledger = store.public.execute(
        """SELECT subject_ref, message_key FROM processed_updates
           WHERE update_id=243"""
    ).fetchone()
    assert ledger[0].startswith("subject_") and ledger[1].startswith("message_")


@pytest.mark.parametrize("crash_stage", ["after_tombstone", "after_pending_delete"])
def test_disconnect_tombstone_purges_unconsented_body_after_crash(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
    crash_stage: str,
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.outcome == "awaiting_consent"
    assert result.reply is not None

    def crash(stage: str) -> None:
        if stage == crash_stage:
            raise TransferInterrupted(stage)

    with pytest.raises(TransferInterrupted):
        store.purge_unconsented_connection(CONNECTION_ID, crash_hook=crash)
    store.close()
    reopened = Unit1Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    assert reopened.counts()["pending"] == 0
    assert reopened.counts()["messages"] == 0
    assert reopened.get_reply(result.reply.reply_id).state == DeliveryState.CANCELLED
    reopened.close()


def test_pending_edit_preserves_original_source_update_binding(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    assert (
        service.handle_message(inbound(clock, update_id=245, message_id=246)).outcome
        == "awaiting_consent"
    )
    assert (
        service.handle_edit(
            inbound(clock, update_id=247, message_id=246, text="edited", edited=True)
        ).outcome
        == "pending_body_replaced"
    )
    row = store.pending.execute(
        """SELECT source_update_id, last_update_id, body FROM pending_messages
           WHERE message_id=246"""
    ).fetchone()
    assert tuple(row) == (245, 247, "edited")


@pytest.mark.asyncio
async def test_disabled_business_connection_update_immediately_purges_pending(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    assert service.handle_message(inbound(clock)).outcome == "awaiting_consent"
    update = Update.de_json(
        {
            "update_id": 244,
            "business_connection": {
                "id": CONNECTION_ID,
                "user": {"id": OWNER_ID, "is_bot": False, "first_name": "Owner"},
                "user_chat_id": OWNER_ID + 1,
                "date": int(clock.timestamp()),
                "is_enabled": False,
                "rights": {"can_reply": False},
            },
        },
        Bot(BOT_TOKEN),
    )
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    await adapter.on_business_connection(update, SimpleNamespace())
    assert store.counts()["pending"] == 0
    assert (
        store.public.execute("SELECT state FROM replies").fetchone()[0]
        == DeliveryState.CANCELLED.value
    )


def test_consent_and_reconsent_store_canonical_scope_and_policy(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    row = store.public.execute(
        """SELECT privacy_policy_version, processors, purposes FROM consents"""
    ).fetchone()
    assert row[0] == config.privacy_policy_version
    assert json.loads(row[1]) == ["OpenAI", "Google Calendar", "Todoist"]
    assert json.loads(row[2]) == [
        "assistant replies",
        "meeting actions",
        "external tasks",
    ]
    privacy = service.handle_message(
        inbound(clock, update_id=250, message_id=251, text="privacy")
    )
    assert privacy.reply is not None
    assert control(service, store, privacy.reply, "Revoke", message_id=252) == "revoked"
    stopped = service.handle_message(
        inbound(clock, update_id=253, message_id=254, text="not stored")
    )
    assert stopped.reply is not None
    sent_reply(store, stopped.reply, 255)
    assert (
        service.handle_control(
            callback(stopped.reply, "Enable processing"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            connection_id=CONNECTION_ID,
            origin_message_id=255,
        )
        == "accepted"
    )
    row = store.public.execute(
        "SELECT privacy_policy_version, processors, purposes FROM consents"
    ).fetchone()
    assert row[0] == config.privacy_policy_version
    assert json.loads(row[1]) == ["OpenAI", "Google Calendar", "Todoist"]


def test_credential_paths_and_material_are_isolated(
    config: PublicAssistantConfig, tmp_path: Path
) -> None:
    environment = {
        "PUBLIC_ASSISTANT_SELECTED_SENDERS": str(SENDER_ID),
        "PUBLIC_ASSISTANT_OWNER_ID": str(OWNER_ID),
        "PUBLIC_ASSISTANT_DATA_DIR": str(tmp_path / "live"),
        "PUBLIC_ASSISTANT_BACKUP_DIR": str(tmp_path / "backup"),
        "PUBLIC_ASSISTANT_BOT_TOKEN_FILE": str(config.bot_token_file),
        "PUBLIC_ASSISTANT_PENDING_DATABASE_KEY_FILE": str(
            config.pending_database_key_file
        ),
        "PUBLIC_ASSISTANT_PUBLIC_DATABASE_KEY_FILE": str(
            config.public_database_key_file
        ),
        "PUBLIC_ASSISTANT_PSEUDONYM_KEY_FILE": str(config.pseudonym_key_file),
        "PUBLIC_ASSISTANT_PRIVACY_URL": config.privacy_url,
        "PUBLIC_ASSISTANT_PRIVACY_POLICY_VERSION": "policy",
        "PUBLIC_ASSISTANT_PROCESSING_AUTHORIZATION_VERSION": "scope",
    }
    protected_paths = (
        tmp_path / "live" / "token",
        tmp_path / "backup" / "token",
        Path("pyproject.toml").resolve(),
    )
    for protected in protected_paths[:2]:
        protected.parent.mkdir(exist_ok=True)
        credential(protected, BOT_TOKEN)
    for protected in protected_paths:
        with pytest.raises(PublicAssistantConfigurationError, match="outside"):
            PublicAssistantConfig.from_environment(
                environment | {"PUBLIC_ASSISTANT_BOT_TOKEN_FILE": str(protected)}
            )
    config.public_database_key_file.write_text(PENDING_KEY)
    config.public_database_key_file.chmod(0o600)
    with pytest.raises(PublicAssistantConfigurationError, match="material"):
        config.load_runtime_credentials()


def test_backup_missing_source_fails_without_creating_live_database(
    config: PublicAssistantConfig, tmp_path: Path
) -> None:
    backup_key_file = credential(tmp_path / "separate-backup-key", BACKUP_KEY)
    missing_data = tmp_path / "missing-live"
    maintenance = BackupConfig(
        missing_data,
        config.backup_dir,
        config.public_database_key_file,
        backup_key_file,
    )
    with pytest.raises(PublicAssistantConfigurationError, match="does not exist"):
        export_public_backup(maintenance, config.backup_dir / "missing.db")
    assert not (missing_data / "public.db").exists()


def test_wal_is_bounded_checkpointed_and_rolls_back_crashed_transaction(
    store: Unit1Store,
) -> None:
    assert store.public.execute("PRAGMA wal_autocheckpoint").fetchone()[0] == 1000
    assert store.public.execute("PRAGMA journal_size_limit").fetchone()[0] == 67108864
    with pytest.raises(RuntimeError, match="crash"):
        with store.public.transaction() as connection:
            connection.execute(
                "INSERT INTO privacy_state VALUES ('crash-subject', 'revoked', 1)"
            )
            raise RuntimeError("crash")
    assert (
        store.public.execute(
            "SELECT 1 FROM privacy_state WHERE subject_ref='crash-subject'"
        ).fetchone()
        is None
    )
    checkpoint = store.public.checkpoint("TRUNCATE")
    assert len(checkpoint) == 3
    assert os.path.getsize(store.data_dir / "public.db-wal") == 0


def test_deletion_ledger_is_subject_bound_and_removed_by_erasure_and_ttl(
    config: PublicAssistantConfig, clock: Clock, tmp_path: Path
) -> None:
    def build(data_dir: Path) -> tuple[Unit1Store, SecretaryService]:
        local_store = Unit1Store(
            data_dir, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.timestamp
        )
        local_service = SecretaryService(config, local_store, now=clock.now)
        local_service.observe_connection(
            ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
        )
        return local_store, local_service

    erased_store, erased_service = build(tmp_path / "erasure-ledger")
    authorize(erased_service, erased_store, clock)
    privacy = erased_service.handle_message(
        inbound(clock, update_id=280, message_id=281, text="privacy")
    )
    assert privacy.reply is not None
    sent_reply(erased_store, privacy.reply, 282)
    assert (
        erased_service.handle_delete(
            DeleteNotice(CONNECTION_ID, SENDER_ID, (11,), 283)
        ).outcome
        == "deleted"
    )
    ledger = erased_store.public.execute(
        "SELECT subject_ref FROM processed_updates WHERE update_id=283"
    ).fetchone()
    assert ledger[0].startswith("subject_")
    assert (
        erased_service.handle_control(
            callback(privacy.reply, "Delete data"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            connection_id=CONNECTION_ID,
            origin_message_id=282,
        )
        == "erased"
    )
    assert (
        erased_store.public.execute("SELECT count(*) FROM deletion_links").fetchone()[0]
        == 0
    )
    assert (
        erased_store.public.execute(
            "SELECT count(*) FROM processed_updates WHERE update_id=283"
        ).fetchone()[0]
        == 0
    )
    erased_store.close()

    ttl_store, ttl_service = build(tmp_path / "ttl-ledger")
    authorize(ttl_service, ttl_store, clock)
    assert (
        ttl_service.handle_delete(
            DeleteNotice(CONNECTION_ID, SENDER_ID, (11,), 284)
        ).outcome
        == "deleted"
    )
    clock.advance(days=90)
    assert ttl_store.expire_public(config.retention_seconds) == 1
    assert (
        ttl_store.public.execute(
            "SELECT count(*) FROM deletion_links WHERE update_id=284"
        ).fetchone()[0]
        == 0
    )
    assert (
        ttl_store.public.execute(
            "SELECT count(*) FROM processed_updates WHERE update_id=284"
        ).fetchone()[0]
        == 0
    )
    ttl_store.close()


@pytest.mark.asyncio
async def test_polling_bootstrap_and_network_retry_are_bounded_but_conflict_is_fast(
    store: Unit1Store, clock: Clock
) -> None:
    sleeps: list[float] = []

    class RetryBot(PollBot):
        attempts = 0

        async def get_updates(self, **kwargs: Any) -> tuple[Update, ...]:
            self.attempts += 1
            if self.attempts < 3:
                raise NetworkError("temporary")
            return ()

    bot = RetryBot(clock, [])
    runner = DurablePollingRunner(
        FakeApplication(bot),
        SimpleNamespace(
            config=SimpleNamespace(retention_seconds=1), deliver_due_replies=_noop_due
        ),
        store,  # type: ignore[arg-type]
        sleep=lambda seconds: _record_sleep(sleeps, seconds),
    )
    assert await runner.run_once() is False
    assert bot.attempts >= 3
    assert sleeps[:2] == [1.0, 2.0]

    class ConflictBot(PollBot):
        attempts = 0

        async def get_updates(self, **kwargs: Any) -> tuple[Update, ...]:
            self.attempts += 1
            raise Conflict("another poller")

    conflict_bot = ConflictBot(clock, [])
    conflict_runner = DurablePollingRunner(
        FakeApplication(conflict_bot),
        SimpleNamespace(
            config=SimpleNamespace(retention_seconds=1), deliver_due_replies=_noop_due
        ),
        store,  # type: ignore[arg-type]
        sleep=lambda seconds: _record_sleep(sleeps, seconds),
    )
    with pytest.raises(Conflict):
        await conflict_runner.run_once()
    assert conflict_bot.attempts == 1


@pytest.mark.asyncio
async def test_delete_webhook_bootstrap_retries_network_and_never_drops_updates(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    sleeps: list[float] = []

    class BootstrapBot(PollBot):
        webhook_attempts = 0

        async def delete_webhook(self, **kwargs: Any) -> bool:
            assert kwargs == {"drop_pending_updates": False}
            self.webhook_attempts += 1
            if self.webhook_attempts < 3:
                raise NetworkError("temporary bootstrap failure")
            return True

    class BootstrapApplication(FakeApplication):
        events: list[str]

        def __init__(self, bot: PollBot) -> None:
            super().__init__(bot)
            self.events = []

        async def initialize(self) -> None:
            self.events.append("initialize")

        async def start(self) -> None:
            self.events.append("start")

        async def stop(self) -> None:
            self.events.append("stop")

        async def shutdown(self) -> None:
            self.events.append("shutdown")

    stopped = asyncio.Event()
    stopped.set()
    bot = BootstrapBot(clock, [])
    application = BootstrapApplication(bot)
    adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)
    runner = DurablePollingRunner(
        application,
        adapter,
        store,  # type: ignore[arg-type]
        sleep=lambda seconds: _record_sleep(sleeps, seconds),
    )
    await runner.run(stopped)
    assert bot.webhook_attempts == 3
    assert sleeps == [1.0, 2.0]
    assert application.events == ["initialize", "start", "stop", "shutdown"]


async def _noop_due(bot: Any) -> None:
    return None


@pytest.mark.parametrize("privacy_action", ["Revoke", "Delete data"])
def test_sender_privacy_actions_preserve_owner_takeover_state(
    privacy_action: str,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    authorize(service, store, clock)
    privacy = service.handle_message(
        inbound(clock, update_id=270, message_id=271, text="privacy")
    )
    assert privacy.reply is not None
    sent_reply(store, privacy.reply, 272)
    assert (
        service.handle_owner_message(
            OwnerMessage(CONNECTION_ID, SENDER_ID, OWNER_ID, 273, 274, None)
        ).outcome
        == "owner_takeover"
    )
    outcome = service.handle_control(
        callback(privacy.reply, privacy_action),
        actor_id=SENDER_ID,
        conversation_id=SENDER_ID,
        connection_id=CONNECTION_ID,
        origin_message_id=272,
    )
    assert outcome == ("revoked" if privacy_action == "Revoke" else "erased")
    assert store.is_taken_over(CONNECTION_ID, SENDER_ID)
    columns = [
        str(row[1])
        for row in store.public.execute("PRAGMA table_info(chat_state)").fetchall()
    ]
    assert columns == ["chat_key", "takeover_at"]
    state = store.public.execute("SELECT chat_key FROM chat_state").fetchone()
    assert state[0] == store.chat_key(CONNECTION_ID, SENDER_ID)
