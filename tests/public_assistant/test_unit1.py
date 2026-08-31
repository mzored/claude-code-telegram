"""Integration evidence for the deterministic Telegram Business delivery unit."""

from __future__ import annotations

import ast
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

from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.service import SecretaryService
from src.public_assistant.sqlcipher import EncryptedStoreError, SqlCipherDatabase
from src.public_assistant.storage import PUBLIC_SCHEMA, TransferInterrupted, Unit1Store
from src.public_assistant.telegram_adapter import (
    EXPLICIT_ALLOWED_UPDATES,
    TelegramBusinessAdapter,
    build_application,
    run_polling,
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


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value

    def timestamp(self) -> float:
        return self.value.timestamp()

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def config(tmp_path: Path) -> PublicAssistantConfig:
    return PublicAssistantConfig(
        bot_token="123456:test-token-never-used",
        owner_id=OWNER_ID,
        selected_sender_ids=frozenset({SENDER_ID}),
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backups",
        pending_database_key="pending-key-" + "p" * 32,
        public_database_key="public-key-" + "u" * 32,
        backup_database_key="backup-key-" + "b" * 32,
        pseudonym_key=b"log-key-" + b"l" * 32,
        privacy_url="https://example.test/privacy",
        privacy_policy_version="privacy-wording-1",
        processing_authorization_version="processing-scope-1",
    )


@pytest.fixture
def store(config: PublicAssistantConfig, clock: Clock) -> Any:
    value = Unit1Store(
        config.data_dir,
        config.pending_database_key,
        config.public_database_key,
        config.backup_database_key,
        config.pseudonym_key,
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
        ConnectionObservation(
            connection_id=CONNECTION_ID,
            owner_id=OWNER_ID,
            enabled=True,
            can_reply=True,
            observed_at=clock.now(),
        )
    )
    return value


def inbound(
    clock: Clock,
    *,
    update_id: int = 1,
    message_id: int = 11,
    text: str = BODY,
    sender_id: int = SENDER_ID,
    chat_type: str = "private",
    edited: bool = False,
) -> InboundMessage:
    return InboundMessage(
        connection_id=CONNECTION_ID,
        conversation_id=sender_id,
        sender_id=sender_id,
        message_id=message_id,
        update_id=update_id,
        text=text,
        sent_at=clock.now(),
        chat_type=chat_type,
        edited_at=clock.now() if edited else None,
    )


def callback(reply: Any, label: str) -> str:
    keyboard = json.loads(reply.keyboard_json)
    for row in keyboard:
        for button in row:
            if button["text"] == label:
                return str(button["callback_data"])
    raise AssertionError(f"button {label!r} not found")


def authorize(
    service: SecretaryService, clock: Clock, *, update_id: int = 1
) -> InboundMessage:
    message = inbound(clock, update_id=update_id, message_id=update_id + 10)
    result = service.handle_message(message)
    assert result.outcome == "awaiting_consent"
    assert result.reply is not None
    assert (
        service.handle_control(
            callback(result.reply, "Continue"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
        )
        == "accepted"
    )
    return message


def open_encrypted(path: Path, key: str) -> Any:
    connection = sqlcipher.connect(str(path))
    key_hex = key.encode().hex()
    connection.execute(f"PRAGMA key = \"x'{key_hex}'\"")
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return connection


def test_sqlcipher_stores_wal_backup_and_permissions_are_real(
    config: PublicAssistantConfig,
    store: Unit1Store,
    service: SecretaryService,
    clock: Clock,
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.outcome == "awaiting_consent"
    assert store.counts() == {"pending": 1, "messages": 0, "receipts": 0}

    backup = config.backup_dir / "public-backup.db"
    store.backup_public(backup)
    assert backup.exists()
    assert backup.read_bytes()[:16] != b"SQLite format 3\x00"
    assert BODY.encode() not in backup.read_bytes()
    assert BODY.encode() not in (config.data_dir / "pending.db").read_bytes()
    assert BODY.encode() not in (config.data_dir / "pending.db-wal").read_bytes()
    for protected_file in (
        config.data_dir / "pending.db",
        config.data_dir / "pending.db-wal",
        config.data_dir / "public.db",
        config.data_dir / "public.db-wal",
        backup,
    ):
        assert str(SENDER_ID).encode() not in protected_file.read_bytes()

    restored = open_encrypted(backup, config.backup_database_key)
    assert restored.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
    assert (
        restored.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='pending_messages'"
        ).fetchone()[0]
        == 0
    )
    restored.close()
    with pytest.raises(sqlcipher.DatabaseError):
        wrong = open_encrypted(backup, config.public_database_key)
        wrong.close()

    cipher_version = store.public.execute("PRAGMA cipher_version").fetchone()[0]
    assert str(cipher_version).startswith("4.6.1")
    assert os.stat(config.data_dir).st_mode & 0o777 == 0o700
    assert os.stat(config.data_dir / "pending.db").st_mode & 0o777 == 0o600
    assert os.stat(config.data_dir / "pending.db-wal").st_mode & 0o777 == 0o600
    assert os.stat(backup).st_mode & 0o777 == 0o600


def test_plaintext_and_wrong_key_databases_fail_closed(
    tmp_path: Path, config: PublicAssistantConfig, store: Unit1Store
) -> None:
    store.close()
    with pytest.raises(EncryptedStoreError):
        SqlCipherDatabase(
            config.data_dir / "public.db", "not-the-right-key" * 3, PUBLIC_SCHEMA
        )

    plaintext_path = tmp_path / "plaintext.db"
    plaintext = sqlite3.connect(plaintext_path)
    plaintext.execute("CREATE TABLE leaked(value TEXT)")
    plaintext.commit()
    plaintext.close()
    with pytest.raises(EncryptedStoreError):
        SqlCipherDatabase(plaintext_path, "encrypted-key" * 3, PUBLIC_SCHEMA)


@pytest.mark.parametrize(
    ("owner_id", "enabled", "can_reply"),
    [
        (OWNER_ID + 1, True, True),
        (OWNER_ID, False, True),
        (OWNER_ID, True, None),
        (OWNER_ID, True, False),
    ],
)
def test_wrong_owner_disabled_and_missing_rights_never_store_a_body(
    config: PublicAssistantConfig,
    store: Unit1Store,
    clock: Clock,
    owner_id: int,
    enabled: bool,
    can_reply: bool | None,
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    assert not service.observe_connection(
        ConnectionObservation(CONNECTION_ID, owner_id, enabled, can_reply, clock.now())
    )
    assert service.handle_message(inbound(clock)).outcome == "connection_denied"
    assert store.counts()["pending"] == 0
    assert BODY.encode() not in (config.data_dir / "public.db-wal").read_bytes()


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"chat_type": "group"}, "non_private_chat"),
        ({"sender_id": SENDER_ID + 1}, "sender_not_selected"),
    ],
)
def test_only_selected_private_sender_messages_enter_pending_storage(
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
    change: dict[str, Any],
    expected: str,
) -> None:
    message = inbound(clock)
    message = replace(
        message,
        **change,
        conversation_id=change.get("sender_id", message.conversation_id),
    )
    assert service.handle_message(message).outcome == expected
    assert store.counts()["pending"] == 0


def test_durable_rate_limit_denies_excess_selected_sender_updates(
    config: PublicAssistantConfig,
    store: Unit1Store,
    clock: Clock,
) -> None:
    limited = SecretaryService(
        replace(config, rate_limit_count=1), store, now=clock.now
    )
    limited.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    assert limited.handle_message(inbound(clock)).outcome == "awaiting_consent"
    assert (
        limited.handle_message(inbound(clock, update_id=2, message_id=12)).outcome
        == "rate_limited"
    )
    assert store.counts()["pending"] == 1


def test_explicit_consent_decline_expiry_and_version_rules(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    first = service.handle_message(inbound(clock))
    assert first.outcome == "awaiting_consent"
    assert first.reply is not None
    assert BODY not in first.reply.text
    continue_token = callback(first.reply, "Continue")
    assert continue_token.startswith("pa:") and len(continue_token) < 64
    assert (
        service.handle_control(
            continue_token, actor_id=SENDER_ID + 1, conversation_id=SENDER_ID
        )
        == "neutral"
    )
    assert (
        service.handle_control(
            continue_token, actor_id=SENDER_ID, conversation_id=SENDER_ID
        )
        == "accepted"
    )
    assert (
        service.handle_control(
            continue_token, actor_id=SENDER_ID, conversation_id=SENDER_ID
        )
        == "replayed"
    )
    assert store.counts() == {"pending": 0, "messages": 1, "receipts": 1}

    wording_only = SecretaryService(
        replace(config, privacy_policy_version="privacy-wording-2"),
        store,
        now=clock.now,
    )
    assert (
        wording_only.handle_message(
            inbound(clock, update_id=2, message_id=12, text="second")
        ).outcome
        == "stored_after_consent"
    )

    processing_change = SecretaryService(
        replace(config, processing_authorization_version="processing-scope-2"),
        store,
        now=clock.now,
    )
    changed = processing_change.handle_message(
        inbound(clock, update_id=3, message_id=13, text="third")
    )
    assert changed.outcome == "awaiting_consent"

    decline = service.handle_message(
        inbound(clock, update_id=4, message_id=14, text="decline this")
    )
    assert decline.reply is not None
    assert (
        service.handle_control(
            callback(decline.reply, "Revoke"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
        )
        == "revoked"
    )


def test_unconsented_body_decline_and_twenty_four_hour_expiry(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    first = service.handle_message(inbound(clock))
    assert first.reply is not None
    assert (
        service.handle_control(
            callback(first.reply, "Decline"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
        )
        == "declined"
    )
    assert store.counts()["pending"] == 0

    second = service.handle_message(
        inbound(clock, update_id=2, message_id=12, text="expires")
    )
    assert second.reply is not None
    token = callback(second.reply, "Continue")
    clock.advance(hours=24)
    assert store.expire_pending() == 1
    assert (
        service.handle_control(token, actor_id=SENDER_ID, conversation_id=SENDER_ID)
        == "replayed"
    )
    assert store.counts()["messages"] == 0


@pytest.mark.parametrize(
    "crash_stage",
    ["before_copy", "after_copy", "after_receipt", "before_pending_delete"],
)
def test_consent_transfer_recovers_every_cross_database_crash_boundary(
    tmp_path: Path,
    config: PublicAssistantConfig,
    clock: Clock,
    crash_stage: str,
) -> None:
    data_dir = tmp_path / crash_stage
    local = replace(config, data_dir=data_dir)
    first_store = Unit1Store(
        local.data_dir,
        local.pending_database_key,
        local.public_database_key,
        local.backup_database_key,
        local.pseudonym_key,
        clock=clock.timestamp,
    )
    first_service = SecretaryService(local, first_store, now=clock.now)
    first_service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    result = first_service.handle_message(inbound(clock))
    assert result.reply is not None

    def crash(stage: str) -> None:
        if stage == crash_stage:
            raise TransferInterrupted(stage)

    with pytest.raises(TransferInterrupted, match=crash_stage):
        first_service.handle_control(
            callback(result.reply, "Continue"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
            crash_hook=crash,
        )
    first_store.close()

    recovered = Unit1Store(
        local.data_dir,
        local.pending_database_key,
        local.public_database_key,
        local.backup_database_key,
        local.pseudonym_key,
        clock=clock.timestamp,
    )
    assert recovered.counts() == {"pending": 0, "messages": 1, "receipts": 1}
    row = recovered.public.execute("SELECT body FROM messages").fetchone()
    assert row[0] == BODY
    recovered.close()


def test_update_replay_edit_and_delete_converge_on_final_body(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    first = service.handle_message(inbound(clock))
    duplicate = service.handle_message(inbound(clock))
    assert duplicate.outcome == "duplicate"
    assert duplicate.reply == first.reply
    assert store.counts()["pending"] == 1

    edited = service.handle_edit(
        inbound(
            clock,
            update_id=2,
            message_id=11,
            text="final edited body",
            edited=True,
        )
    )
    assert edited.outcome == "pending_body_replaced"
    assert first.reply is not None
    assert (
        service.handle_control(
            callback(first.reply, "Continue"),
            actor_id=SENDER_ID,
            conversation_id=SENDER_ID,
        )
        == "accepted"
    )
    assert store.public.execute("SELECT body FROM messages").fetchone()[0] == (
        "final edited body"
    )

    notice = DeleteNotice(CONNECTION_ID, SENDER_ID, (11,), 3)
    assert service.handle_delete(notice).outcome == "deleted"
    assert service.handle_delete(notice).outcome == "duplicate"
    row = store.public.execute("SELECT body, deleted_at FROM messages").fetchone()
    assert row[0] is None and row[1] is not None


def test_delete_cancels_unsent_disclosure_and_removes_pending_body(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    assert result.reply.state == DeliveryState.PENDING
    assert (
        service.handle_delete(DeleteNotice(CONNECTION_ID, SENDER_ID, (11,), 2)).outcome
        == "deleted"
    )
    assert store.counts()["pending"] == 0
    assert store.get_reply(result.reply.reply_id).state == DeliveryState.CANCELLED


def test_manual_owner_takeover_stops_replies_but_sender_business_bot_does_not(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    own_delivery = OwnerMessage(
        CONNECTION_ID, SENDER_ID, OWNER_ID, 90, 900, sender_business_bot_id=303003
    )
    assert service.handle_owner_message(own_delivery).outcome == "assistant_delivery"
    first = service.handle_message(inbound(clock))
    assert first.outcome == "awaiting_consent"

    manual = replace(
        own_delivery, update_id=91, message_id=901, sender_business_bot_id=None
    )
    assert service.handle_owner_message(manual).outcome == "owner_takeover"
    assert store.get_reply(first.reply.reply_id).state == DeliveryState.CANCELLED
    later = service.handle_message(inbound(clock, update_id=2, message_id=12))
    assert later.outcome == "owner_takeover"
    assert store.counts()["pending"] == 1


@pytest.mark.asyncio
async def test_timeout_is_durable_delivery_uncertainty_and_never_auto_retries(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    attempts = 0

    async def timeout_sender(reply: Any) -> int:
        nonlocal attempts
        attempts += 1
        raise TimeoutError(reply.reply_id)

    assert await service.deliver_reply(result.reply, timeout_sender) == (
        DeliveryState.DELIVERY_UNCERTAIN
    )
    assert await service.deliver_reply(result.reply, timeout_sender) == (
        DeliveryState.DELIVERY_UNCERTAIN
    )
    assert attempts == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("deny_by", ["rights", "age"])
async def test_rights_and_reply_window_are_rechecked_immediately_before_send(
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
    deny_by: str,
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    if deny_by == "rights":
        service.observe_connection(
            ConnectionObservation(CONNECTION_ID, OWNER_ID, True, False, clock.now())
        )
    else:
        clock.advance(hours=24)
    attempts = 0

    async def sender(reply: Any) -> int:
        nonlocal attempts
        attempts += 1
        return 999

    assert await service.deliver_reply(result.reply, sender) == DeliveryState.CANCELLED
    assert attempts == 0


def test_update_id_replay_with_changed_binding_fails_closed(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    original = service.handle_message(inbound(clock))
    assert original.reply is not None
    changed = service.handle_message(inbound(clock, text="changed replay payload"))
    assert changed.outcome == "duplicate"
    assert changed.reply is None
    assert store.counts()["pending"] == 1


def test_restart_replay_resumes_an_incomplete_ingress_ledger(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    message = inbound(clock)
    assert store.begin_update(message, "business_message", "received") == (True, None)
    store.stage_pending(
        message,
        privacy_policy_version=config.privacy_policy_version,
        processing_authorization_version=(config.processing_authorization_version),
        ttl_seconds=config.pending_ttl_seconds,
    )
    resumed = service.handle_message(message)
    assert resumed.outcome == "awaiting_consent"
    assert resumed.reply is not None
    assert store.counts()["pending"] == 1


def test_restart_converts_in_flight_reply_to_uncertain(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    clock: Clock,
) -> None:
    result = service.handle_message(inbound(clock))
    assert result.reply is not None
    assert store.mark_reply_sending(result.reply.reply_id)
    store.close()
    reopened = Unit1Store(
        config.data_dir,
        config.pending_database_key,
        config.public_database_key,
        config.backup_database_key,
        config.pseudonym_key,
        clock=clock.timestamp,
    )
    assert reopened.get_reply(result.reply.reply_id).state == (
        DeliveryState.DELIVERY_UNCERTAIN
    )
    reopened.close()


def test_revoke_and_delete_controls_are_opaque_replayed_and_fail_closed(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    authorize(service, clock)
    privacy = service.handle_message(
        inbound(clock, update_id=2, message_id=12, text="/privacy")
    )
    assert privacy.reply is not None
    revoke = callback(privacy.reply, "Revoke")
    assert (
        service.handle_control(revoke, actor_id=SENDER_ID, conversation_id=SENDER_ID)
        == "revoked"
    )
    assert (
        service.handle_control(revoke, actor_id=SENDER_ID, conversation_id=SENDER_ID)
        == "neutral"
    )
    assert (
        service.handle_message(inbound(clock, update_id=3, message_id=13)).outcome
        == "privacy_stopped"
    )

    # Use a distinct subject/store to prove full deletion removes content.
    assert (
        store.privacy_state(store.subject_ref(CONNECTION_ID, SENDER_ID, SENDER_ID))
        == "revoked"
    )


def test_delete_control_removes_all_sender_content(
    service: SecretaryService, store: Unit1Store, clock: Clock
) -> None:
    authorize(service, clock)
    privacy = service.handle_message(
        inbound(clock, update_id=2, message_id=12, text="privacy")
    )
    assert privacy.reply is not None
    delete = callback(privacy.reply, "Delete data")
    assert (
        service.handle_control(delete, actor_id=SENDER_ID, conversation_id=SENDER_ID)
        == "erased"
    )
    assert store.public.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
    assert store.public.execute("SELECT count(*) FROM consents").fetchone()[0] == 0
    assert store.counts()["pending"] == 0


def test_logs_contain_only_pseudonymous_references(caplog: Any) -> None:
    logger = logging.getLogger("unit1-redaction")
    privacy_log = PrivacyLog(b"k" * 32, logger)
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
    assert "subject" not in rendered
    assert "sender_" in rendered and "update_" in rendered


def test_ptb_business_connection_uses_user_id_and_explicit_can_reply(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    adapter = TelegramBusinessAdapter(config, service, store)
    update = Update.de_json(
        {
            "update_id": 500,
            "business_connection": {
                "id": CONNECTION_ID,
                "user": {
                    "id": OWNER_ID,
                    "is_bot": False,
                    "first_name": "Owner",
                },
                "user_chat_id": OWNER_ID + 999,
                "date": int(clock.timestamp()),
                "is_enabled": True,
                "rights": {"can_reply": True},
            },
        },
        Bot(config.bot_token),
    )
    import asyncio

    asyncio.run(adapter.on_business_connection(update, SimpleNamespace()))
    assert store.connection_can_reply(CONNECTION_ID, OWNER_ID)


def test_ptb_sender_business_bot_delivery_does_not_trigger_takeover(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    adapter = TelegramBusinessAdapter(config, service, store)
    common = {
        "message_id": 700,
        "date": int(clock.timestamp()),
        "chat": {"id": SENDER_ID, "type": "private", "first_name": "Pilot"},
        "from": {"id": OWNER_ID, "is_bot": False, "first_name": "Owner"},
        "business_connection_id": CONNECTION_ID,
        "text": "outgoing",
    }
    assistant_payload = dict(common)
    assistant_payload["sender_business_bot"] = {
        "id": 303003,
        "is_bot": True,
        "first_name": "Assistant",
    }
    assistant = Update.de_json(
        {"update_id": 701, "business_message": assistant_payload},
        Bot(config.bot_token),
    )
    import asyncio

    asyncio.run(adapter.on_business_message(assistant, SimpleNamespace(bot=None)))
    assert not store.is_taken_over(CONNECTION_ID, SENDER_ID)

    manual = Update.de_json(
        {"update_id": 702, "business_message": common}, Bot(config.bot_token)
    )
    asyncio.run(adapter.on_business_message(manual, SimpleNamespace(bot=None)))
    assert store.is_taken_over(CONNECTION_ID, SENDER_ID)


def test_ptb_inbound_text_is_normalized_stored_and_replied_durably(
    config: PublicAssistantConfig, store: Unit1Store, clock: Clock
) -> None:
    service = SecretaryService(config, store, now=clock.now)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    adapter = TelegramBusinessAdapter(config, service, store)
    update = Update.de_json(
        {
            "update_id": 800,
            "business_message": {
                "message_id": 801,
                "date": int(clock.timestamp()),
                "chat": {
                    "id": SENDER_ID,
                    "type": "private",
                    "first_name": "Pilot",
                },
                "from": {
                    "id": SENDER_ID,
                    "is_bot": False,
                    "first_name": "Pilot",
                },
                "business_connection_id": CONNECTION_ID,
                "text": BODY,
            },
        },
        Bot(config.bot_token),
    )

    class BoundaryBot:
        calls: list[dict[str, Any]] = []

        async def send_message(self, **kwargs: Any) -> Any:
            self.calls.append(kwargs)
            return SimpleNamespace(message_id=802)

    boundary = BoundaryBot()
    import asyncio

    asyncio.run(adapter.on_business_message(update, SimpleNamespace(bot=boundary)))
    assert store.counts()["pending"] == 1
    assert len(boundary.calls) == 1
    assert boundary.calls[0]["business_connection_id"] == CONNECTION_ID
    reply_state = store.public.execute("SELECT state FROM replies").fetchone()[0]
    assert reply_state == DeliveryState.SENT.value


def test_application_builds_only_unit1_handler_surface(
    config: PublicAssistantConfig, store: Unit1Store, service: SecretaryService
) -> None:
    application = build_application(config, service, store)
    handler_names = [
        type(handler).__name__
        for handlers in application.handlers.values()
        for handler in handlers
    ]
    assert handler_names == [
        "BusinessConnectionHandler",
        "MessageHandler",
        "MessageHandler",
        "BusinessMessagesDeletedHandler",
        "CallbackQueryHandler",
    ]


def test_polling_contract_has_only_explicit_business_updates_and_native_pause() -> None:
    captured: dict[str, Any] = {}

    class FakeApplication:
        def run_polling(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    run_polling(FakeApplication())  # type: ignore[arg-type]
    assert captured == {
        "allowed_updates": [
            "business_connection",
            "business_message",
            "edited_business_message",
            "deleted_business_messages",
            "callback_query",
        ],
        "drop_pending_updates": False,
    }
    assert "message" not in EXPLICIT_ALLOWED_UPDATES
    assert "pause" not in PUBLIC_SCHEMA.casefold()


def test_unit1_package_has_no_model_integration_or_private_agent_imports() -> None:
    package = Path("src/public_assistant")
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
    for source_path in package.glob("*.py"):
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
