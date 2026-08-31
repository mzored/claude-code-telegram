"""Integration-style evidence for consented Public Assistant Unit 2 behavior."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlcipher3 import dbapi2 as sqlcipher

from src.public_assistant.backup import (
    export_public_backup,
    prune_expired_backups,
    restore_public_backup,
)
from src.public_assistant.config import (
    BackupConfig,
    PublicAssistantConfig,
    PublicAssistantConfigurationError,
    Unit2Config,
)
from src.public_assistant.conversation import AssistantService
from src.public_assistant.inbox import Unit2Store
from src.public_assistant.model import (
    AssistantTurn,
    ConversationItem,
    ModelFailure,
    ModelResult,
    OpenAIResponsesModel,
    RequestPatch,
)
from src.public_assistant.storage import Unit1Store
from src.public_assistant.telegram_adapter import TelegramBusinessAdapter
from src.public_assistant.types import (
    ConnectionObservation,
    DeleteNotice,
    DeliveryState,
    InboundMessage,
)

OWNER_ID = 101001
SENDER_A = 202002
SENDER_B = 303003
CONNECTION_ID = "business-connection-opaque"
PENDING_KEY = "pending-key-" + "p" * 32
PUBLIC_KEY = "public-key-" + "u" * 32
BACKUP_KEY = "backup-key-" + "b" * 32
PSEUDONYM_KEY = b"log-key-" + b"l" * 32
OPENAI_KEY = "openai-key-" + "o" * 32
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


def public_config(tmp_path: Path, senders: frozenset[int]) -> PublicAssistantConfig:
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    return PublicAssistantConfig(
        bot_token_file=credential(credentials / "bot", BOT_TOKEN),
        pending_database_key_file=credential(credentials / "pending", PENDING_KEY),
        public_database_key_file=credential(credentials / "public", PUBLIC_KEY),
        pseudonym_key_file=credential(
            credentials / "pseudonym", PSEUDONYM_KEY.decode()
        ),
        owner_id=OWNER_ID,
        selected_sender_ids=senders,
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backups",
        privacy_url="https://example.test/privacy",
        privacy_policy_version="privacy-wording-1",
        processing_authorization_version="processing-scope-1",
    )


def unit2_config(config: PublicAssistantConfig) -> Unit2Config:
    openai_key_file = credential(config.data_dir.parent / "openai", OPENAI_KEY)
    return Unit2Config(
        openai_api_key_file=openai_key_file,
        model="gpt-4.1-mini",
        owner_alert_chat_id=OWNER_ID,
        timeout_seconds=5.0,
        max_output_tokens=80,
        max_context_items=12,
        max_context_characters=2400,
        daily_call_limit=20,
        daily_input_token_limit=100_000,
        daily_output_token_limit=20_000,
        daily_cost_microusd_limit=100_000_000,
        input_microusd_per_million=1_000_000,
        output_microusd_per_million=1_000_000,
        concurrency_limit=1,
        backup_retention_seconds=90 * 24 * 60 * 60,
    )


def unit2_environment(
    config: PublicAssistantConfig, openai_key_file: Path
) -> dict[str, str]:
    return {
        "PUBLIC_ASSISTANT_OPENAI_API_KEY_FILE": str(openai_key_file),
        "PUBLIC_ASSISTANT_OPENAI_MODEL": "gpt-4.1-mini",
        "PUBLIC_ASSISTANT_OWNER_ALERT_CHAT_ID": str(OWNER_ID),
        "PUBLIC_ASSISTANT_MODEL_TIMEOUT_SECONDS": "5",
        "PUBLIC_ASSISTANT_MODEL_MAX_OUTPUT_TOKENS": "80",
        "PUBLIC_ASSISTANT_MODEL_MAX_CONTEXT_ITEMS": "12",
        "PUBLIC_ASSISTANT_MODEL_MAX_CONTEXT_CHARACTERS": "2400",
        "PUBLIC_ASSISTANT_MODEL_DAILY_CALL_LIMIT": "20",
        "PUBLIC_ASSISTANT_MODEL_DAILY_INPUT_TOKEN_LIMIT": "100000",
        "PUBLIC_ASSISTANT_MODEL_DAILY_OUTPUT_TOKEN_LIMIT": "20000",
        "PUBLIC_ASSISTANT_MODEL_DAILY_COST_MICROUSD_LIMIT": "100000000",
        "PUBLIC_ASSISTANT_MODEL_INPUT_MICROUSD_PER_MILLION": "1000000",
        "PUBLIC_ASSISTANT_MODEL_OUTPUT_MICROUSD_PER_MILLION": "1000000",
        "PUBLIC_ASSISTANT_MODEL_CONCURRENCY_LIMIT": "1",
        "PUBLIC_ASSISTANT_BACKUP_RETENTION_SECONDS": str(90 * 24 * 60 * 60),
    }


def inbound(
    clock: Clock,
    *,
    sender_id: int = SENDER_A,
    update_id: int = 1,
    message_id: int = 11,
    text: str = "Please capture this request.",
) -> InboundMessage:
    return InboundMessage(
        connection_id=CONNECTION_ID,
        conversation_id=sender_id,
        sender_id=sender_id,
        message_id=message_id,
        update_id=update_id,
        text=text,
        sent_at=clock.now(),
    )


def callback(reply: Any, label: str) -> str:
    for row in json.loads(reply.keyboard_json):
        for item in row:
            if item["text"] == label:
                return str(item["callback_data"])
    raise AssertionError(f"missing {label!r} control")


def send_reply(store: Unit1Store, reply: Any, message_id: int) -> None:
    store.finalize_reply(reply.reply_id, DeliveryState.SENT, message_id)


def request_turn(content: str = "Follow up on the requested outcome.") -> ModelResult:
    return ModelResult(
        AssistantTurn(
            reply_text="I will pass this to Misha.",
            turn_kind="request",
            request_patch=RequestPatch(content),
        ),
        input_tokens=20,
        output_tokens=10,
        provider_request_id="req_safe_1",
    )


def answer_turn(text: str = "I can help with that.") -> ModelResult:
    return ModelResult(
        AssistantTurn(reply_text=text, turn_kind="answer"),
        input_tokens=20,
        output_tokens=10,
        provider_request_id="req_safe_1",
    )


class RecordingModel:
    def __init__(self, outcomes: list[ModelResult | BaseException]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[tuple[ConversationItem, ...], str]] = []

    def generate(
        self,
        conversation: list[ConversationItem] | tuple[ConversationItem, ...],
        safety_identifier: str,
    ) -> ModelResult:
        self.calls.append((tuple(conversation), safety_identifier))
        if not self.outcomes:
            raise AssertionError("unexpected model invocation")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def make_service(
    tmp_path: Path,
    clock: Clock,
    model: RecordingModel,
    *,
    senders: frozenset[int] = frozenset({SENDER_A}),
    config: PublicAssistantConfig | None = None,
    limits: Unit2Config | None = None,
) -> tuple[PublicAssistantConfig, Unit2Config, Unit2Store, AssistantService]:
    config = config or public_config(tmp_path, senders)
    limits = limits or unit2_config(config)
    store = Unit2Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    service = AssistantService(config, limits, store, model, now=clock.now)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    return config, limits, store, service


def authorize(
    service: AssistantService,
    store: Unit2Store,
    clock: Clock,
    *,
    sender_id: int = SENDER_A,
    update_id: int = 1,
    message_id: int = 11,
    text: str = "Please capture this request.",
) -> tuple[InboundMessage, str]:
    message = inbound(
        clock,
        sender_id=sender_id,
        update_id=update_id,
        message_id=message_id,
        text=text,
    )
    staged = service.handle_message(message)
    assert staged.outcome == "awaiting_consent"
    assert staged.reply is not None
    assert "OpenAI" in staged.reply.text
    assert "Google Calendar" not in staged.reply.text
    assert "Todoist" not in staged.reply.text
    callback_message_id = 9000 + update_id
    send_reply(store, staged.reply, callback_message_id)
    result = service.handle_control(
        callback(staged.reply, "Continue"),
        actor_id=sender_id,
        conversation_id=sender_id,
        connection_id=CONNECTION_ID,
        origin_message_id=callback_message_id,
    )
    assert result.startswith("accepted:")
    return message, result.split(":", 1)[1]


def encrypted_connection(path: Path, key: str) -> Any:
    connection = sqlcipher.connect(str(path))
    connection.execute(f"PRAGMA key = \"x'{key.encode().hex()}'\"")
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return connection


def test_consent_binds_current_version_and_revocation_stops_next_model_call(
    tmp_path: Path,
) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn()])
    config, limits, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock)
        assert len(model.calls) == 1
        consent = store.public.execute(
            "SELECT processors, purposes FROM consents"
        ).fetchone()
        assert consent is not None
        assert json.loads(consent[0]) == ["OpenAI"]
        assert json.loads(consent[1]) == ["assistant replies", "request capture"]

        changed_scope = AssistantService(
            replace(config, processing_authorization_version="processing-scope-2"),
            limits,
            store,
            model,
            now=clock.now,
        )
        clock.advance(seconds=1)
        current_scope = changed_scope.handle_message(
            inbound(clock, update_id=2, message_id=12, text="Still there?")
        )
        assert current_scope.outcome == "awaiting_consent"
        assert len(model.calls) == 1

        privacy = service.handle_message(
            inbound(clock, update_id=3, message_id=13, text="privacy")
        )
        assert privacy.reply is not None
        send_reply(store, privacy.reply, 9003)
        assert (
            service.handle_control(
                callback(privacy.reply, "Revoke"),
                actor_id=SENDER_A,
                conversation_id=SENDER_A,
                connection_id=CONNECTION_ID,
                origin_message_id=9003,
            )
            == "revoked"
        )
        clock.advance(seconds=1)
        stopped = service.handle_message(
            inbound(clock, update_id=4, message_id=14, text="Do not call the model.")
        )
        assert stopped.outcome == "privacy_stopped"
        assert len(model.calls) == 1
    finally:
        store.close()


def test_awaiting_consent_crash_replay_creates_one_fallback_and_reference(
    tmp_path: Path,
) -> None:
    clock = Clock()
    model = RecordingModel([])
    config, limits, store, service = make_service(tmp_path, clock, model)
    message = inbound(clock, text="Recover this consented request.")
    staged = service.handle_message(message)
    assert staged.outcome == "awaiting_consent"
    assert staged.reply is not None
    send_reply(store, staged.reply, 9001)
    token = callback(staged.reply, "Continue")

    def crash(stage: str) -> None:
        if stage == "after_copy":
            raise RuntimeError(stage)

    try:
        with pytest.raises(RuntimeError, match="after_copy"):
            service.handle_control(
                token,
                actor_id=SENDER_A,
                conversation_id=SENDER_A,
                connection_id=CONNECTION_ID,
                origin_message_id=9001,
                crash_hook=crash,
            )
    finally:
        store.close()

    recovered = Unit2Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    recovered_model = RecordingModel([ModelFailure("provider unavailable")])
    recovered_service = AssistantService(
        config, limits, recovered, recovered_model, now=clock.now
    )
    recovered_service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    try:
        result = recovered_service.handle_control(
            token,
            actor_id=SENDER_A,
            conversation_id=SENDER_A,
            connection_id=CONNECTION_ID,
            origin_message_id=9001,
        )
        assert result.startswith("accepted:")
        reference = result.split(":", 1)[1]
        assert len(recovered_model.calls) == 1
        assert (
            recovered.public.execute(
                "SELECT count(*) FROM replies WHERE purpose='assistant'"
            ).fetchone()[0]
            == 1
        )
        assert (
            recovered.public.execute("SELECT count(*) FROM inbox_requests").fetchone()[
                0
            ]
            == 1
        )
        assert (
            recovered.prepare_erasure_preview(reference, "replay-test").outcome
            == "preview_ready"
        )
        assert (
            recovered.prepare_erasure_preview(reference, "replay-test").outcome
            == "neutral"
        )
    finally:
        recovered.close()


def test_unit2_configuration_rejects_inline_keys_and_alert_diversion(
    tmp_path: Path,
) -> None:
    config = public_config(tmp_path, frozenset({SENDER_A}))
    openai_key_file = credential(tmp_path / "openai", OPENAI_KEY)
    environment = unit2_environment(config, openai_key_file)

    parsed = Unit2Config.from_environment(config, environment)
    assert parsed.owner_alert_chat_id == OWNER_ID
    with pytest.raises(PublicAssistantConfigurationError, match="configured owner"):
        Unit2Config.from_environment(
            config,
            environment | {"PUBLIC_ASSISTANT_OWNER_ALERT_CHAT_ID": str(OWNER_ID + 1)},
        )
    with pytest.raises(PublicAssistantConfigurationError, match="forbidden"):
        Unit2Config.from_environment(
            config,
            environment | {"PUBLIC_ASSISTANT_OPENAI_API_KEY": "inline-secret"},
        )


def test_model_context_and_safety_identifier_are_isolated_per_chat(
    tmp_path: Path,
) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn("A"), answer_turn("B")])
    _, _, store, service = make_service(
        tmp_path, clock, model, senders=frozenset({SENDER_A, SENDER_B})
    )
    try:
        authorize(
            service,
            store,
            clock,
            sender_id=SENDER_A,
            update_id=1,
            message_id=11,
            text="A-only confidential context.",
        )
        clock.advance(seconds=1)
        authorize(
            service,
            store,
            clock,
            sender_id=SENDER_B,
            update_id=2,
            message_id=12,
            text="B-only confidential context.",
        )

        first_context, first_safety = model.calls[0]
        second_context, second_safety = model.calls[1]
        assert "A-only confidential context." in [item.text for item in first_context]
        assert "B-only confidential context." not in [
            item.text for item in first_context
        ]
        assert "B-only confidential context." in [item.text for item in second_context]
        assert "A-only confidential context." not in [
            item.text for item in second_context
        ]
        assert first_safety != second_safety
        for safety_identifier in (first_safety, second_safety):
            assert safety_identifier.startswith("safety_")
            assert len(safety_identifier) <= 64
            assert str(SENDER_A) not in safety_identifier
            assert str(SENDER_B) not in safety_identifier
            assert CONNECTION_ID not in safety_identifier
    finally:
        store.close()


@pytest.mark.parametrize(
    "failure",
    [ModelFailure("invalid response"), TimeoutError("provider timeout")],
)
def test_invalid_or_timed_out_model_captures_a_safe_inbox_request(
    tmp_path: Path, failure: BaseException
) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn(), failure])
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock)
        clock.advance(seconds=1)
        body = "A coherent request that survives model failure."
        result = service.handle_message(
            inbound(clock, update_id=2, message_id=12, text=body)
        )
        assert result.outcome == "model_fallback"
        request = store.public.execute(
            "SELECT body FROM inbox_requests WHERE source_update_id=2"
        ).fetchone()
        assert request is not None and request[0] == body
        assert result.reply is not None
        assert "couldn't complete" in result.reply.text
    finally:
        store.close()


def test_budget_exhaustion_uses_the_same_safe_inbox_fallback(tmp_path: Path) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn()])
    config = public_config(tmp_path, frozenset({SENDER_A}))
    limits = replace(unit2_config(config), daily_call_limit=1)
    _, _, store, service = make_service(
        tmp_path, clock, model, config=config, limits=limits
    )
    try:
        authorize(service, store, clock)
        clock.advance(seconds=1)
        result = service.handle_message(
            inbound(clock, update_id=2, message_id=12, text="Budget fallback request.")
        )
        assert result.outcome == "model_budget_exhausted"
        assert len(model.calls) == 1
        assert (
            store.public.execute(
                "SELECT count(*) FROM inbox_requests WHERE source_update_id=2"
            ).fetchone()[0]
            == 1
        )
    finally:
        store.close()


def test_greetings_and_abuse_never_create_inbox_requests(tmp_path: Path) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn()])
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock)
        model.calls.clear()
        clock.advance(seconds=1)
        greeting = service.handle_message(
            inbound(clock, update_id=2, message_id=12, text="hello")
        )
        clock.advance(seconds=1)
        abuse = service.handle_message(
            inbound(clock, update_id=3, message_id=13, text="I will kill you")
        )
        assert greeting.outcome == "greeting"
        assert abuse.outcome == "rejected"
        assert not model.calls
        assert (
            store.public.execute("SELECT count(*) FROM inbox_requests").fetchone()[0]
            == 0
        )
    finally:
        store.close()


def test_privacy_reference_is_hashed_and_one_use_after_disconnect(
    tmp_path: Path,
) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn()])
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        message, reference = authorize(service, store, clock)
        stored_reference = store.public.execute(
            "SELECT reference_hash, subject_ref FROM privacy_references"
        ).fetchone()
        assert stored_reference is not None
        assert reference not in str(tuple(stored_reference))

        store.deny_connection(CONNECTION_ID)
        preview = store.prepare_erasure_preview(reference, "off-chat-requester")
        assert preview.outcome == "preview_ready"
        assert preview.preview_id is not None
        assert (
            store.public.execute(
                "SELECT subject_ref FROM privacy_previews WHERE preview_id=?",
                (preview.preview_id,),
            ).fetchone()[0]
            == stored_reference[1]
        )
        assert (
            store.prepare_erasure_preview(reference, "off-chat-requester").outcome
            == "neutral"
        )
        assert (
            store.prepare_erasure_preview("guessed", "off-chat-requester").outcome
            == "neutral"
        )
        attempt_ref = store.public.execute(
            "SELECT attempt_ref FROM privacy_attempts LIMIT 1"
        ).fetchone()[0]
        assert attempt_ref != "off-chat-requester"
        assert (
            store.public.execute(
                "SELECT count(*) FROM messages WHERE source_update_id=?",
                (message.update_id,),
            ).fetchone()[0]
            == 1
        )
    finally:
        store.close()


def test_expired_privacy_reference_is_neutral_and_cannot_create_a_preview(
    tmp_path: Path,
) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn()])
    config, _, store, service = make_service(tmp_path, clock, model)
    try:
        _, reference = authorize(service, store, clock)
        clock.advance(seconds=config.retention_seconds + 1)
        store.expire_public(config.retention_seconds)

        preview = store.prepare_erasure_preview(reference, "off-chat-requester")
        assert preview.outcome == "neutral"
        assert (
            store.public.execute("SELECT count(*) FROM privacy_previews").fetchone()[0]
            == 0
        )
    finally:
        store.close()


def test_open_and_closed_inbox_content_expire_on_their_own_ttl(tmp_path: Path) -> None:
    clock = Clock()
    model = RecordingModel([])
    config, limits, store, _ = make_service(tmp_path, clock, model)
    try:
        old = inbound(clock, update_id=1, message_id=11, text="Old sender data")
        store.store_consented_message(old, config.retention_seconds)
        old_request = store.upsert_request(
            old, "Old Inbox content", config.retention_seconds
        )
        store.public.execute(
            "UPDATE inbox_requests SET state='closed' WHERE request_id=?",
            (old_request,),
        )
        store.add_assistant_context(
            old, "Old assistant content", config.retention_seconds
        )

        clock.advance(seconds=config.retention_seconds - 1)
        fresh = inbound(clock, update_id=2, message_id=12, text="Fresh sender data")
        store.store_consented_message(fresh, config.retention_seconds)
        fresh_request = store.upsert_request(
            fresh, "Fresh Inbox content", config.retention_seconds
        )
        store.add_assistant_context(
            fresh, "Fresh assistant content", config.retention_seconds
        )

        clock.advance(seconds=2)
        store.expire_public(config.retention_seconds)
        assert (
            store.public.execute(
                "SELECT count(*) FROM inbox_requests WHERE request_id=?", (old_request,)
            ).fetchone()[0]
            == 0
        )
        assert (
            store.public.execute(
                "SELECT count(*) FROM inbox_requests WHERE request_id=?",
                (fresh_request,),
            ).fetchone()[0]
            == 1
        )
        assert (
            store.public.execute(
                "SELECT count(*) FROM assistant_context WHERE source_update_id=1"
            ).fetchone()[0]
            == 0
        )
        assert (
            store.public.execute(
                "SELECT count(*) FROM assistant_context WHERE source_update_id=2"
            ).fetchone()[0]
            == 1
        )
    finally:
        store.close()


def test_tombstone_replays_before_a_restored_public_database_is_returned(
    tmp_path: Path,
) -> None:
    clock = Clock()
    body = "Erased content must never survive restore."
    model = RecordingModel([request_turn(body)])
    config, limits, store, service = make_service(tmp_path, clock, model)
    backup_key_file = credential(config.data_dir.parent / "backup", BACKUP_KEY)
    maintenance = BackupConfig(
        config.data_dir,
        config.backup_dir,
        config.public_database_key_file,
        backup_key_file,
        limits.backup_retention_seconds,
    )
    try:
        _, _ = authorize(service, store, clock, text=body)
        config.backup_dir.mkdir()
        snapshot = config.backup_dir / "public-unit2.db"
        export_public_backup(maintenance, snapshot)

        privacy = service.handle_message(
            inbound(clock, update_id=2, message_id=12, text="privacy")
        )
        assert privacy.reply is not None
        send_reply(store, privacy.reply, 9002)
        assert (
            service.handle_control(
                callback(privacy.reply, "Delete data"),
                actor_id=SENDER_A,
                conversation_id=SENDER_A,
                connection_id=CONNECTION_ID,
                origin_message_id=9002,
            )
            == "erased"
        )
    finally:
        store.close()

    for suffix in ("", "-wal", "-shm"):
        (config.data_dir / f"public.db{suffix}").unlink(missing_ok=True)
    restored = restore_public_backup(maintenance, snapshot)
    connection = encrypted_connection(restored, PUBLIC_KEY)
    try:
        assert connection.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
        assert (
            connection.execute("SELECT count(*) FROM inbox_requests").fetchone()[0] == 0
        )
        assert (
            connection.execute("SELECT state FROM privacy_state").fetchone()[0]
            == "erased"
        )
        assert body not in restored.read_bytes().decode("latin-1", errors="ignore")
    finally:
        connection.close()


def test_restore_rejects_an_orphaned_live_journal(tmp_path: Path) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn()])
    config, limits, store, service = make_service(tmp_path, clock, model)
    backup_key_file = credential(config.data_dir.parent / "backup", BACKUP_KEY)
    maintenance = BackupConfig(
        config.data_dir,
        config.backup_dir,
        config.public_database_key_file,
        backup_key_file,
        limits.backup_retention_seconds,
    )
    try:
        authorize(service, store, clock)
        config.backup_dir.mkdir()
        snapshot = config.backup_dir / "public-unit2.db"
        export_public_backup(maintenance, snapshot)
    finally:
        store.close()

    (config.data_dir / "public.db").unlink()
    (config.data_dir / "public.db-wal").write_bytes(b"orphaned journal")
    with pytest.raises(
        PublicAssistantConfigurationError, match="destination and journal"
    ):
        restore_public_backup(maintenance, snapshot)


def test_expired_snapshots_are_pruned_from_the_flat_backup_set(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    root.mkdir()
    expired = root / "expired.db"
    expired.write_bytes(b"encrypted-looking-test-data")
    os.utime(expired, (10, 10))
    current = root / "current.db"
    current.write_bytes(b"encrypted-looking-test-data")
    os.utime(current, (99, 99))

    assert prune_expired_backups(root, 50, now=100) == 1
    assert not expired.exists()
    assert current.exists()


@pytest.mark.asyncio
async def test_owner_alerts_are_fixed_and_independent_of_sender_reply_delivery(
    tmp_path: Path,
) -> None:
    clock = Clock()
    body = "This sender-authored request must not reach the owner alert."
    model = RecordingModel([request_turn(body)])
    config, _, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock, text=body)
        adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)

        class AlertBot:
            def __init__(self) -> None:
                self.sent: list[dict[str, Any]] = []

            async def send_message(self, **kwargs: Any) -> Any:
                self.sent.append(kwargs)
                return SimpleNamespace(message_id=1)

        bot = AlertBot()
        await adapter.deliver_due_notifications(bot)
        assert len(bot.sent) == 1
        alert = bot.sent[0]
        assert alert["chat_id"] == OWNER_ID
        assert re.fullmatch(
            r"Assistant Inbox request REQ-[A-F0-9]{12} is ready\.", alert["text"]
        )
        assert body not in alert["text"]
        assert "business_connection_id" not in alert
        assert len(model.calls) == 1

        state = store.public.execute(
            "SELECT state FROM notification_outbox"
        ).fetchone()[0]
        assert state == "sent"
    finally:
        store.close()


@pytest.mark.asyncio
async def test_tampered_owner_alert_never_sends_external_or_model_text(
    tmp_path: Path,
) -> None:
    clock = Clock()
    body = "Untrusted body must not become alert text."
    model = RecordingModel([request_turn(body)])
    config, _, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock, text=body)
        store.public.execute("UPDATE notification_outbox SET text=?", (body,))
        adapter = TelegramBusinessAdapter(config, service, store, now=clock.now)

        class AlertBot:
            async def send_message(self, **kwargs: Any) -> Any:
                raise AssertionError(f"unexpected alert: {kwargs!r}")

        await adapter.deliver_due_notifications(AlertBot())
        assert (
            store.public.execute("SELECT state FROM notification_outbox").fetchone()[0]
            == "failed"
        )
        assert len(model.calls) == 1
    finally:
        store.close()


def test_invalid_responses_payload_uses_the_safe_inbox_fallback(tmp_path: Path) -> None:
    class Responses:
        def create(self, **kwargs: Any) -> Any:
            del kwargs
            return SimpleNamespace(
                status="completed",
                output_text="not valid JSON",
                usage=SimpleNamespace(input_tokens=7, output_tokens=4),
            )

    clock = Clock()
    config = public_config(tmp_path, frozenset({SENDER_A}))
    limits = unit2_config(config)
    store = Unit2Store(
        config.data_dir,
        PENDING_KEY,
        PUBLIC_KEY,
        PSEUDONYM_KEY,
        clock=clock.timestamp,
    )
    model = OpenAIResponsesModel(
        "unused",
        "gpt-4.1-mini",
        timeout_seconds=3.0,
        max_output_tokens=80,
        client=SimpleNamespace(responses=Responses()),
    )
    service = AssistantService(config, limits, store, model, now=clock.now)
    service.observe_connection(
        ConnectionObservation(CONNECTION_ID, OWNER_ID, True, True, clock.now())
    )
    try:
        message, _ = authorize(
            service,
            store,
            clock,
            text="Capture this despite invalid model JSON.",
        )
        assert (
            store.public.execute(
                "SELECT body FROM inbox_requests WHERE source_update_id=?",
                (message.update_id,),
            ).fetchone()[0]
            == message.text
        )
        assert (
            store.public.execute(
                "SELECT outcome FROM processed_updates WHERE update_id=?",
                (message.update_id,),
            ).fetchone()[0]
            == "model_fallback"
        )
    finally:
        store.close()


def test_responses_adapter_forbids_hosted_state_and_tools() -> None:
    captured: dict[str, Any] = {}

    class Responses:
        def create(self, **kwargs: Any) -> Any:
            captured.update(kwargs)
            return SimpleNamespace(
                status="completed",
                output_text=json.dumps(
                    {
                        "reply_text": "A concise answer.",
                        "turn_kind": "answer",
                        "missing_information": [],
                        "request_patch": None,
                        "task_candidate": None,
                    }
                ),
                usage=SimpleNamespace(input_tokens=7, output_tokens=4),
                _request_id="req_safe_2",
            )

    client = SimpleNamespace(responses=Responses())
    model = OpenAIResponsesModel(
        "unused",
        "gpt-4.1-mini",
        timeout_seconds=3.0,
        max_output_tokens=80,
        client=client,
    )
    result = model.generate([ConversationItem("user", "Hello")], "safety_abc")

    assert result.input_tokens == 7
    assert captured["store"] is False
    assert captured["background"] is False
    assert captured["tools"] == []
    assert captured["max_tool_calls"] == 0
    assert "conversation" not in captured
    assert "previous_response_id" not in captured
    assert "timeout" not in captured
    assert captured["safety_identifier"] == "safety_abc"


@pytest.mark.parametrize(
    "owner_claim",
    [
        "Misha approved and completed your request.",
        "Misha has given his approval.",
        "Ваш запрос уже одобрен Мишей.",
    ],
)
def test_responses_adapter_rejects_schema_valid_owner_claims(
    owner_claim: str,
) -> None:
    class Responses:
        def create(self, **kwargs: Any) -> Any:
            return SimpleNamespace(
                status="completed",
                output_text=json.dumps(
                    {
                        "reply_text": owner_claim,
                        "turn_kind": "answer",
                        "missing_information": [],
                        "request_patch": None,
                        "task_candidate": None,
                    }
                ),
                usage=SimpleNamespace(input_tokens=7, output_tokens=4),
            )

    model = OpenAIResponsesModel(
        "unused",
        "gpt-4.1-mini",
        timeout_seconds=3.0,
        max_output_tokens=80,
        client=SimpleNamespace(responses=Responses()),
    )
    with pytest.raises(ModelFailure, match="forbidden owner claim"):
        model.generate([ConversationItem("user", "Hello")], "safety_abc")


def test_edit_and_delete_supersede_one_inbox_request_and_alert(tmp_path: Path) -> None:
    clock = Clock()
    model = RecordingModel(
        [request_turn("Original request"), request_turn("Correction")]
    )
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        message, _ = authorize(service, store, clock, text="Original request")
        clock.advance(seconds=1)
        edited = replace(
            message,
            update_id=2,
            text="Correction",
            edited_at=clock.now(),
        )
        assert service.handle_edit(edited).outcome == "request_captured"
        rows = store.public.execute("SELECT body FROM inbox_requests").fetchall()
        assert [str(row[0]) for row in rows] == ["Correction"]
        assert (
            store.public.execute("SELECT count(*) FROM notification_outbox").fetchone()[
                0
            ]
            == 1
        )

        assert (
            service.handle_delete(
                DeleteNotice(CONNECTION_ID, SENDER_A, (message.message_id,), 3)
            ).outcome
            == "deleted"
        )
        assert (
            store.public.execute("SELECT count(*) FROM inbox_requests").fetchone()[0]
            == 0
        )
        assert (
            store.public.execute("SELECT count(*) FROM notification_outbox").fetchone()[
                0
            ]
            == 0
        )
    finally:
        store.close()


def test_deleting_a_follow_up_removes_its_stable_request_chain(tmp_path: Path) -> None:
    clock = Clock()
    model = RecordingModel(
        [request_turn("Original request"), request_turn("Corrected request")]
    )
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock, text="Original request")
        clock.advance(seconds=1)
        follow_up = inbound(
            clock,
            update_id=2,
            message_id=12,
            text="Corrected request",
        )
        assert service.handle_message(follow_up).outcome == "request_captured"
        assert (
            store.public.execute("SELECT count(*) FROM inbox_requests").fetchone()[0]
            == 1
        )

        assert (
            service.handle_delete(
                DeleteNotice(CONNECTION_ID, SENDER_A, (follow_up.message_id,), 3)
            ).outcome
            == "deleted"
        )
        assert (
            store.public.execute("SELECT count(*) FROM inbox_requests").fetchone()[0]
            == 0
        )
        assert (
            store.public.execute("SELECT count(*) FROM notification_outbox").fetchone()[
                0
            ]
            == 0
        )
        assert (
            store.public.execute("SELECT count(*) FROM assistant_context").fetchone()[0]
            == 0
        )
    finally:
        store.close()


def test_multiple_edits_then_delete_remove_the_entire_request_context_chain(
    tmp_path: Path,
) -> None:
    clock = Clock()
    model = RecordingModel(
        [
            request_turn("Original request"),
            request_turn("First correction"),
            request_turn("Second correction"),
            answer_turn("Fresh answer."),
        ]
    )
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        message, _ = authorize(service, store, clock, text="Original request")
        clock.advance(seconds=1)
        assert (
            service.handle_edit(
                replace(
                    message,
                    update_id=2,
                    text="First correction",
                    edited_at=clock.now(),
                )
            ).outcome
            == "request_captured"
        )
        clock.advance(seconds=1)
        assert (
            service.handle_edit(
                replace(
                    message,
                    update_id=3,
                    text="Second correction",
                    edited_at=clock.now(),
                )
            ).outcome
            == "request_captured"
        )
        assert (
            service.handle_delete(
                DeleteNotice(CONNECTION_ID, SENDER_A, (message.message_id,), 4)
            ).outcome
            == "deleted"
        )
        assert (
            store.public.execute("SELECT count(*) FROM inbox_requests").fetchone()[0]
            == 0
        )
        assert (
            store.public.execute("SELECT count(*) FROM assistant_context").fetchone()[0]
            == 0
        )

        clock.advance(seconds=1)
        assert (
            service.handle_message(
                inbound(clock, update_id=5, message_id=15, text="A fresh question")
            ).outcome
            == "answer"
        )
        context, _ = model.calls[-1]
        assert "Original request" not in [item.text for item in context]
        assert "First correction" not in [item.text for item in context]
        assert "Second correction" not in [item.text for item in context]
    finally:
        store.close()


@pytest.mark.parametrize(
    ("text", "language"),
    [
        ("Your request has been approved.", "en"),
        ("Ваш запрос уже одобрен.", "ru"),
    ],
)
def test_owner_status_text_is_replaced_by_a_trusted_template(
    tmp_path: Path, text: str, language: str
) -> None:
    clock = Clock()
    model = RecordingModel([answer_turn("Initial answer."), answer_turn(text)])
    _, _, store, service = make_service(tmp_path, clock, model)
    try:
        authorize(service, store, clock)
        clock.advance(seconds=1)
        prompt = "Any status update?" if language == "en" else "Есть обновления?"
        result = service.handle_message(
            inbound(clock, update_id=2, message_id=12, text=prompt)
        )
        assert result.reply is not None
        expected = {
            "en": "I can't confirm Misha's request status. I can pass a request to him.",
            "ru": "Я не могу подтверждать статус запроса у Миши. Я могу передать ему запрос.",
        }
        assert result.reply.text == expected[language]
        assert text not in result.reply.text
    finally:
        store.close()


def test_responses_adapter_configures_the_official_client_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class OpenAI:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=OpenAI))
    model = OpenAIResponsesModel(
        "unit-test-key", "gpt-4.1-mini", timeout_seconds=2.5, max_output_tokens=80
    )
    assert captured == {"api_key": "unit-test-key", "timeout": 2.5, "max_retries": 0}
    assert isinstance(model.client, OpenAI)
