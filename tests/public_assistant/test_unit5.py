from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from src.policy_gate.calendar import CalendarPolicy, FakeCalendarApi
from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import (
    AdminDraft,
    AdminKind,
    Operation,
    Scope,
    TrustedReference,
)
from src.public_assistant.action_store import Unit3Store
from src.public_assistant.actions import ActionAssistantService, ActionCoordinator
from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.model import ActionProposal
from src.public_assistant.telegram_adapter import TelegramBusinessAdapter
from src.public_assistant.types import (
    ConnectionObservation,
    DeliveryState,
    InboundMessage,
)

PENDING_KEY = "pending-" + "p" * 40
PUBLIC_KEY = "public-" + "u" * 40
PSEUDONYM_KEY = b"pseudonym-" + b"s" * 40


class Clock:
    def __init__(self) -> None:
        self.value = int(datetime(2026, 8, 31, 12, tzinfo=UTC).timestamp())

    def now(self) -> float:
        return float(self.value)


def message(update_id: int = 1) -> InboundMessage:
    return InboundMessage(
        connection_id="connection-unit5",
        conversation_id=202005,
        sender_id=202005,
        message_id=17,
        update_id=update_id,
        text="Can we meet tomorrow?",
        sent_at=datetime(2026, 8, 31, 12, tzinfo=UTC),
    )


def calendar_gate(
    tmp_path: Path, clock: Clock, calendar: FakeCalendarApi
) -> tuple[PolicyGateService, GateStore]:
    store = GateStore(tmp_path / "gate.db", "g" * 40, clock=clock.now)
    gate = PolicyGateService(
        store,
        MockExecutor(),
        policy=PolicyConfig(
            enabled_operations=frozenset(
                {Operation.MEETING_OPTIONS, Operation.MEETING_SCHEDULE}
            ),
            calendar=CalendarPolicy(
                enabled=True,
                booking_calendar_id="booking",
                availability_calendar_ids=("booking",),
                timezone="America/New_York",
                credential_file=Path("/tmp/unit5-calendar-credential.json"),
            ),
        ),
        calendar_api=calendar,
        clock=clock.now,
    )
    return gate, store


def activate(coordinator: ActionCoordinator, item: InboundMessage) -> None:
    assert coordinator.activate_integration_authorization(
        item,
        "calendar-v1",
        1,
        {"Google Calendar": ("meeting options", "meeting scheduling")},
    )


def offered_callback(
    store: Unit3Store,
    item: InboundMessage,
    callback_data: str,
) -> None:
    reply = store.create_reply(
        item,
        "meeting_options",
        "Choose a time.",
        [[{"text": "Tomorrow at 10:00", "callback_data": callback_data}]],
    )
    store.finalize_reply(reply.reply_id, DeliveryState.SENT, telegram_message_id=817)


def proposal(clock: Clock) -> ActionProposal:
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    return ActionProposal(
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
    )


def test_sender_callback_creates_only_an_owner_confirmable_offer_binding(
    tmp_path: Path,
) -> None:
    clock = Clock()
    calendar = FakeCalendarApi()
    gate, gate_store = calendar_gate(tmp_path, clock, calendar)
    store = Unit3Store(
        tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.now
    )
    item = message()
    coordinator = ActionCoordinator(store, gate)
    try:
        activate(coordinator, item)
        delivery = coordinator.meeting_options(
            item,
            "REQ-UNIT5-OPTIONS",
            proposal(clock),
            90 * 24 * 60 * 60,
            coordinator.discover(item),
        )
        assert delivery.result.outcome == "verified_success"
        assert delivery.result.timezone == "America/New_York"
        assert len(delivery.controls) == 1
        label = ActionAssistantService._meeting_option_label(
            delivery.controls[0], delivery.result.timezone
        )
        expected_start = datetime.fromtimestamp(
            delivery.controls[0].start_at, ZoneInfo("America/New_York")
        )
        assert f"{expected_start:%H:%M}" in label
        assert label.endswith("America/New_York")
        assert not label.endswith("UTC")
        callback = delivery.controls[0].callback_data
        offered_callback(store, item, callback)

        assert (
            coordinator.select_meeting_offer(
                callback,
                actor_id=item.sender_id + 1,
                conversation_id=item.conversation_id,
                connection_id=item.connection_id,
                origin_message_id=817,
                callback_update_id=91,
            ).outcome
            == "denied"
        )
        selected = coordinator.select_meeting_offer(
            callback,
            actor_id=item.sender_id,
            conversation_id=item.conversation_id,
            connection_id=item.connection_id,
            origin_message_id=817,
            callback_update_id=91,
        )
        assert selected.outcome == "awaiting_owner_confirmation"
        notifications = store.due_notifications()
        assert len(notifications) == 1
        notification = notifications[0]
        assert notification.text == (
            f"Assistant Inbox request {notification.request_id} is ready."
        )
        confirmation = store.public.execute(
            "SELECT body FROM inbox_requests WHERE request_id=?",
            (notification.request_id,),
        ).fetchone()
        assert confirmation is not None
        assert str(confirmation["body"]) == (
            "Meeting selection requires exact owner confirmation. "
            f"Action reference: {selected.action_id}."
        )
        assert delivery.result.slots[0][0] not in str(confirmation["body"])
        row = store.public.execute(
            "SELECT arguments_json FROM public_action_intents WHERE action_id=?",
            (selected.action_id,),
        ).fetchone()
        assert row is not None
        assert (
            row["arguments_json"]
            == '{"offer_ref":"' + delivery.result.slots[0][0] + '"}'
        )
        assert "start_at" not in str(row["arguments_json"])
        assert calendar.insert_calls == []

        prepared = gate.prepare_admin(
            TrustedReference("action", selected.action_id),
            AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
            owner_id=1,
            control_chat_id=1,
            preview_message_id=10,
        )
        confirmed = gate.confirm_admin(
            prepared.intent_id, owner_id=1, control_chat_id=1, preview_message_id=10
        )
        assert confirmed.outcome == "executed"
        assert confirmed.action_result is not None
        assert confirmed.action_result.outcome == "verified_success"
        assert len(calendar.insert_calls) == 1
    finally:
        store.close()
        gate_store.close()


def test_sender_callback_submits_only_when_current_delegation_allows_it(
    tmp_path: Path,
) -> None:
    clock = Clock()
    calendar = FakeCalendarApi()
    gate, gate_store = calendar_gate(tmp_path, clock, calendar)
    store = Unit3Store(
        tmp_path / "public", PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.now
    )
    item = message()
    coordinator = ActionCoordinator(store, gate)
    try:
        activate(coordinator, item)
        subject = store.subject_ref(
            item.connection_id, item.conversation_id, item.sender_id
        )
        gate.register_subject(subject, {"managed_chat": "MCHAT-UNIT5-SUBJECT"})
        prepared = gate.prepare_admin(
            TrustedReference("managed_chat", "MCHAT-UNIT5-SUBJECT"),
            AdminDraft(
                AdminKind.GRANT,
                operation=Operation.MEETING_SCHEDULE,
                scope=Scope.BOUNDED,
                remaining_uses=1,
            ),
            owner_id=1,
            control_chat_id=1,
            preview_message_id=11,
        )
        assert gate.confirm_admin(prepared.intent_id, 1, 1, 11).outcome == "applied"
        delivery = coordinator.meeting_options(
            item,
            "REQ-UNIT5-DELEGATED",
            proposal(clock),
            90 * 24 * 60 * 60,
            coordinator.discover(item),
        )
        callback = delivery.controls[0].callback_data
        offered_callback(store, item, callback)
        selected = coordinator.select_meeting_offer(
            callback,
            actor_id=item.sender_id,
            conversation_id=item.conversation_id,
            connection_id=item.connection_id,
            origin_message_id=817,
            callback_update_id=92,
        )
        assert selected.outcome == "verified_success"
        assert len(calendar.insert_calls) == 1
    finally:
        store.close()
        gate_store.close()


@pytest.mark.asyncio
async def test_telegram_option_callback_uses_refreshed_authority_and_trusted_fields(
    tmp_path: Path,
) -> None:
    clock = Clock()
    item = message()
    config = PublicAssistantConfig(
        bot_token_file=tmp_path / "bot-token",
        pending_database_key_file=tmp_path / "pending-key",
        public_database_key_file=tmp_path / "public-key",
        pseudonym_key_file=tmp_path / "pseudonym-key",
        owner_id=101001,
        selected_sender_ids=frozenset({item.sender_id}),
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backup",
        privacy_url="https://example.test/privacy",
        privacy_policy_version="privacy-v1",
        processing_authorization_version="calendar-v1",
    )
    store = Unit3Store(
        config.data_dir, PENDING_KEY, PUBLIC_KEY, PSEUDONYM_KEY, clock=clock.now
    )
    calls: list[tuple[str, dict[str, int | str]]] = []

    class CallbackService:
        def observe_connection(self, observation: ConnectionObservation) -> bool:
            store.observe_connection(observation)
            return True

        def handle_meeting_offer(self, token: str, **kwargs: int | str) -> str:
            calls.append((token, kwargs))
            return "awaiting_owner_confirmation"

    class Bot:
        id = 8080
        can_reply = True

        async def get_business_connection(self, connection_id: str) -> Any:
            return SimpleNamespace(
                id=connection_id,
                user=SimpleNamespace(id=config.owner_id),
                is_enabled=True,
                rights=SimpleNamespace(can_reply=self.can_reply),
            )

    answers: list[str] = []

    async def answer(*, text: str) -> None:
        answers.append(text)

    query = SimpleNamespace(
        data="pa:mo:trusted-callback-token",
        from_user=SimpleNamespace(id=item.sender_id),
        message=SimpleNamespace(
            business_connection_id=item.connection_id,
            sender_business_bot=SimpleNamespace(id=Bot.id),
            chat=SimpleNamespace(id=item.conversation_id),
            message_id=817,
        ),
        answer=answer,
    )
    bot = Bot()
    adapter = TelegramBusinessAdapter(config, CallbackService(), store)
    try:
        await adapter.on_callback_query(
            SimpleNamespace(callback_query=query, update_id=99),
            SimpleNamespace(bot=bot),
        )
        assert calls == [
            (
                "pa:mo:trusted-callback-token",
                {
                    "actor_id": item.sender_id,
                    "conversation_id": item.conversation_id,
                    "connection_id": item.connection_id,
                    "origin_message_id": 817,
                    "callback_update_id": 99,
                },
            )
        ]
        assert answers == ["Selection recorded. It needs owner confirmation."]

        bot.can_reply = False
        await adapter.on_callback_query(
            SimpleNamespace(callback_query=query, update_id=100),
            SimpleNamespace(bot=bot),
        )
        assert len(calls) == 1
        assert answers[-1] == "This control is unavailable."
    finally:
        store.close()
