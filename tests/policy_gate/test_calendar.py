from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Protocol
from zoneinfo import ZoneInfo

import pytest

from src.policy_gate.calendar import (
    GOOGLE_CALENDAR_SCOPES,
    BusyInterval,
    CalendarConfigurationError,
    CalendarCredentials,
    CalendarEvent,
    CalendarEventMismatchError,
    CalendarPolicy,
    FakeCalendarApi,
    GoogleCalendarApi,
    candidate_blocks,
    deterministic_event_id,
)
from src.policy_gate.config import GateConfig
from src.policy_gate.executors import MockExecutor
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import (
    ActionBinding,
    AdminDraft,
    AdminKind,
    Operation,
    Scope,
    TrustedReference,
)


class _TimeoutAfterInsert(FakeCalendarApi):
    def insert_private_block(self, calendar_id: str, event: object) -> None:
        super().insert_private_block(calendar_id, event)  # type: ignore[arg-type]
        raise TimeoutError("provider response lost")


class _UnresolvedCalendar(_TimeoutAfterInsert):
    def __init__(self) -> None:
        super().__init__()
        self.lookup_calls = 0

    def get_event(self, calendar_id: str, event_id: str) -> CalendarEvent | None:
        del calendar_id, event_id
        self.lookup_calls += 1
        raise TimeoutError("provider lookup unavailable")


class _Clock(Protocol):
    value: int

    def now(self) -> float: ...


def _calendar_gate(
    tmp_path: Path,
    clock: _Clock,
    calendar: FakeCalendarApi,
    *,
    unresolved_write_breaker_threshold: int = 3,
) -> PolicyGateService:
    policy = PolicyConfig(
        enabled_operations=frozenset(
            {Operation.MEETING_OPTIONS, Operation.MEETING_SCHEDULE}
        ),
        unresolved_write_breaker_threshold=unresolved_write_breaker_threshold,
        calendar=CalendarPolicy(
            enabled=True,
            booking_calendar_id="booking",
            availability_calendar_ids=("availability", "booking"),
            timezone="America/New_York",
            credential_file=Path("/tmp/unit5-calendar-credential.json"),
        ),
    )
    service = PolicyGateService(
        GateStore(tmp_path / "calendar.db", "k" * 40, clock=clock.now),
        MockExecutor(),
        policy=policy,
        calendar_api=calendar,
        clock=clock.now,
    )
    service.register_subject("calendar-subject", {"managed_chat": "calendar-chat"})
    service.activate_receipt(
        "calendar-subject",
        "calendar-v1",
        1,
        {"Google Calendar": ("meeting options", "meeting scheduling")},
    )
    return service


def _binding(
    service: PolicyGateService,
    clock: _Clock,
    operation: Operation,
    arguments: dict[str, object],
    update_id: int,
) -> ActionBinding:
    return ActionBinding.create(
        subject_id="calendar-subject",
        connection_id="calendar-connection",
        conversation_id=33,
        update_id=update_id,
        request_id="CAL-REQUEST",
        operation=operation,
        arguments=arguments,
        processing_authorization_version="calendar-v1",
        processing_authorization_revision=1,
        processor_purpose=(
            "meeting options"
            if operation is Operation.MEETING_OPTIONS
            else "meeting scheduling"
        ),
    )


def _grant_schedule(service: PolicyGateService, *, remaining_uses: int = 1) -> None:
    prepared = service.prepare_admin(
        TrustedReference("managed_chat", "calendar-chat"),
        AdminDraft(
            AdminKind.GRANT,
            operation=Operation.MEETING_SCHEDULE,
            scope=Scope.BOUNDED,
            remaining_uses=remaining_uses,
        ),
        owner_id=1,
        control_chat_id=1,
        preview_message_id=1,
    )
    assert (
        service.confirm_admin(
            prepared.intent_id, owner_id=1, control_chat_id=1, preview_message_id=1
        ).outcome
        == "applied"
    )


def test_offers_are_opaque_and_only_a_granted_offer_can_schedule(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = FakeCalendarApi()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 2},
        1,
    )
    result = service.meeting_options(options)
    assert result.outcome == "verified_success"
    assert result.slots and result.slots[0][0].startswith("OFR-")
    assert service.allowed_actions("calendar-subject", "calendar-v1", 1) == (
        Operation.MEETING_OPTIONS,
    )
    arbitrary = _binding(
        service,
        clock,
        Operation.MEETING_SCHEDULE,
        {"start_at": result.slots[0][1], "duration_minutes": 30},
        2,
    )
    assert service.submit_action(arbitrary).outcome == "binding_mismatch"
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": result.slots[0][0]}, 3
    )
    assert service.submit_action(schedule).outcome == "verified_success"
    assert len(fake.insert_calls) == 1


def test_final_conflict_and_timeout_reconcile_without_second_insert(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = _TimeoutAfterInsert()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
        10,
    )
    offer = service.meeting_options(options).slots[0]
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": offer[0]}, 11
    )
    assert service.submit_action(schedule).outcome == "uncertain"
    assert service.reconcile_action(schedule.action_id).outcome == "verified_success"
    assert len(fake.insert_calls) == 1


def test_present_mismatched_event_stays_unresolved_and_blocks_erasure(
    tmp_path: Path, clock: _Clock
) -> None:
    credentials = CalendarCredentials(
        "client", "secret", "refresh", "https://oauth2.googleapis.com/token"
    )

    def request(method: str, url: str, body: bytes | None, headers: object) -> object:
        del body, headers
        if url == "https://oauth2.googleapis.com/token":
            return {
                "access_token": "test-token",
                "scope": " ".join(sorted(GOOGLE_CALENDAR_SCOPES)),
            }
        if url.endswith("/freeBusy"):
            return {
                "calendars": {
                    "availability": {"busy": []},
                    "booking": {"busy": []},
                }
            }
        if method == "POST":
            raise TimeoutError("provider response lost")
        if method == "GET":
            return {
                "id": url.rsplit("/", 1)[-1],
                "summary": "different summary",
                "description": "Created by the public assistant; contains no sender or request data.",
                "visibility": "private",
                "transparency": "opaque",
                "start": {"dateTime": "2026-09-01T12:00:00+00:00"},
                "end": {"dateTime": "2026-09-01T12:30:00+00:00"},
            }
        raise AssertionError("unexpected Calendar request")

    service = _calendar_gate(
        tmp_path,
        clock,
        GoogleCalendarApi(credentials, request_json=request),  # type: ignore[arg-type]
    )
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
        15,
    )
    offer = service.meeting_options(options).slots[0]
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": offer[0]}, 16
    )

    assert service.submit_action(schedule).outcome == "uncertain"
    assert service.reconcile_action(schedule.action_id).outcome == "uncertain"
    journal = service.store.database.execute(
        "SELECT state, outcome, binding_json FROM action_journal WHERE action_id=?",
        (schedule.action_id,),
    ).fetchone()
    assert journal is not None
    assert journal["state"] == "uncertain"
    assert journal["outcome"] == "uncertain"
    assert str(journal["binding_json"]) != "{}"
    assert (
        service.store.remaining_uses("calendar-subject", Operation.MEETING_SCHEDULE)
        == 0
    )
    reservation = service.store.database.execute(
        "SELECT action_id FROM calendar_reservations WHERE action_id=?",
        (schedule.action_id,),
    ).fetchone()
    assert reservation is not None
    assert service.erase_subject("calendar-subject") == "pending_reconciliation"
    assert (
        service.store.database.execute(
            "SELECT action_id FROM calendar_reservations WHERE action_id=?",
            (schedule.action_id,),
        ).fetchone()
        is not None
    )


def test_worker_reconciles_a_crash_after_claim_and_retries_only_after_absence(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = FakeCalendarApi()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
        20,
    )
    offer = service.meeting_options(options).slots[0]
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": offer[0]}, 21
    )

    def crash_after_claim(stage: str) -> None:
        if stage == "after_claim":
            raise RuntimeError("simulated process crash")

    with pytest.raises(RuntimeError, match="simulated process crash"):
        service.submit_action(schedule, crash_hook=crash_after_claim)
    reservation = service.store.database.execute(
        "SELECT event_id FROM calendar_reservations WHERE action_id=?",
        (schedule.action_id,),
    ).fetchone()
    assert reservation is not None
    clock.value += service.policy.claim_lease_seconds + 1
    assert service.recover_claimed_actions() == 1
    assert service.reconcile_action(schedule.action_id).outcome == "denied"
    assert service.submit_action(schedule).outcome == "verified_success"
    assert len(fake.insert_calls) == 1


def test_verified_absence_does_not_reopen_an_expired_offer(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = FakeCalendarApi()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
        25,
    )
    offer = service.meeting_options(options).slots[0]
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": offer[0]}, 26
    )

    def crash_after_claim(stage: str) -> None:
        if stage == "after_claim":
            raise RuntimeError("simulated process crash")

    with pytest.raises(RuntimeError, match="simulated process crash"):
        service.submit_action(schedule, crash_hook=crash_after_claim)
    clock.value += (
        max(
            service.policy.claim_lease_seconds,
            service.policy.calendar.offer_ttl_seconds,
        )
        + 1
    )
    assert service.recover_claimed_actions() == 1
    journal = service.store.database.execute(
        "SELECT state, outcome FROM action_journal WHERE action_id=?",
        (schedule.action_id,),
    ).fetchone()
    assert journal is not None
    assert tuple(journal) == ("definite_failure", "verified_absent")
    assert service.submit_action(schedule).outcome == "denied"
    assert fake.insert_calls == []


def test_repeated_unresolved_calendar_lookups_keep_the_write_breaker_open(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = _UnresolvedCalendar()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    _grant_schedule(service, remaining_uses=3)
    schedules: list[ActionBinding] = []
    for index in range(3):
        options = _binding(
            service,
            clock,
            Operation.MEETING_OPTIONS,
            {
                "date": requested.isoformat(),
                "duration_minutes": 30,
                "candidate_count": 1,
            },
            40 + index * 2,
        )
        offer = service.meeting_options(options).slots[0]
        schedule = _binding(
            service,
            clock,
            Operation.MEETING_SCHEDULE,
            {"offer_ref": offer[0]},
            41 + index * 2,
        )
        schedules.append(schedule)
        assert service.submit_action(schedule).outcome == "uncertain"

    breaker = service.store.database.execute(
        "SELECT is_open FROM breakers WHERE name='writes'"
    ).fetchone()
    assert breaker is not None and int(breaker["is_open"]) == 1
    assert service.reconcile_action(schedules[0].action_id).outcome == "uncertain"
    assert service.reconcile_action(schedules[0].action_id).outcome == "uncertain"
    assert fake.lookup_calls == 2
    journal = service.store.database.execute(
        "SELECT state, binding_json FROM action_journal WHERE action_id=?",
        (schedules[0].action_id,),
    ).fetchone()
    assert journal is not None
    assert tuple(journal)[0] == "uncertain"
    assert str(journal["binding_json"]) != "{}"


def test_verified_absence_allows_clean_subject_erasure(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = FakeCalendarApi()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
        50,
    )
    offer = service.meeting_options(options).slots[0]
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": offer[0]}, 51
    )

    def crash_after_claim(stage: str) -> None:
        if stage == "after_claim":
            raise RuntimeError("simulated process crash")

    with pytest.raises(RuntimeError, match="simulated process crash"):
        service.submit_action(schedule, crash_hook=crash_after_claim)
    clock.value += service.policy.claim_lease_seconds + 1
    assert service.recover_claimed_actions() == 1
    assert service.erase_subject("calendar-subject") == "erased"
    journal = service.store.database.execute(
        "SELECT binding_json FROM action_journal WHERE action_id=?",
        (schedule.action_id,),
    ).fetchone()
    assert journal is not None and journal["binding_json"] == "{}"
    assert (
        service.store.database.execute(
            "SELECT action_id FROM calendar_reservations WHERE action_id=?",
            (schedule.action_id,),
        ).fetchone()
        is None
    )


def test_calendar_definite_failure_does_not_reclaim_the_same_offer(
    tmp_path: Path, clock: _Clock
) -> None:
    fake = FakeCalendarApi()
    service = _calendar_gate(tmp_path, clock, fake)
    requested = datetime.fromtimestamp(
        clock.value, ZoneInfo("America/New_York")
    ).date() + timedelta(days=1)
    options = _binding(
        service,
        clock,
        Operation.MEETING_OPTIONS,
        {"date": requested.isoformat(), "duration_minutes": 30, "candidate_count": 1},
        30,
    )
    offer = service.meeting_options(options).slots[0]
    _grant_schedule(service)
    schedule = _binding(
        service, clock, Operation.MEETING_SCHEDULE, {"offer_ref": offer[0]}, 31
    )
    # The final recheck sees this conflict after an offer was issued.
    fake.busy["booking"] = [BusyInterval(offer[1], offer[2])]
    assert service.submit_action(schedule).outcome == "definite_failure"
    assert service.submit_action(schedule).outcome == "definite_failure"
    assert fake.insert_calls == []


def test_dst_and_event_identifier_are_provider_safe() -> None:
    policy = CalendarPolicy(
        enabled=True,
        booking_calendar_id="booking",
        availability_calendar_ids=("booking",),
        timezone="America/New_York",
        working_days=frozenset({6}),
        working_hour_start=1,
        working_hour_end=4,
        grid_minutes=30,
        credential_file=Path("/tmp/unit5-calendar-credential.json"),
    )
    blocks = candidate_blocks(policy, date(2026, 3, 8), 30, 0)
    assert all(
        datetime.fromtimestamp(block.start_at, policy.zone).hour != 2
        for block in blocks
    )
    event_id = deterministic_event_id("calendar-test", "action-test")
    assert event_id == deterministic_event_id("calendar-test", "action-test")
    assert set(event_id) <= set("0123456789abcdefghijklmnopqrstuv")

    lord_howe = CalendarPolicy(
        enabled=True,
        booking_calendar_id="booking",
        availability_calendar_ids=("booking",),
        timezone="Australia/Lord_Howe",
        working_days=frozenset({6}),
        working_hour_start=1,
        working_hour_end=4,
        grid_minutes=30,
        credential_file=Path("/tmp/unit5-calendar-credential.json"),
    )
    half_hour_transition = candidate_blocks(lord_howe, date(2026, 10, 4), 60, 0)
    assert half_hour_transition
    assert all(
        block.end_at - block.start_at == 60 * 60 for block in half_hour_transition
    )


def test_google_adapter_has_a_fixed_anonymous_event_body() -> None:
    calls: list[tuple[str, str, bytes | None, object]] = []

    def request(method: str, url: str, body: bytes | None, headers: object) -> object:
        calls.append((method, url, body, headers))
        if url == "https://oauth2.googleapis.com/token":
            return {
                "access_token": "test-token",
                "scope": " ".join(sorted(GOOGLE_CALENDAR_SCOPES)),
            }
        return {}

    adapter = GoogleCalendarApi(
        CalendarCredentials(
            "client", "secret", "refresh", "https://oauth2.googleapis.com/token"
        ),
        request_json=request,  # type: ignore[arg-type]
    )
    from src.policy_gate.calendar import CalendarEvent

    adapter.insert_private_block("booking", CalendarEvent("0123abc", 100, 200))
    assert len(calls) == 2
    assert calls[1][1].endswith("/calendars/booking/events?sendUpdates=none")
    assert calls[1][2] == (
        b'{"id":"0123abc","summary":"Reserved via public assistant",'
        b'"description":"Created by the public assistant; contains no sender or request data.",'
        b'"visibility":"private","transparency":"opaque",'
        b'"start":{"dateTime":"1970-01-01T00:01:40+00:00"},'
        b'"end":{"dateTime":"1970-01-01T00:03:20+00:00"}}'
    )


def test_google_adapter_rejects_missing_scope_calendar_errors_and_risky_recovery_event() -> (
    None
):
    credentials = CalendarCredentials(
        "client", "secret", "refresh", "https://oauth2.googleapis.com/token"
    )

    def wrong_scope(
        method: str, url: str, body: bytes | None, headers: object
    ) -> object:
        del method, url, body, headers
        return {"access_token": "test-token", "scope": "calendar.events"}

    with pytest.raises(ValueError, match="token refresh"):
        GoogleCalendarApi(credentials, request_json=wrong_scope).validate_startup()  # type: ignore[arg-type]

    def calendar_error(
        method: str, url: str, body: bytes | None, headers: object
    ) -> object:
        del method, body, headers
        if url == "https://oauth2.googleapis.com/token":
            return {
                "access_token": "test-token",
                "scope": " ".join(sorted(GOOGLE_CALENDAR_SCOPES)),
            }
        return {
            "calendars": {"booking": {"busy": [], "errors": [{"reason": "forbidden"}]}}
        }

    with pytest.raises(ValueError, match="free/busy"):
        GoogleCalendarApi(credentials, request_json=calendar_error).free_busy(  # type: ignore[arg-type]
            ("booking",), 100, 200
        )

    def naive_busy(
        method: str, url: str, body: bytes | None, headers: object
    ) -> object:
        del method, body, headers
        if url == "https://oauth2.googleapis.com/token":
            return {
                "access_token": "test-token",
                "scope": " ".join(sorted(GOOGLE_CALENDAR_SCOPES)),
            }
        return {
            "calendars": {
                "booking": {
                    "busy": [
                        {
                            "start": "1970-01-01T00:01:40",
                            "end": "1970-01-01T00:03:20",
                        }
                    ]
                }
            }
        }

    with pytest.raises(ValueError, match="busy interval"):
        GoogleCalendarApi(credentials, request_json=naive_busy).free_busy(  # type: ignore[arg-type]
            ("booking",), 100, 200
        )

    def risky_event(
        method: str, url: str, body: bytes | None, headers: object
    ) -> object:
        del method, body, headers
        if url == "https://oauth2.googleapis.com/token":
            return {
                "access_token": "test-token",
                "scope": " ".join(sorted(GOOGLE_CALENDAR_SCOPES)),
            }
        return {
            "id": "event-a",
            "summary": "Reserved via public assistant",
            "description": "Created by the public assistant; contains no sender or request data.",
            "visibility": "private",
            "transparency": "opaque",
            "start": {"dateTime": "1970-01-01T00:01:40+00:00"},
            "end": {"dateTime": "1970-01-01T00:03:20+00:00"},
            "extendedProperties": {"private": {"untrusted": "value"}},
        }

    with pytest.raises(CalendarEventMismatchError, match="event mismatch"):
        GoogleCalendarApi(credentials, request_json=risky_event).get_event(  # type: ignore[arg-type]
            "booking", "event-a"
        )


def test_calendar_credentials_require_exact_fixed_scope_set() -> None:
    with pytest.raises(CalendarConfigurationError, match="credentials"):
        CalendarCredentials.from_json(
            '{"client_id":"client","client_secret":"secret","refresh_token":"refresh",'
            '"token_uri":"https://oauth2.googleapis.com/token","scopes":[]}'
        )


def test_disabled_configuration_never_reads_calendar_credential(tmp_path: Path) -> None:
    env = {
        "POLICY_GATE_DATA_DIR": str(tmp_path / "data"),
        "POLICY_GATE_DATABASE_KEY_FILE": str(tmp_path / "db-key"),
        "POLICY_GATE_SOCKET_PATH": str(tmp_path / "gate.sock"),
        "POLICY_GATE_PUBLIC_UID": "1001",
        "POLICY_GATE_CONTROLLER_UID": "1002",
        "POLICY_GATE_CLIENT_GID": "1003",
        "POLICY_GATE_CALENDAR_ENABLED": "0",
        "POLICY_GATE_CALENDAR_CREDENTIAL_FILE": str(tmp_path / "missing.json"),
    }
    config = GateConfig.from_environment(env)
    assert not config.calendar.enabled
