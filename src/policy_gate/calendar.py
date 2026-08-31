"""Narrow Calendar provider contract used only by the Policy Gate.

This module deliberately has no Telegram, model, controller, or public-store
dependency.  The production adapter is kept behind the same small contract as
the in-memory test adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

FIXED_EVENT_SUMMARY = "Reserved via public assistant"
FIXED_EVENT_DESCRIPTION = (
    "Created by the public assistant; contains no sender or request data."
)
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_CALENDAR_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/calendar.events",
        "https://www.googleapis.com/auth/calendar.events.freebusy",
    }
)


class CalendarConfigurationError(ValueError):
    """Calendar enablement is incomplete or grants more than the fixed adapter needs."""


@dataclass(frozen=True)
class BusyInterval:
    start_at: int
    end_at: int


@dataclass(frozen=True)
class OfferedSlot:
    offer_ref: str
    start_at: int
    end_at: int
    duration_minutes: int


@dataclass(frozen=True)
class CalendarEvent:
    event_id: str
    start_at: int
    end_at: int


class CalendarApi(Protocol):
    """The complete provider surface for Unit 5."""

    def free_busy(
        self, calendar_ids: Sequence[str], start_at: int, end_at: int
    ) -> tuple[BusyInterval, ...]: ...

    def insert_private_block(self, calendar_id: str, event: CalendarEvent) -> None: ...

    def get_event(self, calendar_id: str, event_id: str) -> CalendarEvent | None: ...


@dataclass(frozen=True)
class CalendarCredentials:
    """Only the refresh grant fields the Gate-owned adapter may use."""

    client_id: str
    client_secret: str
    refresh_token: str
    token_uri: str
    scopes: tuple[str, ...] = tuple(sorted(GOOGLE_CALENDAR_SCOPES))

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(value, str) and value
                for value in (
                    self.client_id,
                    self.client_secret,
                    self.refresh_token,
                    self.token_uri,
                )
            )
            or self.token_uri != GOOGLE_TOKEN_ENDPOINT
            or frozenset(self.scopes) != GOOGLE_CALENDAR_SCOPES
            or len(self.scopes) != len(GOOGLE_CALENDAR_SCOPES)
        ):
            raise CalendarConfigurationError("Calendar credentials are invalid")

    @classmethod
    def from_json(cls, value: str) -> "CalendarCredentials":
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise CalendarConfigurationError(
                "Calendar credential JSON is invalid"
            ) from exc
        if (
            not isinstance(parsed, dict)
            or set(parsed)
            != {"client_id", "client_secret", "refresh_token", "token_uri", "scopes"}
            or any(
                not isinstance(parsed.get(field), str) or not parsed[field]
                for field in (
                    "client_id",
                    "client_secret",
                    "refresh_token",
                    "token_uri",
                )
            )
            or not isinstance(parsed["scopes"], list)
            or any(
                not isinstance(scope, str) or not scope for scope in parsed["scopes"]
            )
        ):
            raise CalendarConfigurationError("Calendar credential fields are invalid")
        return cls(
            client_id=str(parsed["client_id"]),
            client_secret=str(parsed["client_secret"]),
            refresh_token=str(parsed["refresh_token"]),
            token_uri=str(parsed["token_uri"]),
            scopes=tuple(str(scope) for scope in parsed["scopes"]),
        )


HttpJson = Callable[[str, str, bytes | None, Mapping[str, str]], Mapping[str, object]]


def _http_json(
    method: str, url: str, body: bytes | None, headers: Mapping[str, str]
) -> Mapping[str, object]:
    request = Request(url, data=body, headers=dict(headers), method=method)
    with urlopen(request, timeout=10) as response:  # nosec B310: fixed HTTPS endpoints
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Calendar response must be an object")
    return value


class GoogleCalendarApi:
    """Fixed Google Calendar v3 adapter; it exposes no raw provider response."""

    def __init__(
        self, credentials: CalendarCredentials, *, request_json: HttpJson = _http_json
    ) -> None:
        self._credentials = credentials
        self._request_json = request_json

    def _access_token(self) -> str:
        body = urlencode(
            {
                "client_id": self._credentials.client_id,
                "client_secret": self._credentials.client_secret,
                "refresh_token": self._credentials.refresh_token,
                "grant_type": "refresh_token",
            }
        ).encode("ascii")
        value = self._request_json(
            "POST",
            self._credentials.token_uri,
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        token = value.get("access_token")
        scope = value.get("scope")
        if (
            not isinstance(token, str)
            or not token
            or not isinstance(scope, str)
            or frozenset(scope.split()) != GOOGLE_CALENDAR_SCOPES
        ):
            raise ValueError("Calendar token refresh failed")
        return token

    def validate_startup(self) -> None:
        """Verify the fixed refresh grant and exact least-privilege scope."""

        self._access_token()

    def _request(
        self, method: str, path: str, body: Mapping[str, object] | None = None
    ) -> Mapping[str, object]:
        encoded = (
            None
            if body is None
            else json.dumps(body, separators=(",", ":")).encode("utf-8")
        )
        headers = {"Authorization": f"Bearer {self._access_token()}"}
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        return self._request_json(
            method, "https://www.googleapis.com/calendar/v3" + path, encoded, headers
        )

    def free_busy(
        self, calendar_ids: Sequence[str], start_at: int, end_at: int
    ) -> tuple[BusyInterval, ...]:
        value = self._request(
            "POST",
            "/freeBusy",
            {
                "timeMin": datetime.fromtimestamp(start_at, UTC).isoformat(),
                "timeMax": datetime.fromtimestamp(end_at, UTC).isoformat(),
                "items": [{"id": item} for item in calendar_ids],
            },
        )
        calendars = value.get("calendars")
        if not isinstance(calendars, dict):
            raise ValueError("Calendar free/busy response is invalid")
        busy: list[BusyInterval] = []
        for calendar_id in calendar_ids:
            item = calendars.get(calendar_id)
            if (
                not isinstance(item, dict)
                or "errors" in item
                or not isinstance(item.get("busy"), list)
            ):
                raise ValueError("Calendar free/busy response is invalid")
            for interval in item["busy"]:
                if (
                    not isinstance(interval, dict)
                    or not isinstance(interval.get("start"), str)
                    or not isinstance(interval.get("end"), str)
                ):
                    raise ValueError("Calendar busy interval is invalid")
                try:
                    start_value = datetime.fromisoformat(
                        interval["start"].replace("Z", "+00:00")
                    )
                    end_value = datetime.fromisoformat(
                        interval["end"].replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise ValueError("Calendar busy interval is invalid") from exc
                if start_value.tzinfo is None or end_value.tzinfo is None:
                    raise ValueError("Calendar busy interval is invalid")
                start = int(start_value.timestamp())
                end = int(end_value.timestamp())
                if end <= start:
                    raise ValueError("Calendar busy interval is invalid")
                busy.append(BusyInterval(start, end))
        return tuple(busy)

    def insert_private_block(self, calendar_id: str, event: CalendarEvent) -> None:
        self._request(
            "POST",
            f"/calendars/{quote(calendar_id, safe='')}/events?sendUpdates=none",
            {
                "id": event.event_id,
                "summary": FIXED_EVENT_SUMMARY,
                "description": FIXED_EVENT_DESCRIPTION,
                "visibility": "private",
                "transparency": "opaque",
                "start": {
                    "dateTime": datetime.fromtimestamp(event.start_at, UTC).isoformat()
                },
                "end": {
                    "dateTime": datetime.fromtimestamp(event.end_at, UTC).isoformat()
                },
            },
        )

    def get_event(self, calendar_id: str, event_id: str) -> CalendarEvent | None:
        try:
            value = self._request(
                "GET",
                f"/calendars/{quote(calendar_id, safe='')}/events/"
                f"{quote(event_id, safe='')}",
            )
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        start = value.get("start")
        end = value.get("end")
        if (
            value.get("id") != event_id
            or value.get("summary") != FIXED_EVENT_SUMMARY
            or value.get("description") != FIXED_EVENT_DESCRIPTION
            or value.get("visibility") != "private"
            or value.get("transparency") != "opaque"
            or value.get("attendees") not in (None, [])
            or value.get("location") not in (None, "")
            or value.get("conferenceData") is not None
            or value.get("extendedProperties") is not None
            or value.get("attachments") not in (None, [])
            or value.get("recurrence") not in (None, [])
            or value.get("hangoutLink") is not None
            or value.get("eventType") not in (None, "default")
            or value.get("status") not in (None, "confirmed")
            or not isinstance(start, dict)
            or not isinstance(end, dict)
            or not isinstance(start.get("dateTime"), str)
            or not isinstance(end.get("dateTime"), str)
        ):
            return None
        try:
            starts_at = datetime.fromisoformat(start["dateTime"].replace("Z", "+00:00"))
            ends_at = datetime.fromisoformat(end["dateTime"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if starts_at.tzinfo is None or ends_at.tzinfo is None:
            return None
        start_at = int(starts_at.timestamp())
        end_at = int(ends_at.timestamp())
        if end_at <= start_at:
            return None
        return CalendarEvent(event_id, start_at, end_at)


@dataclass(frozen=True)
class CalendarPolicy:
    """Reviewed Calendar settings.  Disabled mode reads no provider credential."""

    enabled: bool = False
    booking_calendar_id: str = ""
    availability_calendar_ids: tuple[str, ...] = ()
    timezone: str = "UTC"
    working_days: frozenset[int] = frozenset({0, 1, 2, 3, 4})
    working_hour_start: int = 9
    working_hour_end: int = 18
    grid_minutes: int = 30
    before_buffer_minutes: int = 0
    after_buffer_minutes: int = 0
    offer_ttl_seconds: int = 15 * 60
    namespace: str = "public-assistant-calendar-v1"
    credential_file: Path | None = None

    def __post_init__(self) -> None:
        if not self.enabled:
            return
        identifiers = (self.booking_calendar_id, *self.availability_calendar_ids)
        if (
            not self.booking_calendar_id
            or not self.availability_calendar_ids
            or any(
                not isinstance(identifier, str)
                or not identifier
                or len(identifier) > 512
                or any(
                    character.isspace() or ord(character) < 32
                    for character in identifier
                )
                for identifier in identifiers
            )
        ):
            raise CalendarConfigurationError("Calendar IDs are required when enabled")
        if self.booking_calendar_id not in self.availability_calendar_ids:
            raise CalendarConfigurationError("booking calendar must be rechecked")
        if len(set(self.availability_calendar_ids)) != len(
            self.availability_calendar_ids
        ):
            raise CalendarConfigurationError("availability calendars must be distinct")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise CalendarConfigurationError(
                "Calendar timezone must be an IANA zone"
            ) from exc
        if (
            not self.working_days
            or not self.working_days.issubset(frozenset(range(7)))
            or not 0 <= self.working_hour_start < self.working_hour_end <= 24
            or self.grid_minutes <= 0
            or 60 % self.grid_minutes != 0
            or self.before_buffer_minutes < 0
            or self.after_buffer_minutes < 0
            or self.offer_ttl_seconds <= 0
            or self.credential_file is None
            or not self.credential_file.is_absolute()
            or not self.namespace
        ):
            raise CalendarConfigurationError("Calendar policy is invalid")

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)


def deterministic_event_id(namespace: str, action_id: str) -> str:
    """Return Google-compliant lowercase base32hex without padding."""

    encoded = (
        base64.b32hexencode(
            hashlib.sha256(f"{namespace}\0{action_id}".encode("utf-8")).digest()
        )
        .decode("ascii")
        .rstrip("=")
        .lower()
    )
    if not 5 <= len(encoded) <= 1024 or any(
        character not in "0123456789abcdefghijklmnopqrstuv" for character in encoded
    ):
        raise AssertionError("Calendar event ID is not base32hex")
    return encoded


def _valid_local_instants(local: datetime, zone: ZoneInfo) -> tuple[datetime, ...]:
    """Round-trip wall time and reject both skipped and repeated DST times."""

    instants: list[datetime] = []
    for fold in (0, 1):
        aware = local.replace(tzinfo=zone, fold=fold)
        instant = aware.astimezone(UTC)
        if (
            instant.astimezone(zone).replace(tzinfo=None) == local
            and instant not in instants
        ):
            instants.append(instant)
    return tuple(instants) if len(instants) == 1 else ()


def candidate_blocks(
    policy: CalendarPolicy,
    requested_date: date,
    duration_minutes: int,
    now: int,
) -> tuple[BusyInterval, ...]:
    """Calculate bounded UTC blocks, skipping invalid or ambiguous wall times."""

    if not policy.enabled or requested_date.weekday() not in policy.working_days:
        return ()
    earliest = now
    latest = now
    start = datetime(
        requested_date.year,
        requested_date.month,
        requested_date.day,
        policy.working_hour_start,
    )
    finish = datetime(
        requested_date.year,
        requested_date.month,
        requested_date.day,
        policy.working_hour_end,
    )
    duration = timedelta(minutes=duration_minutes)
    before = timedelta(minutes=policy.before_buffer_minutes)
    after = timedelta(minutes=policy.after_buffer_minutes)
    result: list[BusyInterval] = []
    current = start
    while current + duration <= finish:
        instant = _valid_local_instants(current, policy.zone)
        end_instant = _valid_local_instants(current + duration, policy.zone)
        if instant and end_instant:
            start_at = int((instant[0] - before).timestamp())
            end_at = int((end_instant[0] + after).timestamp())
            if start_at >= earliest and end_at > start_at and end_at >= latest:
                result.append(BusyInterval(start_at, end_at))
        current += timedelta(minutes=policy.grid_minutes)
    return tuple(result)


def fresh_offer_ref() -> str:
    return "OFR-" + secrets.token_urlsafe(18)


class FakeCalendarApi:
    """In-memory provider used by contract tests.  It never performs I/O."""

    def __init__(self) -> None:
        self.busy: dict[str, list[BusyInterval]] = {}
        self.events: dict[tuple[str, str], CalendarEvent] = {}
        self.free_busy_calls: list[tuple[tuple[str, ...], int, int]] = []
        self.insert_calls: list[tuple[str, CalendarEvent]] = []

    def free_busy(
        self, calendar_ids: Sequence[str], start_at: int, end_at: int
    ) -> tuple[BusyInterval, ...]:
        self.free_busy_calls.append((tuple(calendar_ids), start_at, end_at))
        return tuple(
            interval
            for calendar_id in calendar_ids
            for interval in self.busy.get(calendar_id, [])
            if interval.start_at < end_at and interval.end_at > start_at
        )

    def insert_private_block(self, calendar_id: str, event: CalendarEvent) -> None:
        self.insert_calls.append((calendar_id, event))
        key = (calendar_id, event.event_id)
        existing = self.events.get(key)
        if existing is not None and existing != event:
            raise ValueError("Calendar event ID collision")
        self.events[key] = event
        self.busy.setdefault(calendar_id, []).append(
            BusyInterval(event.start_at, event.end_at)
        )

    def get_event(self, calendar_id: str, event_id: str) -> CalendarEvent | None:
        return self.events.get((calendar_id, event_id))
