"""Strict DTOs shared with Policy Gate clients."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class Operation(str, Enum):
    MEETING_OPTIONS = "meeting.options"
    MEETING_SCHEDULE = "meeting.schedule"
    TASK_CREATE = "task.create"


class Scope(str, Enum):
    EXACT = "exact"
    BOUNDED = "bounded"
    STANDING = "standing"


class AdminKind(str, Enum):
    BLOCK = "block"
    UNBLOCK = "unblock"
    GRANT = "grant"
    REVOKE = "revoke"


class JournalState(str, Enum):
    CLAIMED = "claimed"
    SUCCEEDED = "succeeded"
    DEFINITE_FAILURE = "definite_failure"
    UNCERTAIN = "uncertain"
    CANCELLED = "cancelled"


class CandidateProvenance(str, Enum):
    """The code-owned origin class for a staged immutable action."""

    ORDINARY_PUBLIC = "ordinary_public"
    EXTERNAL_UNTRUSTED = "external_untrusted"


class ActionOrigin(str, Enum):
    """Immutable execution origin carried by every canonical action binding."""

    PUBLIC_SENDER = "public_sender"
    OWNER_EXTERNAL = "owner_external"


_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ExternalActionLink:
    """Digest-only identity that binds an external candidate to its source."""

    link_identity: str
    source_digest: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not _SHA256_HEX.fullmatch(value)
            for value in (self.link_identity, self.source_digest)
        ):
            raise ValueError("external action link must contain SHA-256 digests")


@dataclass(frozen=True)
class ExternalActionConfirmation:
    """Controller evidence that one newer owner control revalidated a source."""

    link: ExternalActionLink
    confirmation_sequence: int

    def __post_init__(self) -> None:
        if not isinstance(self.link, ExternalActionLink):
            raise ValueError("external action confirmation link is invalid")
        if (
            not isinstance(self.confirmation_sequence, int)
            or isinstance(self.confirmation_sequence, bool)
            or self.confirmation_sequence <= 0
        ):
            raise ValueError("external confirmation sequence is invalid")


JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]


def _canonical_value(value: object) -> JsonValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError("floating-point action values are forbidden")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("action object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError(
                    "action object keys collide after Unicode normalization"
                )
            normalized[normalized_key] = _canonical_value(item)
        return normalized
    raise ValueError("action value is not canonical JSON")


def canonical_json(value: object) -> str:
    """Return one locale-independent representation for security bindings."""

    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrustedReference:
    kind: str
    value: str


@dataclass(frozen=True)
class ActionBinding:
    """Complete trusted envelope plus model-bounded operation arguments."""

    action_id: str
    subject_id: str
    connection_id: str
    conversation_id: int
    update_id: int
    request_id: str
    operation: Operation
    arguments: Mapping[str, object]
    processing_authorization_version: str
    processing_authorization_revision: int
    processor_purpose: str
    origin: ActionOrigin = ActionOrigin.PUBLIC_SENDER
    _legacy_public_identity: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.origin, ActionOrigin):
            raise ValueError("action origin is invalid")
        if (
            self._legacy_public_identity
            and self.origin is not ActionOrigin.PUBLIC_SENDER
        ):
            raise ValueError("legacy action identity must be public")

    @classmethod
    def create(
        cls,
        *,
        subject_id: str,
        connection_id: str,
        conversation_id: int,
        update_id: int,
        request_id: str,
        operation: Operation,
        arguments: Mapping[str, object],
        processing_authorization_version: str,
        processing_authorization_revision: int,
        processor_purpose: str,
        origin: ActionOrigin = ActionOrigin.PUBLIC_SENDER,
    ) -> "ActionBinding":
        if (
            not isinstance(processing_authorization_revision, int)
            or isinstance(processing_authorization_revision, bool)
            or processing_authorization_revision <= 0
        ):
            raise ValueError("processing authorization revision must be positive")
        if not isinstance(origin, ActionOrigin):
            raise ValueError("action origin is invalid")
        fields: dict[str, object] = {
            "subject_id": subject_id,
            "connection_id": connection_id,
            "conversation_id": conversation_id,
            "update_id": update_id,
            "request_id": request_id,
            "operation": operation.value,
            "arguments": dict(arguments),
            "processing_authorization_version": processing_authorization_version,
            "processing_authorization_revision": processing_authorization_revision,
            "processor_purpose": processor_purpose,
            "origin": origin.value,
        }
        return cls(
            action_id=digest(fields),
            subject_id=subject_id,
            connection_id=connection_id,
            conversation_id=conversation_id,
            update_id=update_id,
            request_id=request_id,
            operation=operation,
            arguments=dict(arguments),
            processing_authorization_version=processing_authorization_version,
            processing_authorization_revision=processing_authorization_revision,
            processor_purpose=processor_purpose,
            origin=origin,
        )

    @property
    def uses_legacy_public_identity(self) -> bool:
        """Whether this is a pre-origin Unit 3 public binding.

        The flag is deliberately not serialised.  It exists only while a
        trusted durable pre-origin envelope is being recovered, so fresh
        callers cannot choose an origin-free external identity.
        """

        return self._legacy_public_identity

    @property
    def payload_digest(self) -> str:
        return digest(dict(self.arguments))

    @property
    def binding_digest(self) -> str:
        return digest(self.as_dict(include_action_id=False))

    def verify(self) -> bool:
        return self.action_id == self.binding_digest

    def as_dict(self, *, include_action_id: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "subject_id": self.subject_id,
            "connection_id": self.connection_id,
            "conversation_id": self.conversation_id,
            "update_id": self.update_id,
            "request_id": self.request_id,
            "operation": self.operation.value,
            "arguments": dict(self.arguments),
            "processing_authorization_version": self.processing_authorization_version,
            "processing_authorization_revision": self.processing_authorization_revision,
            "processor_purpose": self.processor_purpose,
        }
        if not self._legacy_public_identity:
            value["origin"] = self.origin.value
        if include_action_id:
            value["action_id"] = self.action_id
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ActionBinding":
        arguments = value.get("arguments")
        conversation_id = value.get("conversation_id")
        update_id = value.get("update_id")
        if not isinstance(arguments, dict):
            raise ValueError("stored action arguments are invalid")
        if not isinstance(conversation_id, int) or not isinstance(update_id, int):
            raise ValueError("stored action envelope is invalid")
        authorization_revision = value.get("processing_authorization_revision")
        if (
            not isinstance(authorization_revision, int)
            or isinstance(authorization_revision, bool)
            or authorization_revision <= 0
        ):
            raise ValueError("stored action authorization revision is invalid")
        try:
            origin = ActionOrigin(str(value["origin"]))
        except (KeyError, ValueError) as exc:
            raise ValueError("stored action origin is invalid") from exc
        return cls(
            action_id=str(value["action_id"]),
            subject_id=str(value["subject_id"]),
            connection_id=str(value["connection_id"]),
            conversation_id=conversation_id,
            update_id=update_id,
            request_id=str(value["request_id"]),
            operation=Operation(str(value["operation"])),
            arguments=arguments,
            processing_authorization_version=str(
                value["processing_authorization_version"]
            ),
            processing_authorization_revision=authorization_revision,
            processor_purpose=str(value["processor_purpose"]),
            origin=origin,
        )

    @classmethod
    def from_legacy_public_dict(cls, value: Mapping[str, object]) -> "ActionBinding":
        """Hydrate one exact pre-origin Unit 3 binding as public-only.

        This parser is intentionally separate from :meth:`from_dict`.  New
        wire and storage envelopes must carry an explicit origin; only a
        verified migration/recovery path may use the historic origin-free
        identity format.
        """

        expected_fields = {
            "action_id",
            "subject_id",
            "connection_id",
            "conversation_id",
            "update_id",
            "request_id",
            "operation",
            "arguments",
            "processing_authorization_version",
            "processing_authorization_revision",
            "processor_purpose",
        }
        if set(value) != expected_fields:
            raise ValueError("legacy action binding fields are invalid")
        arguments = value.get("arguments")
        conversation_id = value.get("conversation_id")
        update_id = value.get("update_id")
        if not isinstance(arguments, dict):
            raise ValueError("stored action arguments are invalid")
        if not isinstance(conversation_id, int) or not isinstance(update_id, int):
            raise ValueError("stored action envelope is invalid")
        authorization_revision = value.get("processing_authorization_revision")
        if (
            not isinstance(authorization_revision, int)
            or isinstance(authorization_revision, bool)
            or authorization_revision <= 0
        ):
            raise ValueError("stored action authorization revision is invalid")
        binding = cls(
            action_id=str(value["action_id"]),
            subject_id=str(value["subject_id"]),
            connection_id=str(value["connection_id"]),
            conversation_id=conversation_id,
            update_id=update_id,
            request_id=str(value["request_id"]),
            operation=Operation(str(value["operation"])),
            arguments=arguments,
            processing_authorization_version=str(
                value["processing_authorization_version"]
            ),
            processing_authorization_revision=authorization_revision,
            processor_purpose=str(value["processor_purpose"]),
            origin=ActionOrigin.PUBLIC_SENDER,
            _legacy_public_identity=True,
        )
        if not binding.verify():
            raise ValueError("legacy action binding identity is invalid")
        return binding


@dataclass(frozen=True)
class AdminDraft:
    kind: AdminKind
    operation: Operation | None = None
    scope: Scope | None = None
    constraints: Mapping[str, object] | None = None
    expires_at: int | None = None
    remaining_uses: int | None = None
    exact_binding: ActionBinding | None = None


@dataclass(frozen=True)
class PreparedIntent:
    intent_id: str
    preview: Mapping[str, object]
    expires_at: int


@dataclass(frozen=True)
class AdminResult:
    outcome: str
    action_result: "ActionResult | None" = None


@dataclass(frozen=True)
class ActionResult:
    outcome: str
    action_id: str


@dataclass(frozen=True)
class MeetingOptionsResult:
    """Safe Calendar output.  Busy data never crosses the Gate boundary."""

    outcome: str
    action_id: str
    slots: tuple[tuple[str, int, int, int], ...] = ()
    timezone: str = "UTC"


@dataclass(frozen=True)
class ActionSchema:
    operation: Operation
    arguments_schema: Mapping[str, object]
