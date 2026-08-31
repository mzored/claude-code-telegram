"""Typed hostile-data contracts shared by the Unit 4 broker and controller."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Protocol

from src.policy_gate.types import digest


class ExternalSource(str, Enum):
    """The only external record kinds Unit 4 understands."""

    INBOX = "inbox"
    TODOIST = "todoist"


_OPAQUE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_OPAQUE_METADATA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_PREFIX = b"assist-ai/external-read/v1\0"
EXTERNAL_SUMMARY_PREFIX = "External and untrusted summary: "


class ExternalReadError(RuntimeError):
    """The isolated read path could not safely satisfy a request."""


class ExternalReadUnavailable(ExternalReadError):
    """A source exists but its dedicated processor is not authorized or available."""


@dataclass(frozen=True)
class ExternalRecordRef:
    """One canonical opaque identifier, never a search expression or raw text."""

    source: ExternalSource
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, ExternalSource):
            raise ValueError("external source is invalid")
        if not isinstance(self.value, str) or not _OPAQUE_REFERENCE.fullmatch(
            self.value
        ):
            raise ValueError("external reference must be opaque and canonical")

    @classmethod
    def parse(cls, value: str) -> "ExternalRecordRef":
        if not isinstance(value, str) or value.count(":") != 1:
            raise ValueError("external reference is invalid")
        source, opaque = value.split(":", 1)
        try:
            return cls(ExternalSource(source), opaque)
        except ValueError as exc:
            raise ValueError("external reference is invalid") from exc

    def as_text(self) -> str:
        return f"{self.source.value}:{self.value}"

    def reference_hash(self) -> str:
        return hashlib.sha256(
            _DIGEST_PREFIX + b"ref\0" + self.as_text().encode("utf-8")
        ).hexdigest()


def source_digest(reference: ExternalRecordRef, content: str) -> str:
    """Bind source bytes to their exact opaque identifier without retaining either."""

    if not isinstance(content, str):
        raise ValueError("external content must be text")
    return hashlib.sha256(
        _DIGEST_PREFIX
        + b"content\0"
        + reference.as_text().encode("utf-8")
        + b"\0"
        + content.encode("utf-8")
    ).hexdigest()


def external_link_identity(reference_hash: str, source_digest_value: str) -> str:
    """Bind one digest-only source locator to its exact observed source bytes."""

    if not isinstance(reference_hash, str) or not _SHA256_HEX.fullmatch(reference_hash):
        raise ValueError("external reference hash is invalid")
    if not isinstance(source_digest_value, str) or not _SHA256_HEX.fullmatch(
        source_digest_value
    ):
        raise ValueError("external source digest is invalid")
    return hashlib.sha256(
        _DIGEST_PREFIX
        + b"link\0"
        + reference_hash.encode("ascii")
        + b"\0"
        + source_digest_value.encode("ascii")
    ).hexdigest()


@dataclass(frozen=True)
class ExternalSourceMetadata:
    """Trusted action envelope fields that contain no source body or title."""

    reference: ExternalRecordRef
    subject_id: str
    connection_id: str
    conversation_id: int
    update_id: int
    request_id: str
    processing_authorization_version: str
    processing_authorization_revision: int
    source_digest: str

    def __post_init__(self) -> None:
        opaque_strings = (
            self.subject_id,
            self.connection_id,
            self.request_id,
            self.processing_authorization_version,
        )
        if any(
            not isinstance(value, str) or not _OPAQUE_METADATA.fullmatch(value)
            for value in opaque_strings
        ):
            raise ValueError("external source metadata is incomplete")
        if not isinstance(self.source_digest, str) or not _SHA256_HEX.fullmatch(
            self.source_digest
        ):
            raise ValueError("external source digest is invalid")
        numeric = (
            self.conversation_id,
            self.update_id,
            self.processing_authorization_revision,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in numeric
        ):
            raise ValueError("external source metadata is invalid")


@dataclass(frozen=True)
class ExternalRecord:
    """A raw external record whose content is intentionally hidden from repr()."""

    metadata: ExternalSourceMetadata
    content: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, str) or not self.content:
            raise ValueError("external record content is required")
        if len(self.content.encode("utf-8")) > 16_000:
            raise ValueError("external record content is too large")
        if (
            source_digest(self.metadata.reference, self.content)
            != self.metadata.source_digest
        ):
            raise ValueError("external record source digest does not match content")

    @classmethod
    def create(
        cls,
        reference: ExternalRecordRef,
        *,
        subject_id: str,
        connection_id: str,
        conversation_id: int,
        update_id: int,
        request_id: str,
        processing_authorization_version: str,
        processing_authorization_revision: int,
        content: str,
    ) -> "ExternalRecord":
        return cls(
            ExternalSourceMetadata(
                reference=reference,
                subject_id=subject_id,
                connection_id=connection_id,
                conversation_id=conversation_id,
                update_id=update_id,
                request_id=request_id,
                processing_authorization_version=processing_authorization_version,
                processing_authorization_revision=processing_authorization_revision,
                source_digest=source_digest(reference, content),
            ),
            content,
        )


@dataclass(frozen=True)
class ExternalInspection:
    """A single labelled response that callers may show directly to the owner."""

    metadata: ExternalSourceMetadata
    summary: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.summary, str)
            or not self.summary.startswith(EXTERNAL_SUMMARY_PREFIX)
            or not self.summary[len(EXTERNAL_SUMMARY_PREFIX) :].strip()
        ):
            raise ValueError("external inspection summary is empty")
        if len(self.summary.encode("utf-8")) > 1_600:
            raise ValueError("external inspection summary is too large")


@dataclass(frozen=True)
class PublicTaskCandidateEnvelope:
    """Minimized task proposal available only through the owner-read broker."""

    candidate_id: str
    metadata: ExternalSourceMetadata
    arguments: Mapping[str, str | None]
    payload_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.candidate_id, str)
            or not _OPAQUE_METADATA.fullmatch(self.candidate_id)
            or set(self.arguments) != {"title", "due_date"}
            or not isinstance(self.arguments["title"], str)
            or not self.arguments["title"].strip()
            or (
                self.arguments["due_date"] is not None
                and not isinstance(self.arguments["due_date"], str)
            )
            or not isinstance(self.payload_digest, str)
            or not _SHA256_HEX.fullmatch(self.payload_digest)
            or self.payload_digest != digest(dict(self.arguments))
            or self.metadata.source_digest != self.payload_digest
        ):
            raise ValueError("public task candidate envelope is invalid")


class ExternalReadClient(Protocol):
    """The controller receives summaries and metadata, never record bodies."""

    def inspect(self, reference: ExternalRecordRef) -> ExternalInspection: ...

    def validate_for_prepare(
        self, reference: ExternalRecordRef
    ) -> ExternalSourceMetadata: ...

    def public_task_candidate(
        self, reference: ExternalRecordRef
    ) -> PublicTaskCandidateEnvelope: ...


__all__ = [
    "ExternalInspection",
    "ExternalReadClient",
    "ExternalReadError",
    "ExternalReadUnavailable",
    "ExternalRecord",
    "ExternalRecordRef",
    "ExternalSource",
    "ExternalSourceMetadata",
    "PublicTaskCandidateEnvelope",
    "EXTERNAL_SUMMARY_PREFIX",
    "external_link_identity",
    "source_digest",
]
