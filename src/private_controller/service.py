"""One-shot drafting plus model-free confirmation for owner administration."""

from __future__ import annotations

from typing import Callable, Protocol

from src.external_read import (
    ExternalInspection,
    ExternalReadClient,
    ExternalReadError,
    ExternalRecordRef,
    ExternalSourceMetadata,
    external_link_identity,
)
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    AdminDraft,
    AdminKind,
    AdminResult,
    ExternalActionConfirmation,
    ExternalActionLink,
    Operation,
    PreparedIntent,
    Scope,
    TrustedReference,
)
from src.private_controller.origin import (
    PersistedRun,
    RunOrigin,
    RunOriginLedger,
    RunSource,
)


class IntentInterpreter(Protocol):
    """No-tools one-shot interpreter supplied by the private controller."""

    def draft(self, instruction: str) -> AdminDraft: ...


class ControllerGateClient(Protocol):
    """Administration-only Gate client; it exposes no Gate storage surface."""

    def prepare_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent: ...

    def confirm_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
    ) -> AdminResult: ...

    def stage_owner_exact_action(
        self,
        request_reference: TrustedReference,
        binding: ActionBinding,
        external_link: ExternalActionLink,
    ) -> bool: ...

    def prepare_external_admin(
        self,
        reference: TrustedReference,
        draft: AdminDraft,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_link: ExternalActionLink,
        minimum_confirmation_sequence: int,
        ttl_seconds: int = 300,
    ) -> PreparedIntent: ...

    def confirm_external_admin(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_confirmation: ExternalActionConfirmation,
    ) -> AdminResult: ...

    def external_intent_execution_started(
        self,
        intent_id: str,
        owner_id: int,
        control_chat_id: int,
        preview_message_id: int,
        external_link: ExternalActionLink,
    ) -> bool: ...


class PrivateControllerService:
    """Resolve identity locally; the interpreter can propose scope only."""

    def __init__(
        self,
        gate: ControllerGateClient,
        runs: RunOriginLedger,
        interpreter: IntentInterpreter,
        owner_id: int,
        control_chat_id: int,
        *,
        external_reads: ExternalReadClient | None = None,
    ) -> None:
        if owner_id <= 0 or control_chat_id <= 0:
            raise ValueError("one explicit owner and control chat are required")
        self.gate = gate
        self.runs = runs
        self.interpreter = interpreter
        self.owner_id = owner_id
        self.control_chat_id = control_chat_id
        self.external_reads = external_reads

    def _require_fresh_direct_owner(self, run_id: str) -> PersistedRun:
        run = self.runs.require(run_id)
        if (
            run.origin is not RunOrigin.DIRECT_OWNER
            or not run.fresh
            or run.forwarded
            or run.context_only
            or run.actor_id != self.owner_id
            or run.chat_id != self.control_chat_id
        ):
            raise PermissionError("only a fresh direct-owner run may use this control")
        return run

    def _require_fresh_external_owner(self, run_id: str) -> PersistedRun:
        """Accept only a new Telegram command, never a session or callback path."""

        run = self._require_fresh_direct_owner(run_id)
        if run.source is not RunSource.TELEGRAM or run.resumed_session:
            raise PermissionError("external control requires a fresh owner message")
        return run

    def prepare(
        self,
        run_id: str,
        reference: TrustedReference,
        instruction: str,
        *,
        preview_message_id: int,
    ) -> PreparedIntent:
        self._require_fresh_direct_owner(run_id)
        if not instruction.strip():
            raise ValueError("owner instruction is empty")
        draft = self.interpreter.draft(instruction)
        prepared = self.gate.prepare_admin(
            reference,
            draft,
            owner_id=self.owner_id,
            control_chat_id=self.control_chat_id,
            preview_message_id=preview_message_id,
        )
        self.runs.link_intent(prepared.intent_id, run_id)
        return prepared

    def _external_reads(self) -> ExternalReadClient:
        if self.external_reads is None:
            raise ValueError("external inspection is disabled")
        return self.external_reads

    def inspect_external(
        self, run_id: str, reference: ExternalRecordRef
    ) -> ExternalInspection:
        """Inspect one exact hostile record without invoking the private agent."""

        self._require_fresh_external_owner(run_id)
        self.runs.claim_external_control(run_id)
        return self._external_reads().inspect(reference)

    @staticmethod
    def _owner_task_arguments(title: str) -> dict[str, object]:
        if not isinstance(title, str):
            raise ValueError("owner task title is invalid")
        normalized = title.strip()
        if not normalized or len(normalized) > 200:
            raise ValueError("owner task title is invalid")
        return {"title": normalized, "due_date": None}

    def _exact_external_binding(
        self, metadata: ExternalSourceMetadata, title: str
    ) -> ActionBinding:
        return ActionBinding.create(
            subject_id=metadata.subject_id,
            connection_id=metadata.connection_id,
            conversation_id=metadata.conversation_id,
            update_id=metadata.update_id,
            request_id=metadata.request_id,
            operation=Operation.TASK_CREATE,
            arguments=self._owner_task_arguments(title),
            processing_authorization_version=metadata.processing_authorization_version,
            processing_authorization_revision=(
                metadata.processing_authorization_revision
            ),
            processor_purpose="external task creation",
            origin=ActionOrigin.OWNER_EXTERNAL,
        )

    @staticmethod
    def _external_gate_link(
        reference: ExternalRecordRef, metadata: ExternalSourceMetadata
    ) -> ExternalActionLink:
        if metadata.reference != reference:
            raise PermissionError("external source reference is invalid")
        return ExternalActionLink(
            # The source reference itself remains outside the Gate.  The public
            # broker and controller retain only this deterministic hash linkage.
            external_link_identity(reference.reference_hash(), metadata.source_digest),
            metadata.source_digest,
        )

    def prepare_external(
        self,
        run_id: str,
        reference: ExternalRecordRef,
        owner_task_title: str,
        *,
        preview_message_id: int,
        crash_hook: Callable[[str], None] | None = None,
    ) -> PreparedIntent:
        """Stage exactly one owner-authored task from current trusted metadata."""

        preparation = self._require_fresh_external_owner(run_id)
        self.runs.claim_external_control(run_id)
        metadata = self._external_reads().validate_for_prepare(reference)
        external_link = self._external_gate_link(reference, metadata)
        binding = self._exact_external_binding(metadata, owner_task_title)
        if not self.gate.stage_owner_exact_action(
            TrustedReference("request", metadata.request_id),
            binding,
            external_link,
        ):
            raise PermissionError("exact external action was rejected")
        prepared = self.gate.prepare_external_admin(
            TrustedReference("action", binding.action_id),
            AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
            owner_id=self.owner_id,
            control_chat_id=self.control_chat_id,
            preview_message_id=preview_message_id,
            external_link=external_link,
            minimum_confirmation_sequence=preparation.sequence,
        )
        if crash_hook is not None:
            crash_hook("after_gate_preview")
        self.runs.link_external_intent(
            prepared.intent_id,
            run_id,
            reference,
            metadata,
        )
        return prepared

    def confirm(
        self,
        run_id: str,
        intent_id: str,
        preview_message_id: int,
        *,
        external_reference: ExternalRecordRef | None = None,
    ) -> AdminResult:
        confirmation = self.runs.require_second_fresh_control(intent_id, run_id)
        external_intent = self.runs.has_external_link(intent_id)
        if external_intent:
            if external_reference is None:
                raise PermissionError("external source reference is required")
            if (
                confirmation.source is not RunSource.TELEGRAM
                or confirmation.resumed_session
            ):
                raise PermissionError("external control requires a fresh owner message")
            self.runs.claim_external_control(run_id)
            self.runs.require_external_reference(intent_id, external_reference)
            external_link = self.runs.external_gate_link(intent_id)
            recovery_confirmation = ExternalActionConfirmation(
                external_link, confirmation.sequence
            )
            execution_started = self.gate.external_intent_execution_started(
                intent_id,
                self.owner_id,
                self.control_chat_id,
                preview_message_id,
                external_link,
            )
            if execution_started:
                result = self.gate.confirm_external_admin(
                    intent_id,
                    self.owner_id,
                    self.control_chat_id,
                    preview_message_id,
                    recovery_confirmation,
                )
                if result.outcome in {"applied", "replayed"} or (
                    result.outcome == "executed"
                    and result.action_result is not None
                    and result.action_result.outcome
                    in {"verified_success", "replayed_success"}
                ):
                    self.runs.mark_external_terminal(intent_id)
                return result
            try:
                metadata = self._external_reads().validate_for_prepare(
                    external_reference
                )
                linked = self.runs.require_external_source_link(
                    intent_id,
                    external_reference,
                    metadata,
                )
            except (ExternalReadError, PermissionError) as source_error:
                # Once Gate committed the exact immutable intent, a retry resumes
                # its journal. It never rebuilds or reparses a source record.
                try:
                    execution_started = self.gate.external_intent_execution_started(
                        intent_id,
                        self.owner_id,
                        self.control_chat_id,
                        preview_message_id,
                        external_link,
                    )
                except Exception:
                    raise source_error from None
                if not execution_started:
                    raise source_error
            else:
                if (
                    self._external_gate_link(external_reference, metadata)
                    != external_link
                ):
                    raise PermissionError("external source link does not match Gate")
                if linked.minimum_confirmation_sequence >= confirmation.sequence:
                    raise PermissionError("external confirmation is stale")
            result = self.gate.confirm_external_admin(
                intent_id,
                self.owner_id,
                self.control_chat_id,
                preview_message_id,
                recovery_confirmation,
            )
            if result.outcome in {"applied", "replayed"} or (
                result.outcome == "executed"
                and result.action_result is not None
                and result.action_result.outcome
                in {"verified_success", "replayed_success"}
            ):
                self.runs.mark_external_terminal(intent_id)
            return result
        elif external_reference is not None:
            raise PermissionError("administration intent is not an external action")
        result = self.gate.confirm_admin(
            intent_id,
            owner_id=self.owner_id,
            control_chat_id=self.control_chat_id,
            preview_message_id=preview_message_id,
        )
        return result
