"""Channel-neutral bridge from one bounded model proposal to Policy Gate."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Mapping, Protocol, Sequence
from zoneinfo import ZoneInfo

from src.policy_gate.types import (
    ActionBinding,
    ActionResult,
    ActionSchema,
    MeetingOptionsResult,
    Operation,
    canonical_json,
)
from src.private_controller.erasure import (
    ExternalIntentLinkEraser,
    ExternalIntentLinkEraseRequest,
)
from src.private_controller.origin import external_subject_hash
from src.public_assistant.action_store import (
    IntegrationAuthorization,
    MeetingOfferControl,
    Unit3Store,
)
from src.public_assistant.config import PublicAssistantConfig, Unit2Config
from src.public_assistant.conversation import (
    _ABUSE,
    _GREETINGS,
    _OWNER_STATUS_TERMS,
    OWNER_STATUS,
    REQUEST_CONFIRMED,
    AssistantService,
)
from src.public_assistant.model import (
    ActionProposal,
    PublicModel,
    action_schemas,
)
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.service import _language
from src.public_assistant.types import InboundMessage, ProcessingResult, ReplyRecord


class PublicGateClient(Protocol):
    """The public process receives decisions, never Gate storage or credentials."""

    def allowed_actions(
        self,
        subject_id: str,
        processing_authorization_version: str,
        processing_authorization_revision: int,
    ) -> tuple[Operation, ...]: ...

    def submit_action(self, binding: ActionBinding) -> ActionResult: ...

    def meeting_options(self, binding: ActionBinding) -> MeetingOptionsResult: ...

    def stage_action(self, binding: ActionBinding) -> bool: ...

    def register_subject(
        self, subject_id: str, references: Mapping[str, str]
    ) -> None: ...

    def activate_receipt(
        self,
        subject_id: str,
        version: str,
        revision: int,
        processor_purposes: Mapping[str, Sequence[str]],
    ) -> bool: ...

    def revoke_receipt(self, subject_id: str, revision: int) -> bool: ...

    def erase_subject(self, subject_id: str) -> str: ...


@dataclass(frozen=True)
class ActionDiscovery:
    authorization: IntegrationAuthorization | None
    schemas: tuple[ActionSchema, ...]


@dataclass(frozen=True)
class MeetingOptionsDelivery:
    """Gate-produced slots plus durable Telegram callback controls."""

    result: MeetingOptionsResult
    controls: tuple[MeetingOfferControl, ...] = ()


class ActionCoordinator:
    """Persist the trusted binding before asking Gate to claim it."""

    def __init__(
        self,
        store: Unit3Store,
        gate: PublicGateClient,
        *,
        external_link_eraser: ExternalIntentLinkEraser | None = None,
    ) -> None:
        self.store = store
        self.gate = gate
        self.external_link_eraser = external_link_eraser
        self._locks_guard = threading.Lock()
        self._subject_locks: dict[str, threading.Lock] = {}

    def _subject_lock(self, subject_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._subject_locks.setdefault(subject_id, threading.Lock())

    def _current_authorization(
        self, message: InboundMessage, discovery: ActionDiscovery
    ) -> bool:
        return (
            self.store.active_integration_authorization(message)
            == discovery.authorization
        )

    def activate_integration_authorization(
        self,
        message: InboundMessage,
        version: str,
        revision: int,
        processor_purposes: Mapping[str, tuple[str, ...]],
    ) -> bool:
        authorization = self.store.begin_integration_activation(
            message, version, revision, processor_purposes
        )
        acknowledged = self.gate.activate_receipt(
            authorization.subject_id,
            authorization.version,
            authorization.revision,
            authorization.processor_purposes,
        )
        if acknowledged:
            self.store.acknowledge_integration_activation(authorization)
        return acknowledged

    def revoke_integration_authorization(
        self, message: InboundMessage, revision: int
    ) -> bool:
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self._subject_lock(subject):
            subject = self.store.begin_integration_revocation(message, revision)
            acknowledged = self.gate.revoke_receipt(subject, revision)
            if acknowledged:
                self.store.acknowledge_integration_revocation(subject, revision)
            return acknowledged

    def discover(self, message: InboundMessage) -> ActionDiscovery:
        authorization = self.store.active_integration_authorization(message)
        if authorization is None:
            return ActionDiscovery(None, ())
        return ActionDiscovery(
            authorization,
            action_schemas(
                self.gate.allowed_actions(
                    authorization.subject_id,
                    authorization.version,
                    authorization.revision,
                )
            ),
        )

    def register_request(self, message: InboundMessage, request_id: str) -> None:
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        self.gate.register_subject(
            subject,
            {
                "managed_chat": self.store.managed_chat_reference(message),
                "request": request_id,
            },
        )
        self.gate.register_subject(
            subject,
            {"managed_chat": self.store.managed_chat_reference(message)},
        )

    def erase_subject(self, subject_id: str) -> str:
        """Converge public, Gate, then digest-only controller link erasure."""

        result = self.gate.erase_subject(subject_id)
        if result != "erased" or self.external_link_eraser is None:
            return result
        try:
            self.external_link_eraser.erase_external_links(
                ExternalIntentLinkEraseRequest(external_subject_hash(subject_id))
            )
        except Exception:
            # The public tombstone is deliberately retained and the polling loop
            # retries this fixed deletion; neither the raw subject nor a source
            # reference is persisted in a new public recovery record.
            return "pending_private_erasure"
        return "erased"

    def submit(
        self,
        message: InboundMessage,
        request_id: str,
        proposal: ActionProposal,
        retention_seconds: int,
        discovery: ActionDiscovery,
    ) -> ActionResult:
        if proposal.operation is Operation.MEETING_OPTIONS:
            delivery = self.meeting_options(
                message,
                request_id,
                proposal,
                retention_seconds,
                discovery,
            )
            return ActionResult(delivery.result.outcome, delivery.result.action_id)
        if discovery.authorization is None:
            return ActionResult("denied", "")
        if proposal.operation not in {action.operation for action in discovery.schemas}:
            return ActionResult("denied", "")
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self._subject_lock(subject):
            if not self._current_authorization(message, discovery):
                return ActionResult("denied", "")
            binding = self.store.prepare_action(
                message,
                request_id,
                proposal.operation,
                proposal.arguments,
                discovery.authorization.version,
                discovery.authorization.revision,
                retention_seconds,
            )
            self.gate.register_subject(
                binding.subject_id,
                {"request": request_id, "action": binding.action_id},
            )
            if not self._current_authorization(message, discovery):
                denied = ActionResult("denied", binding.action_id)
                self.store.finish_action(denied)
                return denied
            if not self.gate.stage_action(binding):
                denied = ActionResult("denied", binding.action_id)
                self.store.finish_action(denied)
                return denied
            if not self._current_authorization(message, discovery):
                denied = ActionResult("denied", binding.action_id)
                self.store.finish_action(denied)
                return denied
            result = self.gate.submit_action(binding)
            self.store.finish_action(result)
            return result

    def stage_exact_task_candidate(
        self,
        message: InboundMessage,
        request_id: str,
        title: str,
        due_date: str | None,
        retention_seconds: int,
        discovery: ActionDiscovery,
    ) -> ActionBinding | None:
        """Persist a public-sender task for the owner-only exact-control flow.

        This deliberately stages but never submits: public schema discovery does
        not reveal exact authority, and the owner must use the existing fresh
        draft/preview/confirm controls against this immutable action reference.
        """

        if (
            discovery.authorization is None
            or not isinstance(title, str)
            or not 0 < len(title.strip()) <= 200
            or due_date is not None
            and not isinstance(due_date, str)
        ):
            return None
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self._subject_lock(subject):
            if not self._current_authorization(message, discovery):
                return None
            binding = self.store.prepare_action(
                message,
                request_id,
                Operation.TASK_CREATE,
                {"title": title.strip(), "due_date": due_date},
                discovery.authorization.version,
                discovery.authorization.revision,
                retention_seconds,
            )
            self.gate.register_subject(
                binding.subject_id,
                {"request": request_id, "action": binding.action_id},
            )
            if not self._current_authorization(message, discovery):
                self.store.finish_action(ActionResult("denied", binding.action_id))
                return None
            if not self.gate.stage_action(binding):
                self.store.finish_action(ActionResult("denied", binding.action_id))
                return None
            return binding

    def meeting_options(
        self,
        message: InboundMessage,
        request_id: str,
        proposal: ActionProposal,
        retention_seconds: int,
        discovery: ActionDiscovery,
    ) -> MeetingOptionsDelivery:
        """Ask Gate for options, then bind each returned offer to one callback."""

        denied = MeetingOptionsResult("denied", "")
        if (
            discovery.authorization is None
            or proposal.operation is not Operation.MEETING_OPTIONS
            or proposal.operation
            not in {action.operation for action in discovery.schemas}
        ):
            return MeetingOptionsDelivery(denied)
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        with self._subject_lock(subject):
            if not self._current_authorization(message, discovery):
                return MeetingOptionsDelivery(denied)
            binding = self.store.prepare_action(
                message,
                request_id,
                proposal.operation,
                proposal.arguments,
                discovery.authorization.version,
                discovery.authorization.revision,
                retention_seconds,
            )
            self.gate.register_subject(
                binding.subject_id,
                {"request": request_id, "action": binding.action_id},
            )
            if not self._current_authorization(
                message, discovery
            ) or not self.gate.stage_action(binding):
                self.store.finish_action(ActionResult("denied", binding.action_id))
                return MeetingOptionsDelivery(
                    MeetingOptionsResult("denied", binding.action_id)
                )
            if not self._current_authorization(message, discovery):
                self.store.finish_action(ActionResult("denied", binding.action_id))
                return MeetingOptionsDelivery(
                    MeetingOptionsResult("denied", binding.action_id)
                )
            result = self.gate.meeting_options(binding)
            self.store.finish_action(ActionResult(result.outcome, binding.action_id))
            if result.outcome != "verified_success":
                return MeetingOptionsDelivery(result)
            controls = self.store.create_meeting_offer_controls(
                message, binding, result.slots, retention_seconds
            )
            return MeetingOptionsDelivery(result, controls)

    def select_meeting_offer(
        self,
        token: str,
        *,
        actor_id: int,
        conversation_id: int,
        connection_id: str,
        origin_message_id: int,
        callback_update_id: int,
    ) -> ActionResult:
        """Turn a delivered callback into a staged exact action.

        Gate makes the only authority decision.  A denied direct claim stays
        staged for the established controller exact-confirmation path.
        """

        binding = self.store.prepare_meeting_selection(
            token,
            actor_id=actor_id,
            conversation_id=conversation_id,
            connection_id=connection_id,
            origin_message_id=origin_message_id,
            callback_update_id=callback_update_id,
        )
        if binding is None:
            return ActionResult("denied", "")
        with self._subject_lock(binding.subject_id):
            self.gate.register_subject(
                binding.subject_id,
                {"action": binding.action_id},
            )
            if not self.gate.stage_action(binding):
                result = ActionResult("denied", binding.action_id)
                self.store.finish_action(result)
                return result
            result = self.gate.submit_action(binding)
            if result.outcome == "denied":
                self.store.create_meeting_owner_confirmation_request(binding)
                pending = ActionResult("awaiting_owner_confirmation", binding.action_id)
                self.store.finish_action(pending)
                return pending
            self.store.finish_action(result)
            return result


DRY_RUN_ACCEPTED = {
    "en": "The requested action passed the dry-run policy check. No external provider was contacted.",
    "ru": "Запрошенное действие прошло проверку в тестовом режиме. Внешний сервис не вызывался.",
}
TODOIST_SUCCEEDED = {
    "en": "The task was created in the configured external requests list.",
    "ru": "Задача создана в настроенном списке внешних запросов.",
}

MEETING_OPTIONS_PROMPT = {
    "en": "Choose one of these available times.",
    "ru": "Выберите один из доступных вариантов времени.",
}
MEETING_OPTIONS_EMPTY = {
    "en": "I could not find an available time in that window.",
    "ru": "В этом диапазоне не нашлось свободного времени.",
}


class ActionAssistantService(AssistantService):
    """Unit 2 conversation plus one locally schema-bounded dry-run action."""

    def __init__(
        self,
        config: PublicAssistantConfig,
        unit2_config: Unit2Config,
        store: Unit3Store,
        model: PublicModel,
        coordinator: ActionCoordinator,
        *,
        logger: PrivacyLog | None = None,
    ) -> None:
        super().__init__(config, unit2_config, store, model, logger=logger)
        self.store: Unit3Store = store
        self.coordinator = coordinator
        self.reconcile_erasures()

    def reconcile_erasures(self) -> None:
        """Retry the fixed Gate erasure operation from durable public tombstones."""

        for subject_id in self.store.active_erasure_subjects():
            self.coordinator.erase_subject(subject_id)

    def handle_control(
        self,
        token: str,
        *,
        actor_id: int,
        conversation_id: int,
        connection_id: str,
        origin_message_id: int,
        crash_hook: Callable[[str], None] | None = None,
    ) -> str:
        control = self.store.resolve_control(
            token, actor_id, conversation_id, connection_id, origin_message_id
        )
        result = super().handle_control(
            token,
            actor_id=actor_id,
            conversation_id=conversation_id,
            connection_id=connection_id,
            origin_message_id=origin_message_id,
            crash_hook=crash_hook,
        )
        if (
            control is not None
            and control.action == "delete"
            and result
            in {
                "erased",
                "replayed",
            }
        ):
            self.coordinator.erase_subject(control.subject_ref)
        return result

    def _register_request(self, message: InboundMessage, request_id: str) -> None:
        try:
            self.coordinator.register_request(message, request_id)
        except Exception:
            return

    def _process_without_actions(self, message: InboundMessage) -> ProcessingResult:
        result = super()._process_consented(message)
        request_id = self.store.request_id_for_update(message.update_id)
        if request_id is not None:
            self._register_request(message, request_id)
        return result

    def _fallback_request(
        self, message: InboundMessage, outcome: str
    ) -> ProcessingResult:
        result = super()._fallback_request(message, outcome)
        request_id = self.store.request_id_for_update(message.update_id)
        if request_id is not None:
            self._register_request(message, request_id)
        return result

    def _process_consented(self, message: InboundMessage) -> ProcessingResult:
        normalized = " ".join(message.text.casefold().split()).strip(".!?,")
        if normalized in _GREETINGS or any(marker in normalized for marker in _ABUSE):
            return self._process_without_actions(message)
        try:
            discovery = self.coordinator.discover(message)
        except Exception:
            return self._process_without_actions(message)
        if not self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            return ProcessingResult("consent_stopped")
        conversation = self.store.conversation(
            message,
            max_items=self.unit2_config.max_context_items,
            max_characters=self.unit2_config.max_context_characters,
        )
        reservation = self.store.reserve_model_call(
            message, conversation, self.unit2_config
        )
        if reservation is None:
            return self._fallback_request(message, "model_budget_exhausted")
        if not self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            self.store.finish_model_call(reservation, None, self.unit2_config)
            return ProcessingResult("consent_stopped")
        try:
            result = self.model.generate(
                conversation,
                self.store.model_safety_identifier(message),
                policy_context={
                    "processing_authorization_version": (
                        None
                        if discovery.authorization is None
                        else discovery.authorization.version
                    ),
                    "processing_authorization_revision": (
                        None
                        if discovery.authorization is None
                        else discovery.authorization.revision
                    ),
                    "allowed_actions": [
                        action.operation.value for action in discovery.schemas
                    ],
                },
                allowed_actions=discovery.schemas,
            )
            turn = result.turn
            self.store.finish_model_call(reservation, result, self.unit2_config)
        except Exception:
            self.store.finish_model_call(reservation, None, self.unit2_config)
            return self._fallback_request(message, "model_fallback")

        if turn.action_proposal is not None:
            if not self.store.has_active_consent(
                message.connection_id,
                message.conversation_id,
                message.sender_id,
                self.config.processing_authorization_version,
            ):
                return ProcessingResult("consent_stopped")
            if turn.action_proposal.operation is Operation.MEETING_OPTIONS:
                delivery = self.coordinator.meeting_options(
                    message,
                    self.store.action_request_id(message),
                    turn.action_proposal,
                    self.config.retention_seconds,
                    discovery,
                )
                if delivery.result.outcome == "verified_success":
                    language = _language(message.text)
                    if delivery.controls:
                        text = MEETING_OPTIONS_PROMPT[language]
                        reply = self._meeting_options_reply(
                            message, text, delivery.controls, delivery.result.timezone
                        )
                        outcome = "meeting_options_offered"
                    else:
                        text = MEETING_OPTIONS_EMPTY[language]
                        reply = self._assistant_reply(message, text)
                        outcome = "meeting_options_empty"
                    self.store.add_assistant_context(
                        message, text, self.config.retention_seconds
                    )
                    self.store.set_update_outcome(
                        message.update_id, outcome, reply.reply_id
                    )
                    return ProcessingResult(outcome, reply)
                return self._fallback_request(message, "action_denied")
            action_result = self.coordinator.submit(
                message,
                self.store.action_request_id(message),
                turn.action_proposal,
                self.config.retention_seconds,
                discovery,
            )
            if action_result.outcome in {"verified_success", "replayed_success"}:
                text = (
                    TODOIST_SUCCEEDED[_language(message.text)]
                    if turn.action_proposal.operation is Operation.TASK_CREATE
                    else DRY_RUN_ACCEPTED[_language(message.text)]
                )
                reply = self._assistant_reply(message, text)
                self.store.add_assistant_context(
                    message, text, self.config.retention_seconds
                )
                outcome = (
                    "todoist_task_created"
                    if turn.action_proposal.operation is Operation.TASK_CREATE
                    else "dry_run_action_validated"
                )
                self.store.set_update_outcome(
                    message.update_id, outcome, reply.reply_id
                )
                return ProcessingResult(outcome, reply)
            return self._fallback_request(message, "action_denied")

        request_id = None
        staged_task = False
        reply_text = turn.reply_text
        if turn.turn_kind == "task":
            if turn.task_candidate is None:
                return self._fallback_request(message, "model_fallback")
            # Persist only model-minimized typed fields: never the sender's
            # free-form message. The action remains staged until a fresh direct
            # owner confirmation grants exact authority for this same binding.
            candidate_content = canonical_json(
                {
                    "due_date": turn.task_candidate.due_date,
                    "title": turn.task_candidate.title,
                }
            )
            request_id = self.store.upsert_request(
                message, candidate_content, self.config.retention_seconds
            )
            staged_task = (
                self.coordinator.stage_exact_task_candidate(
                    message,
                    request_id,
                    turn.task_candidate.title,
                    turn.task_candidate.due_date,
                    self.config.retention_seconds,
                    discovery,
                )
                is not None
            )
            self._register_request(message, request_id)
            # An unavailable current receipt leaves the typed Inbox record and
            # owner alert intact, but never creates an executable public action.
            reply_text = REQUEST_CONFIRMED[_language(message.text)]
        elif turn.turn_kind == "request":
            if turn.request_patch is None:
                self.store.finish_model_call(reservation, None, self.unit2_config)
                return self._fallback_request(message, "model_fallback")
            request_id = self.store.upsert_request(
                message,
                turn.request_patch.content,
                self.config.retention_seconds,
            )
            self._register_request(message, request_id)
            reply_text = REQUEST_CONFIRMED[_language(message.text)]
        elif _OWNER_STATUS_TERMS.search(reply_text):
            reply_text = OWNER_STATUS[_language(message.text)]
        reply = self._assistant_reply(message, reply_text)
        self.store.add_assistant_context(
            message, reply_text, self.config.retention_seconds
        )
        outcome = (
            "task_exact_staged"
            if turn.turn_kind == "task" and staged_task
            else (
                "task_inbox_captured"
                if turn.turn_kind == "task" and request_id is not None
                else "request_captured" if request_id is not None else turn.turn_kind
            )
        )
        self.store.set_update_outcome(message.update_id, outcome, reply.reply_id)
        return ProcessingResult(outcome, reply)

    @staticmethod
    def _meeting_option_label(control: MeetingOfferControl, timezone: str) -> str:
        zone = ZoneInfo(timezone)
        start = datetime.fromtimestamp(control.start_at, zone)
        end = datetime.fromtimestamp(control.end_at, zone)
        return f"{start:%a %d %b %H:%M} to {end:%H:%M} {timezone}"

    def _meeting_options_reply(
        self,
        message: InboundMessage,
        text: str,
        controls: tuple[MeetingOfferControl, ...],
        timezone: str,
    ) -> ReplyRecord:
        language = _language(message.text)
        revoke, delete = self.store.create_maintenance_controls(
            message,
            self.config.privacy_policy_version,
            self.config.processing_authorization_version,
            self.config.pending_ttl_seconds,
        )
        keyboard: list[list[dict[str, str]]] = [
            [
                {
                    "text": self._meeting_option_label(control, timezone),
                    "callback_data": control.callback_data,
                }
            ]
            for control in controls
        ]
        keyboard.extend(
            [
                [
                    {
                        "text": "Revoke" if language == "en" else "Отозвать",
                        "callback_data": revoke,
                    },
                    {
                        "text": "Delete data" if language == "en" else "Удалить данные",
                        "callback_data": delete,
                    },
                ],
                [
                    {
                        "text": "Privacy" if language == "en" else "Конфиденциальность",
                        "url": self.config.privacy_url,
                    }
                ],
            ]
        )
        return self.store.create_reply(message, "meeting_options", text, keyboard)

    def handle_meeting_offer(
        self,
        token: str,
        *,
        actor_id: int,
        conversation_id: int,
        connection_id: str,
        origin_message_id: int,
        callback_update_id: int,
    ) -> str:
        """Handle a delivered, sender-bound Calendar option callback."""

        return self.coordinator.select_meeting_offer(
            token,
            actor_id=actor_id,
            conversation_id=conversation_id,
            connection_id=connection_id,
            origin_message_id=origin_message_id,
            callback_update_id=callback_update_id,
        ).outcome
