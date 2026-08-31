"""Deterministic consent, privacy, takeover, and delivery behavior."""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.storage import Unit1Store
from src.public_assistant.types import (
    ConnectionObservation,
    ControlRecord,
    DeleteNotice,
    DeliveryState,
    InboundMessage,
    OwnerMessage,
    ProcessingResult,
    ReplyRecord,
)

DISCLOSURE = {
    "en": (
        "I’m Misha’s automated assistant. Before I process this message, please "
        "choose Continue. Your text may then be processed by OpenAI to assist with "
        "replies, by Google Calendar for requested meeting actions, and by Todoist "
        "for requested external tasks. Local sender-derived content is retained for "
        "up to 90 days. You can revoke processing or request deletion at any time."
    ),
    "ru": (
        "Я автоматический помощник Миши. Прежде чем обработать это сообщение, "
        "нажмите «Продолжить». После этого текст может обрабатываться OpenAI для "
        "ответов, Google Calendar для запрошенных действий со встречами и Todoist "
        "для запрошенных внешних задач. Локальные данные отправителя хранятся не "
        "более 90 дней. Согласие можно отозвать или запросить удаление данных."
    ),
}

MAINTENANCE = {
    "en": (
        "Your message was stored securely. This pilot currently provides only "
        "deterministic privacy and account-maintenance responses; no AI model or "
        "external integration processed it."
    ),
    "ru": (
        "Сообщение сохранено в защищённом хранилище. Сейчас пилот предоставляет "
        "только детерминированные ответы о конфиденциальности и обслуживании; "
        "модель ИИ и внешние интеграции его не обрабатывали."
    ),
}

PRIVACY = {
    "en": (
        "Privacy controls: processing is optional and revocable. Sender-derived "
        "local content expires within 90 days. Use the buttons below to revoke "
        "processing or request deletion."
    ),
    "ru": (
        "Управление конфиденциальностью: обработка добровольна, а согласие можно "
        "отозвать. Локальные данные отправителя удаляются не позднее чем через 90 "
        "дней. Кнопки ниже позволяют отозвать согласие или запросить удаление."
    ),
}


class DefiniteDeliveryError(RuntimeError):
    """The Telegram boundary proved the message was rejected before acceptance."""


def _language(text: str) -> str:
    return (
        "ru" if any("\u0400" <= character <= "\u04ff" for character in text) else "en"
    )


class SecretaryService:
    """Unit 1 application core with no model or integration capability."""

    def __init__(
        self,
        config: PublicAssistantConfig,
        store: Unit1Store,
        *,
        logger: PrivacyLog | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.log = logger or PrivacyLog(
            config.pseudonym_key, logging.getLogger("public_assistant")
        )
        self._now = now or (lambda: datetime.now(UTC))

    def observe_connection(self, observation: ConnectionObservation) -> bool:
        self.store.observe_connection(observation)
        accepted = bool(
            observation.owner_id == self.config.owner_id
            and observation.enabled
            and observation.can_reply is True
        )
        self.log.event(
            "business_connection_observed",
            connection_id=observation.connection_id,
            state="reply_enabled" if accepted else "denied",
        )
        return accepted

    def _validate_message(self, message: InboundMessage) -> str | None:
        if message.chat_type != "private":
            return "non_private_chat"
        if message.sender_id == self.config.owner_id:
            return "owner_not_sender"
        if message.sender_id not in self.config.selected_sender_ids:
            return "sender_not_selected"
        if message.conversation_id != message.sender_id:
            return "private_identity_mismatch"
        if not self.store.connection_can_reply(
            message.connection_id, self.config.owner_id
        ):
            return "connection_denied"
        if self.store.is_taken_over(message.connection_id, message.conversation_id):
            return "owner_takeover"
        age = (self._now() - message.sent_at).total_seconds()
        if age < -300 or age >= self.config.reply_window_seconds:
            return "outside_reply_window"
        subject_ref = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        if self.store.privacy_state(subject_ref) is not None:
            return "privacy_stopped"
        if not message.text.strip():
            return "unsupported_empty_text"
        if not self.store.rate_limit(
            subject_ref,
            limit=self.config.rate_limit_count,
            window_seconds=self.config.rate_limit_window_seconds,
        ):
            return "rate_limited"
        return None

    def handle_message(self, message: InboundMessage) -> ProcessingResult:
        denial = self._validate_message(message)
        if denial is not None:
            self.log.event(
                "business_message_denied",
                connection_id=message.connection_id,
                chat_id=message.conversation_id,
                sender_id=message.sender_id,
                update_id=message.update_id,
                state=denial,
            )
            return ProcessingResult(denial)

        is_new, prior_reply = self.store.begin_update(
            message, "business_message", "received"
        )
        if not is_new:
            return ProcessingResult("duplicate", prior_reply)

        if self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            self.store.store_consented_message(message)
            reply = self._maintenance_reply(message)
            self.store.set_update_outcome(
                message.update_id, "stored_after_consent", reply.reply_id
            )
            self._log_message(message, "stored_after_consent")
            return ProcessingResult("stored_after_consent", reply)
        return self._stage_consent(message)

    def _stage_consent(self, message: InboundMessage) -> ProcessingResult:
        _, continue_token, decline_token = self.store.stage_pending(
            message,
            privacy_policy_version=self.config.privacy_policy_version,
            processing_authorization_version=(
                self.config.processing_authorization_version
            ),
            ttl_seconds=self.config.pending_ttl_seconds,
        )
        lang = _language(message.text)
        keyboard = [
            [
                {
                    "text": "Continue" if lang == "en" else "Продолжить",
                    "callback_data": continue_token,
                },
                {
                    "text": "Decline" if lang == "en" else "Отказаться",
                    "callback_data": decline_token,
                },
            ],
            [
                {
                    "text": "Privacy" if lang == "en" else "Конфиденциальность",
                    "url": self.config.privacy_url,
                }
            ],
        ]
        reply = self.store.create_reply(
            message, "consent_disclosure", DISCLOSURE[lang], keyboard
        )
        self.store.set_update_outcome(
            message.update_id, "awaiting_consent", reply.reply_id
        )
        self._log_message(message, "awaiting_consent")
        return ProcessingResult("awaiting_consent", reply)

    def _log_message(self, message: InboundMessage, state: str) -> None:
        self.log.event(
            "business_message_processed",
            connection_id=message.connection_id,
            chat_id=message.conversation_id,
            sender_id=message.sender_id,
            update_id=message.update_id,
            state=state,
        )

    def _maintenance_reply(self, message: InboundMessage) -> ReplyRecord:
        lang = _language(message.text)
        revoke_token, delete_token = self.store.create_maintenance_controls(
            message,
            self.config.processing_authorization_version,
            self.config.pending_ttl_seconds,
        )
        is_privacy = message.text.strip().casefold() in {
            "/privacy",
            "privacy",
            "конфиденциальность",
        }
        text = PRIVACY[lang] if is_privacy else MAINTENANCE[lang]
        keyboard = [
            [
                {
                    "text": "Revoke" if lang == "en" else "Отозвать",
                    "callback_data": revoke_token,
                },
                {
                    "text": "Delete data" if lang == "en" else "Удалить данные",
                    "callback_data": delete_token,
                },
            ],
            [
                {
                    "text": (
                        "Privacy policy"
                        if lang == "en"
                        else "Политика конфиденциальности"
                    ),
                    "url": self.config.privacy_url,
                }
            ],
        ]
        return self.store.create_reply(message, "maintenance", text, keyboard)

    def handle_edit(self, message: InboundMessage) -> ProcessingResult:
        denial = self._validate_message(message)
        if denial is not None:
            return ProcessingResult(denial)
        is_new, prior_reply = self.store.begin_update(
            message, "edited_business_message", "received_edit"
        )
        if not is_new:
            return ProcessingResult("duplicate", prior_reply)
        if self.store.edit_pending(message):
            self.store.set_update_outcome(message.update_id, "pending_body_replaced")
            return ProcessingResult("pending_body_replaced")
        if self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            self.store.store_consented_message(message)
            reply = self._maintenance_reply(message)
            self.store.set_update_outcome(
                message.update_id, "consented_body_replaced", reply.reply_id
            )
            return ProcessingResult("consented_body_replaced", reply)
        return self._stage_consent(message)

    def handle_delete(self, notice: DeleteNotice) -> ProcessingResult:
        if notice.chat_type != "private":
            return ProcessingResult("non_private_chat")
        if notice.conversation_id not in self.config.selected_sender_ids:
            return ProcessingResult("sender_not_selected")
        if not self.store.connection_can_reply(
            notice.connection_id, self.config.owner_id
        ):
            return ProcessingResult("connection_denied")
        if not self.store.begin_non_message_update(
            update_id=notice.update_id,
            kind="deleted_business_messages",
            connection_id=notice.connection_id,
            conversation_id=notice.conversation_id,
            outcome="deleting",
        ):
            return ProcessingResult("duplicate")
        self.store.delete_messages(
            notice.connection_id, notice.conversation_id, notice.message_ids
        )
        self.store.set_update_outcome(notice.update_id, "deleted")
        return ProcessingResult("deleted")

    def handle_owner_message(self, message: OwnerMessage) -> ProcessingResult:
        if message.chat_type != "private":
            return ProcessingResult("non_private_chat")
        if message.conversation_id not in self.config.selected_sender_ids:
            return ProcessingResult("sender_not_selected")
        if message.sender_business_bot_id is not None:
            return ProcessingResult("assistant_delivery")
        if message.owner_id != self.config.owner_id:
            return ProcessingResult("wrong_owner")
        if not self.store.connection_can_reply(
            message.connection_id, self.config.owner_id
        ):
            return ProcessingResult("connection_denied")
        recorded = self.store.record_takeover(
            message.connection_id,
            message.conversation_id,
            message.conversation_id,
            message.update_id,
            message.message_id,
        )
        return ProcessingResult("owner_takeover" if recorded else "duplicate")

    def handle_control(
        self,
        token: str,
        *,
        actor_id: int,
        conversation_id: int,
        crash_hook: Callable[[str], None] | None = None,
    ) -> str:
        control = self.store.resolve_control(token, actor_id, conversation_id)
        if control is None:
            return "neutral"
        if not self._control_connection_valid(control):
            return "neutral"
        if control.action == "consent":
            result = self.store.accept_consent(
                control,
                expected_processing_version=(
                    self.config.processing_authorization_version
                ),
                crash_hook=crash_hook,
            )
        elif control.action == "decline":
            result = self.store.decline(control)
        else:
            result = self.store.apply_privacy_control(control)
        self.log.event(
            "privacy_control_processed",
            connection_id=control.connection_id,
            chat_id=control.conversation_id,
            sender_id=control.sender_id,
            state=result,
        )
        return result

    def _control_connection_valid(self, control: ControlRecord) -> bool:
        return bool(
            control.sender_id in self.config.selected_sender_ids
            and self.store.connection_can_reply(
                control.connection_id, self.config.owner_id
            )
            and not self.store.is_taken_over(
                control.connection_id, control.conversation_id
            )
        )

    async def deliver_reply(
        self,
        reply: ReplyRecord,
        sender: Callable[[ReplyRecord], Awaitable[int]],
    ) -> DeliveryState:
        current = self.store.get_reply(reply.reply_id)
        if current is None:
            return DeliveryState.CANCELLED
        if current.state is not DeliveryState.PENDING:
            return current.state
        if not self.store.reply_allowed(
            reply.reply_id,
            owner_id=self.config.owner_id,
            reply_window_seconds=self.config.reply_window_seconds,
        ):
            self.store.finalize_reply(reply.reply_id, DeliveryState.CANCELLED)
            self.log.event(
                "reply_delivery",
                connection_id=reply.connection_id,
                chat_id=reply.conversation_id,
                state=DeliveryState.CANCELLED.value,
            )
            return DeliveryState.CANCELLED
        if not self.store.mark_reply_sending(reply.reply_id):
            raced = self.store.get_reply(reply.reply_id)
            return raced.state if raced is not None else DeliveryState.CANCELLED
        try:
            telegram_message_id = await sender(reply)
        except DefiniteDeliveryError:
            self.store.finalize_reply(reply.reply_id, DeliveryState.DEFINITE_FAILURE)
            self.log.event(
                "reply_delivery",
                connection_id=reply.connection_id,
                chat_id=reply.conversation_id,
                state=DeliveryState.DEFINITE_FAILURE.value,
            )
            return DeliveryState.DEFINITE_FAILURE
        except Exception:
            self.store.finalize_reply(reply.reply_id, DeliveryState.DELIVERY_UNCERTAIN)
            self.log.event(
                "reply_delivery",
                connection_id=reply.connection_id,
                chat_id=reply.conversation_id,
                state=DeliveryState.DELIVERY_UNCERTAIN.value,
            )
            return DeliveryState.DELIVERY_UNCERTAIN
        self.store.finalize_reply(
            reply.reply_id, DeliveryState.SENT, telegram_message_id
        )
        self.log.event(
            "reply_delivery",
            connection_id=reply.connection_id,
            chat_id=reply.conversation_id,
            state=DeliveryState.SENT.value,
        )
        return DeliveryState.SENT

    @staticmethod
    def keyboard(reply: ReplyRecord) -> list[list[dict[str, str]]]:
        value = json.loads(reply.keyboard_json)
        if not isinstance(value, list):
            raise ValueError("invalid stored keyboard")
        return value
