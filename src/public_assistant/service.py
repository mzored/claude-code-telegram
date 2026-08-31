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
    "en": "Your message was stored securely. This pilot currently provides only deterministic privacy and account-maintenance responses; no AI model or external integration processed it.",
    "ru": "Сообщение сохранено в защищённом хранилище. Сейчас пилот предоставляет только детерминированные ответы о конфиденциальности и обслуживании; модель ИИ и внешние интеграции его не обрабатывали.",
}

PRIVACY = {
    "en": "Privacy controls: processing is optional and revocable. Sender-derived local content expires within 90 days. Use the buttons below to revoke processing or request deletion.",
    "ru": "Управление конфиденциальностью: обработка добровольна, а согласие можно отозвать. Локальные данные отправителя удаляются не позднее чем через 90 дней. Кнопки ниже позволяют отозвать согласие или запросить удаление.",
}

RECONSENT = {
    "en": "Processing is currently revoked. No text from this message was stored. You may enable the current processing scope again or request deletion.",
    "ru": "Обработка сейчас отозвана. Текст этого сообщения не сохранялся. Можно снова разрешить текущий объём обработки или запросить удаление.",
}


class DefiniteDeliveryError(RuntimeError):
    """Telegram proved a request was rejected before acceptance."""


class RetryableDeliveryError(RuntimeError):
    """Telegram proved non-acceptance and supplied a retry delay."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Telegram requested a retry")
        self.retry_after_seconds = max(1, retry_after_seconds)


def _language(text: str) -> str:
    return (
        "ru" if any("\u0400" <= character <= "\u04ff" for character in text) else "en"
    )


class SecretaryService:
    """Unit 1 core; it has no model or external-integration capability."""

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
            store.pseudonym_key, logging.getLogger("public_assistant")
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

    def _validate_new_text(self, message: InboundMessage) -> str | None:
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
        if not message.text.strip():
            return "unsupported_empty_text"
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        if not self.store.rate_limit(
            message.update_id,
            subject,
            limit=self.config.rate_limit_count,
            window_seconds=self.config.rate_limit_window_seconds,
        ):
            return "rate_limited"
        return None

    def handle_message(self, message: InboundMessage) -> ProcessingResult:
        denial = self._validate_new_text(message)
        if denial is not None:
            return ProcessingResult(denial)
        subject = self.store.subject_ref(
            message.connection_id, message.conversation_id, message.sender_id
        )
        if self.store.privacy_state(subject) is not None:
            return self._revoked_reply(message)
        is_new, prior = self.store.begin_update(message, "business_message", "received")
        if not is_new:
            return ProcessingResult("duplicate", prior)
        if self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            self.store.store_consented_message(message, self.config.retention_seconds)
            reply = self._maintenance_reply(message)
            self.store.set_update_outcome(
                message.update_id, "stored_after_consent", reply.reply_id
            )
            return ProcessingResult("stored_after_consent", reply)
        return self._stage_consent(message)

    def _stage_consent(self, message: InboundMessage) -> ProcessingResult:
        _, consent, decline = self.store.stage_pending(
            message,
            privacy_policy_version=self.config.privacy_policy_version,
            processing_authorization_version=self.config.processing_authorization_version,
            ttl_seconds=self.config.pending_ttl_seconds,
        )
        lang = _language(message.text)
        keyboard = [
            [
                {
                    "text": "Continue" if lang == "en" else "Продолжить",
                    "callback_data": consent,
                },
                {
                    "text": "Decline" if lang == "en" else "Отказаться",
                    "callback_data": decline,
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
        return ProcessingResult("awaiting_consent", reply)

    def _maintenance_reply(self, message: InboundMessage) -> ReplyRecord:
        lang = _language(message.text)
        revoke, delete = self.store.create_maintenance_controls(
            message,
            self.config.processing_authorization_version,
            self.config.pending_ttl_seconds,
        )
        is_privacy = message.text.strip().casefold() in {
            "/privacy",
            "privacy",
            "конфиденциальность",
        }
        keyboard = [
            [
                {
                    "text": "Revoke" if lang == "en" else "Отозвать",
                    "callback_data": revoke,
                },
                {
                    "text": "Delete data" if lang == "en" else "Удалить данные",
                    "callback_data": delete,
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
        return self.store.create_reply(
            message,
            "maintenance",
            PRIVACY[lang] if is_privacy else MAINTENANCE[lang],
            keyboard,
        )

    def _revoked_reply(self, message: InboundMessage) -> ProcessingResult:
        is_new, prior = self.store.begin_update(
            message, "revoked_privacy_maintenance", "received", store_digest=False
        )
        if not is_new:
            return ProcessingResult("duplicate", prior)
        lang = _language(message.text)
        reconsent, delete = self.store.create_maintenance_controls(
            message,
            self.config.processing_authorization_version,
            self.config.pending_ttl_seconds,
            reconsent=True,
        )
        keyboard = [
            [
                {
                    "text": (
                        "Enable processing" if lang == "en" else "Разрешить обработку"
                    ),
                    "callback_data": reconsent,
                },
                {
                    "text": "Delete data" if lang == "en" else "Удалить данные",
                    "callback_data": delete,
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
        reply = self.store.create_reply(message, "reconsent", RECONSENT[lang], keyboard)
        self.store.set_update_outcome(
            message.update_id, "privacy_stopped", reply.reply_id
        )
        return ProcessingResult("privacy_stopped", reply)

    def handle_edit(self, message: InboundMessage) -> ProcessingResult:
        if (
            message.chat_type != "private"
            or message.conversation_id != message.sender_id
        ):
            return ProcessingResult("untrusted_edit")
        if not self.store.connection_owner_matches(
            message.connection_id, self.config.owner_id
        ):
            return ProcessingResult("connection_denied")
        if not self.store.stored_message_binding(
            message.connection_id,
            message.conversation_id,
            message.message_id,
            message.sender_id,
        ):
            return ProcessingResult("unknown_message")
        is_new, prior = self.store.begin_update(
            message, "edited_business_message", "received_edit"
        )
        if not is_new:
            return ProcessingResult("duplicate", prior)
        if self.store.edit_pending(message):
            self.store.set_update_outcome(message.update_id, "pending_body_replaced")
            return ProcessingResult("pending_body_replaced")
        if self.store.edit_public(message, self.config.retention_seconds):
            self.store.set_update_outcome(message.update_id, "consented_body_replaced")
            return ProcessingResult("consented_body_replaced")
        return ProcessingResult("unknown_message")

    def handle_delete(self, notice: DeleteNotice) -> ProcessingResult:
        if notice.chat_type != "private":
            return ProcessingResult("non_private_chat")
        if not self.store.connection_owner_matches(
            notice.connection_id, self.config.owner_id
        ):
            return ProcessingResult("connection_denied")
        trusted = tuple(
            message_id
            for message_id in notice.message_ids
            if self.store.stored_message_binding(
                notice.connection_id, notice.conversation_id, message_id
            )
        )
        if not trusted:
            return ProcessingResult("unknown_message")
        if not self.store.begin_non_message_update(
            update_id=notice.update_id,
            kind="deleted_business_messages",
            connection_id=notice.connection_id,
            conversation_id=notice.conversation_id,
            outcome="deleting",
        ):
            return ProcessingResult("duplicate")
        self.store.delete_messages(
            notice.connection_id, notice.conversation_id, trusted
        )
        self.store.set_update_outcome(notice.update_id, "deleted")
        return ProcessingResult("deleted")

    def handle_owner_message(self, message: OwnerMessage) -> ProcessingResult:
        if message.sender_business_bot_id is not None:
            return ProcessingResult("assistant_delivery")
        if message.is_from_offline:
            return ProcessingResult("offline_delivery")
        if message.chat_type != "private" or message.owner_id != self.config.owner_id:
            return ProcessingResult("wrong_owner")
        if not self.store.connection_owner_matches(
            message.connection_id, self.config.owner_id
        ):
            return ProcessingResult("connection_denied")
        if (
            message.conversation_id not in self.config.selected_sender_ids
            and not self.store.known_conversation(
                message.connection_id, message.conversation_id
            )
        ):
            return ProcessingResult("sender_not_selected")
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
        connection_id: str,
        origin_message_id: int,
        crash_hook: Callable[[str], None] | None = None,
    ) -> str:
        control = self.store.resolve_control(
            token, actor_id, conversation_id, connection_id, origin_message_id
        )
        if control is None:
            return "neutral"
        if control.action in {"consent", "reconsent"} and not self._consent_authority(
            control
        ):
            return "neutral"
        if control.action == "consent":
            result = self.store.accept_consent(
                control,
                expected_processing_version=self.config.processing_authorization_version,
                crash_hook=crash_hook,
            )
        elif control.action == "reconsent":
            result = self.store.reconsent(
                control, self.config.processing_authorization_version
            )
        elif control.action == "decline":
            result = self.store.decline(control, crash_hook=crash_hook)
        else:
            result = self.store.apply_privacy_control(control, crash_hook=crash_hook)
        self.log.event(
            "privacy_control_processed",
            connection_id=control.connection_id,
            chat_id=control.conversation_id,
            sender_id=control.sender_id,
            state=result,
        )
        return result

    def _consent_authority(self, control: ControlRecord) -> bool:
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
        *,
        authority_check: Callable[[str], Awaitable[bool]] | None = None,
    ) -> DeliveryState:
        current = self.store.get_reply(reply.reply_id)
        if current is None:
            return DeliveryState.CANCELLED
        if current.state not in {DeliveryState.PENDING, DeliveryState.RETRY_PENDING}:
            return current.state
        if authority_check is not None and not await authority_check(
            current.connection_id
        ):
            self.store.finalize_reply(reply.reply_id, DeliveryState.CANCELLED)
            return DeliveryState.CANCELLED
        if not self.store.reply_allowed(
            reply.reply_id,
            owner_id=self.config.owner_id,
            reply_window_seconds=self.config.reply_window_seconds,
        ):
            self.store.finalize_reply(reply.reply_id, DeliveryState.CANCELLED)
            return DeliveryState.CANCELLED
        if not self.store.mark_reply_sending(reply.reply_id):
            raced = self.store.get_reply(reply.reply_id)
            return raced.state if raced else DeliveryState.CANCELLED
        try:
            telegram_message_id = await sender(current)
        except RetryableDeliveryError as exc:
            self.store.finalize_reply(
                reply.reply_id,
                DeliveryState.RETRY_PENDING,
                retry_after_seconds=exc.retry_after_seconds,
            )
            return DeliveryState.RETRY_PENDING
        except DefiniteDeliveryError:
            self.store.finalize_reply(reply.reply_id, DeliveryState.DEFINITE_FAILURE)
            return DeliveryState.DEFINITE_FAILURE
        except Exception:
            self.store.finalize_reply(reply.reply_id, DeliveryState.DELIVERY_UNCERTAIN)
            return DeliveryState.DELIVERY_UNCERTAIN
        self.store.finalize_reply(
            reply.reply_id, DeliveryState.SENT, telegram_message_id
        )
        return DeliveryState.SENT

    @staticmethod
    def keyboard(reply: ReplyRecord) -> list[list[dict[str, str]]]:
        value = json.loads(reply.keyboard_json)
        if not isinstance(value, list):
            raise ValueError("invalid stored keyboard")
        return value
