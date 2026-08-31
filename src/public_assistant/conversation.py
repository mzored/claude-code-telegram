"""Consented conversation and Assistant Inbox behavior for Unit 2."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

from src.public_assistant.config import PublicAssistantConfig, Unit2Config
from src.public_assistant.inbox import Unit2Store
from src.public_assistant.model import PublicModel
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.service import SecretaryService, _language
from src.public_assistant.types import (
    DeleteNotice,
    InboundMessage,
    ProcessingResult,
    ReplyRecord,
)

REQUEST_CONFIRMED = {
    "en": "I passed this request to Misha. He will respond directly if appropriate.",
    "ru": "Я передал запрос Мише. Если потребуется, он ответит напрямую.",
}
FALLBACK = {
    "en": "I couldn't complete an automated reply, but I passed your message to Misha as a request. He will respond directly if appropriate.",
    "ru": "Я не смог подготовить автоматический ответ, но передал сообщение Мише как запрос. Если потребуется, он ответит напрямую.",
}
GREETING = {
    "en": "Hello. I'm Misha's automated assistant. How can I help?",
    "ru": "Здравствуйте. Я автоматический помощник Миши. Чем могу помочь?",
}
REJECTED = {
    "en": "I can't help with abusive or threatening messages.",
    "ru": "Я не могу помогать с оскорбительными или угрожающими сообщениями.",
}

UNIT2_DISCLOSURE = {
    "en": (
        "I’m Misha’s automated assistant. Before I process this message, please "
        "choose Continue. Your text may then be processed by OpenAI to assist with "
        "replies and request capture. Local sender-derived content is retained for "
        "up to 90 days. You can revoke processing or request deletion at any time."
    ),
    "ru": (
        "Я автоматический помощник Миши. Прежде чем обработать это сообщение, "
        "нажмите «Продолжить». После этого текст может обрабатываться OpenAI для "
        "ответов и фиксации запросов. Локальные данные отправителя хранятся не "
        "более 90 дней. Согласие можно отозвать или запросить удаление данных."
    ),
}

_GREETINGS = {
    "hi",
    "hello",
    "hey",
    "привет",
    "здравствуйте",
    "добрый день",
    "добрый вечер",
}
_ABUSE = (
    "kill yourself",
    "i will kill",
    "я тебя убью",
    "сдохни",
)


class AssistantService(SecretaryService):
    """Useful post-consent assistant with no owner or integration authority."""

    def __init__(
        self,
        config: PublicAssistantConfig,
        unit2_config: Unit2Config,
        store: Unit2Store,
        model: PublicModel,
        *,
        logger: PrivacyLog | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(config, store, logger=logger, now=now)
        self.store: Unit2Store = store
        self.unit2_config = unit2_config
        self.model = model

    def _consent_disclosure(self, language: str) -> str:
        """Unit 2 asks consent only for the processor it can actually invoke."""

        return UNIT2_DISCLOSURE[language]

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
        if not self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            return self._stage_consent(message)
        self.store.store_consented_message(message, self.config.retention_seconds)
        self.store.extend_privacy_reference(subject, self.config.retention_seconds)
        if message.text.strip().casefold() in {
            "/privacy",
            "privacy",
            "конфиденциальность",
        }:
            reply = self._maintenance_reply(message)
            self.store.set_update_outcome(message.update_id, "privacy", reply.reply_id)
            return ProcessingResult("privacy", reply)
        return self._process_consented(message)

    def handle_edit(self, message: InboundMessage) -> ProcessingResult:
        result = super().handle_edit(message)
        if result.outcome != "consented_body_replaced":
            return result
        message_key = self.store.message_key(
            message.connection_id, message.conversation_id, message.message_id
        )
        self.store.cancel_linked_replies(message_key)
        self.store.supersede_message_artifacts(
            message.connection_id, message.conversation_id, (message.message_id,)
        )
        return self._process_consented(message)

    def handle_delete(self, notice: DeleteNotice) -> ProcessingResult:
        result = super().handle_delete(notice)
        if result.outcome == "deleted":
            self.store.supersede_message_artifacts(
                notice.connection_id, notice.conversation_id, notice.message_ids
            )
        return result

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
            result in {"accepted", "replayed"}
            and control is not None
            and control.action in {"consent", "reconsent"}
        ):
            message = (
                self.store.message_for_key(control.pending_key)
                if control.pending_key is not None
                else None
            )
            replay_pending = (
                result == "replayed"
                and message is not None
                and self.store.update_outcome(message.update_id)
                in {"received", "awaiting_consent"}
            )
            reference = (
                self.store.replace_privacy_reference(
                    control.subject_ref, self.config.retention_seconds
                )
                if replay_pending
                else self.store.create_privacy_reference(
                    control.subject_ref, self.config.retention_seconds
                )
            )
            if control.pending_key is not None:
                if message is not None and (result == "accepted" or replay_pending):
                    self._process_consented(message)
            if reference is not None:
                return f"accepted:{reference}"
        return result

    def _process_consented(self, message: InboundMessage) -> ProcessingResult:
        if not self.store.has_active_consent(
            message.connection_id,
            message.conversation_id,
            message.sender_id,
            self.config.processing_authorization_version,
        ):
            return ProcessingResult("consent_stopped")
        normalized = " ".join(message.text.casefold().split()).strip(".!?,")
        lang = _language(message.text)
        if normalized in _GREETINGS:
            reply = self._assistant_reply(message, GREETING[lang])
            self.store.add_assistant_context(
                message, GREETING[lang], self.config.retention_seconds
            )
            self.store.set_update_outcome(message.update_id, "greeting", reply.reply_id)
            return ProcessingResult("greeting", reply)
        if any(marker in normalized for marker in _ABUSE):
            reply = self._assistant_reply(message, REJECTED[lang])
            self.store.add_assistant_context(
                message, REJECTED[lang], self.config.retention_seconds
            )
            self.store.set_update_outcome(message.update_id, "rejected", reply.reply_id)
            return ProcessingResult("rejected", reply)

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
        result = None
        try:
            result = self.model.generate(
                conversation,
                self.store.model_safety_identifier(message),
            )
            turn = result.turn
            self.store.finish_model_call(reservation, result, self.unit2_config)
        except Exception:
            self.store.finish_model_call(reservation, None, self.unit2_config)
            return self._fallback_request(message, "model_fallback")

        request_id = None
        reply_text = turn.reply_text
        if turn.turn_kind == "request":
            if turn.request_patch is None:
                self.store.finish_model_call(reservation, None, self.unit2_config)
                return self._fallback_request(message, "model_fallback")
            body = turn.request_patch.content
            request_id = self.store.upsert_request(
                message, body, self.config.retention_seconds
            )
            reply_text = REQUEST_CONFIRMED[lang]
        reply = self._assistant_reply(message, reply_text)
        self.store.add_assistant_context(
            message, reply_text, self.config.retention_seconds
        )
        outcome = "request_captured" if request_id is not None else turn.turn_kind
        self.store.set_update_outcome(message.update_id, outcome, reply.reply_id)
        return ProcessingResult(outcome, reply)

    def _fallback_request(
        self, message: InboundMessage, outcome: str
    ) -> ProcessingResult:
        self.store.upsert_request(
            message, message.text.strip()[:4000], self.config.retention_seconds
        )
        text = FALLBACK[_language(message.text)]
        reply = self._assistant_reply(message, text)
        self.store.add_assistant_context(message, text, self.config.retention_seconds)
        self.store.set_update_outcome(message.update_id, outcome, reply.reply_id)
        return ProcessingResult(outcome, reply)

    def _assistant_reply(self, message: InboundMessage, text: str) -> ReplyRecord:
        lang = _language(message.text)
        revoke, delete = self.store.create_maintenance_controls(
            message,
            self.config.privacy_policy_version,
            self.config.processing_authorization_version,
            self.config.pending_ttl_seconds,
        )
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
                    "text": "Privacy" if lang == "en" else "Конфиденциальность",
                    "url": self.config.privacy_url,
                }
            ],
        ]
        reply = self.store.create_reply(message, "assistant", text, keyboard)
        if not json.loads(reply.keyboard_json):
            raise RuntimeError("assistant privacy controls were not stored")
        return reply
