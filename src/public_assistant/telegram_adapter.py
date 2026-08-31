"""python-telegram-bot 22.6 boundary for Telegram Business updates."""

from __future__ import annotations

import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    BusinessConnectionHandler,
    BusinessMessagesDeletedHandler,
    CallbackContext,
    CallbackQueryHandler,
    MessageHandler,
    filters,
)

from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.service import DefiniteDeliveryError, SecretaryService
from src.public_assistant.storage import Unit1Store
from src.public_assistant.types import (
    ConnectionObservation,
    DeleteNotice,
    InboundMessage,
    OwnerMessage,
    ProcessingResult,
    ReplyRecord,
)

EXPLICIT_ALLOWED_UPDATES = (
    "business_connection",
    "business_message",
    "edited_business_message",
    "deleted_business_messages",
    "callback_query",
)


class TelegramBusinessAdapter:
    """Normalize trusted PTB fields and keep Telegram semantics at ingress."""

    def __init__(
        self,
        config: PublicAssistantConfig,
        service: SecretaryService,
        store: Unit1Store,
    ) -> None:
        self.config = config
        self.service = service
        self.store = store
        self.logger = logging.getLogger("public_assistant.telegram")

    async def on_business_connection(
        self, update: Update, context: CallbackContext
    ) -> None:
        del context
        connection = update.business_connection
        if connection is None:
            return
        rights = connection.rights
        self.service.observe_connection(
            ConnectionObservation(
                connection_id=connection.id,
                owner_id=connection.user.id,
                enabled=connection.is_enabled,
                can_reply=(rights.can_reply if rights is not None else None),
                observed_at=connection.date,
            )
        )

    async def on_business_message(
        self, update: Update, context: CallbackContext
    ) -> None:
        message = update.business_message
        if message is None or message.business_connection_id is None:
            return
        from_user = message.from_user
        if from_user is None:
            return
        sender_business_bot = message.sender_business_bot
        if from_user.id == self.config.owner_id or sender_business_bot is not None:
            result = self.service.handle_owner_message(
                OwnerMessage(
                    connection_id=message.business_connection_id,
                    conversation_id=message.chat.id,
                    owner_id=from_user.id,
                    update_id=update.update_id,
                    message_id=message.message_id,
                    sender_business_bot_id=(
                        sender_business_bot.id
                        if sender_business_bot is not None
                        else None
                    ),
                    chat_type=message.chat.type,
                )
            )
        elif message.text is not None:
            result = self.service.handle_message(
                InboundMessage(
                    connection_id=message.business_connection_id,
                    conversation_id=message.chat.id,
                    sender_id=from_user.id,
                    message_id=message.message_id,
                    update_id=update.update_id,
                    text=message.text,
                    sent_at=message.date,
                    chat_type=message.chat.type,
                )
            )
        else:
            return
        await self._deliver_result(result, context)

    async def on_edited_business_message(
        self, update: Update, context: CallbackContext
    ) -> None:
        message = update.edited_business_message
        if (
            message is None
            or message.business_connection_id is None
            or message.from_user is None
            or message.text is None
        ):
            return
        if (
            message.from_user.id == self.config.owner_id
            or message.sender_business_bot is not None
        ):
            return
        result = self.service.handle_edit(
            InboundMessage(
                connection_id=message.business_connection_id,
                conversation_id=message.chat.id,
                sender_id=message.from_user.id,
                message_id=message.message_id,
                update_id=update.update_id,
                text=message.text,
                sent_at=message.date,
                chat_type=message.chat.type,
                edited_at=message.edit_date,
            )
        )
        await self._deliver_result(result, context)

    async def on_deleted_business_messages(
        self, update: Update, context: CallbackContext
    ) -> None:
        del context
        deletion = update.deleted_business_messages
        if deletion is None:
            return
        self.service.handle_delete(
            DeleteNotice(
                connection_id=deletion.business_connection_id,
                conversation_id=deletion.chat.id,
                message_ids=tuple(deletion.message_ids),
                update_id=update.update_id,
                chat_type=deletion.chat.type,
            )
        )

    async def on_callback_query(self, update: Update, context: CallbackContext) -> None:
        del context
        query = update.callback_query
        if query is None or query.data is None or query.message is None:
            return
        result = self.service.handle_control(
            query.data,
            actor_id=query.from_user.id,
            conversation_id=query.message.chat.id,
        )
        answers = {
            "accepted": "Processing enabled.",
            "declined": "Processing declined.",
            "revoked": "Processing revoked.",
            "erased": "Stored data deleted.",
            "expired": "This control expired.",
            "stale_version": "A new confirmation is required.",
            "replayed": "This control was already used.",
            "neutral": "This control is unavailable.",
            "invalid": "This control is unavailable.",
        }
        await query.answer(text=answers.get(result, "This control is unavailable."))

    async def expire_pending(self, context: CallbackContext) -> None:
        del context
        self.store.expire_pending()

    async def _deliver_result(
        self, result: ProcessingResult, context: CallbackContext
    ) -> None:
        if result.reply is None:
            return

        async def sender(reply: ReplyRecord) -> int:
            rows: list[list[InlineKeyboardButton]] = []
            for row in self.service.keyboard(reply):
                buttons: list[InlineKeyboardButton] = []
                for item in row:
                    buttons.append(
                        InlineKeyboardButton(
                            text=item["text"],
                            callback_data=item.get("callback_data"),
                            url=item.get("url"),
                        )
                    )
                rows.append(buttons)
            try:
                sent = await context.bot.send_message(
                    chat_id=reply.conversation_id,
                    text=reply.text,
                    business_connection_id=reply.connection_id,
                    reply_markup=InlineKeyboardMarkup(rows),
                )
            except BadRequest as exc:
                raise DefiniteDeliveryError("Telegram rejected stored reply") from exc
            return int(sent.message_id)

        await self.service.deliver_reply(result.reply, sender)


def build_application(
    config: PublicAssistantConfig, service: SecretaryService, store: Unit1Store
) -> Application:
    """Build a dedicated long-polling Application with only Unit 1 handlers."""

    adapter = TelegramBusinessAdapter(config, service, store)
    application = (
        Application.builder().token(config.bot_token).concurrent_updates(False).build()
    )
    application.add_handler(BusinessConnectionHandler(adapter.on_business_connection))
    application.add_handler(
        MessageHandler(
            filters.UpdateType.BUSINESS_MESSAGE & filters.TEXT,
            adapter.on_business_message,
        )
    )
    application.add_handler(
        MessageHandler(
            filters.UpdateType.EDITED_BUSINESS_MESSAGE & filters.TEXT,
            adapter.on_edited_business_message,
        )
    )
    application.add_handler(
        BusinessMessagesDeletedHandler(adapter.on_deleted_business_messages)
    )
    application.add_handler(CallbackQueryHandler(adapter.on_callback_query))
    if application.job_queue is not None:
        application.job_queue.run_repeating(adapter.expire_pending, interval=60)
    return application


def run_polling(application: Application) -> None:
    """Start only after encrypted stores and handlers have initialized."""

    application.run_polling(
        allowed_updates=list(EXPLICIT_ALLOWED_UPDATES),
        drop_pending_updates=False,
    )
