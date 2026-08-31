"""python-telegram-bot 22.6 boundary with durable sequential polling."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest, Conflict, Forbidden, NetworkError, RetryAfter
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
from src.public_assistant.inbox import Unit2Store
from src.public_assistant.service import (
    DefiniteDeliveryError,
    RetryableDeliveryError,
    SecretaryService,
)
from src.public_assistant.storage import Unit1Store
from src.public_assistant.types import (
    ConnectionObservation,
    DeleteNotice,
    InboundMessage,
    OwnerMessage,
    ReplyRecord,
)

EXPLICIT_ALLOWED_UPDATES = (
    "business_connection",
    "business_message",
    "edited_business_message",
    "deleted_business_messages",
    "callback_query",
)


class TransientConnectionError(RuntimeError):
    """Current connection authority could not be observed after bounded retries."""


class TelegramBusinessAdapter:
    """Normalize trusted PTB fields and propagate every handler failure."""

    def __init__(
        self,
        config: PublicAssistantConfig,
        service: SecretaryService,
        store: Unit1Store,
        *,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.config = config
        self.service = service
        self.store = store
        self._now = now or (lambda: datetime.now(UTC))
        self._sleep = sleep
        self.logger = logging.getLogger("public_assistant.telegram")

    async def _refresh_connection(self, bot: Any, connection_id: str) -> bool:
        """Observe authority; transient lookup failures must replay the update."""

        connection = None
        for attempt in range(3):
            try:
                connection = await bot.get_business_connection(connection_id)
                break
            except Conflict:
                raise
            except (BadRequest, Forbidden):
                self.store.deny_connection(connection_id)
                self.store.purge_unconsented_connection(connection_id)
                return False
            except RetryAfter as exc:
                delay = exc.retry_after
                seconds = (
                    delay.total_seconds()
                    if isinstance(delay, timedelta)
                    else float(delay)
                )
                if attempt == 2:
                    raise TransientConnectionError(
                        "business connection observation unavailable"
                    ) from exc
                await self._sleep(max(0.0, seconds))
            except NetworkError as exc:
                if attempt == 2:
                    raise TransientConnectionError(
                        "business connection observation unavailable"
                    ) from exc
                await self._sleep(float(2**attempt))
            except Exception as exc:
                raise TransientConnectionError(
                    "business connection observation unavailable"
                ) from exc
        if connection is None:
            raise TransientConnectionError(
                "business connection observation unavailable"
            )
        rights = connection.rights
        self.service.observe_connection(
            ConnectionObservation(
                connection_id=connection.id,
                owner_id=connection.user.id,
                enabled=connection.is_enabled,
                can_reply=rights.can_reply if rights is not None else None,
                observed_at=self._now(),
            )
        )
        if not connection.is_enabled or connection.user.id != self.config.owner_id:
            self.store.purge_unconsented_connection(connection.id)
        return True

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
                can_reply=rights.can_reply if rights is not None else None,
                observed_at=self._now(),
            )
        )
        if not connection.is_enabled or connection.user.id != self.config.owner_id:
            self.store.purge_unconsented_connection(connection.id)

    async def on_business_message(
        self, update: Update, context: CallbackContext
    ) -> None:
        message = update.business_message
        if message is None or message.business_connection_id is None:
            return
        if message.sender_business_bot is not None or message.is_from_offline:
            return
        from_user = message.from_user
        if from_user is None:
            return
        if not await self._refresh_connection(
            context.bot, message.business_connection_id
        ):
            return
        if not self.store.connection_owner_matches(
            message.business_connection_id, self.config.owner_id
        ):
            return
        if from_user.id == self.config.owner_id:
            result = self.service.handle_owner_message(
                OwnerMessage(
                    connection_id=message.business_connection_id,
                    conversation_id=message.chat.id,
                    owner_id=from_user.id,
                    update_id=update.update_id,
                    message_id=message.message_id,
                    sender_business_bot_id=None,
                    chat_type=message.chat.type,
                    is_from_offline=bool(message.is_from_offline),
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
        del result

    async def on_edited_business_message(
        self, update: Update, context: CallbackContext
    ) -> None:
        message = update.edited_business_message
        if (
            message is None
            or message.business_connection_id is None
            or message.from_user is None
            or message.text is None
            or message.sender_business_bot is not None
            or message.is_from_offline
            or message.from_user.id == self.config.owner_id
        ):
            return
        if not await self._refresh_connection(
            context.bot, message.business_connection_id
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
        del result

    async def on_deleted_business_messages(
        self, update: Update, context: CallbackContext
    ) -> None:
        deletion = update.deleted_business_messages
        if deletion is None:
            return
        if not await self._refresh_connection(
            context.bot, deletion.business_connection_id
        ):
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
        query = update.callback_query
        if query is None or query.data is None:
            return
        if query.message is None:
            await self._answer_callback(query, "This control is unavailable.")
            return
        message = query.message
        connection_id = getattr(message, "business_connection_id", None)
        sender_bot = getattr(message, "sender_business_bot", None)
        if (
            connection_id is None
            or sender_bot is None
            or sender_bot.id != context.bot.id
        ):
            await self._answer_callback(query, "This control is unavailable.")
            return
        control = self.store.resolve_control(
            query.data,
            query.from_user.id,
            message.chat.id,
            connection_id,
            message.message_id,
        )
        if control is not None and control.action in {"consent", "reconsent"}:
            if not await self._refresh_connection(context.bot, connection_id):
                await self._answer_callback(query, "This control is unavailable.")
                return
        result = self.service.handle_control(
            query.data,
            actor_id=query.from_user.id,
            conversation_id=message.chat.id,
            connection_id=connection_id,
            origin_message_id=message.message_id,
        )
        reference = None
        if result.startswith("accepted:"):
            result, reference = "accepted", result.split(":", 1)[1]
        answers = {
            "accepted": "Processing enabled.",
            "declined": "Processing declined.",
            "revoked": "Processing revoked.",
            "erased": "Stored data deleted.",
            "expired": "This control expired.",
            "stale_version": "A new confirmation is required.",
            "replayed": "This control was already used.",
        }
        answer = answers.get(result, "This control is unavailable.")
        if reference is not None:
            answer = f"Processing enabled. Save privacy reference: {reference}"
        await self._answer_callback(query, answer)

    async def _answer_callback(self, query: Any, text: str) -> None:
        """Treat Telegram's definite answer rejection as terminal UI feedback."""

        try:
            await query.answer(text=text)
        except (BadRequest, Forbidden):
            self.logger.warning("callback answer rejected after durable handling")

    async def expire_data(self, context: CallbackContext) -> None:
        del context
        self.store.expire_pending()
        self.store.expire_public(self.config.retention_seconds)
        reconcile_erasures = getattr(self.service, "reconcile_erasures", None)
        if callable(reconcile_erasures):
            reconcile_erasures()

    async def _deliver_reply(self, reply: ReplyRecord, bot: Any) -> None:
        async def sender(stored: ReplyRecord) -> int:
            rows: list[list[InlineKeyboardButton]] = []
            for row in self.service.keyboard(stored):
                rows.append(
                    [
                        InlineKeyboardButton(
                            text=item["text"],
                            callback_data=item.get("callback_data"),
                            url=item.get("url"),
                        )
                        for item in row
                    ]
                )
            try:
                sent = await bot.send_message(
                    chat_id=stored.conversation_id,
                    text=stored.text,
                    business_connection_id=stored.connection_id,
                    reply_markup=InlineKeyboardMarkup(rows),
                )
            except RetryAfter as exc:
                delay = exc.retry_after
                seconds = (
                    int(delay.total_seconds())
                    if isinstance(delay, timedelta)
                    else int(delay)
                )
                raise RetryableDeliveryError(seconds) from exc
            except (Forbidden, BadRequest) as exc:
                raise DefiniteDeliveryError("Telegram rejected stored reply") from exc
            return int(sent.message_id)

        await self.service.deliver_reply(
            reply,
            sender,
            authority_check=lambda connection_id: self._refresh_reply_authority(
                bot, connection_id
            ),
        )

    async def _refresh_reply_authority(self, bot: Any, connection_id: str) -> bool:
        return bool(
            await self._refresh_connection(bot, connection_id)
            and self.store.connection_can_reply(connection_id, self.config.owner_id)
        )

    async def deliver_due_replies(self, bot: Any) -> None:
        for reply in self.store.due_replies():
            try:
                await self._deliver_reply(reply, bot)
            except TransientConnectionError:
                self.logger.warning("reply authority observation deferred")
                break
        await self.deliver_due_notifications(bot)

    async def deliver_due_notifications(self, bot: Any) -> None:
        """Deliver fixed Inbox alerts directly, without any private-agent path."""

        if not isinstance(self.store, Unit2Store):
            return
        unit2_config = getattr(self.service, "unit2_config", None)
        if unit2_config is None:
            return
        for notification in self.store.due_notifications():
            expected = f"Assistant Inbox request {notification.request_id} is ready."
            if notification.text != expected:
                if self.store.mark_notification_sending(notification.notification_id):
                    self.store.finish_notification(
                        notification.notification_id, "failed"
                    )
                continue
            if not self.store.mark_notification_sending(notification.notification_id):
                continue
            try:
                await bot.send_message(
                    chat_id=unit2_config.owner_alert_chat_id,
                    text=expected,
                )
            except (BadRequest, Forbidden):
                self.store.finish_notification(notification.notification_id, "failed")
            except Exception:
                self.store.finish_notification(
                    notification.notification_id, "uncertain"
                )
            else:
                self.store.finish_notification(notification.notification_id, "sent")

    async def dispatch(self, update: Update, bot: Any) -> None:
        """Dedicated sequential dispatcher whose exceptions are never swallowed."""

        context = cast(CallbackContext, SimpleNamespace(bot=bot))
        if update.business_connection is not None:
            await self.on_business_connection(update, context)
        elif update.business_message is not None:
            await self.on_business_message(update, context)
        elif update.edited_business_message is not None:
            await self.on_edited_business_message(update, context)
        elif update.deleted_business_messages is not None:
            await self.on_deleted_business_messages(update, context)
        elif update.callback_query is not None and (
            update.callback_query.data or ""
        ).startswith("pa:"):
            await self.on_callback_query(update, context)


class DurablePollingRunner:
    """Fetch one update at a time and acknowledge only after durable handling."""

    def __init__(
        self,
        application: Application,
        adapter: TelegramBusinessAdapter,
        store: Unit1Store,
        *,
        crash_hook: Callable[[str], None] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.application = application
        self.adapter = adapter
        self.store = store
        self.crash_hook = crash_hook
        self._sleep = sleep

    def _hook(self, stage: str) -> None:
        if self.crash_hook is not None:
            self.crash_hook(stage)

    async def _network_call(self, operation: Callable[[], Awaitable[Any]]) -> Any:
        for attempt in range(3):
            try:
                return await operation()
            except Conflict:
                raise
            except RetryAfter as exc:
                delay = exc.retry_after
                seconds = (
                    delay.total_seconds()
                    if isinstance(delay, timedelta)
                    else float(delay)
                )
                if attempt == 2:
                    raise
                await self._sleep(max(0.0, seconds))
            except NetworkError:
                if attempt == 2:
                    raise
                await self._sleep(float(2**attempt))
        raise RuntimeError("unreachable Telegram retry state")

    async def _fetch(self, timeout: int) -> tuple[Update, ...]:
        result = await self._network_call(
            lambda: self.application.bot.get_updates(
                offset=self.store.get_next_update_id(),
                limit=1,
                timeout=timeout,
                allowed_updates=list(EXPLICIT_ALLOWED_UPDATES),
            )
        )
        return tuple(result)

    async def _process(self, update: Update) -> None:
        self._hook("after_fetch")
        await self.adapter.dispatch(update, self.application.bot)
        self._hook("after_handler")
        self.store.commit_update_offset(update.update_id)
        self._hook("after_offset")

    async def run_once(self) -> bool:
        self.store.expire_pending()
        self.store.expire_public(self.adapter.config.retention_seconds)
        self.store.prune_restrictive_tombstones()
        updates = await self._fetch(0)
        if not updates:
            await self.adapter.deliver_due_replies(self.application.bot)
            updates = await self._fetch(30)
        processed = False
        while updates:
            await self._process(updates[0])
            processed = True
            updates = await self._fetch(0)
        await self.adapter.deliver_due_replies(self.application.bot)
        self._hook("before_next_poll")
        return processed

    async def run(self, stop_event: asyncio.Event | None = None) -> None:
        await self.application.initialize()
        started = False
        try:
            await self._network_call(
                lambda: self.application.bot.delete_webhook(drop_pending_updates=False)
            )
            await self.application.start()
            started = True
            while stop_event is None or not stop_event.is_set():
                await self.run_once()
                await asyncio.sleep(0)
        finally:
            if started:
                await self.application.stop()
            await self.application.shutdown()


def build_application(
    config: PublicAssistantConfig,
    service: SecretaryService,
    store: Unit1Store,
    bot_token: str,
) -> tuple[Application, TelegramBusinessAdapter]:
    """Build PTB handler metadata while polling through the durable dispatcher."""

    adapter = TelegramBusinessAdapter(config, service, store)
    application = (
        Application.builder().token(bot_token).concurrent_updates(False).build()
    )
    application.add_handler(
        BusinessConnectionHandler(adapter.on_business_connection, block=True), group=0
    )
    application.add_handler(
        MessageHandler(
            filters.UpdateType.BUSINESS_MESSAGE, adapter.on_business_message, block=True
        ),
        group=0,
    )
    application.add_handler(
        MessageHandler(
            filters.UpdateType.EDITED_BUSINESS_MESSAGE,
            adapter.on_edited_business_message,
            block=True,
        ),
        group=0,
    )
    application.add_handler(
        BusinessMessagesDeletedHandler(
            adapter.on_deleted_business_messages, block=True
        ),
        group=0,
    )
    application.add_handler(
        CallbackQueryHandler(adapter.on_callback_query, pattern=r"^pa:", block=True),
        group=0,
    )
    return application, adapter
