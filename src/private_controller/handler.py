"""Fresh-owner Telegram command for deterministic Policy Gate administration."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from src.policy_gate.types import TrustedReference, canonical_json
from src.private_controller.service import PrivateControllerService
from src.private_controller.telegram import telegram_run_trigger

_USAGE = (
    "Usage:\n"
    "/policy <managed_chat|request|action>:<opaque-reference> <instruction>\n"
    "/policy confirm <intent-id> <preview-message-id>"
)


async def policy_control(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Prepare or confirm one immutable owner administration intent."""

    controller = context.bot_data.get("private_controller")
    message = update.effective_message
    if not isinstance(controller, PrivateControllerService) or message is None:
        if message is not None:
            await message.reply_text("Policy administration is disabled.")
        return
    trigger = telegram_run_trigger(update)
    run = controller.runs.begin(
        trigger,
        owner_id=controller.owner_id,
        control_chat_id=controller.control_chat_id,
    )
    arguments = list(context.args or [])
    if arguments and arguments[0].casefold() == "confirm":
        if len(arguments) != 3:
            await message.reply_text(_USAGE)
            return
        try:
            preview_message_id = int(arguments[2])
            result = controller.confirm(run.run_id, arguments[1], preview_message_id)
        except (PermissionError, ValueError):
            await message.reply_text("Policy confirmation was rejected.")
            return
        await message.reply_text(f"Policy confirmation result: {result.outcome}.")
        return
    if len(arguments) < 2 or ":" not in arguments[0]:
        await message.reply_text(_USAGE)
        return
    kind, value = arguments[0].split(":", 1)
    placeholder = await message.reply_text("Preparing immutable policy preview…")
    try:
        prepared = controller.prepare(
            run.run_id,
            TrustedReference(kind, value),
            " ".join(arguments[1:]),
            preview_message_id=placeholder.message_id,
        )
    except (PermissionError, ValueError):
        await placeholder.edit_text("Policy preview was rejected.")
        return
    preview = canonical_json(dict(prepared.preview))
    await placeholder.edit_text(
        "Policy preview (no authority changed):\n"
        f"{preview}\n\n"
        "Confirm from a fresh owner message with:\n"
        f"/policy confirm {prepared.intent_id} {placeholder.message_id}"
    )
