"""Fresh-owner Telegram command for deterministic Policy Gate administration."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from src.external_read import ExternalReadError, ExternalRecordRef
from src.policy_gate.rpc import GateRpcError
from src.policy_gate.types import TrustedReference, canonical_json
from src.private_controller.service import PrivateControllerService
from src.private_controller.telegram import telegram_run_trigger

_USAGE = (
    "Usage:\n"
    "/policy <managed_chat|request|action>:<opaque-reference> <instruction>\n"
    "/policy confirm <intent-id> <preview-message-id>"
)

_EXTERNAL_USAGE = (
    "Usage:\n"
    "/external inspect <inbox|todoist>:<opaque-reference>\n"
    "/external prepare <inbox|todoist>:<opaque-reference> <owner task title>\n"
    "/external confirm <intent-id> <preview-message-id> "
    "<inbox|todoist>:<opaque-reference>"
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


async def external_control(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run the deterministic Unit 4 read/prepare/confirm control path."""

    controller = context.bot_data.get("private_controller")
    message = update.effective_message
    if not isinstance(controller, PrivateControllerService) or message is None:
        if message is not None:
            await message.reply_text("External inspection is disabled.")
        return
    trigger = telegram_run_trigger(update)
    run = controller.runs.begin(
        trigger,
        owner_id=controller.owner_id,
        control_chat_id=controller.control_chat_id,
    )
    arguments = list(context.args or [])
    if len(arguments) == 2 and arguments[0].casefold() == "inspect":
        try:
            inspection = controller.inspect_external(
                run.run_id, ExternalRecordRef.parse(arguments[1])
            )
        except (ExternalReadError, GateRpcError, PermissionError, ValueError):
            await message.reply_text("External inspection was rejected or unavailable.")
            return
        await message.reply_text(inspection.summary)
        return
    if len(arguments) >= 3 and arguments[0].casefold() == "prepare":
        placeholder = await message.reply_text("Preparing immutable external preview…")
        try:
            prepared = controller.prepare_external(
                run.run_id,
                ExternalRecordRef.parse(arguments[1]),
                " ".join(arguments[2:]),
                preview_message_id=placeholder.message_id,
            )
        except (ExternalReadError, GateRpcError, PermissionError, ValueError):
            await placeholder.edit_text("External action preview was rejected.")
            return
        preview = canonical_json(dict(prepared.preview))
        await placeholder.edit_text(
            "External action preview (no authority changed):\n"
            f"{preview}\n\n"
            "Confirm from a fresh owner message with:\n"
            f"/external confirm {prepared.intent_id} {placeholder.message_id} "
            f"{arguments[1]}"
        )
        return
    if len(arguments) == 4 and arguments[0].casefold() == "confirm":
        try:
            preview_message_id = int(arguments[2])
            result = controller.confirm(
                run.run_id,
                arguments[1],
                preview_message_id,
                external_reference=ExternalRecordRef.parse(arguments[3]),
            )
        except (ExternalReadError, GateRpcError, PermissionError, ValueError):
            await message.reply_text("External action confirmation was rejected.")
            return
        await message.reply_text(
            f"External action confirmation result: {result.outcome}."
        )
        return
    await message.reply_text(_EXTERNAL_USAGE)
