"""Dedicated process entry point for Public Assistant Delivery Unit 2."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys

from src.public_assistant.config import (
    PublicAssistantConfig,
    PublicAssistantConfigurationError,
    Unit2Config,
)
from src.public_assistant.conversation import AssistantService
from src.public_assistant.inbox import Unit2Store
from src.public_assistant.model import OpenAIResponsesModel
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.telegram_adapter import (
    DurablePollingRunner,
    build_application,
)

_TELEGRAM_TOKEN = re.compile(r"(?<=api\.telegram\.org/bot)[^/\s\"']+")


class CredentialRedactingFormatter(logging.Formatter):
    """Redact Telegram credentials from transport errors before rendering."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        public_fields = getattr(record, "public_fields", None)
        if isinstance(public_fields, dict):
            rendered += " " + json.dumps(public_fields, sort_keys=True)
        return _TELEGRAM_TOKEN.sub("<redacted>", rendered)


class DependencyPrivacyFilter(logging.Filter):
    """Replace dependency diagnostics that may embed raw Telegram updates."""

    _PRIVATE_PREFIXES = ("telegram", "httpx", "httpcore")

    def filter(self, record: logging.LogRecord) -> bool:
        if any(
            record.name == prefix or record.name.startswith(prefix + ".")
            for prefix in self._PRIVATE_PREFIXES
        ):
            record.msg = "dependency diagnostic redacted"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CredentialRedactingFormatter("%(levelname)s %(message)s"))
    handler.addFilter(DependencyPrivacyFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)


def run() -> None:
    """Run with a fixed top-level failure message that cannot expose input data."""

    os.umask(0o077)
    configure_logging()
    try:
        _run()
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except BaseException:
        logging.getLogger("public_assistant").critical(
            "public assistant stopped due to an unrecoverable error"
        )
        raise SystemExit(1) from None


def _run() -> None:
    """Validate keys and stores before constructing a Telegram client."""

    config = PublicAssistantConfig.from_environment()
    unit2_config = Unit2Config.from_environment(config)
    credentials = config.load_runtime_credentials()
    openai_api_key = unit2_config.read_openai_api_key()
    if openai_api_key.encode() in {
        credentials.bot_token.encode(),
        credentials.pending_database_key.encode(),
        credentials.public_database_key.encode(),
        credentials.pseudonym_key,
    }:
        raise PublicAssistantConfigurationError(
            "OpenAI credential material must differ from runtime credentials"
        )
    store = Unit2Store(
        config.data_dir,
        credentials.pending_database_key,
        credentials.public_database_key,
        credentials.pseudonym_key,
    )
    log = PrivacyLog(credentials.pseudonym_key, logging.getLogger("public_assistant"))
    model = OpenAIResponsesModel(
        openai_api_key,
        unit2_config.model,
        timeout_seconds=unit2_config.timeout_seconds,
        max_output_tokens=unit2_config.max_output_tokens,
    )
    service = AssistantService(config, unit2_config, store, model, logger=log)
    application, adapter = build_application(
        config, service, store, credentials.bot_token
    )
    try:
        asyncio.run(DurablePollingRunner(application, adapter, store).run())
    finally:
        store.close()


if __name__ == "__main__":
    run()
