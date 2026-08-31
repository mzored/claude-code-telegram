"""Dedicated process entry point for Delivery Unit 1."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys

from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.service import SecretaryService
from src.public_assistant.storage import Unit1Store
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


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CredentialRedactingFormatter("%(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)


def run() -> None:
    """Validate keys and stores before constructing a Telegram client."""

    os.umask(0o077)
    configure_logging()
    config = PublicAssistantConfig.from_environment()
    credentials = config.load_runtime_credentials()
    store = Unit1Store(
        config.data_dir,
        credentials.pending_database_key,
        credentials.public_database_key,
        credentials.pseudonym_key,
    )
    log = PrivacyLog(credentials.pseudonym_key, logging.getLogger("public_assistant"))
    service = SecretaryService(config, store, logger=log)
    application, adapter = build_application(
        config, service, store, credentials.bot_token
    )
    try:
        asyncio.run(DurablePollingRunner(application, adapter, store).run())
    finally:
        store.close()


if __name__ == "__main__":
    run()
