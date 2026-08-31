"""Dedicated process entry point for Delivery Unit 1."""

from __future__ import annotations

import json
import logging
import os
import re
import sys

from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.privacy_log import PrivacyLog
from src.public_assistant.service import SecretaryService
from src.public_assistant.storage import Unit1Store
from src.public_assistant.telegram_adapter import build_application, run_polling

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
    store = Unit1Store(
        config.data_dir,
        config.pending_database_key,
        config.public_database_key,
        config.backup_database_key,
        config.pseudonym_key,
    )
    log = PrivacyLog(config.pseudonym_key, logging.getLogger("public_assistant"))
    service = SecretaryService(config, store, logger=log)
    application = build_application(config, service, store)
    try:
        run_polling(application)
    finally:
        store.close()


if __name__ == "__main__":
    run()
