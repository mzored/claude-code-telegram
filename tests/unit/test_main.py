"""Tests for application startup helpers."""

import logging

from src.main import TelegramTokenRedactingFormatter, setup_logging


def test_logging_formatter_redacts_telegram_bot_token_from_url() -> None:
    formatter = TelegramTokenRedactingFormatter("%(message)s")
    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=(
            "HTTP Request: POST "
            "https://api.telegram.org/bot123456789:secret-value/getUpdates"
        ),
        args=(),
        exc_info=None,
    )

    rendered = formatter.format(record)

    assert "123456789:secret-value" not in rendered
    assert "https://api.telegram.org/bot<redacted>/getUpdates" in rendered


def test_setup_logging_suppresses_http_transport_info_logs() -> None:
    setup_logging(debug=True)

    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() == logging.WARNING
