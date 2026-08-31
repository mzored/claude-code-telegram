"""Isolated Telegram Business public assistant.

This package has no dependency on the private Claude agent or external-action
integrations. Delivery Unit 2 adds one consent-gated, tool-free OpenAI
Responses boundary for bounded conversation and request capture.
"""

from src.public_assistant.config import PublicAssistantConfig
from src.public_assistant.service import SecretaryService
from src.public_assistant.storage import Unit1Store

__all__ = ["PublicAssistantConfig", "SecretaryService", "Unit1Store"]
