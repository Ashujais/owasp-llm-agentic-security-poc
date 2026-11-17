"""
Factory for instantiating model adapters dynamically.
"""
from typing import Optional
from app.models.base import BaseLLMAdapter
from app.models.claude_adapter import ClaudeAdapter
from app.models.gemini_adapter import GeminiAdapter
from app.config import DEFAULT_CLAUDE_MODEL, DEFAULT_GEMINI_MODEL

def get_model_adapter(
    provider: str = "claude",
    model_name: Optional[str] = None,
    api_key: Optional[str] = None
) -> BaseLLMAdapter:
    """
    Returns an instantiated BaseLLMAdapter.
    provider: 'claude' or 'gemini'
    """
    clean_provider = provider.lower().strip()
    if "claude" in clean_provider or "anthropic" in clean_provider:
        chosen_model = model_name or DEFAULT_CLAUDE_MODEL
        return ClaudeAdapter(model_name=chosen_model, api_key=api_key)
    elif "gemini" in clean_provider or "google" in clean_provider:
        chosen_model = model_name or DEFAULT_GEMINI_MODEL
        return GeminiAdapter(model_name=chosen_model, api_key=api_key)
    else:
        raise ValueError(f"Unsupported model provider: '{provider}'. Supported options: 'claude', 'gemini'.")
