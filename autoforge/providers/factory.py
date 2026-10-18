from __future__ import annotations

from autoforge.providers.base import Provider, ProviderError
from autoforge.providers.http_providers import AnthropicProvider, OpenAICompatibleProvider
from autoforge.providers.mock import MockProvider

PROVIDER_TYPES = ("mock", "openai_compatible", "anthropic")


def build_provider(provider_type: str, model: str, *, base_url: str | None = None,
                   secret_reference: str | None = None, settings: dict | None = None) -> Provider:
    settings = settings or {}
    timeout = float(settings.get("timeout_seconds", 120))
    max_tokens = int(settings.get("max_tokens", 8000))
    if provider_type == "mock":
        return MockProvider(model or "mock-deterministic")
    if provider_type == "openai_compatible":
        if not base_url:
            raise ProviderError("base_url is required for openai_compatible providers", transient=False)
        return OpenAICompatibleProvider(base_url, model, secret_reference, timeout, max_tokens)
    if provider_type == "anthropic":
        return AnthropicProvider(model, secret_reference or "env:ANTHROPIC_API_KEY", base_url or "https://api.anthropic.com", timeout, max_tokens)
    raise ProviderError(f"unknown provider type {provider_type}", transient=False)
