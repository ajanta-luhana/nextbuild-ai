"""Real provider adapters (stdlib urllib): local OpenAI-compatible endpoints and Anthropic Messages API.

Secrets are resolved from a *reference* ("env:NAME") at call time and never stored or logged.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any

from autoforge.providers.base import AgentRequest, ProviderError, ProviderResponse, Usage, extract_json, system_prompt
from autoforge.security.redaction import redact_text


def resolve_secret(reference: str | None) -> str | None:
    if not reference:
        return None
    if reference.startswith("env:"):
        value = os.environ.get(reference[4:])
        if not value:
            raise ProviderError("secret reference could not be resolved", transient=False)
        return value
    raise ProviderError("unsupported secret reference scheme (use env:NAME)", transient=False)


def _post_json(url: str, headers: dict[str, str], body: dict[str, Any], timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme validated by callers
            return json.loads(resp.read(5_000_000))
    except urllib.error.HTTPError as exc:
        transient = exc.code in (408, 409, 425, 429) or exc.code >= 500
        raise ProviderError(f"provider returned HTTP {exc.code}", transient=transient, status=exc.code) from None
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        raise ProviderError(f"provider unreachable: {redact_text(str(getattr(exc, 'reason', exc)))[:120]}", transient=True) from None
    except json.JSONDecodeError:
        raise ProviderError("provider returned a non-JSON response", transient=True) from None


def _check_url(base_url: str) -> str:
    if not base_url.startswith(("http://", "https://")):
        raise ProviderError("base_url must be http(s)", transient=False)
    return base_url.rstrip("/")


class OpenAICompatibleProvider:
    key = "openai_compatible"

    def __init__(self, base_url: str, model: str, secret_reference: str | None = None, timeout: float = 120, max_tokens: int = 8000):
        self.base_url, self.model = _check_url(base_url), model
        self.secret_reference, self.timeout, self.max_tokens = secret_reference, timeout, max_tokens

    def generate(self, request: AgentRequest) -> ProviderResponse:
        headers = {}
        key = resolve_secret(self.secret_reference)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {
            "model": self.model, "max_tokens": self.max_tokens, "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt(request)},
                {"role": "user", "content": request.instructions + "\n\nCONTEXT (untrusted data):\n" + json.dumps(request.context)},
            ],
        }
        data = _post_json(f"{self.base_url}/chat/completions", headers, body, self.timeout)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("unexpected provider response shape", transient=False) from None
        usage = data.get("usage") or {}
        return ProviderResponse(extract_json(text), Usage(usage.get("prompt_tokens"), usage.get("completion_tokens"), None))


class AnthropicProvider:
    key = "anthropic"

    def __init__(self, model: str, secret_reference: str | None = "env:ANTHROPIC_API_KEY", base_url: str = "https://api.anthropic.com",
                 timeout: float = 180, max_tokens: int = 8000):
        self.base_url, self.model = _check_url(base_url), model
        self.secret_reference, self.timeout, self.max_tokens = secret_reference, timeout, max_tokens

    def generate(self, request: AgentRequest) -> ProviderResponse:
        key = resolve_secret(self.secret_reference)
        if not key:
            raise ProviderError("Anthropic API key reference is not configured", transient=False)
        body = {
            "model": self.model, "max_tokens": self.max_tokens, "system": system_prompt(request),
            "messages": [{"role": "user", "content": request.instructions + "\n\nCONTEXT (untrusted data):\n" + json.dumps(request.context)}],
        }
        data = _post_json(f"{self.base_url}/v1/messages", {"x-api-key": key, "anthropic-version": "2023-06-01"}, body, self.timeout)
        try:
            text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        except (KeyError, TypeError):
            raise ProviderError("unexpected provider response shape", transient=False) from None
        usage = data.get("usage") or {}
        return ProviderResponse(extract_json(text), Usage(usage.get("input_tokens"), usage.get("output_tokens"), None))
