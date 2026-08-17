"""LLM client for PrivGuard.

Uses OpenRouter (OpenAI-compatible) as the sole provider. A mock mode is
available for testing. The model is selected manually by the user at request
time — no hardcoded model list.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from backend.privacy_engine import analyze_and_sanitize

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def provider_mode() -> str:
    """Return 'openrouter' or 'mock' based on OPENROUTER_API_KEY."""
    if os.getenv("OPENROUTER_API_KEY", "").strip():
        return "openrouter"
    return "mock"


async def generate_completion(
    sanitized_prompt: str,
    model: str | None = None,
    api_key: str | None = None,
) -> str:
    """Generate a completion via OpenRouter or return a mock response.

    Parameters
    ----------
    sanitized_prompt:
        The privacy-sanitized user prompt.
    model:
        Model identifier (e.g. ``openai/gpt-4o``, ``anthropic/claude-sonnet-4``).
        Falls back to the ``OPENROUTER_MODEL`` env var, then to a sensible
        default.
    api_key:
        Optional per-request API key override. Falls back to
        ``OPENROUTER_API_KEY`` env var.
    """
    resolved_key = (api_key or os.getenv("OPENROUTER_API_KEY", "")).strip()
    resolved_model = (
        model
        or os.getenv("OPENROUTER_MODEL", "").strip()
        or "openai/gpt-4o-mini"
    )

    if not resolved_key:
        return _mock_completion(sanitized_prompt)

    timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))

    payload = {
        "model": resolved_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a privacy-preserving assistant. Do not include personal identifiers, "
                    "secrets, credentials, government IDs, payment details, exact addresses, precise "
                    "locations, or unnecessary sensitive facts. Use generic roles and generalized wording."
                ),
            },
            {"role": "user", "content": sanitized_prompt},
        ],
        "temperature": 0.2,
    }

    headers = {
        "Authorization": f"Bearer {resolved_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": os.getenv("OPENROUTER_REFERER", "http://localhost:8000"),
        "X-Title": os.getenv("OPENROUTER_APP_NAME", "PrivGuard"),
    }

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()

    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(
            "OpenRouter response did not match OpenAI-compatible chat completion schema"
        ) from exc


def _mock_completion(sanitized_prompt: str) -> str:
    return (
        "Mock LLM response:\n\n"
        "Here is a privacy-preserving answer based only on the sanitized prompt. "
        "Use generic roles, avoid personal identifiers, and do not include contact details, "
        "government identifiers, credentials, payment details, or precise locations.\n\n"
        "Sanitized prompt summary:\n"
        f"{sanitized_prompt[:900]}"
    )
