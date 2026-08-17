import asyncio

import pytest

from backend.llm_client import generate_completion, provider_mode


def test_provider_mode_returns_mock_when_no_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert provider_mode() == "mock"


def test_provider_mode_returns_openrouter_when_key_set(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
    assert provider_mode() == "openrouter"


def test_mock_completion_when_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    response = asyncio.run(generate_completion("Explain data minimization."))
    assert "Mock" in response


def test_mock_completion_contains_prompt_summary(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    response = asyncio.run(generate_completion("Explain data minimization."))
    assert "data minimization" in response.lower() or "sanitized prompt" in response.lower()
