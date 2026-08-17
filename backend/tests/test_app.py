"""FastAPI endpoint tests for PrivGuard."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "provider_mode" in data

    def test_health_provider_mode_value(self):
        response = client.get("/api/health")
        data = response.json()
        # Without OPENROUTER_API_KEY set, mode should be "mock"
        assert data["provider_mode"] in ("mock", "openrouter")


class TestAnalyzeEndpoint:
    def test_analyze_input_stage(self):
        response = client.post(
            "/api/analyze",
            json={
                "text": "My name is Sarah Khan. I have diabetes.",
                "stage": "input",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "detected_categories" in data
        assert "sanitized_text" in data
        assert "original_risk_score" in data
        assert "sanitized_risk_score" in data

    def test_analyze_output_stage(self):
        response = client.post(
            "/api/analyze",
            json={
                "text": "Dear Dr. Sarah Khan, please call +971501234567.",
                "stage": "output",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "CONTACT_PHONE" in data["detected_categories"] or "PERSON_NAME" in data["detected_categories"]

    def test_analyze_empty_text(self):
        response = client.post(
            "/api/analyze",
            json={"text": "", "stage": "input"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["original_risk_score"] == 0
        assert data["sanitized_risk_score"] == 0

    def test_analyze_low_risk_passthrough(self):
        response = client.post(
            "/api/analyze",
            json={"text": "Explain supervised vs unsupervised machine learning.", "stage": "input"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["original_risk_score"] <= 20
        assert data["sanitized_risk_score"] <= 20
        assert data["send_to_llm"] is True

    def test_analyze_high_risk_is_rewritten(self):
        response = client.post(
            "/api/analyze",
            json={
                "text": "My API key is sk-test-1234567890abcdef. Can you debug my code?",
                "stage": "input",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["original_risk_score"] > 20
        assert "CREDENTIAL_SECRET" in data["detected_categories"]


class TestChatEndpoint:
    def test_chat_mock_mode(self):
        """Without OPENROUTER_API_KEY, chat should return a mock response."""
        response = client.post(
            "/api/chat",
            json={
                "sanitized_prompt": "Explain supervised learning.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "safe_response" in data
        assert data["provider_mode"] == "mock"

    def test_chat_missing_sanitized_prompt(self):
        response = client.post(
            "/api/chat",
            json={},
        )
        # sanitized_prompt defaults to "", which triggers 400
        assert response.status_code == 400
        assert "sanitized_prompt" in response.json()["detail"]

    def test_chat_returns_guard_reports(self):
        response = client.post(
            "/api/chat",
            json={
                "sanitized_prompt": "My name is John. I have diabetes.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "input_guard_report" in data
        assert "output_guard_report" in data
        assert "prompt_sent_to_provider" in data
        assert isinstance(data["input_guard_report"]["detected_categories"], list)

    def test_chat_sanitized_prompt_in_response(self):
        response = client.post(
            "/api/chat",
            json={
                "sanitized_prompt": "My name is Sarah Khan. I have diabetes and take metformin. Please write an email to Dr. Ahmed asking if I should change my dosage. Tell him to call me at +971501234567.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "prompt_sent_to_provider" in data
        prompt_sent = data["prompt_sent_to_provider"]
        assert "email" in prompt_sent.lower()
        assert "Sarah Khan" not in prompt_sent
        assert "+971501234567" not in prompt_sent

    def test_chat_with_model_param(self):
        response = client.post(
            "/api/chat",
            json={
                "sanitized_prompt": "What is deep learning?",
                "model": "openai/gpt-4o-mini",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "model" in data


class TestSwaggerDocs:
    def test_openapi_json_available(self):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert data["info"]["title"] == "PrivGuard Prototype"

    def test_docs_page_available(self):
        response = client.get("/docs")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_redoc_page_available(self):
        response = client.get("/redoc")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
