"""Chat router for PrivGuard."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.llm_client import generate_completion, provider_mode
from backend.privacy_engine import analyze_and_sanitize


class ChatRequest(BaseModel):
    sanitized_prompt: str = Field(
        default="",
        max_length=20000,
        description="The sanitized prompt text to send to the LLM provider.",
        examples=["Write a polite email to a healthcare provider..."],
    )
    model: str | None = Field(
        default=None,
        max_length=120,
        description="OpenRouter model identifier (e.g. openai/gpt-4o, anthropic/claude-sonnet-4, google/gemini-2.0-flash).",
    )
    api_key: str | None = Field(
        default=None,
        max_length=500,
        description="Optional per-request OpenRouter API key override.",
    )
    client_report: dict[str, Any] | None = Field(
        default=None,
        description="Client-side privacy report (for defense-in-depth verification).",
    )


class ChatResponse(BaseModel):
    safe_response: str = Field(description="Privacy-sanitized LLM response.")
    provider_mode: str = Field(description="Current backend provider mode.")
    model: str = Field(description="Model identifier used for this request.")
    input_guard_report: dict = Field(description="Backend input privacy analysis report.")
    output_guard_report: dict = Field(description="Backend output privacy analysis report.")
    prompt_sent_to_provider: str = Field(description="The exact prompt text sent to the LLM provider.")


router = APIRouter(prefix="/api", tags=["chat"])


@router.post(
    "/chat",
    summary="Send sanitized prompt to OpenRouter",
    description=(
        "Receives a browser-sanitized prompt, performs defense-in-depth backend sanitization, "
        "sends it to OpenRouter using the selected model, applies output sanitization, and returns the safe response. "
        "The model is chosen manually by the user."
    ),
    response_description="Safe LLM response with full privacy guard reports.",
    response_model=ChatResponse,
)
async def chat(req: ChatRequest) -> dict:
    if not req.sanitized_prompt.strip():
        raise HTTPException(status_code=400, detail="sanitized_prompt is required")

    input_guard_report = analyze_and_sanitize(req.sanitized_prompt, stage="input")
    prompt_to_provider = input_guard_report["sanitized_text"]

    if input_guard_report["sanitized_risk_score"] > 20:
        raise HTTPException(
            status_code=400,
            detail="Prompt remained above low-risk threshold after backend sanitization",
        )

    try:
        raw_response = await generate_completion(
            prompt_to_provider,
            model=req.model,
            api_key=req.api_key,
        )
    except Exception as exc:
        detail = str(exc)
        status = 502
        if hasattr(exc, "response") and exc.response is not None:
            try:
                error_body = exc.response.text[:600]
                detail = f"Provider returned {exc.response.status_code}: {error_body}"
                status = exc.response.status_code if 400 <= exc.response.status_code < 500 else 502
            except Exception:
                pass
        elif isinstance(exc, ValueError):
            detail = str(exc)
            status = 502
        raise HTTPException(status_code=status, detail=detail) from exc

    output_guard_report = analyze_and_sanitize(raw_response, stage="output")
    safe_response = output_guard_report["sanitized_text"]

    resolved_model = (
        req.model
        or os.getenv("OPENROUTER_MODEL", "").strip()
        or "openai/gpt-4o-mini"
    )

    return {
        "safe_response": safe_response,
        "provider_mode": provider_mode(),
        "model": resolved_model,
        "input_guard_report": input_guard_report,
        "output_guard_report": output_guard_report,
        "prompt_sent_to_provider": prompt_to_provider,
    }
