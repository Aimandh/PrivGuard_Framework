"""Analyze router for PrivGuard."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.privacy_engine import analyze_and_sanitize


class AnalyzeRequest(BaseModel):
    text: str = Field(
        default="",
        max_length=20000,
        description="Raw text to analyze for sensitive data.",
        examples=["My name is Sarah Khan. I have diabetes..."],
    )
    stage: Literal["input", "output"] = Field(
        default="input",
        description="Analysis stage: input (before sending to LLM) or output (after receiving from LLM).",
    )


class AnalyzeResponse(BaseModel):
    original_risk_score: int = Field(description="Risk score before sanitization (0-100).")
    sanitized_risk_score: int = Field(description="Risk score after sanitization (0-100).")
    risk_level_before: str = Field(description="Risk level before: Low, Medium, High, or Critical.")
    risk_level_after: str = Field(description="Risk level after: Low, Medium, High, or Critical.")
    detected_categories: list[str] = Field(description="List of detected sensitive data categories.")
    actions_applied: list[str] = Field(description="Sanitization actions applied.")
    sanitized_text: str = Field(description="Sanitized version of the input text.")
    send_to_llm: bool = Field(description="Whether the sanitized text is safe to send to an LLM.")
    notes: list[str] = Field(description="Additional notes about the analysis.")


router = APIRouter(prefix="/api", tags=["analyze"])


@router.post(
    "/analyze",
    summary="Analyze text for sensitive data",
    description=(
        "Performs privacy analysis on the provided text. "
        "Detects sensitive data categories, computes a risk score, and returns a sanitized version. "
        "Use stage='input' for prompts before sending to an LLM, or stage='output' for LLM responses. "
        "This endpoint does not store any data."
    ),
    response_description="Privacy analysis report with detections, risk scores, and sanitized text.",
    response_model=AnalyzeResponse,
)
async def analyze(req: AnalyzeRequest) -> dict:
    return analyze_and_sanitize(req.text, stage=req.stage)
