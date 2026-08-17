"""Health router for PrivGuard."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.llm_client import provider_mode


class HealthResponse(BaseModel):
    status: str
    provider_mode: str


router = APIRouter(prefix="/api", tags=["health"])


@router.get(
    "/health",
    summary="Health check",
    description="Returns the current provider mode.",
    response_description="Service health status.",
    response_model=HealthResponse,
)
async def health() -> dict:
    return {
        "status": "ok",
        "provider_mode": provider_mode(),
    }
