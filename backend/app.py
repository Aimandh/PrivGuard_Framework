"""FastAPI app for PrivGuard.

The API is designed to be stateless and zero-retention by default. It does not
write prompt or response bodies to storage. Configure production access logs to
avoid request bodies and sensitive headers.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.routers import analyze, chat, health
from backend.rate_limit import RateLimitMiddleware

app = FastAPI(
    title="PrivGuard Prototype",
    version="0.1.0",
    description="""## Zero-retention dual-stage prompt privacy gateway

PrivGuard protects user privacy by analyzing prompts **before** they reach an LLM
(input sanitization) and **after** the LLM responds (output sanitization).

### Features
- **OpenRouter gateway**: access hundreds of models through a single API (model selected manually)
- **Zero retention**: No prompt or response bodies are stored
- **Explainable risk scoring**: 0-100 score with category detection and actions applied

### Privacy headers
All responses include `Cache-Control: no-store`, `Pragma: no-cache`, and other
privacy-preserving headers.
""",
    openapi_tags=[
        {
            "name": "health",
            "description": "Service health and provider availability.",
        },
        {
            "name": "analyze",
            "description": "Analyze text for sensitive data without sending to an LLM.",
        },
        {
            "name": "chat",
            "description": "Send sanitized prompts to an LLM with dual-stage privacy protection.",
        },
    ],
    # Disable docs in production
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    redoc_url=None if os.getenv("ENV") == "production" else "/redoc",
)

# Configure CORS with environment variable support
allowed_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://127.0.0.1:8000,http://localhost:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Add rate limiting (60 requests per minute, burst of 10)
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
    burst_size=int(os.getenv("RATE_LIMIT_BURST", "10")),
)


@app.middleware("http")
async def add_privacy_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(chat.router)


@app.exception_handler(Exception)
async def safe_exception_handler(request: Request, exc: Exception):
    # Do not include request bodies or sensitive values in error messages.
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(exc).__name__}"})


# Serve the frontend after API routes are registered.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
