"""Rate limiting middleware for PrivGuard."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""

    pass


class TokenBucket:
    """Simple token bucket rate limiter."""

    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware with IP-based tracking."""

    def __init__(
        self,
        app,
        requests_per_minute: int = 60,
        burst_size: int = 10,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.buckets: dict[str, TokenBucket] = {}
        # Rate: requests per second
        self.rate = requests_per_minute / 60.0

    def _get_bucket(self, client_ip: str) -> TokenBucket:
        """Get or create a token bucket for a client IP."""
        if client_ip not in self.buckets:
            self.buckets[client_ip] = TokenBucket(rate=self.rate, capacity=self.burst_size)
        return self.buckets[client_ip]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Check rate limit before processing request."""
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Skip rate limiting for health checks
        if request.url.path == "/api/health":
            return await call_next(request)

        # Check rate limit
        bucket = self._get_bucket(client_ip)
        if not bucket.consume():
            return Response(
                status_code=429,
                content='{"detail": "Rate limit exceeded. Please try again later."}',
                media_type="application/json",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        remaining = int(bucket.tokens)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response
