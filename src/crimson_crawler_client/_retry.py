"""Retry transport for the Crimson Crawler client.

Implements the retry/backoff contract shared with the TypeScript SDK and MCP
server. Only safe HTTP methods are replayed because the same transport serves
non-idempotent Platform mutations that do not accept idempotency keys.

The transport is installed via ``AuthenticatedClient(httpx_args={"transport":
RetryTransport(...)})`` — the generated client passes the same instance to its
``httpx.Client`` and ``httpx.AsyncClient`` — so every convenience method AND the
``client.api`` escape hatch (sync or async) inherit retry for free. On
budget exhaustion the final response
or transport error is returned/re-raised unchanged — the wrapper's
``_ensure_ok`` still produces the normal ``UnexpectedStatus`` with the final
status and body, and no new exception type is introduced.
"""

from __future__ import annotations

import asyncio
import email.utils
import random
import time
from typing import Awaitable, Callable

import httpx

# Backoff constants — fixed (no caller-tunable knob), identical across all three
# client surfaces (Python SDK, TS SDK, MCP server).
RETRY_BASE_DELAY = 0.5  # seconds
RETRY_MAX_DELAY = 8.0  # seconds (cap on the computed exponential delay)
RETRY_JITTER_RATIO = 0.25  # ±25% of the computed (pre-cap) delay
RETRY_AFTER_MAX = 60.0  # seconds — ceiling on an honored Retry-After header

# The public API returns 429 on rate-limit; 502/503/504 are transient edge
# failures. 500 is an application bug, not transient — never retried.
_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
_RETRYABLE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Parse a ``Retry-After`` header into a delay in seconds.

    Handles both RFC 7231 forms: delta-seconds (integer string) and HTTP-date.
    Returns ``None`` when the header is absent or unparseable (caller falls back
    to the computed exponential delay). The returned delay is non-negative and
    clamped to :data:`RETRY_AFTER_MAX`.
    """
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.isdigit():
        return min(RETRY_AFTER_MAX, float(raw))
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    target = parsed.timestamp()
    current = time.time() if now is None else now
    delay = max(0.0, target - current)
    return min(RETRY_AFTER_MAX, delay)


def _compute_backoff(attempt: int, rng: Callable[[float, float], float]) -> float:
    """Exponential backoff with full ±25% jitter, capped at :data:`RETRY_MAX_DELAY`.

    ``attempt`` is 0-based: ``0`` is the first retry (the 2nd request overall).
    Nominal pre-jitter sleeps: 0.5, 1.0, 2.0, 4.0, 8.0, 8.0, … (capped).
    """
    raw = RETRY_BASE_DELAY * (2**attempt)
    jitter = raw * RETRY_JITTER_RATIO * rng(-1.0, 1.0)
    delay = min(RETRY_MAX_DELAY, raw + jitter)
    return max(0.0, delay)


class RetryTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """An httpx transport that retries retryable failures with backoff.

    Serves both the sync ``httpx.Client`` and the async ``httpx.AsyncClient``
    that the generated ``AuthenticatedClient`` builds from the same
    ``httpx_args`` — ``handle_request`` and ``handle_async_request`` are twin
    loops making identical retry decisions over separate inner transports.

    Retries safe-method requests on retryable HTTP statuses (429/502/503/504)
    and on ``httpx.TransportError`` (connect/read/write/pool/protocol failures).
    Mutation requests return or raise after the first attempt. Honors
    ``Retry-After`` over the computed exponential delay. Never swallows the
    final failure: when the budget is exhausted it returns the final response
    unchanged or re-raises the final transport error unchanged.
    """

    def __init__(
        self,
        max_retries: int,
        *,
        verify: str | bool = True,
        wrapped: httpx.AsyncBaseTransport | None = None,
        sync_wrapped: httpx.BaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        sync_sleep: Callable[[float], None] | None = None,
        rng: Callable[[float, float], float] | None = None,
    ) -> None:
        self._max_retries = max_retries
        if wrapped is None or sync_wrapped is None:
            # Build the TLS context once and share it across both default inner
            # transports (verify=True loads the CA bundle — don't do it twice).
            ssl_context = httpx.create_ssl_context(verify=verify)
        self._wrapped = wrapped if wrapped is not None else httpx.AsyncHTTPTransport(verify=ssl_context)
        self._sync_wrapped = sync_wrapped if sync_wrapped is not None else httpx.HTTPTransport(verify=ssl_context)
        # Injectable in tests so jitter is reproducible and sleeps don't wait.
        self._sleep = sleep or asyncio.sleep
        self._sync_sleep = sync_sleep or time.sleep
        self._rng = rng or random.uniform

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        honored = _parse_retry_after(retry_after)
        return honored if honored is not None else _compute_backoff(attempt, self._rng)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Sync twin of :meth:`handle_async_request` — identical retry decisions."""
        retryable = request.method.upper() in _RETRYABLE_METHODS
        attempt = 0
        while True:
            try:
                response = self._sync_wrapped.handle_request(request)
            except httpx.TransportError:
                if not retryable or attempt >= self._max_retries:
                    raise  # exhausted → re-raise the final transport error unchanged
                self._sync_sleep(self._retry_delay(attempt, retry_after=None))
                attempt += 1
                continue
            if retryable and response.status_code in _RETRYABLE_STATUS and attempt < self._max_retries:
                retry_after = response.headers.get("retry-after")
                try:
                    response.read()  # drain so the connection can be reused
                except Exception:  # noqa: BLE001 — cleanup failure must not mask the retry
                    try:
                        response.close()
                    except Exception:  # noqa: BLE001 — best-effort release
                        pass
                self._sync_sleep(self._retry_delay(attempt, retry_after=retry_after))
                attempt += 1
                continue
            return response  # success, non-retryable, or budget exhausted

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        retryable = request.method.upper() in _RETRYABLE_METHODS
        attempt = 0
        while True:
            try:
                response = await self._wrapped.handle_async_request(request)
            except httpx.TransportError:
                if not retryable or attempt >= self._max_retries:
                    raise  # exhausted → re-raise the final transport error unchanged
                await self._sleep(self._retry_delay(attempt, retry_after=None))
                attempt += 1
                continue
            if retryable and response.status_code in _RETRYABLE_STATUS and attempt < self._max_retries:
                retry_after = response.headers.get("retry-after")
                try:
                    await response.aread()  # drain so the connection can be reused
                except Exception:  # noqa: BLE001 — cleanup failure must not mask the retry
                    try:
                        await response.aclose()
                    except Exception:  # noqa: BLE001 — best-effort release
                        pass
                await self._sleep(self._retry_delay(attempt, retry_after=retry_after))
                attempt += 1
                continue
            return response  # success, non-retryable, or budget exhausted

    def close(self) -> None:
        self._sync_wrapped.close()

    async def aclose(self) -> None:
        await self._wrapped.aclose()
