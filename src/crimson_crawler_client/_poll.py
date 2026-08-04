"""Shared submit→poll core for the two async-enrichment engines (Enricher + Inventory).

Both ``client.enricher.enrich`` and ``client.inventory_manager.enrich_inventory`` submit a job to a
``/v1/*-enrich`` engine and then poll ``GET /v1/*-enrich/{id}`` until it finishes. The loop lives here
so the two engines cannot drift. The optional ``on_progress`` callback surfaces the live job on every
tick. Status polls are billing-exempt.
"""

from __future__ import annotations

import asyncio
import inspect
import math
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .exceptions import UnexpectedStatus

_TRANSPORT_TIMEOUT_SECONDS = 90.0
ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


def _timeout_error(enrichment_id: str, timeout: float) -> TimeoutError:
    return TimeoutError(f"enrichment {enrichment_id} did not finish within {timeout}s")


async def _before_deadline(
    operation: Awaitable[Any],
    remaining: float,
    enrichment_id: str,
    timeout: float,
) -> Any:
    if remaining <= 0:
        if inspect.iscoroutine(operation):
            operation.close()
        raise _timeout_error(enrichment_id, timeout)
    task = asyncio.ensure_future(operation)
    done, _pending = await asyncio.wait({task}, timeout=remaining)
    if task not in done:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise _timeout_error(enrichment_id, timeout)
    return task.result()


async def _emit(
    on_progress: ProgressCallback | None,
    job: dict[str, Any],
    remaining: float,
    enrichment_id: str,
    timeout: float,
) -> None:
    if on_progress is None:
        return
    try:
        result = on_progress(job)
    except Exception:  # noqa: BLE001 — telemetry must never break the enrichment poll
        return
    if inspect.isawaitable(result):
        try:
            await _before_deadline(result, remaining, enrichment_id, timeout)
        except TimeoutError:
            raise
        except Exception:  # noqa: BLE001 — telemetry must never break the enrichment poll
            return


def validate_poll_options(poll_interval: float, timeout: float) -> None:
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("timeout must be finite and non-negative")
    if not math.isfinite(poll_interval) or poll_interval < 0:
        raise ValueError("poll_interval must be finite and non-negative")


async def poll_until_done(
    request: Callable[..., Awaitable[Any]],
    enrichment_id: str,
    status_path: str,
    *,
    poll_interval: float,
    timeout: float,
    on_progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Poll an async-enrichment job under a hard end-to-end deadline.

    The deadline covers each status request, progress callback, and sleep. ``request`` must accept the
    per-status-call ``timeout`` keyword and pass it to the HTTP transport. Raises
    :class:`UnexpectedStatus` on an engine error and :class:`TimeoutError` on the deadline.
    """
    validate_poll_options(poll_interval, timeout)

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        response = await _before_deadline(
            request("GET", status_path, timeout=min(_TRANSPORT_TIMEOUT_SECONDS, remaining)),
            remaining,
            enrichment_id,
            timeout,
        )
        if time.monotonic() >= deadline:
            raise _timeout_error(enrichment_id, timeout)

        job = response.json()
        remaining = deadline - time.monotonic()
        await _emit(on_progress, job, remaining, enrichment_id, timeout)
        if time.monotonic() >= deadline:
            raise _timeout_error(enrichment_id, timeout)

        status = job.get("status")
        if status == "done":
            return job
        if status == "error":
            raise UnexpectedStatus(502, b"", f"enrichment {enrichment_id} errored: {job.get('error')}")

        remaining = deadline - time.monotonic()
        await _before_deadline(
            asyncio.sleep(min(poll_interval, remaining)),
            remaining,
            enrichment_id,
            timeout,
        )
        if time.monotonic() >= deadline:
            raise _timeout_error(enrichment_id, timeout)
