"""Shared submit→poll core for the two async-enrichment engines (Enricher + Inventory).

Both ``client.enricher.enrich`` and ``client.inventory_manager.enrich_inventory`` submit a job to a
``/v1/*-enrich`` engine and then poll ``GET /v1/*-enrich/{id}`` until it finishes. The poll loop was
duplicated; it now lives here so the two engines can't drift — and so a single place carries the
optional ``on_progress`` callback that surfaces the LIVE job (status, per-stage progress, and the
granular ``events[]`` feed — each event stamped with the overall % it reached) to the caller on every
tick. The CLI uses it to render a live progress bar + the streaming per-unit feed; programmatic callers
can log or ignore it. The status polls are billing-exempt, so calling back frequently costs no usage.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .exceptions import UnexpectedStatus

# A progress callback receives the raw job dict each poll: {status, progress, stages, events, result?}.
# It may be sync or async; any exception it raises is swallowed (telemetry must never break the poll).
ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


async def _emit(on_progress: ProgressCallback | None, job: dict[str, Any]) -> None:
    if on_progress is None:
        return
    try:
        res = on_progress(job)
        if inspect.isawaitable(res):
            await res
    except Exception:  # noqa: BLE001 — a progress callback must never break the enrichment poll
        pass


async def poll_until_done(
    request: Callable[..., Awaitable[Any]],
    enrichment_id: str,
    status_path: str,
    *,
    poll_interval: float,
    timeout: float,
    on_progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Poll a ``/v1`` async-enrichment job to completion and return its final job dict.

    ``request`` is the engine client's bound ``_request`` (``(method, path) -> httpx.Response``).
    Calls ``on_progress(job)`` on every tick (including the terminal ``done`` poll, so a UI can show
    100%). Raises :class:`UnexpectedStatus` on an engine error, :class:`TimeoutError` on the deadline.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = (await request("GET", status_path)).json()
        await _emit(on_progress, job)
        status = job.get("status")
        if status == "done":
            return job
        if status == "error":
            raise UnexpectedStatus(502, b"", f"enrichment {enrichment_id} errored: {job.get('error')}")
        await asyncio.sleep(poll_interval)
    raise TimeoutError(f"enrichment {enrichment_id} did not finish within {timeout}s")
