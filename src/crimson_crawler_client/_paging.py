"""Collect snapshot-bound pages without exposing a partial restart to callers."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, TypeVar

from .exceptions import UnexpectedStatus

_T = TypeVar("_T")


def _snapshot_expired(exc: UnexpectedStatus) -> bool:
    if exc.status != 409:
        return False
    try:
        body = json.loads(exc.body) if isinstance(exc.body, (str, bytes, bytearray)) else exc.body
    except ValueError:
        return False
    if not isinstance(body, dict):
        return False
    detail = body.get("detail")
    return body.get("error") == "snapshot_expired" or (
        isinstance(detail, dict) and detail.get("error") == "snapshot_expired"
    )


async def iter_snapshot_pages(
    fetch: Callable[[int, str | None], Awaitable[_T]], *, next_field: str
) -> AsyncIterator[_T]:
    """Buffer one consistent walk; restart once if its snapshot expires."""
    for attempt in range(2):
        pages: list[_T] = []
        offset = 0
        snapshot_id: str | None = None
        try:
            while True:
                page = await fetch(offset, snapshot_id)
                data: dict[str, Any] = page.to_dict()  # type: ignore[attr-defined]
                current = data.get("snapshot_id")
                next_offset = data.get(next_field)
                if (
                    (current is not None and (not isinstance(current, str) or not current))
                    or (snapshot_id is not None and current != snapshot_id)
                    or (next_offset is not None and current is None)
                ):
                    raise ValueError("Enrichment returned an invalid snapshot identifier")
                snapshot_id = current
                pages.append(page)
                if next_offset is None:
                    break
                if not isinstance(next_offset, int) or isinstance(next_offset, bool) or next_offset <= offset:
                    raise ValueError("Enrichment returned an invalid next offset")
                offset = next_offset
        except UnexpectedStatus as exc:
            if attempt == 0 and _snapshot_expired(exc):
                continue
            raise
        for page in pages:
            yield page
        return


async def iter_osv_pages(fetch: Callable[[int, str | None], Awaitable[_T]]) -> AsyncIterator[_T]:
    """Stream one OSV advisory walk without an aggregate buffer.

    Each page binds the original request, the stored OSV generation, the licence tier and the page
    boundary server-side. A changed or expired snapshot raises (409 ``snapshot_expired`` as
    :class:`UnexpectedStatus`) instead of restarting, because earlier pages were already yielded.
    Follow ``osv_next_offset``, never ``offset + len(page)``: byte limits shorten pages, and page zero
    may legitimately return ``0`` when the non-OSV sections used the whole budget.
    """
    offset = 0
    snapshot_id: str | None = None
    while True:
        page = await fetch(offset, snapshot_id)
        data: dict[str, Any] = page.to_dict()  # type: ignore[attr-defined]
        if snapshot_id is not None and any(
            error.get("service") == "osv" and error.get("error") == "stored_copy_unavailable"
            for error in data.get("errors") or []
        ):
            raise RuntimeError("stored_copy_unavailable")
        current, next_offset = data.get("osv_snapshot_id"), data.get("osv_next_offset")
        if (current is not None and (not isinstance(current, str) or not current)) or (
            current is not None and snapshot_id is not None and current != snapshot_id
        ):
            raise ValueError("Enrichment returned an invalid OSV snapshot identifier")
        if next_offset is not None and (
            current is None
            or not isinstance(next_offset, int)
            or isinstance(next_offset, bool)
            or next_offset < 0
            or (snapshot_id is not None and next_offset <= offset)
        ):
            raise ValueError("Enrichment returned an invalid OSV continuation")
        yield page
        if next_offset is None:
            return
        offset, snapshot_id = next_offset, current
