"""Snapshot iterators do not expose pages from an expired walk."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from crimson_crawler_client._paging import iter_snapshot_pages
from crimson_crawler_client.exceptions import UnexpectedStatus


def page(snapshot_id, next_offset, cve_id):
    return SimpleNamespace(
        to_dict=lambda: {
            "snapshot_id": snapshot_id,
            "cves_next_offset": next_offset,
            "cve_id": cve_id,
        }
    )


@pytest.mark.asyncio
async def test_expired_walk_restarts_before_yielding_any_page():
    expired = UnexpectedStatus(409, b'{"detail":{"error":"snapshot_expired"}}')
    fetch = AsyncMock(
        side_effect=[
            page("old", 1, "old-only"),
            expired,
            page("new", 1, "new-first"),
            page("new", None, "new-second"),
        ]
    )
    rows = [item.to_dict()["cve_id"] async for item in iter_snapshot_pages(fetch, next_field="cves_next_offset")]
    assert rows == ["new-first", "new-second"]
    assert fetch.await_args_list[0].args == (0, None)
    assert fetch.await_args_list[1].args == (1, "old")
    assert fetch.await_args_list[2].args == (0, None)
    assert fetch.await_args_list[3].args == (1, "new")


@pytest.mark.asyncio
async def test_second_expiry_fails_without_yielding_partial_pages():
    expired = UnexpectedStatus(409, b'{"detail":{"error":"snapshot_expired"}}')
    fetch = AsyncMock(side_effect=[page("old", 1, "first"), expired, page("new", 1, "second"), expired])
    rows = []
    with pytest.raises(UnexpectedStatus):
        async for item in iter_snapshot_pages(fetch, next_field="cves_next_offset"):
            rows.append(item)
    assert rows == []


@pytest.mark.asyncio
async def test_single_page_requires_no_snapshot():
    fetch = AsyncMock(return_value=page(None, None, "only"))
    rows = [item.to_dict()["cve_id"] async for item in iter_snapshot_pages(fetch, next_field="cves_next_offset")]
    assert rows == ["only"]


@pytest.mark.asyncio
async def test_next_page_without_snapshot_fails():
    fetch = AsyncMock(return_value=page(None, 1, "first"))
    with pytest.raises(ValueError, match="invalid snapshot"):
        _ = [item async for item in iter_snapshot_pages(fetch, next_field="cves_next_offset")]
