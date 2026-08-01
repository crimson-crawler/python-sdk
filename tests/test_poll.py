"""Unit tests for the shared submit→poll core (`client._poll`).

Mocks the httpx layer — no network. Covers the deadline-based timeout, the progress
callback (sync + async), and callback-error swallowing for the two async engines.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from crimson_crawler_client._poll import poll_until_done
from crimson_crawler_client.exceptions import UnexpectedStatus


def _resp(status: int = 200, body: object = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"")


class TestPollUntilDone:
    async def test_progress_callback_streams_each_poll(self):
        request = AsyncMock(
            side_effect=[
                _resp(200, {"status": "running", "progress": 0.3}),
                _resp(200, {"status": "done", "progress": 1.0, "result": {"ok": True}}),
            ]
        )
        seen: list[tuple[str, float | None]] = []

        async def on_progress(job: dict) -> None:
            seen.append((job.get("status"), job.get("progress")))

        job = await poll_until_done(
            request,
            "a" * 32,
            "/v1/artifact-enrich/a" * 32,
            poll_interval=0,
            timeout=10,
            on_progress=on_progress,
        )
        assert job["status"] == "done"
        assert seen == [("running", 0.3), ("done", 1.0)]

    async def test_sync_progress_callback_error_is_swallowed(self):
        request = AsyncMock(
            side_effect=[
                _resp(200, {"status": "running"}),
                _resp(200, {"status": "done", "result": {"ok": True}}),
            ]
        )

        def boom(_job: dict) -> None:
            raise RuntimeError("ui crashed")

        job = await poll_until_done(
            request,
            "b" * 32,
            "/v1/artifact-enrich/b" * 32,
            poll_interval=0,
            timeout=10,
            on_progress=boom,
        )
        assert job["result"] == {"ok": True}

    async def test_deadline_based_timeout_raises(self):
        request = AsyncMock(return_value=_resp(200, {"status": "running"}))
        with pytest.raises(TimeoutError):
            await poll_until_done(
                request,
                "c" * 32,
                "/v1/artifact-enrich/c" * 32,
                poll_interval=0,
                timeout=-1,
            )

    async def test_engine_error_status_raises_unexpected_status(self):
        request = AsyncMock(return_value=_resp(200, {"status": "error", "error": "oom"}))
        with pytest.raises(UnexpectedStatus) as exc:
            await poll_until_done(
                request,
                "d" * 32,
                "/v1/artifact-enrich/d" * 32,
                poll_interval=0,
                timeout=10,
            )
        assert exc.value.status == 502
