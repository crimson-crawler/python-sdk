"""Unit tests for the shared submit→poll core (`client._poll`).

Mocks the httpx layer — no network. Covers the deadline-based timeout, the progress
callback (sync + async), and callback-error swallowing for the two async engines.
"""

from __future__ import annotations

import asyncio
import json
import time
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

    async def test_invalid_deadline_and_interval_raise(self):
        request = AsyncMock(return_value=_resp(200, {"status": "running"}))
        with pytest.raises(ValueError, match="timeout"):
            await poll_until_done(
                request,
                "c" * 32,
                "/v1/artifact-enrich/" + "c" * 32,
                poll_interval=0,
                timeout=-1,
            )
        with pytest.raises(ValueError, match="poll_interval"):
            await poll_until_done(
                request,
                "c" * 32,
                "/v1/artifact-enrich/" + "c" * 32,
                poll_interval=float("inf"),
                timeout=1,
            )

    async def test_hung_status_request_obeys_hard_deadline(self):
        async def hung_request(*_args, **_kwargs):
            await asyncio.Event().wait()

        started = time.monotonic()
        with pytest.raises(TimeoutError, match="did not finish"):
            await poll_until_done(
                hung_request,
                "c" * 32,
                "/v1/artifact-enrich/" + "c" * 32,
                poll_interval=0.01,
                timeout=0.05,
            )
        assert time.monotonic() - started < 0.25

    async def test_never_settling_progress_callback_obeys_hard_deadline(self):
        request = AsyncMock(return_value=_resp(200, {"status": "running"}))

        async def hung_progress(_job):
            await asyncio.Event().wait()

        started = time.monotonic()
        with pytest.raises(TimeoutError, match="did not finish"):
            await poll_until_done(
                request,
                "c" * 32,
                "/v1/artifact-enrich/" + "c" * 32,
                poll_interval=0.01,
                timeout=0.05,
                on_progress=hung_progress,
            )
        assert time.monotonic() - started < 0.25

    async def test_long_sleep_is_clamped_to_remaining_deadline(self):
        request = AsyncMock(return_value=_resp(200, {"status": "running"}))
        started = time.monotonic()
        with pytest.raises(TimeoutError, match="did not finish"):
            await poll_until_done(
                request,
                "c" * 32,
                "/v1/artifact-enrich/" + "c" * 32,
                poll_interval=60,
                timeout=0.05,
            )
        assert time.monotonic() - started < 0.25
        assert 0 < request.call_args.kwargs["timeout"] <= 0.05

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
