"""Unit tests for the Event Enricher surface of the hand-written Enricher API client.

Covers the raw engine pair (`client.event_enrich` / `client.event_enrich_status` — generated-tree
wrappers, exercised with the httpx layer mocked) and the submit→poll convenience
(`client.enricher.enrich_event`) — asserts the right /v1/event-enrich paths are hit and the raw
event/event_id ride the submit body.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from crimson_crawler_client import CrawlerClient, UnexpectedStatus
from crimson_crawler_client.enricher import EnricherAPI


def _resp(status: int = 200, body: object = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"")


@pytest.fixture
def ws() -> tuple[EnricherAPI, AsyncMock]:
    http = AsyncMock(spec=httpx.AsyncClient)
    return EnricherAPI(http), http


class TestEnrichEvent:
    async def test_submit_poll_returns_result(self, ws):
        api, http = ws
        enrichment_id = "a" * 32
        result = {"event_id": "ev-1", "extracted_count": 2, "threat_assessment": {"verdict": "critical"}}
        http.request.side_effect = [
            _resp(202, {"enrichment_id": enrichment_id, "status": "queued"}),
            _resp(200, {"status": "done", "result": result}),
        ]
        out = await api.enrich_event(event="CVE-2024-3400", event_id="ev-1", poll_interval=0)
        assert out == {"enrichment_id": enrichment_id, "result": result}
        # submit hits the /v1 engine and carries the raw event + event_id
        submit = http.request.call_args_list[0]
        assert submit.args == ("POST", "/v1/event-enrich")
        assert submit.kwargs["json"] == {"event": "CVE-2024-3400", "event_id": "ev-1"}
        # poll GETs the /v1 status endpoint; no save POST ever
        assert http.request.call_args_list[1].args == ("GET", f"/v1/event-enrich/{enrichment_id}")
        assert http.request.call_count == 2

    async def test_omits_event_id_when_absent(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "b" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        await api.enrich_event(event="just an IP 8.8.8.8", poll_interval=0)
        assert http.request.call_args_list[0].kwargs["json"] == {"event": "just an IP 8.8.8.8"}

    async def test_on_progress_streams_polls(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "c" * 32}),
            _resp(200, {"status": "running", "progress": 0.5}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        seen = []
        await api.enrich_event(event="x", poll_interval=0, on_progress=lambda job: seen.append(job["status"]))
        assert seen == ["running", "done"]

    async def test_raises_on_engine_error_status(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "d" * 32}),
            _resp(200, {"status": "error", "error": {"error": "boom"}}),
        ]
        with pytest.raises(UnexpectedStatus):
            await api.enrich_event(event="x", poll_interval=0)

    async def test_raises_on_non_2xx_submit(self, ws):
        api, http = ws
        http.request.return_value = _resp(402, {"error": "no active key"})
        with pytest.raises(UnexpectedStatus) as exc:
            await api.enrich_event(event="x", poll_interval=0)
        assert exc.value.status == 402

    async def test_timeout_cap(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "e" * 32}),
            _resp(200, {"status": "running"}),
        ]
        # timeout=0 → the very first status poll already past the deadline raises
        with pytest.raises(TimeoutError, match="did not finish"):
            await api.enrich_event(event="x", poll_interval=0, timeout=0)


class TestClientEngineMethods:
    """The typed raw pair on CrawlerClient (event_enrich / event_enrich_status)."""

    async def test_event_enrich_submit_202(self):
        from crimson_crawler_client._generated.models import EnrichmentSubmitResponse

        parsed = EnrichmentSubmitResponse(enrichment_id="f" * 32)
        with patch("crimson_crawler_client.client.event_enrich.asyncio_detailed", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _ok(parsed)
            client = CrawlerClient(api_key="test-key")
            resp = await client.event_enrich(event="CVE-2024-3400", event_id="ev-9")
        assert resp is parsed
        body = mock_call.call_args.kwargs["body"]
        assert body.event == "CVE-2024-3400"
        assert body.event_id == "ev-9"

    async def test_event_enrich_status_returns_job(self):
        from crimson_crawler_client._generated.models import EventEnrichmentJobResponse

        parsed = EventEnrichmentJobResponse(
            enrichment_id="c" * 32,
            status="done",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:01Z",
            stages=[],
            progress=1.0,
        )
        with patch(
            "crimson_crawler_client.client.event_enrich_status.asyncio_detailed", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = _ok(parsed)
            client = CrawlerClient(api_key="test-key")
            resp = await client.event_enrich_status("c" * 32)
        assert resp is parsed


def _ok(parsed: object):
    from crimson_crawler_client._generated.types import Response

    return Response(status_code=200, headers={}, parsed=parsed, content=b"")
