"""Unit tests for the hand-written Enricher API client (client.enricher).

Mocks the httpx layer — no network. Asserts the enrichment lifecycle hits the right /v1/artifact-enrich
paths (submit → poll, no save/discard).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from crimson_crawler_client import CrawlerClient, EnricherAPI, UnexpectedStatus


def _resp(status: int = 200, body: object = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"")


@pytest.fixture
def ws() -> tuple[EnricherAPI, AsyncMock]:
    http = AsyncMock(spec=httpx.AsyncClient)
    return EnricherAPI(http), http


class TestWiring:
    def test_client_exposes_enricher(self):
        client = CrawlerClient(api_key="test-key")
        assert isinstance(client.enricher, EnricherAPI)
        assert client.enricher is client.enricher  # cached


class TestEnrich:
    async def test_submit_poll_returns_report(self, ws):
        api, http = ws
        enrichment_id = "a" * 32
        http.request.side_effect = [
            _resp(202, {"enrichment_id": enrichment_id, "status": "queued"}),
            _resp(200, {"status": "running"}),
            _resp(200, {"status": "done", "result": {"meta": {}}}),
        ]
        out = await api.enrich(text="CVE-2021-44228", include=["exploits"], poll_interval=0)
        assert out == {"enrichment_id": enrichment_id, "report": {"meta": {}}}
        # submit hits the /v1 engine and carries text + include
        submit = http.request.call_args_list[0]
        assert submit.args == ("POST", "/v1/artifact-enrich")
        assert submit.kwargs["json"]["text"] == "CVE-2021-44228"
        assert submit.kwargs["json"]["include"] == ["exploits"]
        # poll GETs the /v1 status endpoint
        assert http.request.call_args_list[1].args == ("GET", f"/v1/artifact-enrich/{enrichment_id}")
        assert http.request.call_count == 3  # no save POST

    async def test_on_progress_streams_each_poll(self, ws):
        api, http = ws
        eid = "d" * 32
        http.request.side_effect = [
            _resp(202, {"enrichment_id": eid, "status": "queued"}),
            _resp(200, {"status": "running", "progress": 0.4, "events": [{"message": "✓ CVE-1", "progress": 0.4}]}),
            _resp(200, {"status": "done", "progress": 1.0, "result": {"meta": {}}}),
        ]
        seen: list[tuple[str, float]] = []

        async def on_progress(job):  # async callback supported
            seen.append((job.get("status"), job.get("progress")))

        out = await api.enrich(text="x", poll_interval=0, on_progress=on_progress)
        assert out["report"] == {"meta": {}}
        assert seen == [("running", 0.4), ("done", 1.0)]  # called every poll incl. the terminal done

    async def test_on_progress_callback_error_never_breaks_poll(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "e" * 32}),
            _resp(200, {"status": "done", "result": {"ok": True}}),
        ]

        def boom(_job):  # sync callback that raises — must be swallowed
            raise RuntimeError("render crashed")

        out = await api.enrich(text="x", poll_interval=0, on_progress=boom)
        assert out["report"] == {"ok": True}  # enrichment still completes

    async def test_omits_unset_body_fields(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "b" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        await api.enrich(text="x", poll_interval=0)
        assert http.request.call_args_list[0].kwargs["json"] == {"text": "x"}

    async def test_files_body(self, ws):
        api, http = ws
        files = [{"filename": "scan.xml", "content_b64": "PG5tYXA+"}]
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "c" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        await api.enrich(files=files, formats=["markdown"], poll_interval=0)
        body = http.request.call_args_list[0].kwargs["json"]
        assert body == {"files": files, "formats": ["markdown"]}

    async def test_stakeholder_rides_into_submit(self, ws):
        api, http = ws
        sh = {
            "method": "deployer",
            "exposure": "open",
            "human_impact": "high",
            "mission_prevalence": "essential",
            "public_wellbeing_impact": "material",
        }
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "d" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        await api.enrich(text="CVE-2021-44228", include=["ssvc"], stakeholder=sh, poll_interval=0)
        assert http.request.call_args_list[0].kwargs["json"]["stakeholder"] == sh

    async def test_raises_on_engine_error_status(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "d" * 32}),
            _resp(200, {"status": "error", "error": "boom"}),
        ]
        with pytest.raises(UnexpectedStatus):
            await api.enrich(text="x", poll_interval=0)

    async def test_raises_on_non_2xx_submit(self, ws):
        api, http = ws
        http.request.return_value = _resp(401, {"error": "no key"})
        with pytest.raises(UnexpectedStatus) as exc:
            await api.enrich(text="x", poll_interval=0)
        assert exc.value.status == 401

    async def test_times_out(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "e" * 32}),
            _resp(200, {"status": "running"}),
        ]
        with pytest.raises(TimeoutError):
            await api.enrich(text="x", poll_interval=0, timeout=-1)


class TestSaveAfterEnrich:
    async def test_save_true_files_report_and_carries_save_response(self, ws):
        api, http = ws
        eid = "a" * 32
        http.request.side_effect = [
            _resp(202, {"enrichment_id": eid}),
            _resp(200, {"status": "done", "result": {"meta": {}}}),
            _resp(201, {"enrichment_artifact_id": "art-1"}),
        ]
        out = await api.enrich(text="CVE-2021-44228", poll_interval=0, save=True, new_folder_name="inc")
        assert out["enrichment_id"] == eid
        assert out["saved"] == {"enrichment_artifact_id": "art-1"}
        save = http.request.call_args_list[-1]
        assert save.args == ("POST", "/artifact-manager/artifacts/from-enrichment")
        assert save.kwargs["json"] == {
            "enrichment_id": eid,
            "folder": {"folder_id": None, "new_folder_name": "inc"},
        }

    async def test_default_does_not_save(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(202, {"enrichment_id": "a" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        out = await api.enrich(text="x", poll_interval=0)
        assert "saved" not in out
        assert http.request.call_count == 2  # no save POST


class TestGapS2EnrichLifecycle:
    """S2: enrich() submit → poll → return, with on_progress and save=True."""

    async def test_enrich_submit_poll_return_with_progress_and_save(self, ws):
        api, http = ws
        eid = "s" * 32
        http.request.side_effect = [
            _resp(202, {"enrichment_id": eid, "status": "queued"}),
            _resp(200, {"status": "running", "progress": 0.5}),
            _resp(200, {"status": "done", "progress": 1.0, "result": {"report": 1}}),
            _resp(201, {"enrichment_artifact_id": "saved-1"}),
        ]
        progress: list[float] = []

        def on_progress(job: dict) -> None:
            p = job.get("progress")
            if p is not None:
                progress.append(p)

        out = await api.enrich(
            text="CVE-2024-3400",
            include=["kev"],
            poll_interval=0,
            on_progress=on_progress,
            save=True,
        )
        assert out["enrichment_id"] == eid
        assert out["report"] == {"report": 1}
        assert out["saved"] == {"enrichment_artifact_id": "saved-1"}
        assert progress == [0.5, 1.0]
        submit = http.request.call_args_list[0]
        assert submit.args == ("POST", "/v1/artifact-enrich")
        assert submit.kwargs["json"]["text"] == "CVE-2024-3400"
        assert submit.kwargs["json"]["include"] == ["kev"]
