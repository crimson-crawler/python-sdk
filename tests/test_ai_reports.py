"""Unit tests for the hand-written Report Generator (AI Reports) API client (client.ai_reports).

Mocks the httpx layer — no network. Asserts each method hits the right /ai-reports path/method/body
and that the generate_report convenience runs create_draft → fill_section* → get_report.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from crimson_crawler_client import AiReportsAPI, CrawlerClient, UnexpectedStatus


def _resp(status: int = 200, body: object = None, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"", headers=headers or {})


def _raw_resp(text: str, headers: dict[str, str]) -> httpx.Response:
    return httpx.Response(200, content=text.encode(), headers=headers)


@pytest.fixture
def ws() -> tuple[AiReportsAPI, AsyncMock]:
    http = AsyncMock(spec=httpx.AsyncClient)
    return AiReportsAPI(http), http


class TestWiring:
    def test_client_exposes_ai_reports(self):
        client = CrawlerClient(api_key="test-key")
        assert isinstance(client.ai_reports, AiReportsAPI)
        assert client.ai_reports is client.ai_reports  # cached

    async def test_non_2xx_raises_unexpected_status(self, ws):
        api, http = ws
        http.request.return_value = _resp(404, {"error": "not found"})
        with pytest.raises(UnexpectedStatus) as exc:
            await api.get_report("missing")
        assert exc.value.status == 404


class TestReadAndManage:
    async def test_list_templates(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"templates": [{"id": "exec", "name": "Executive"}]})
        out = await api.list_templates()
        assert out == [{"id": "exec", "name": "Executive"}]
        http.request.assert_called_once_with("GET", "/ai-reports/templates", params=None, json=None)

    async def test_list_reports(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"reports": [{"id": "r1"}]})
        assert await api.list_reports() == [{"id": "r1"}]
        http.request.assert_called_once_with("GET", "/ai-reports/reports", params=None, json=None)

    async def test_get_report(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"report": {"id": "r1", "content": "<h1>x</h1>"}})
        out = await api.get_report("r1")
        assert out["id"] == "r1"
        http.request.assert_called_once_with("GET", "/ai-reports/reports/r1", params=None, json=None)

    async def test_get_report_raw(self, ws):
        api, http = ws
        http.send.return_value = _raw_resp(
            "<h1>Report</h1>", {"x-artifact-id": "r1", "x-artifact-format": "html_report"}
        )
        out = await api.get_report_raw("r1")
        assert out["content"] == "<h1>Report</h1>"
        assert out["format"] == "html_report"
        http.build_request.assert_called_once_with("GET", "/ai-reports/reports/r1", params={"raw": "1"})
        assert http.send.call_args.kwargs["stream"] is True

    async def test_get_report_raw_rejects_body_above_buffer_limit(self, ws):
        api, http = ws
        http.send.return_value = _raw_resp(
            "oversized",
            {"content-length": "10000001"},
        )

        with pytest.raises(ValueError, match="10000000-byte"):
            await api.get_report_raw("r1")
        http.send.assert_awaited_once()

    async def test_rename_report(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"report": {"id": "r1", "name": "New"}})
        out = await api.rename_report("r1", "New")
        assert out["name"] == "New"
        call = http.request.call_args
        assert call.args == ("PATCH", "/ai-reports/reports/r1")
        assert call.kwargs["json"] == {"name": "New"}

    async def test_delete_report(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"deleted": True})
        assert await api.delete_report("r1") is True
        http.request.assert_called_with("DELETE", "/ai-reports/reports/r1", params=None, json=None)

    async def test_discovery(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"endpoints": []})
        await api.discovery()
        http.request.assert_called_once_with("GET", "/ai-reports", params=None, json=None)


class TestCreateAndFill:
    async def test_create_draft_full_body(self, ws):
        api, http = ws
        http.request.return_value = _resp(
            201, {"id": "r1", "name": "Brief", "html": "<h1/>", "ai_sections": [], "skipped": []}
        )
        out = await api.create_draft("exec", source_ids=["s1"], name="Brief")
        assert out["id"] == "r1"
        call = http.request.call_args
        assert call.args == ("POST", "/ai-reports/reports")
        assert call.kwargs["json"] == {"template": "exec", "source_ids": ["s1"], "name": "Brief"}

    async def test_create_draft_minimal(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "r2", "ai_sections": [], "skipped": []})
        await api.create_draft("technical")
        assert http.request.call_args.kwargs["json"] == {"template": "technical"}

    async def test_fill_section_next_pending(self, ws):
        api, http = ws
        http.request.return_value = _resp(
            200, {"section_type": "bluf", "filled": True, "remaining": [], "complete": True}
        )
        out = await api.fill_section("r1")
        assert out["complete"] is True
        call = http.request.call_args
        assert call.args == ("POST", "/ai-reports/reports/r1/sections")
        assert call.kwargs["json"] == {}

    async def test_fill_section_specific(self, ws):
        api, http = ws
        http.request.return_value = _resp(
            200, {"section_type": "bluf", "filled": True, "remaining": ["x"], "complete": False}
        )
        await api.fill_section("r1", "bluf")
        assert http.request.call_args.kwargs["json"] == {"section_type": "bluf"}

    async def test_section_adhoc(self, ws):
        api, http = ws
        http.request.return_value = _resp(
            200, {"text": "…", "truncated": False, "grounded": True, "unsupported_ids": []}
        )
        out = await api.section(["s1"], section_type="key_judgments", verbosity="detailed")
        assert out["grounded"] is True
        call = http.request.call_args
        assert call.args == ("POST", "/ai-reports/section")
        assert call.kwargs["json"] == {"source_ids": ["s1"], "section_type": "key_judgments", "verbosity": "detailed"}


class TestExport:
    async def test_export_md(self, ws):
        api, http = ws
        http.request.return_value = _raw_resp(
            "# Report\n",
            {
                "content-disposition": 'attachment; filename="exec-brief.md"',
                "content-type": "text/markdown; charset=utf-8",
            },
        )
        out = await api.export_report("r1", "md")
        assert out == {
            "content": "# Report\n",
            "bytes": b"# Report\n",
            "filename": "exec-brief.md",
            "content_type": "text/markdown; charset=utf-8",
        }
        assert http.request.call_args.args == ("GET", "/ai-reports/reports/r1/export/md")

    @pytest.mark.parametrize(
        ("disposition", "expected"),
        [
            ('attachment; filename="../../etc/passwd"', "passwd"),
            ('attachment; filename="/var/tmp/report.md"', "report.md"),
            ('attachment; filename=""', "r1.md"),
            ("attachment; filename*=UTF-8''executive%20brief.md", "executive brief.md"),
        ],
    )
    async def test_export_sanitizes_content_disposition(self, ws, disposition: str, expected: str):
        api, http = ws
        http.request.return_value = _raw_resp("# Report", {"content-disposition": disposition})

        result = await api.export_report("r1", "md")

        assert result["filename"] == expected
        assert "/" not in result["filename"]
        assert "\\" not in result["filename"]

    async def test_export_default_html(self, ws):
        api, http = ws
        http.request.return_value = _raw_resp("<h1>R</h1>", {"content-type": "text/html"})
        out = await api.export_report("r1")
        assert out["content"] == "<h1>R</h1>"
        assert http.request.call_args.args == ("GET", "/ai-reports/reports/r1/export/html")


class TestGenerateReport:
    async def test_create_fill_loop_then_get(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(201, {"id": "r9", "ai_sections": [{"section_type": "a"}, {"section_type": "b"}], "skipped": ["bad"]}),
            _resp(200, {"section_type": "a", "filled": True, "remaining": ["b"], "complete": False}),
            _resp(200, {"section_type": "b", "filled": True, "remaining": [], "complete": True}),
            _resp(200, {"report": {"id": "r9", "content": "<h1>done</h1>"}}),
        ]
        out = await api.generate_report("technical", source_ids=["s1"], name="T")
        assert out["report"]["id"] == "r9"
        assert len(out["sections"]) == 2
        assert out["skipped"] == ["bad"]
        # create → fill → fill → get
        assert http.request.call_args_list[0].args == ("POST", "/ai-reports/reports")
        assert http.request.call_args_list[1].args == ("POST", "/ai-reports/reports/r9/sections")
        assert http.request.call_args_list[3].args == ("GET", "/ai-reports/reports/r9")

    async def test_no_ai_sections_skips_fill(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(201, {"id": "r1", "ai_sections": [], "skipped": []}),
            _resp(200, {"report": {"id": "r1"}}),
        ]
        out = await api.generate_report("exec")
        assert out["sections"] == []
        assert http.request.call_count == 2  # create + get, no fill

    async def test_copilot_blip_records_and_stops(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(201, {"id": "r1", "ai_sections": [{"section_type": "a"}], "skipped": []}),
            _resp(502, {"error": "copilot down"}),
            _resp(200, {"report": {"id": "r1"}}),
        ]
        out = await api.generate_report("exec")
        assert out["sections"] == [{"error": "generation failed", "status": 502}]
        assert out["report"]["id"] == "r1"


class TestGapS4GenerateReportOneShot:
    """S4: generate_report() one-shot create → fill all sections → fetch report."""

    async def test_generate_report_one_shot_returns_report_and_sections(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(201, {"id": "r10", "ai_sections": [{"section_type": "bluf"}], "skipped": []}),
            _resp(200, {"section_type": "bluf", "filled": True, "remaining": [], "complete": True}),
            _resp(200, {"report": {"id": "r10", "name": "Exec brief"}}),
        ]
        out = await api.generate_report("exec", source_ids=["s1"], name="Exec brief")
        assert out["report"]["id"] == "r10"
        assert out["report"]["name"] == "Exec brief"
        assert len(out["sections"]) == 1
        assert http.request.call_args_list[0].args == ("POST", "/ai-reports/reports")
        assert http.request.call_args_list[0].kwargs["json"] == {
            "template": "exec",
            "source_ids": ["s1"],
            "name": "Exec brief",
        }
        assert http.request.call_args_list[2].args == ("GET", "/ai-reports/reports/r10")
