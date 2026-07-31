"""Unit tests for the hand-written Inventory Manager API client (client.inventory_manager).

Mocks the httpx layer — no network. Asserts each method hits the right
/inventory-manager/inventories path/method/body and unwraps the response envelope.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from crimson_crawler_client import CrawlerClient, InventoryManagerAPI, UnexpectedStatus


def _resp(status: int = 200, body: object = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"")


@pytest.fixture
def ws() -> tuple[InventoryManagerAPI, AsyncMock]:
    http = AsyncMock(spec=httpx.AsyncClient)
    return InventoryManagerAPI(http), http


class TestWiring:
    def test_client_exposes_inventory_manager(self):
        client = CrawlerClient(api_key="test-key")
        assert isinstance(client.inventory_manager, InventoryManagerAPI)
        assert client.inventory_manager is client.inventory_manager  # cached

    async def test_non_2xx_raises_unexpected_status(self, ws):
        api, http = ws
        http.request.return_value = _resp(404, {"error": "not found"})
        with pytest.raises(UnexpectedStatus) as exc:
            await api.get_inventory("missing")
        assert exc.value.status == 404


class TestInventories:
    async def test_list_inventories(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"inventories": [{"id": "p1", "name": "Prod"}]})
        out = await api.list_inventories()
        assert out == [{"id": "p1", "name": "Prod"}]
        http.request.assert_called_once_with("GET", "/inventory-manager/inventories", params=None, json=None)

    async def test_get_inventory_manifest(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "inventory": [], "attached": [], "scans": []})
        out = await api.get_inventory("p1")
        assert out["id"] == "p1"
        http.request.assert_called_once_with("GET", "/inventory-manager/inventories/p1", params=None, json=None)

    async def test_get_inventory_context_bundle(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "context": "# Inventory: Prod", "stats": {"total_cves": 5}})
        out = await api.get_inventory_context("p1")
        assert out["context"].startswith("# Inventory")
        http.request.assert_called_once_with("GET", "/inventory-manager/inventories/p1/context", params=None, json=None)

    async def test_list_enrichments(self, ws):
        api, http = ws
        rows = [
            {"id": "e1", "name": "Prod — 06-21", "created_at": "2026-06-21T00:00:00Z", "meta": {"total_cves": 12}},
            {"id": "e2", "name": "Prod — 06-20", "created_at": "2026-06-20T00:00:00Z", "meta": {"total_cves": 9}},
        ]
        http.request.return_value = _resp(200, {"enrichments": rows})
        out = await api.list_enrichments("p1")
        assert out == rows
        http.request.assert_called_once_with(
            "GET", "/inventory-manager/inventories/p1/enrichments", params=None, json=None,
        )

    async def test_list_enrichments_empty(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"enrichments": []})
        assert await api.list_enrichments("p1") == []

    async def test_compare_enrichments(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"matrix": {"counts": {"new": 2}}})
        assert (await api.compare_enrichments(["a", "b"]))["counts"]["new"] == 2
        assert http.request.call_args.args == ("GET", "/inventory-manager/inventories/compare")
        assert http.request.call_args.kwargs["params"] == {"ids": "a,b"}


class TestInventoryWrite:
    async def test_create_inventory_full_body(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "p1", "item_count": 2})
        out = await api.create_inventory(
            "Prod fleet",
            description="crown jewels",
            items=[{"product": "nginx", "vendor": "f5"}, {"product": "lodash", "ecosystem": "npm"}],
            monitoring=True,
        )
        assert out == {"id": "p1", "item_count": 2}
        call = http.request.call_args
        assert call.args == ("POST", "/inventory-manager/inventories")
        body = call.kwargs["json"]
        assert body == {
            "inventory_name": "Prod fleet",
            "description": "crown jewels",
            "items": [{"product": "nginx", "vendor": "f5"}, {"product": "lodash", "ecosystem": "npm"}],
            "monitoring": True,
        }

    async def test_create_inventory_minimal_omits_unset(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "p2", "item_count": 0})
        await api.create_inventory("Bare")
        assert http.request.call_args.kwargs["json"] == {"inventory_name": "Bare"}

    async def test_update_inventory(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "item_count": 1})
        out = await api.update_inventory("p1", inventory_name="Renamed", items=[{"product": "redis"}])
        assert out["item_count"] == 1
        call = http.request.call_args
        assert call.args == ("PATCH", "/inventory-manager/inventories/p1")
        assert call.kwargs["json"] == {"inventory_name": "Renamed", "items": [{"product": "redis"}]}

    async def test_delete_inventory(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"deleted": True})
        assert await api.delete_inventory("p1") is True
        http.request.assert_called_with("DELETE", "/inventory-manager/inventories/p1", params=None, json=None)

    async def test_attach_to_inventory(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"ok": True, "linked": True, "already": False})
        out = await api.attach_to_inventory("p1", "art-9")
        assert out == {"ok": True, "linked": True, "already": False}
        call = http.request.call_args
        assert call.args == ("POST", "/inventory-manager/inventories/p1/attach")
        assert call.kwargs["json"] == {"artifactId": "art-9"}

    async def test_create_inventory_carries_links(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "p3", "item_count": 1})
        await api.create_inventory(
            "Ctx", items=[{"product": "nginx"}],
            linked_artifact_ids=["a1", "a2"],
        )
        assert http.request.call_args.kwargs["json"] == {
            "inventory_name": "Ctx",
            "items": [{"product": "nginx"}],
            "linked_artifact_ids": ["a1", "a2"],
        }

    async def test_detach_from_inventory(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"ok": True, "linked": 1, "removed": True})
        out = await api.detach_from_inventory("p1", "a1")
        assert out == {"ok": True, "linked": 1, "removed": True}
        call = http.request.call_args
        assert call.args == ("POST", "/inventory-manager/inventories/p1/detach")
        assert call.kwargs["json"] == {"artifactId": "a1"}

    async def test_set_monitoring_routes_through_automation(self, ws):
        api, http = ws
        http.request.side_effect = [_resp(200, {"id": "p1", "automation": {}})]
        await api.set_monitoring("p1", monitoring=True)
        call = http.request.call_args
        assert call.args == ("PUT", "/inventory-manager/inventories/p1/automation")
        assert call.kwargs["json"] == {"monitoring": True}  # only the one field — assets/groups/daily untouched

    async def test_set_favorite(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "favorite": True})
        out = await api.set_favorite("p1")
        assert out["favorite"] is True
        call = http.request.call_args
        assert call.args == ("PATCH", "/inventory-manager/inventories/p1")
        assert call.kwargs["json"] == {"favorite": True}  # favorite-only PATCH — content untouched

    async def test_set_favorite_off(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "favorite": False})
        await api.set_favorite("p1", False)
        assert http.request.call_args.kwargs["json"] == {"favorite": False}

    async def test_get_automation(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "automation": {"monitoring": True, "daily_report": False}})
        out = await api.get_automation("p1")
        assert out["automation"]["monitoring"] is True
        http.request.assert_called_once_with(
            "GET", "/inventory-manager/inventories/p1/automation", params=None, json=None)

    async def test_set_automation_sends_only_provided_fields(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "automation": {"daily_report": True}})
        await api.set_automation("p1", daily_report=True, daily_report_template="project_brief")
        http.request.assert_called_once_with(
            "PUT", "/inventory-manager/inventories/p1/automation",
            params=None, json={"daily_report": True, "daily_report_template": "project_brief"},
        )


class TestScanIngest:
    async def test_parse_scan(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"format": "nmap", "items": [{"product": "nginx"}], "count": 1})
        out = await api.parse_scan("<nmaprun/>", "nmap")
        assert out["count"] == 1
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/parse",
            params=None, json={"format": "nmap", "content": "<nmaprun/>"},
        )

    async def test_ingest_scan_parse_enrich_assemble(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(200, {"format": "nmap", "items": [{"product": "nginx"}], "count": 1}),   # parse
            _resp(202, {"enrichment_id": "f" * 32}),                                        # submit
            _resp(200, {"status": "done", "result": {                                       # poll
                "summary": {"asset_count": 1, "total_cves": 2, "total_kev": 1},
                "assets": [{"product": "nginx", "top_cves": [
                    {"cve_id": "CVE-2024-2", "weaponization_score": 50, "kev": False},
                    {"cve_id": "CVE-2024-1", "weaponization_score": 90, "kev": True},
                ]}],
            }}),
        ]
        out = await api.ingest_scan("<nmaprun/>", "nmap", poll_interval=0)
        assert out["format"] == "nmap" and out["parsed_count"] == 1
        # KEV first regardless of input order
        assert out["recommended_actions"][0]["cve_id"] == "CVE-2024-1"
        assert out["report"]["summary"]["total_kev"] == 1

    async def test_parse_scan_xlsx_bytes_base64_encoded(self, ws):
        # The one BINARY format: bytes in → base64 on the wire (server decodes for format='xlsx').
        api, http = ws
        raw = b"PK\x03\x04 xl/ fake workbook bytes"
        http.request.return_value = _resp(200, {"format": "xlsx", "items": [{"product": "nginx"}], "count": 1})
        await api.parse_scan(raw, "xlsx")
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/parse", params=None,
            json={"format": "xlsx", "content": base64.b64encode(raw).decode("ascii")},
        )

    async def test_ingest_scan_empty_short_circuits(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"format": "csv", "items": [], "count": 0})
        out = await api.ingest_scan("", "csv", poll_interval=0)
        assert out["empty"] is True and out["parsed_count"] == 0 and out["enrichment_id"] is None


class TestScanInventory:
    async def test_get_inventory_then_submit_poll(self, ws):
        api, http = ws
        enrichment_id = "e" * 32
        items = [{"product": "nginx", "vendor": "f5"}]
        http.request.side_effect = [
            _resp(200, {"id": "p1", "inventory_name": "Prod", "inventory": items}),
            _resp(202, {"enrichment_id": enrichment_id}),
            _resp(200, {"status": "running"}),
            _resp(200, {"status": "done", "result": {"summary": {"total_cves": 3}}}),
        ]
        out = await api.enrich_inventory("p1", poll_interval=0)
        assert out == {"enrichment_id": enrichment_id, "report": {"summary": {"total_cves": 3}}}
        # 1) read the inventory manifest
        assert http.request.call_args_list[0].args == ("GET", "/inventory-manager/inventories/p1")
        # 2) submit the assets to the /v1 inventory engine
        submit = http.request.call_args_list[1]
        assert submit.args == ("POST", "/v1/inventory-enrich")
        assert submit.kwargs["json"] == {"items": items}  # always full depth — no include unless asked
        # 3) poll the /v1 status endpoint
        assert http.request.call_args_list[2].args == ("GET", f"/v1/inventory-enrich/{enrichment_id}")
        assert http.request.call_count == 4  # no save POST

    async def test_on_progress_threads_through_enrich_inventory(self, ws):
        api, http = ws
        items = [{"product": "nginx"}]
        http.request.side_effect = [
            _resp(200, {"id": "p1", "inventory": items}),
            _resp(202, {"enrichment_id": "f" * 32}),
            _resp(200, {"status": "running", "progress": 0.5, "events": [{"message": "✓ CVE-1", "progress": 0.5}]}),
            _resp(200, {"status": "done", "progress": 1.0, "result": {}}),
        ]
        seen: list[float] = []
        await api.enrich_inventory("p1", poll_interval=0, on_progress=lambda job: seen.append(job.get("progress")))
        assert seen == [0.5, 1.0]  # the per-CVE/live feed reaches the caller on every poll

    async def test_include_rides_into_submit(self, ws):
        api, http = ws
        items = [{"product": "nginx"}]
        http.request.side_effect = [
            _resp(200, {"id": "p1", "inventory": items}),
            _resp(202, {"enrichment_id": "f" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        await api.enrich_inventory("p1", include=["exploits"], poll_interval=0)
        assert http.request.call_args_list[1].kwargs["json"] == {"items": items, "include": ["exploits"]}

    async def test_empty_inventory_short_circuits(self, ws):
        api, http = ws
        # Manifest has no assets → no submit, no poll.
        http.request.return_value = _resp(200, {"id": "p1", "inventory": []})
        out = await api.enrich_inventory("p1", poll_interval=0)
        assert out == {"enrichment_id": None, "empty": True}
        assert http.request.call_count == 1  # only the manifest GET

    async def test_raises_on_engine_error(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(200, {"id": "p1", "inventory": [{"product": "nginx"}]}),
            _resp(202, {"enrichment_id": "h" * 32}),
            _resp(200, {"status": "error", "error": "boom"}),
        ]
        with pytest.raises(UnexpectedStatus):
            await api.enrich_inventory("p1", poll_interval=0)

    async def test_times_out(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(200, {"id": "p1", "inventory": [{"product": "nginx"}]}),
            _resp(202, {"enrichment_id": "i" * 32}),
            _resp(200, {"status": "running"}),
        ]
        with pytest.raises(TimeoutError):
            await api.enrich_inventory("p1", poll_interval=0, timeout=-1)


class TestImportExport:
    async def test_import_inventory_minimal(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "p9", "item_count": 2, "imported": 2, "format": "csv"})
        out = await api.import_inventory(fmt="csv", content="product\nnginx\nopenssl\n")
        assert out == {"id": "p9", "item_count": 2, "imported": 2, "format": "csv"}
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/import", params=None,
            json={"format": "csv", "content": "product\nnginx\nopenssl\n"},
        )

    async def test_import_inventory_xlsx_bytes_base64_encoded(self, ws):
        api, http = ws
        raw = b"PK\x03\x04 xl/ workbook"
        http.request.return_value = _resp(201, {"id": "p9", "item_count": 1, "imported": 1, "format": "xlsx"})
        await api.import_inventory(fmt="xlsx", content=raw)
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/import", params=None,
            json={"format": "xlsx", "content": base64.b64encode(raw).decode("ascii")},
        )

    async def test_import_inventory_with_name_and_description(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "p9", "item_count": 1})
        await api.import_inventory(fmt="nmap", content="<nmaprun/>", inventory_name="DMZ", description="edge")
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/import", params=None,
            json={"format": "nmap", "content": "<nmaprun/>", "inventory_name": "DMZ", "description": "edge"},
        )

    async def test_parse_multi_combines_sources(self, ws):
        api, http = ws
        srcs = [{"format": "csv", "content": "product\nnginx\n"}, {"format": "nmap", "content": "<nmaprun/>"}]
        http.request.return_value = _resp(
            200, {"items": [{"product": "nginx"}], "count": 1, "asset_groups": [], "per_source": []})
        out = await api.parse_multi(srcs)
        assert out["count"] == 1
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/parse-multi", params=None, json={"sources": srcs},
        )

    async def test_parse_multi_base64s_xlsx_source(self, ws):
        api, http = ws
        raw = b"PK\x03\x04xl"
        http.request.return_value = _resp(200, {"items": [], "count": 0, "asset_groups": [], "per_source": []})
        await api.parse_multi([{"format": "xlsx", "content": raw}])
        sent = http.request.call_args.kwargs["json"]["sources"][0]
        assert sent["content"] == base64.b64encode(raw).decode("ascii")

    async def test_import_multi_creates_from_combined(self, ws):
        api, http = ws
        srcs = [
            {"format": "csv", "content": "product\nnginx\n"},
            {"format": "list", "content": "cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*"},
        ]
        http.request.return_value = _resp(
            201, {"id": "p", "item_count": 2, "format": "multi", "multi": True, "per_source": []})
        out = await api.import_multi(srcs, inventory_name="Combined")
        assert out["multi"] is True
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/import", params=None,
            json={"sources": srcs, "inventory_name": "Combined"},
        )

    async def test_import_multi_into_existing(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "replaced": True, "mode": "append"})
        await api.import_multi([{"format": "csv", "content": "product\nx\n"}], inventory_id="p1", mode="append")
        body = http.request.call_args.kwargs["json"]
        assert body["inventory_id"] == "p1"
        assert body["mode"] == "append"

    async def test_list_export_formats(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"formats": [{"key": "json"}, {"key": "csv"}]})
        out = await api.list_export_formats("p1")
        assert out == [{"key": "json"}, {"key": "csv"}]
        http.request.assert_called_once_with(
            "GET", "/inventory-manager/inventories/p1/export", params=None, json=None,
        )

    async def test_export_inventory_returns_raw_text(self, ws):
        api, http = ws
        http.request.return_value = httpx.Response(200, content=b"inventory_name,product\nProd,nginx\n")
        out = await api.export_inventory("p1", fmt="csv")
        assert out == "inventory_name,product\nProd,nginx\n"
        http.request.assert_called_once_with(
            "GET", "/inventory-manager/inventories/p1/export/csv", params=None, json=None,
        )

    async def test_export_inventory_defaults_to_json(self, ws):
        api, http = ws
        http.request.return_value = httpx.Response(200, content=b"{}")
        await api.export_inventory("p1")
        http.request.assert_called_once_with(
            "GET", "/inventory-manager/inventories/p1/export/json", params=None, json=None,
        )

    async def test_export_inventory_workbook_returns_bytes(self, ws):
        # The binary format resolves to bytes (write them straight to a .xlsx); text formats stay str.
        api, http = ws
        http.request.return_value = httpx.Response(200, content=b"PK\x03\x04xlsx")
        out = await api.export_inventory("p1", fmt="workbook")
        assert out == b"PK\x03\x04xlsx"
        assert isinstance(out, bytes)


# Every advertised import + export FORMAT must flow through the thin SDK without the client rejecting it.
_IMPORT_FORMATS = ["json", "sbom", "csv", "nmap", "list", "grype", "trivy", "depcheck", "nessus", "gvm"]
_EXPORT_FORMATS = ["json", "csv", "list", "cyclonedx", "spdx", "spdx2", "workbook"]


class TestFormatParity:
    @pytest.mark.parametrize("fmt", _IMPORT_FORMATS)
    async def test_import_inventory_accepts_every_format(self, ws, fmt):
        api, http = ws
        http.request.return_value = _resp(201, {"id": "p", "item_count": 1, "imported": 1, "format": fmt})
        out = await api.import_inventory(fmt=fmt, content="x")
        assert out["format"] == fmt
        method, path = http.request.call_args.args
        assert method == "POST" and path == "/inventory-manager/inventories/import"
        assert http.request.call_args.kwargs["json"] == {"format": fmt, "content": "x"}

    @pytest.mark.parametrize("fmt", _IMPORT_FORMATS)
    async def test_parse_scan_accepts_every_format(self, ws, fmt):
        api, http = ws
        http.request.return_value = _resp(200, {"format": fmt, "items": [], "count": 0})
        await api.parse_scan("x", fmt)
        method, path = http.request.call_args.args
        assert method == "POST" and path == "/inventory-manager/inventories/parse"
        assert http.request.call_args.kwargs["json"] == {"format": fmt, "content": "x"}

    @pytest.mark.parametrize("fmt", _EXPORT_FORMATS)
    async def test_export_inventory_every_format(self, ws, fmt):
        api, http = ws
        http.request.return_value = httpx.Response(200, content=b"data")
        await api.export_inventory("p1", fmt=fmt)
        method, path = http.request.call_args.args
        assert method == "GET" and path == f"/inventory-manager/inventories/p1/export/{fmt}"


class TestAssetEdit:
    async def test_replace_assets(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "item_count": 1, "mode": "replace"})
        out = await api.replace_assets("p1", [{"product": "nginx"}])
        assert out == {"id": "p1", "item_count": 1, "mode": "replace"}
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/assets", params=None,
            json={"items": [{"product": "nginx"}], "mode": "replace"},
        )

    async def test_add_assets(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "item_count": 3, "mode": "append"})
        await api.add_assets("p1", [{"product": "redis"}])
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/assets", params=None,
            json={"items": [{"product": "redis"}], "mode": "append"},
        )

    async def test_apply_asset_fix(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "product": "nginx", "version": "1.27.4", "item_count": 2})
        out = await api.apply_asset_fix("p1", "nginx", "1.27.4")
        assert out == {"id": "p1", "product": "nginx", "version": "1.27.4", "item_count": 2}
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/asset-version", params=None,
            json={"product": "nginx", "version": "1.27.4"},
        )

    async def test_apply_asset_fix_with_vendor(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "product": "nginx", "version": "1.27.4", "item_count": 2})
        await api.apply_asset_fix("p1", "nginx", "1.27.4", vendor="f5")
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/asset-version", params=None,
            json={"product": "nginx", "version": "1.27.4", "vendor": "f5"},
        )

    async def test_import_into_existing_replace(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "item_count": 2, "replaced": True, "mode": "replace"})
        out = await api.import_inventory(fmt="csv", content="product\nnginx\n", inventory_id="p1")
        assert out["replaced"] is True
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/import", params=None,
            json={"format": "csv", "content": "product\nnginx\n", "inventory_id": "p1", "mode": "replace"},
        )

    async def test_import_into_existing_append(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"id": "p1", "item_count": 5, "replaced": True, "mode": "append"})
        await api.import_inventory(fmt="nmap", content="<nmaprun/>", inventory_id="p1", mode="append")
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/import", params=None,
            json={"format": "nmap", "content": "<nmaprun/>", "inventory_id": "p1", "mode": "append"},
        )


class TestAttachmentsBulk:
    async def test_set_attachments(self, ws):
        api, http = ws
        http.request.return_value = _resp(
            200, {"id": "p1", "linked_count": 2, "attached": 2, "skipped": 0, "mode": "replace"})
        out = await api.set_attachments("p1", ["a1", "a2"])
        assert out["attached"] == 2
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/attachments", params=None,
            json={"artifact_ids": ["a1", "a2"], "mode": "replace"},
        )

    async def test_add_attachments(self, ws):
        api, http = ws
        http.request.return_value = _resp(
            200, {"id": "p1", "linked_count": 3, "attached": 1, "skipped": 0, "mode": "append"})
        await api.add_attachments("p1", ["a3"])
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/attachments", params=None,
            json={"artifact_ids": ["a3"], "mode": "append"},
        )


class TestSaveEnrichment:
    async def test_save_enrichment_posts_to_inventory_history(self, ws):
        api, http = ws
        eid = "c" * 32
        http.request.return_value = _resp(201, {"artifact_id": "inv-7"})
        out = await api.save_enrichment("p1", eid)
        assert out == {"artifact_id": "inv-7"}
        http.request.assert_called_once_with(
            "POST", "/inventory-manager/inventories/p1/enrichments", params=None,
            json={"enrichment_id": eid},
        )

    async def test_enrich_inventory_save_true_files_after_completion(self, ws):
        api, http = ws
        eid = "c" * 32
        http.request.side_effect = [
            _resp(200, {"inventory": [{"product": "nginx", "versions": ["1.25"]}]}),  # get_inventory
            _resp(202, {"enrichment_id": eid}),                                        # submit
            _resp(200, {"status": "done", "result": {"rollup": {}}}),                  # poll
            _resp(201, {"artifact_id": "inv-7"}),                                    # save
        ]
        out = await api.enrich_inventory("p1", poll_interval=0, save=True)
        assert out["enrichment_id"] == eid
        assert out["saved"] == {"artifact_id": "inv-7"}
        assert http.request.call_args_list[-1].args == (
            "POST", "/inventory-manager/inventories/p1/enrichments")

    async def test_enrich_inventory_empty_skips_save(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"inventory": []})  # get_inventory → empty
        out = await api.enrich_inventory("p1", poll_interval=0, save=True)
        assert out == {"enrichment_id": None, "empty": True}
        assert http.request.call_count == 1  # no submit, no save


class TestAttachmentEnrichment:
    async def test_enrich_inventory_resolves_attachments_when_toggle_on(self, ws):
        api, http = ws
        eid = "d" * 32
        http.request.side_effect = [
            _resp(200, {"inventory": [{"product": "nginx"}], "enrich_attachments": True,
                        "attached": [{"id": "att-1"}]}),
            httpx.Response(200, content=b"CVE-2024-9999 seen at 1.2.3.4"),  # get_artifact raw text
            _resp(202, {"enrichment_id": eid}),                              # submit
            _resp(200, {"status": "done", "result": {"rollup": {}}}),        # poll
        ]
        out = await api.enrich_inventory("p1", poll_interval=0)
        assert out["enrichment_id"] == eid
        # the attachment was fetched via the artifact-manager raw endpoint
        assert http.request.call_args_list[1].args == ("GET", "/artifact-manager/artifacts/att-1")
        # the submit body carried the resolved attachments_text
        submit = http.request.call_args_list[2]
        assert submit.args == ("POST", "/v1/inventory-enrich")
        assert "CVE-2024-9999" in submit.kwargs["json"]["attachments_text"]

    async def test_binary_attachment_forwarded_as_file(self, ws):
        api, http = ws
        eid = "e" * 32
        http.request.side_effect = [
            _resp(200, {"inventory": [{"product": "nginx"}], "enrich_attachments": True,
                        "attached": [{"id": "att-x"}]}),
            # a binary (XLSX) attachment — flagged by X-Artifact-Format: file
            httpx.Response(200, content=b"UEsDBASE64XLSX",
                           headers={"X-Artifact-Format": "file", "X-Artifact-Name": "scan.xlsx"}),
            _resp(202, {"enrichment_id": eid}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        out = await api.enrich_inventory("p1", poll_interval=0)
        assert out["enrichment_id"] == eid
        body = http.request.call_args_list[2].kwargs["json"]
        # binary went to attachments_files (raw base64), NOT attachments_text
        assert "attachments_text" not in body
        assert body["attachments_files"] == [{"filename": "scan.xlsx", "content_b64": "UEsDBASE64XLSX"}]

    async def test_toggle_off_skips_attachment_fetch(self, ws):
        api, http = ws
        http.request.side_effect = [
            _resp(200, {"inventory": [{"product": "nginx"}], "enrich_attachments": False,
                        "attached": [{"id": "att-1"}]}),
            _resp(202, {"enrichment_id": "d" * 32}),
            _resp(200, {"status": "done", "result": {}}),
        ]
        out = await api.enrich_inventory("p1", poll_interval=0)
        assert out["enrichment_id"] == "d" * 32
        assert http.request.call_count == 3  # no get_artifact call
        assert "attachments_text" not in http.request.call_args_list[1].kwargs["json"]


class TestGapS5S8InventoryManagerMethods:
    """S5–S8: get_inventory_context, compare_enrichments, apply_asset_fix,
    parse_multi / import_multi.
    """

    async def test_s5_get_inventory_context(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {
            "id": "p1",
            "context": "# Inventory: Prod\n- nginx 1.25.0",
            "stats": {"total_cves": 7, "total_kev": 1},
        })
        out = await api.get_inventory_context("p1")
        assert out["context"].startswith("# Inventory")
        assert out["stats"]["total_kev"] == 1
        http.request.assert_called_once_with(
            "GET", "/inventory-manager/inventories/p1/context", params=None, json=None
        )

    async def test_s6_compare_enrichments_matrix(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {
            "matrix": {
                "counts": {"new": 1, "resolved": 0, "persistent": 5},
                "rows": [{"cve_id": "CVE-2026-26929", "status": "persistent"}],
            }
        })
        ids = ["e0", "e1", "e2"]
        out = await api.compare_enrichments(ids)
        assert out["counts"]["persistent"] == 5
        assert http.request.call_args.args == ("GET", "/inventory-manager/inventories/compare")
        assert http.request.call_args.kwargs["params"] == {"ids": "e0,e1,e2"}

    async def test_s7_apply_asset_fix(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {
            "id": "p1", "product": "nginx", "version": "1.27.4", "item_count": 3,
        })
        out = await api.apply_asset_fix("p1", "nginx", "1.27.4", vendor="f5")
        assert out["version"] == "1.27.4"
        http.request.assert_called_once_with(
            "PATCH", "/inventory-manager/inventories/p1/asset-version", params=None,
            json={"product": "nginx", "version": "1.27.4", "vendor": "f5"},
        )

    async def test_s8_parse_multi_and_import_multi(self, ws):
        api, http = ws
        srcs = [
            {"format": "csv", "content": "product\nnginx\n"},
            {"format": "list", "content": "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"},
        ]
        http.request.side_effect = [
            _resp(200, {"items": [{"product": "nginx", "vendor": "f5"}], "count": 1,
                  "asset_groups": [], "per_source": []}),
            _resp(201, {"id": "p9", "item_count": 1, "format": "multi", "multi": True,
                  "per_source": []}),
        ]
        parsed = await api.parse_multi(srcs)
        assert parsed["count"] == 1
        imported = await api.import_multi(srcs, inventory_name="Combined")
        assert imported["multi"] is True
        assert http.request.call_args_list[0].args == (
            "POST", "/inventory-manager/inventories/parse-multi")
        assert http.request.call_args_list[1].args == (
            "POST", "/inventory-manager/inventories/import")
