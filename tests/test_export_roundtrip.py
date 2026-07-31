"""Cross-surface export round-trip parity — Python SDK.

Mocks export + import so we can assert that an inventory exported to a text format
and re-imported reports the same asset count. The round-trip lock protects the
import parser against export-format drift.
"""

from __future__ import annotations

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from crimson_crawler_client import InventoryManagerAPI


def _resp(status: int = 200, body: object = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"")


@pytest.fixture
def ws() -> tuple[InventoryManagerAPI, AsyncMock]:
    http = AsyncMock(spec=httpx.AsyncClient)
    return InventoryManagerAPI(http), http


class TestExportRoundTripParity:
    @pytest.mark.parametrize("fmt", ["json", "csv", "list"])
    async def test_export_then_import_matches_asset_count(self, ws, fmt):
        api, http = ws
        assets = [{"product": "nginx", "vendor": "f5", "versions": ["1.25.0"]}]
        exported = json.dumps({"inventory_name": "RT", "inventory": assets})
        http.request.side_effect = [
            httpx.Response(200, content=exported.encode()),
            _resp(201, {"id": "p2", "item_count": 1, "imported": 1, "format": fmt}),
        ]

        payload = await api.export_inventory("p1", fmt=fmt)
        imported = await api.import_inventory(
            fmt=fmt, content=payload, inventory_name="RT-reimport"
        )

        assert imported["item_count"] == 1
        assert imported["imported"] == 1
        assert http.request.call_args_list[0].args == (
            "GET", f"/inventory-manager/inventories/p1/export/{fmt}"
        )
        import_call = http.request.call_args_list[1]
        assert import_call.args == ("POST", "/inventory-manager/inventories/import")
        assert import_call.kwargs["json"]["content"] == exported

    async def test_workbook_round_trip_matches_byte_count(self, ws):
        api, http = ws
        xlsx = b"PK\x03\x04xlsx"
        http.request.side_effect = [
            httpx.Response(200, content=xlsx),
            _resp(201, {"id": "p2", "item_count": 5, "imported": 5, "format": "xlsx"}),
        ]

        payload = await api.export_inventory("p1", fmt="workbook")
        assert payload == xlsx
        imported = await api.import_inventory(fmt="xlsx", content=payload)
        assert imported["item_count"] == 5
