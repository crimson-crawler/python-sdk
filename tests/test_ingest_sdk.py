"""Unit tests for the Python SDK's scan→briefing ingest component.

Mocks the InventoryManagerAPI methods — no network. Covers parse_scan → enrich_items
→ assemble_briefing, the empty-scan short-circuit, and KEV-first top-N assembly.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from crimson_crawler_client.ingest import assemble_briefing, ingest_scan


def test_assemble_briefing_kev_first_top_n():
    report = {
        "assets": [
            {
                "product": "Apache httpd",
                "top_cves": [
                    {"cve_id": "CVE-2021-44228", "weaponization_score": 95, "kev": True},
                    {"cve_id": "CVE-2021-45046", "weaponization_score": 80, "kev": False},
                ],
            },
            {
                "product": "log4j-core",
                "top_cves": [
                    {"cve_id": "CVE-2021-44228", "weaponization_score": 99, "kev": True},
                    {"cve_id": "CVE-2021-45105", "weaponization_score": 70, "kev": False},
                ],
            },
        ]
    }
    briefing = assemble_briefing(report, fmt="csv", parsed_count=2, truncated=False, enrichment_id="e" * 32)
    assert briefing["format"] == "csv"
    assert briefing["parsed_count"] == 2
    assert briefing["enrichment_id"] == "e" * 32
    actions = briefing["recommended_actions"]
    assert actions[0]["cve_id"] == "CVE-2021-44228"
    assert actions[0]["kev"] is True
    # the duplicate CVE kept the highest weaponization score across assets
    assert actions[0]["weaponization_score"] == 99


def test_assemble_briefing_no_assets_returns_empty_actions():
    briefing = assemble_briefing({}, fmt="nmap", parsed_count=0, truncated=None, enrichment_id=None)
    assert briefing["recommended_actions"] == []
    assert "truncated" not in briefing


@pytest.mark.asyncio
async def test_ingest_scan_pipeline():
    inv_api = MagicMock()
    inv_api.parse_scan = AsyncMock(
        return_value={
            "format": "csv",
            "items": [{"product": "nginx", "vendor": "f5"}],
            "count": 1,
            "truncated": False,
        }
    )
    inv_api.enrich_items = AsyncMock(
        return_value={
            "enrichment_id": "e" * 32,
            "report": {
                "assets": [
                    {
                        "product": "nginx",
                        "top_cves": [
                            {"cve_id": "CVE-2026-26929", "weaponization_score": 92, "kev": True},
                        ],
                    },
                ]
            },
        }
    )

    result = await ingest_scan(inv_api, "product\nnginx\n", "csv", poll_interval=0)

    inv_api.parse_scan.assert_awaited_once_with("product\nnginx\n", "csv")
    inv_api.enrich_items.assert_awaited_once()
    assert result["format"] == "csv"
    assert result["parsed_count"] == 1
    assert result["enrichment_id"] == "e" * 32
    assert result["recommended_actions"][0]["cve_id"] == "CVE-2026-26929"


@pytest.mark.asyncio
async def test_ingest_scan_empty_short_circuits():
    inv_api = MagicMock()
    inv_api.parse_scan = AsyncMock(return_value={"format": "nmap", "items": [], "count": 0})

    result = await ingest_scan(inv_api, "<nmaprun/>", "nmap", poll_interval=0)

    assert result["empty"] is True
    assert result["enrichment_id"] is None
    inv_api.enrich_items.assert_not_called()
