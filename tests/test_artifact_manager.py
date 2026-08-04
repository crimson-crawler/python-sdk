"""Unit tests for the hand-written Artifact Manager API client (client.artifact_manager).

Mocks the httpx layer — no network. Asserts each method hits the right
path/method/params/body and unwraps the response envelope, and that non-2xx
raises UnexpectedStatus.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from crimson_crawler_client import ArtifactManagerAPI, CrawlerClient, UnexpectedStatus


def _resp(status: int = 200, body: object = None, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode() if body is not None else b"", headers=headers or {})


def _raw_resp(text: str, headers: dict[str, str]) -> httpx.Response:
    return httpx.Response(200, content=text.encode(), headers=headers)


@pytest.fixture
def ws() -> tuple[ArtifactManagerAPI, AsyncMock]:
    http = AsyncMock(spec=httpx.AsyncClient)
    return ArtifactManagerAPI(http), http


class TestWiring:
    def test_client_exposes_artifact_manager(self):
        client = CrawlerClient(api_key="test-key")
        assert isinstance(client.artifact_manager, ArtifactManagerAPI)
        assert client.artifact_manager is client.artifact_manager  # cached

    async def test_non_2xx_raises_unexpected_status(self, ws):
        api, http = ws
        http.request.return_value = _resp(404, {"error": "not found"})
        with pytest.raises(UnexpectedStatus) as exc:
            await api.get_artifact("x")
        assert exc.value.status == 404

    async def test_caller_ids_stay_in_one_encoded_path_segment(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"artifact": {"id": "safe"}})

        await api.get_artifact("../folders?raw=1#fragment%")

        assert http.request.call_args.args[1] == "/artifact-manager/artifacts/..%2Ffolders%3Fraw%3D1%23fragment%25"


class TestArtifacts:
    async def test_list_artifacts_filters(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"artifacts": [{"id": "a1"}]})
        out = await api.list_artifacts(kind="artifact_enrichment", folder="__root__", since="2026-01-01")
        assert out == [{"id": "a1"}]
        http.request.assert_called_once_with(
            "GET",
            "/artifact-manager/artifacts",
            params={"kind": "artifact_enrichment", "folder": "__root__", "since": "2026-01-01"},
            json=None,
        )

    async def test_list_artifacts_no_filters_sends_no_params(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"artifacts": []})
        await api.list_artifacts()
        assert http.request.call_args.kwargs["params"] is None

    async def test_upload_artifacts(self, ws):
        api, http = ws
        http.request.return_value = _resp(201, {"ids": ["n1"], "folderId": "f1"})
        out = await api.upload_artifacts(
            [{"name": "n.txt", "content": "c", "format": "paste"}],
            new_folder_name="case-1",
        )
        assert out["ids"] == ["n1"]
        body = http.request.call_args.kwargs["json"]
        assert body["newFolderName"] == "case-1" and "folderId" not in body

    async def test_get_artifact_and_raw(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"artifact": {"id": "a1", "content": "x"}})
        assert (await api.get_artifact("a1"))["content"] == "x"

        http.send.return_value = _raw_resp(
            '{"report":1}',
            {
                "x-artifact-id": "a1",
                "x-artifact-kind": "artifact_enrichment",
                "x-artifact-name": "Scan%20%C2%B7%205",
                "x-artifact-format": "scan_report",
            },
        )
        raw = await api.get_artifact_raw("a1")
        assert raw["content"] == '{"report":1}'
        assert raw["kind"] == "artifact_enrichment"
        assert raw["name"] == "Scan · 5"  # URL-decoded

    async def test_get_artifact_raw_rejects_body_above_buffer_limit(self, ws):
        api, http = ws
        http.send.return_value = _raw_resp(
            "oversized",
            {"content-length": "10000001"},
        )

        with pytest.raises(ValueError, match="10000000-byte"):
            await api.get_artifact_raw("a1")
        http.send.assert_awaited_once()
        assert http.send.call_args.kwargs["stream"] is True

    async def test_update_artifact_folder_sentinel(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"artifact": {"id": "a1"}})
        await api.update_artifact("a1", name="new", favorite=True)
        assert http.request.call_args.kwargs["json"] == {"name": "new", "favorite": True}

        await api.update_artifact("a1", folder_id=None)  # explicit None = move to root
        assert http.request.call_args.kwargs["json"] == {"folderId": None}

    async def test_delete_and_copy(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"deleted": True})
        assert await api.delete_artifact("a1") is True

        http.request.return_value = _resp(201, {"id": "copy-1"})
        assert await api.copy_artifact("a1") == "copy-1"
        http.request.assert_called_with("POST", "/artifact-manager/artifacts/a1/copy", params=None, json=None)


class TestBulk:
    async def test_bulk_delete(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"op": "delete", "count": 2})
        assert await api.bulk_delete(["a1", "a2"]) == 2
        http.request.assert_called_once_with(
            "POST",
            "/artifact-manager/artifacts/bulk",
            params=None,
            json={"op": "delete", "ids": ["a1", "a2"]},
        )

    async def test_move_to_folder(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"op": "move", "count": 3})
        assert await api.move_to_folder(["a1", "a2", "a3"], "f1") == 3
        assert http.request.call_args.kwargs["json"] == {
            "op": "move",
            "ids": ["a1", "a2", "a3"],
            "folder_id": "f1",
        }

    async def test_move_to_root_defaults_folder_none(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"op": "move", "count": 1})
        assert await api.move_to_folder(["a1"]) == 1
        assert http.request.call_args.kwargs["json"]["folder_id"] is None

    async def test_bulk_set_favorite(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"op": "favorite", "count": 4})
        assert await api.bulk_set_favorite(["a1", "a2"], True) == 4
        assert http.request.call_args.kwargs["json"] == {
            "op": "favorite",
            "ids": ["a1", "a2"],
            "favorite": True,
        }

    async def test_bulk_non_2xx_raises(self, ws):
        api, http = ws
        http.request.return_value = _resp(400, {"error": "ids[] is required"})
        with pytest.raises(UnexpectedStatus) as exc:
            await api.bulk_delete([])
        assert exc.value.status == 400

    async def test_download_bundle(self, ws):
        api, http = ws
        zip_bytes = b"PK\x03\x04bundle"
        http.request.return_value = httpx.Response(200, content=zip_bytes, headers={"content-type": "application/zip"})
        assert await api.download_bundle(["a1", "a2"]) == zip_bytes
        assert http.request.call_args.args[1].endswith("/artifact-manager/artifacts/bundle")
        assert http.request.call_args.kwargs["json"] == {"ids": ["a1", "a2"]}


class TestScanSurface:
    async def test_rating_roundtrip(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"rating": "up", "counts": {"up": 1, "down": 0}})
        assert (await api.get_rating("s1"))["rating"] == "up"

        http.request.return_value = _resp(200, {"ok": True, "cleared": True})
        await api.set_rating("s1", None)
        assert http.request.call_args.kwargs["json"] == {"rating": None}

    async def test_exports(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"formats": ["csv", "stix"]})
        assert await api.list_exports("s1") == ["csv", "stix"]

        http.request.return_value = _raw_resp(
            '{"type":"bundle"}',
            {
                "content-disposition": 'attachment; filename="stix.json"',
                "content-type": "application/json; charset=utf-8",
            },
        )
        exp = await api.get_export("s1", "stix")
        assert exp == {
            "content": '{"type":"bundle"}',
            "bytes": b'{"type":"bundle"}',
            "filename": "stix.json",
            "content_type": "application/json; charset=utf-8",
        }

    @pytest.mark.parametrize(
        ("disposition", "expected"),
        [
            ('attachment; filename="../../etc/passwd"', "passwd"),
            ('attachment; filename="/var/tmp/export.json"', "export.json"),
            ('attachment; filename=""', "stix"),
            ("attachment; filename*=UTF-8''threat%20report.json", "threat report.json"),
        ],
    )
    async def test_get_export_sanitizes_content_disposition(self, ws, disposition: str, expected: str):
        api, http = ws
        http.request.return_value = _raw_resp("{}", {"content-disposition": disposition})

        result = await api.get_export("s1", "stix")

        assert result["filename"] == expected
        assert "/" not in result["filename"]
        assert "\\" not in result["filename"]

    async def test_get_export_binary_xlsx(self, ws):
        api, http = ws
        xlsx = b"PK\x03\x04\x01\x02\x03"  # zip magic — a real XLSX is a zip
        http.request.return_value = httpx.Response(
            200,
            content=xlsx,
            headers={
                "content-disposition": 'attachment; filename="emass.xlsx"',
                "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            },
        )
        exp = await api.get_export("s1", "emass")
        assert exp["bytes"] == xlsx
        assert exp["filename"] == "emass.xlsx"
        assert "spreadsheetml" in exp["content_type"]

    async def test_download_all_exports(self, ws):
        api, http = ws
        zip_bytes = b"PK\x03\x04bundle-of-everything"
        http.request.return_value = httpx.Response(
            200,
            content=zip_bytes,
            headers={
                "content-disposition": 'attachment; filename="my-enrichment-exports.zip"',
                "content-type": "application/zip",
            },
        )
        out = await api.download_all_exports("s1")
        assert out == zip_bytes
        assert http.request.call_args.args[1].endswith("/artifact-manager/artifacts/s1/exports/all")

    async def test_compare_enrichments(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"matrix": {"counts": {"new": 1}}})
        assert (await api.compare_enrichments(["a", "b"]))["counts"]["new"] == 1
        assert http.request.call_args.kwargs["params"] == {"ids": "a,b"}


class TestFolders:
    async def test_folder_crud(self, ws):
        api, http = ws
        http.request.return_value = _resp(200, {"folders": [{"id": "f1", "artifact_count": 2}]})
        assert (await api.list_folders())[0]["id"] == "f1"

        http.request.return_value = _resp(201, {"id": "f2", "name": "evidence"})
        assert await api.create_folder("evidence") == "f2"

        http.request.return_value = _resp(200, {"id": "f2", "name": "renamed"})
        assert (await api.rename_folder("f2", "renamed"))["name"] == "renamed"

        http.request.return_value = _resp(200, {"deleted": True})
        assert await api.delete_folder("f2") is True

    async def test_download_folder(self, ws):
        api, http = ws
        zip_bytes = b"PK\x03\x04folder"
        http.request.return_value = httpx.Response(200, content=zip_bytes, headers={"content-type": "application/zip"})
        assert await api.download_folder("f1") == zip_bytes
        assert http.request.call_args.args[1].endswith("/artifact-manager/folders/f1/exports/all")


class TestSaveEnrichment:
    async def test_save_enrichment_posts_id_only(self, ws):
        api, http = ws
        eid = "b" * 32
        http.request.return_value = _resp(201, {"enrichment_artifact_id": "art-9"})
        out = await api.save_enrichment(eid)
        assert out == {"enrichment_artifact_id": "art-9"}
        http.request.assert_called_once_with(
            "POST",
            "/artifact-manager/artifacts/from-enrichment",
            params=None,
            json={"enrichment_id": eid},
        )

    async def test_save_enrichment_with_folder(self, ws):
        api, http = ws
        eid = "b" * 32
        http.request.return_value = _resp(201, {"enrichment_artifact_id": "art-9"})
        await api.save_enrichment(eid, new_folder_name="incident-2026")
        assert http.request.call_args.kwargs["json"] == {
            "enrichment_id": eid,
            "folder": {"folder_id": None, "new_folder_name": "incident-2026"},
        }

    async def test_save_enrichment_raises_on_non_2xx(self, ws):
        api, http = ws
        http.request.return_value = _resp(409, {"error": "enrichment not complete"})
        with pytest.raises(UnexpectedStatus):
            await api.save_enrichment("b" * 32)
