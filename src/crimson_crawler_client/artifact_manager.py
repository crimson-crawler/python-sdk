"""Artifact Manager API (Artifact Manager) — key-authed access to YOUR stored artifacts.

The Artifact Manager API lives at ``/artifact-manager/*``, outside the versioned
``/v1`` enrichment contract, so it is not part of the
OpenAPI snapshot or the generated layer. This module is the hand-written client
for it, exposed as :attr:`CrawlerClient.artifact_manager`.

Same API key, same base URL, same retry transport as every other call — but
**artifact_manager calls never count toward your API usage** (account self-service
over your own data, not enrichment compute).

Responses are plain ``dict``/``list`` JSON (no generated models — the surface
is small and evolves independently of ``/v1``).

Example::

    async with CrawlerClient() as client:
        enrichments = await client.artifact_manager.list_artifacts(kind="artifact_enrichment")
        stix = await client.artifact_manager.get_export(enrichments[0]["id"], "stix")
        await client.artifact_manager.upload_artifacts(
            [{"name": "notes.txt", "content": "CVE-2024-3400 observed", "format": "paste"}],
            new_folder_name="incident-2026-06",
        )
"""

from __future__ import annotations

from email.message import Message
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import unquote

from ._url import path_segment
from .exceptions import UnexpectedStatus

if TYPE_CHECKING:
    import httpx

_UNSET: Any = object()
"""Sentinel distinguishing "don't touch the folder" from "move to root (None)"."""


def _safe_download_filename(disposition: str, fallback: str) -> str:
    def basename(value: str) -> str:
        filename = PurePosixPath(value.replace("\x00", "").replace("\\", "/")).name
        return "" if filename in {"", ".", ".."} else filename

    safe_fallback = basename(fallback) or "download"
    message = Message()
    message["Content-Disposition"] = disposition
    candidate = message.get_filename()
    if not candidate:
        return safe_fallback
    return basename(candidate) or safe_fallback


class ArtifactManagerAPI:
    """Client for the key-authed Artifact Manager API (Artifact Manager).

    Obtained via :attr:`CrawlerClient.artifact_manager` — never constructed directly.
    Every method raises :class:`UnexpectedStatus` on a non-2xx response.
    """

    def __init__(self, http: httpx.AsyncClient) -> None:
        # The CrawlerClient's configured httpx client: base_url, apikey auth
        # (injected per request by _auth.ApiKeyAuth, never parked on the
        # client), timeout, and the retry transport all already apply.
        self._http = http

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> httpx.Response:
        resp = await self._http.request(method, path, params=params, json=json)
        if not 200 <= resp.status_code < 300:
            raise UnexpectedStatus(resp.status_code, resp.content, f"Artifact Manager API {resp.status_code} on {path}")
        return resp

    # -- Discovery ---------------------------------------------------------- #

    async def discovery(self) -> dict[str, Any]:
        """``GET /artifact-manager`` — the self-documenting endpoint map + your account context."""
        return (await self._request("GET", "/artifact-manager")).json()

    # -- Artifacts ---------------------------------------------------------- #

    async def list_artifacts(
        self,
        *,
        kind: Literal["input", "artifact_enrichment", "report", "inventory_enrichment", "inventory_asset"]
        | None = None,
        folder: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        """List your artifacts (newest first, no content). ``kind`` filters to one of the five library
        kinds — ``input`` / ``enrichment`` / ``report`` plus ``inventory_enrichment`` (saved inventory
        enrichments) and ``asset`` (inventories).

        Args:
            kind: Filter by artifact kind.
            folder: A folder UUID, or ``"__root__"`` for un-filed artifacts.
            since: ISO date/timestamp lower bound on ``created_at``.
            until: ISO date/timestamp upper bound on ``created_at``.
        """
        params = {
            k: v for k, v in {"kind": kind, "folder": folder, "since": since, "until": until}.items() if v is not None
        }
        resp = await self._request("GET", "/artifact-manager/artifacts", params=params or None)
        return resp.json()["artifacts"]

    async def upload_artifacts(
        self,
        artifacts: list[dict[str, Any]],
        *,
        folder_id: str | None = None,
        new_folder_name: str | None = None,
    ) -> dict[str, Any]:
        """Upload input artifacts (max 20/call, ≤10 MB content each).

        Args:
            artifacts: Each ``{"name": …, "content": …, "format": "paste"|"file",
                "mime": …?}`` — pasted text or base64 file content.
            folder_id: File the uploads into an existing folder.
            new_folder_name: Or create (or reuse) a folder by name.

        Returns:
            ``{"ids": [...], "folderId": ...}`` — the new artifact ids.
        """
        body: dict[str, Any] = {"artifacts": artifacts}
        if folder_id is not None:
            body["folderId"] = folder_id
        if new_folder_name is not None:
            body["newFolderName"] = new_folder_name
        return (await self._request("POST", "/artifact-manager/artifacts", json=body)).json()

    async def get_artifact(self, artifact_id: str) -> dict[str, Any]:
        """One artifact in full, including inline ``content``."""
        resp = await self._request("GET", f"/artifact-manager/artifacts/{path_segment(artifact_id)}")
        return resp.json()["artifact"]

    async def get_artifact_raw(self, artifact_id: str) -> dict[str, Any]:
        """Stream an artifact's content as the raw body — the efficient way to pull
        a multi-MB enrichment report (no JSON re-wrap). Metadata rides ``X-Artifact-*``
        headers.

        Returns:
            ``{"content": str, "id", "kind", "name", "format", "mime", "created_at"}``.
        """
        resp = await self._request(
            "GET",
            f"/artifact-manager/artifacts/{path_segment(artifact_id)}",
            params={"raw": "1"},
        )
        return {
            "content": resp.text,
            "id": resp.headers.get("x-artifact-id", artifact_id),
            "kind": resp.headers.get("x-artifact-kind", ""),
            "name": unquote(resp.headers.get("x-artifact-name", "")),
            "format": resp.headers.get("x-artifact-format", ""),
            "mime": resp.headers.get("x-artifact-mime", ""),
            "created_at": resp.headers.get("x-artifact-created", ""),
        }

    async def update_artifact(
        self,
        artifact_id: str,
        *,
        name: str | None = None,
        favorite: bool | None = None,
        folder_id: str | None = _UNSET,
    ) -> dict[str, Any]:
        """Partial update: rename, star/unstar, and/or move between folders.

        Args:
            name: New display name.
            favorite: Star (``True``) or unstar (``False``).
            folder_id: Target folder UUID, or ``None`` to move back to root.
                Omit entirely to leave the folder unchanged.

        Returns:
            The updated artifact.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if favorite is not None:
            body["favorite"] = favorite
        if folder_id is not _UNSET:
            body["folderId"] = folder_id
        resp = await self._request("PATCH", f"/artifact-manager/artifacts/{path_segment(artifact_id)}", json=body)
        return resp.json()["artifact"]

    async def delete_artifact(self, artifact_id: str) -> bool:
        """Delete one artifact. Returns ``True`` on success (404 raises)."""
        resp = await self._request("DELETE", f"/artifact-manager/artifacts/{path_segment(artifact_id)}")
        return bool(resp.json().get("deleted"))

    async def copy_artifact(self, artifact_id: str) -> str:
        """Duplicate an artifact as "Copy of …". Returns the new artifact id."""
        resp = await self._request("POST", f"/artifact-manager/artifacts/{path_segment(artifact_id)}/copy")
        return resp.json()["id"]

    async def save_enrichment(
        self,
        enrichment_id: str,
        *,
        folder_id: str | None = None,
        new_folder_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist a COMPLETED artifact enrichment into your library, by its engine ``enrichment_id``.

        The programmatic equivalent of the portal's "Save enrichment" button. Run
        :meth:`CrawlerClient.enricher.enrich` (``POST /v1/artifact-enrich`` → poll), then pass the
        returned ``enrichment_id`` here to file the finished report as a ``kind=artifact_enrichment`` artifact on
        your account (or use ``enrich(..., save=True)`` to do both in one call). The engine returns the
        report but never persists it — this is the only way to add it to the Artifact Manager.

        Idempotent: a repeat call for the same enrichment is a no-op (returns ``{already_persisted: True}``).
        Optionally file it into a folder by id (``folder_id``) or create one (``new_folder_name``).
        Usage-exempt. Returns ``{enrichment_artifact_id}`` (or ``{already_persisted: True}``). The completed
        job lives ~1 h after finishing, so save within that window. Raises :class:`UnexpectedStatus` (404
        expired/unknown id, 409 not yet complete).
        """
        body: dict[str, Any] = {"enrichment_id": enrichment_id}
        if folder_id or new_folder_name:
            body["folder"] = {"folder_id": folder_id, "new_folder_name": new_folder_name}
        resp = await self._request("POST", "/artifact-manager/artifacts/from-enrichment", json=body)
        return resp.json()

    # -- Bulk operations ---------------------------------------------------- #

    async def bulk_delete(self, artifact_ids: list[str]) -> int:
        """Delete many artifacts in one call (≤200/call). Returns the number removed."""
        resp = await self._request(
            "POST",
            "/artifact-manager/artifacts/bulk",
            json={"op": "delete", "ids": artifact_ids},
        )
        return int(resp.json()["count"])

    async def move_to_folder(self, artifact_ids: list[str], folder_id: str | None = None) -> int:
        """Move many artifacts into a folder (≤200/call). ``folder_id=None`` un-files
        them to root. Returns the number moved."""
        resp = await self._request(
            "POST",
            "/artifact-manager/artifacts/bulk",
            json={"op": "move", "ids": artifact_ids, "folder_id": folder_id},
        )
        return int(resp.json()["count"])

    async def bulk_set_favorite(self, artifact_ids: list[str], favorite: bool) -> int:
        """Star (``favorite=True``) or unstar (``False``) many artifacts at once
        (≤200/call). Returns the number updated."""
        resp = await self._request(
            "POST",
            "/artifact-manager/artifacts/bulk",
            json={"op": "favorite", "ids": artifact_ids, "favorite": favorite},
        )
        return int(resp.json()["count"])

    async def download_bundle(self, artifact_ids: list[str]) -> bytes:
        """Bundle an explicit set of your artifacts into one ``.zip`` (the bulk "Download .zip"). Enrichments
        contribute their machine exports under a per-enrichment subfolder; every other kind contributes its
        raw deliverable. Returns the raw ``.zip`` bytes; choose and validate the destination path before
        writing it. See :meth:`download_folder` for the whole-folder twin."""
        resp = await self._request("POST", "/artifact-manager/artifacts/bundle", json={"ids": artifact_ids})
        return resp.content

    # -- Scan ratings ------------------------------------------------------- #

    async def get_rating(self, enrichment_id: str) -> dict[str, Any]:
        """Your thumbs rating on an enrichment + the aggregate counts:
        ``{"rating": "up"|"down"|None, "counts": {"up": n, "down": n}}``."""
        return (await self._request("GET", f"/artifact-manager/artifacts/{path_segment(enrichment_id)}/rating")).json()

    async def set_rating(self, enrichment_id: str, rating: Literal["up", "down"] | None) -> dict[str, Any]:
        """Rate an enrichment ``"up"``/``"down"``, or clear your rating with ``None``."""
        resp = await self._request(
            "POST", f"/artifact-manager/artifacts/{path_segment(enrichment_id)}/rating", json={"rating": rating}
        )
        return resp.json()

    # -- Scan exports ------------------------------------------------------- #

    async def list_exports(self, enrichment_id: str) -> list[str]:
        """A saved enrichment's machine-export formats (``stix``, ``misp``, ``csaf``,
        ``vex``, ``csv``, ``navigator``, …)."""
        resp = await self._request("GET", f"/artifact-manager/artifacts/{path_segment(enrichment_id)}/exports")
        return resp.json()["formats"]

    async def get_export(self, enrichment_id: str, format: str) -> dict[str, Any]:  # noqa: A002
        """Download one export. The body IS the export file.

        Text formats (``stix``, ``misp``, ``csaf``, ``vex``, ``csv``, ``navigator``, …) live in
        ``content``; the two **binary XLSX** deliverables (``emass``, ``workbook``) live in ``bytes``
        (``content`` is a best-effort lossy decode — write ``bytes`` to a ``.xlsx`` file instead).

        Returns:
            ``{"content": str, "bytes": bytes, "filename": str, "content_type": str}`` —
            filename is sanitized from ``Content-Disposition`` (``<format>.<ext>``).
        """
        resp = await self._request(
            "GET",
            f"/artifact-manager/artifacts/{path_segment(enrichment_id)}/exports/{path_segment(format)}",
        )
        filename = _safe_download_filename(resp.headers.get("content-disposition", ""), format)
        return {
            "content": resp.text,
            "bytes": resp.content,
            "filename": filename,
            "content_type": resp.headers.get("content-type", ""),
        }

    async def download_all_exports(self, enrichment_id: str) -> bytes:
        """Download EVERY machine export of a saved artifact as one ``.zip`` (one file per format —
        ``stix.json``, ``vex.json``, ``emass.xlsx``, …). The bulk twin of :meth:`get_export`, matching the
        export panel's "Download all (.zip)" button. Works for any saved enrichment / inventory-enrichment
        / inventory id. Returns the raw ``.zip`` bytes; choose and validate the destination path before writing it.
        """
        resp = await self._request("GET", f"/artifact-manager/artifacts/{path_segment(enrichment_id)}/exports/all")
        return resp.content

    # -- Scan compare ------------------------------------------------------- #

    async def compare_enrichments(self, enrichment_ids: list[str]) -> dict[str, Any]:
        """Difference matrix across 2–12 of your saved enrichments (oldest → newest).

        Each matrix row is one finding's trajectory: new / resolved / changed /
        persistent. Returns the ``matrix`` object (``columns``, ``rows``, ``counts``).
        """
        resp = await self._request(
            "GET", "/artifact-manager/enrichment-compare", params={"ids": ",".join(enrichment_ids)}
        )
        return resp.json()["matrix"]

    # -- Folders ------------------------------------------------------------ #

    async def list_folders(self) -> list[dict[str, Any]]:
        """Your folders, each with a live ``artifact_count``."""
        return (await self._request("GET", "/artifact-manager/folders")).json()["folders"]

    async def create_folder(self, name: str) -> str:
        """Create a folder. Returns its id."""
        resp = await self._request("POST", "/artifact-manager/folders", json={"name": name})
        return resp.json()["id"]

    async def rename_folder(self, folder_id: str, name: str) -> dict[str, Any]:
        """Rename a folder."""
        resp = await self._request("PATCH", f"/artifact-manager/folders/{path_segment(folder_id)}", json={"name": name})
        return resp.json()

    async def delete_folder(self, folder_id: str) -> bool:
        """Delete a folder — its artifacts move back to root, never deleted with it."""
        resp = await self._request("DELETE", f"/artifact-manager/folders/{path_segment(folder_id)}")
        return bool(resp.json().get("deleted"))

    async def download_folder(self, folder_id: str) -> bytes:
        """Download every artifact filed under a folder as one ``<folder>.zip`` (the folder "Download .zip").
        Enrichments contribute their machine exports under a per-enrichment subfolder; every other kind
        contributes its raw deliverable. Returns the raw ``.zip`` bytes; choose the destination path before writing."""
        resp = await self._request("GET", f"/artifact-manager/folders/{path_segment(folder_id)}/exports/all")
        return resp.content
