"""Inventory Manager API — key-authed access to YOUR monitored inventory context windows.

The Inventory Manager API lives at ``/inventory-manager/inventories/*`` as its
own section, split out of the Artifact Manager API so the two do not cross-contaminate. A
**inventory** is a continuously-monitored context window: a manual asset inventory + attached reference
artifacts + saved enrichment history, re-enrichable on demand and on a daily schedule.

Same API key, same base URL, same retry transport as every other call — but **inventory-manager calls
never count toward your API usage** (account self-service over your own data), EXCEPT the inventory-enrichment
submit, which is enrichment compute and rides your key to ``/v1/inventory-enrich``.

Responses are plain ``dict``/``list`` JSON. Exposed as :attr:`CrawlerClient.inventory_manager`.

Example::

    async with CrawlerClient() as client:
        proj = await client.inventory_manager.create_inventory(
            "Prod web tier",
            items=[{"product": "nginx", "vendor": "f5", "versions": ["1.25.0"]}],
            monitoring=True,
        )
        result = await client.inventory_manager.enrich_inventory(proj["id"])  # submit → poll → report
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from ._poll import ProgressCallback, poll_until_done
from ._url import path_segment
from .exceptions import UnexpectedStatus


def _wire_content(content: str | bytes) -> str:
    """Wire form of a scan/inventory file's content. Text formats pass through as a string; the BINARY
    ``xlsx`` format is read as ``bytes`` and base64-encoded (the server decodes it for ``format='xlsx'``)."""
    if isinstance(content, (bytes, bytearray)):
        return base64.b64encode(bytes(content)).decode("ascii")
    return content


def _wire_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Wire form of a multi-source combine: base64 each source's ``content`` if it's ``bytes`` (xlsx)."""
    out: list[dict[str, Any]] = []
    for s in sources:
        wired = dict(s)
        if "content" in wired:
            wired["content"] = _wire_content(wired["content"])
        out.append(wired)
    return out


if TYPE_CHECKING:
    import httpx


def _inventory_body(
    inventory_name: str,
    description: Any,
    items: Any,
    monitoring: Any,
    linked_artifact_ids: Any,
) -> dict[str, Any]:
    """Build the create/update-inventory request body — inventory_name is required; other fields ride only
    when provided. Shared by create_inventory / update_inventory (and the read-modify-write convenience
    methods) so the full editable field set stays in one place."""
    body: dict[str, Any] = {"inventory_name": inventory_name}
    for key, val in (
        ("description", description),
        ("items", items),
        ("monitoring", monitoring),
        ("linked_artifact_ids", linked_artifact_ids),
    ):
        if val is not None:
            body[key] = val
    return body


class InventoryManagerAPI:
    """Client for the key-authed Inventory Manager API.

    Obtained via :attr:`CrawlerClient.inventory_manager` — never constructed directly.
    Every method raises :class:`UnexpectedStatus` on a non-2xx response.
    """

    def __init__(self, http: httpx.AsyncClient) -> None:
        # The CrawlerClient's configured httpx client: base_url, apikey header,
        # timeout, and the retry transport all already apply.
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
            raise UnexpectedStatus(
                resp.status_code, resp.content, f"Inventory Manager API {resp.status_code} on {path}"
            )
        return resp

    # -- Inventories (context windows) ----------------------------------------- #

    async def list_inventories(self) -> list[dict[str, Any]]:
        """List your Inventory Manager inventories — each a continuously-monitored context window
        (asset inventory + attached artifacts + saved enrichment history). Newest first, no content."""
        resp = await self._request("GET", "/inventory-manager/inventories")
        return resp.json()["inventories"]

    async def get_inventory(self, inventory_id: str) -> dict[str, Any]:
        """One inventory as a manifest: ``{inventory_name, description, monitoring, inventory[],
        attached[], enrichments[]}``. Pull specific artifacts/enrichments via the Artifact Manager API."""
        return (await self._request("GET", f"/inventory-manager/inventories/{path_segment(inventory_id)}")).json()

    async def get_inventory_context(self, inventory_id: str) -> dict[str, Any]:
        """An inventory as a **one-shot, LLM-ready context window** — a single bounded text bundle
        (inventory + latest-enrichment findings + what changed + attached excerpts). Returns
        ``{id, name, inventory_name, description, monitoring, stats, context}`` where ``context`` is
        the ready-to-use text."""
        return (
            await self._request(
                "GET",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/context",
            )
        ).json()

    async def list_enrichments(self, inventory_id: str) -> list[dict[str, Any]]:
        """List an inventory's saved enrichment history — the inventory's ``inventory_enrichment`` artifacts
        (newest first, no content; each row's ``meta`` carries the card stats: asset/CVE/KEV counts,
        scanned-at, monitoring delta). The data behind the UI's "Previous enrichments" strip."""
        resp = await self._request("GET", f"/inventory-manager/inventories/{path_segment(inventory_id)}/enrichments")
        return resp.json()["enrichments"]

    async def compare_enrichments(self, enrichment_ids: list[str]) -> dict[str, Any]:
        """CVE-matched difference matrix across 2–12 of your saved INVENTORY enrichments (oldest → newest).

        The inventory counterpart of ``client.artifact_manager.compare_enrichments``: each matrix row is one
        CVE's trajectory — new / resolved / changed / persistent — across the selected inventory enrichments,
        with its weaponization band / CVSS / KEV state per enrichment. Returns the ``matrix`` object
        (``columns``, ``rows``, ``counts``).
        """
        resp = await self._request(
            "GET", "/inventory-manager/inventories/compare", params={"ids": ",".join(enrichment_ids)}
        )
        return resp.json()["matrix"]

    async def create_inventory(
        self,
        inventory_name: str,
        *,
        description: str | None = None,
        items: list[dict[str, Any]] | None = None,
        monitoring: bool | None = None,
        linked_artifact_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create an Inventory Manager inventory (a continuously-monitored context window).

        Args:
            inventory_name: The inventory's display name.
            description: Optional free-text description.
            items: The asset inventory — each ``{"product": …, "vendor"?, "versions"?,
                "ecosystem"?, "category"?, "criticality"?, "notes"?, "exposure"?,
                "environment"?, "owner"?, "tags"?}``.
            monitoring: Enable scheduled re-enrichments (always full depth — there is no fast/lite mode).
            linked_artifact_ids: Attached reference-artifact ids (the inventory's context window).

        Returns:
            ``{"id": …, "item_count": …}``.
        """
        return (
            await self._request(
                "POST",
                "/inventory-manager/inventories",
                json=_inventory_body(
                    inventory_name,
                    description,
                    items,
                    monitoring,
                    linked_artifact_ids,
                ),
            )
        ).json()

    async def update_inventory(
        self,
        inventory_id: str,
        *,
        inventory_name: str,
        description: str | None = None,
        items: list[dict[str, Any]] | None = None,
        monitoring: bool | None = None,
        linked_artifact_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update an inventory's definition (name, description, inventory, monitoring, attachments). This is
        a **partial merge** (PATCH): only the fields you pass change — omitted fields are PRESERVED,
        including the asset-group metadata and daily-report config this method doesn't expose.
        ``inventory_name`` is still required by the API. Returns ``{"id": …, "item_count": …}``.
        """
        return (
            await self._request(
                "PATCH",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}",
                json=_inventory_body(inventory_name, description, items, monitoring, linked_artifact_ids),
            )
        ).json()

    async def import_inventory(
        self,
        *,
        fmt: str,
        content: str | bytes,
        inventory_name: str | None = None,
        description: str | None = None,
        inventory_id: str | None = None,
        mode: str = "replace",
    ) -> dict[str, Any]:
        """Import an asset-inventory file (you PICK the format — no auto-detect).

        With no ``inventory_id`` this CREATES a new inventory. With ``inventory_id`` it imports the file's
        assets INTO that existing inventory — ``mode="replace"`` (default) swaps the inventory,
        ``mode="append"`` adds to it — PRESERVING the inventory's attachments / monitoring / alert-prefs.

        Args:
            fmt: The file format — one of ``json`` (asset JSON), ``sbom`` (CycloneDX / SPDX SBOM),
                ``csv`` (spreadsheet), ``nmap`` (nmap ``-sV`` XML), ``list`` (CPE / purl list),
                ``grype``, ``trivy`` (SCA scanner JSON), ``depcheck`` (OWASP Dependency-Check JSON),
                ``nessus`` (``.nessus`` XML), ``gvm`` (OpenVAS / Greenbone XML),
                ``xlsx`` (Excel spreadsheet — pass the file as ``bytes``).
            content: The file's text content — or ``bytes`` for the binary ``xlsx`` format (base64-encoded
                for you on the wire).
            inventory_name: Optional inventory name (overrides anything the file carries).
            description: Optional description (overrides the file's).
            inventory_id: Import INTO this existing inventory instead of creating a new one.
            mode: ``replace`` (default) or ``append`` — only used with ``inventory_id``.

        Returns:
            Create → ``{"id", "item_count", "imported", "format", "truncated"?}``;
            into existing → ``{"id", "item_count", "imported", "format", "replaced": True, "mode"}``.
        """
        body: dict[str, Any] = {"format": fmt, "content": _wire_content(content)}
        if inventory_name is not None:
            body["inventory_name"] = inventory_name
        if description is not None:
            body["description"] = description
        if inventory_id is not None:
            body["inventory_id"] = inventory_id
            body["mode"] = mode
        return (await self._request("POST", "/inventory-manager/inventories/import", json=body)).json()

    async def parse_multi(self, sources: list[dict[str, Any]]) -> dict[str, Any]:
        """Parse + COMBINE SEVERAL scan / inventory files into ONE deduped asset set WITHOUT saving (the
        multi-source twin of :meth:`parse_scan`). Stage a CSV of laptops + an nmap scan + an SBOM and merge
        them; duplicate assets are deduped across sources, versions + named groups are unioned, the set is
        capped at 200.

        Args:
            sources: A list of ``{"content": str | bytes, "format"?: <one of the 11>, "label"?: str}``. The
                ``format`` is **optional** — omit it and the file's format is auto-detected from its content
                (+ ``label`` as a filename hint); pin a ``format`` only to override detection. A binary
                ``xlsx`` source can't be sniffed, so it needs ``"format": "xlsx"`` + ``bytes`` content
                (base64-encoded on the wire). A source that fails to parse is ISOLATED (it appears in
                ``per_source`` with its ``error`` and contributes nothing — never failing the whole call).

        Returns:
            ``{"items", "count", "asset_groups", "truncated"?, "per_source": [{"label", "contributed",
            "truncated"?, "error"?}]}``. Usage-exempt.
        """
        return (
            await self._request(
                "POST",
                "/inventory-manager/inventories/parse-multi",
                json={"sources": _wire_sources(sources)},
            )
        ).json()

    async def import_multi(
        self,
        sources: list[dict[str, Any]],
        *,
        inventory_name: str | None = None,
        description: str | None = None,
        inventory_id: str | None = None,
        mode: str = "replace",
    ) -> dict[str, Any]:
        """Import + COMBINE SEVERAL files into ONE inventory in a single call (the multi-source twin of
        :meth:`import_inventory`). Each source is parsed in isolation then merged via the same dedup brain as
        :meth:`parse_multi`. With no ``inventory_id`` this CREATES a new inventory; with ``inventory_id`` the
        combined assets go INTO it (``mode`` ``replace`` / ``append``), preserving its attachments / monitoring.

        Args:
            sources: ``[{"format", "content": str | bytes, "label"?}]`` — see :meth:`parse_multi`.
            inventory_name / description: Optional overrides for the created inventory.
            inventory_id / mode: Import the combined set INTO an existing inventory (replace / append).

        Returns:
            Create → ``{"id", "item_count", "imported", "format": "multi", "multi": True, "per_source", ...}``;
            into existing → ``{..., "replaced": True, "mode"}``.
        """
        body: dict[str, Any] = {"sources": _wire_sources(sources)}
        if inventory_name is not None:
            body["inventory_name"] = inventory_name
        if description is not None:
            body["description"] = description
        if inventory_id is not None:
            body["inventory_id"] = inventory_id
            body["mode"] = mode
        return (await self._request("POST", "/inventory-manager/inventories/import", json=body)).json()

    async def replace_assets(self, inventory_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        """REPLACE an inventory's asset inventory, PRESERVING its name / description / attached artifacts /
        monitoring / alert-prefs (the safe alternative to :meth:`update_inventory`, which resets omitted
        fields). To edit ONE field of ONE asset: :meth:`get_inventory`, change the item in ``inventory``,
        and replace it back. Each item is the usual asset dict. Returns ``{"id", "item_count", "mode"}``.
        """
        return (
            await self._request(
                "PATCH",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/assets",
                json={"items": items, "mode": "replace"},
            )
        ).json()

    async def add_assets(self, inventory_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        """APPEND assets to an inventory's inventory, preserving everything else. Returns
        ``{"id", "item_count", "mode"}``."""
        return (
            await self._request(
                "PATCH",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/assets",
                json={"items": items, "mode": "append"},
            )
        ).json()

    async def apply_asset_fix(
        self,
        inventory_id: str,
        product: str,
        version: str,
        vendor: str | None = None,
    ) -> dict[str, Any]:
        """Apply a recommended upgrade — set the matched asset's version to the published fix the
        Inventory Enricher surfaced (``recommended_fix_version`` / ``recommended_fix_version_kev``),
        PRESERVING everything else on the inventory. Match is by ``product`` (case-insensitive;
        ``vendor`` disambiguates duplicate product names). It writes the inventory only — it does NOT
        re-enrich; the next enrichment / daily monitor confirms the CVEs cleared. Returns
        ``{"id", "product", "version", "item_count"}`` (404 when no asset matches the product).
        """
        body: dict[str, Any] = {"product": product, "version": version}
        if vendor is not None:
            body["vendor"] = vendor
        return (
            await self._request(
                "PATCH",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/asset-version",
                json=body,
            )
        ).json()

    async def list_export_formats(self, inventory_id: str) -> list[dict[str, Any]]:
        """List an inventory's asset-inventory export formats (``json`` / ``csv`` / ``cyclonedx`` / ``spdx``)."""
        return (
            await self._request(
                "GET",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/export",
            )
        ).json()["formats"]

    async def export_inventory(self, inventory_id: str, fmt: str = "json") -> str | bytes:
        """Export an inventory's asset inventory as a file — the returned value IS the file.

        Returns ``str`` for the text formats and ``bytes`` for the binary ``workbook`` (write those
        straight to a ``.xlsx`` file).

        Args:
            inventory_id: The inventory id.
            fmt: ``json`` / ``csv`` / ``list`` (CPE/purl) / ``cyclonedx`` / ``spdx`` (3.0.1) /
                ``spdx2`` (SPDX 2.3) / ``workbook`` (binary Excel .xlsx). ``json`` / ``csv`` / ``list``
                round-trip back through :meth:`import_inventory`.
        """
        resp = await self._request(
            "GET",
            f"/inventory-manager/inventories/{path_segment(inventory_id)}/export/{path_segment(fmt)}",
        )
        return resp.content if fmt == "workbook" else resp.text

    async def delete_inventory(self, inventory_id: str) -> bool:
        """Delete an inventory. Returns ``True`` on success (404 raises)."""
        resp = await self._request("DELETE", f"/inventory-manager/inventories/{path_segment(inventory_id)}")
        return bool(resp.json().get("deleted"))

    async def attach_to_inventory(self, inventory_id: str, artifact_id: str) -> dict[str, Any]:
        """Link an existing artifact to an inventory. Returns
        ``{"ok": …, "linked": …, "already": …}``."""
        resp = await self._request(
            "POST",
            f"/inventory-manager/inventories/{path_segment(inventory_id)}/attach",
            json={"artifactId": artifact_id},
        )
        return resp.json()

    async def detach_from_inventory(self, inventory_id: str, artifact_id: str) -> dict[str, Any]:
        """Remove one attached artifact from an inventory (the inverse of :meth:`attach_to_inventory`).

        Atomic server-side operation that preserves every other field. Idempotent (detaching an
        unlinked id is a no-op). Returns ``{"ok": …, "linked": …, "removed": …}``.
        """
        resp = await self._request(
            "POST",
            f"/inventory-manager/inventories/{path_segment(inventory_id)}/detach",
            json={"artifactId": artifact_id},
        )
        return resp.json()

    async def set_attachments(self, inventory_id: str, artifact_ids: list[str]) -> dict[str, Any]:
        """REPLACE an inventory's attached reference artifacts in one call (the bulk twin of
        :meth:`attach_to_inventory`), PRESERVING the inventory's inventory / monitoring / alert-prefs.
        Only attachable kinds (``input`` / ``enrichment`` / ``report``) are kept; inventories and inventory enrichments
        are skipped. Deduped + capped at 100. Returns ``{"id", "linked_count", "attached", "skipped", "mode"}``.
        """
        return (
            await self._request(
                "PATCH",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/attachments",
                json={"artifact_ids": artifact_ids, "mode": "replace"},
            )
        ).json()

    async def add_attachments(self, inventory_id: str, artifact_ids: list[str]) -> dict[str, Any]:
        """APPEND several artifacts to an inventory's attachments in one call (bulk
        :meth:`attach_to_inventory`), preserving everything else. Same filtering/cap/return as
        :meth:`set_attachments`."""
        return (
            await self._request(
                "PATCH",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/attachments",
                json={"artifact_ids": artifact_ids, "mode": "append"},
            )
        ).json()

    async def set_monitoring(self, inventory_id: str, *, monitoring: bool) -> dict[str, Any]:
        """Toggle an inventory's daily monitoring (= daily enrichment). Routes through the automation endpoint
        (partial read-modify-write) so assets, attachments, asset groups, AND the daily-report config are
        all preserved. Enrichments always run at full depth. Returns ``{"id": …, "automation": {…}}``."""
        return await self.set_automation(inventory_id, monitoring=monitoring)

    async def set_favorite(self, inventory_id: str, favorite: bool = True) -> dict[str, Any]:
        """Star (``favorite=True``) or unstar (``False``) an inventory — the same ★ the inventory cards show.
        A favorite-only PATCH that leaves the asset inventory / attachments / monitoring / automation
        untouched. The list (``list_inventories``) + manifest (``get_inventory``) echo ``favorite`` back.
        Usage-exempt. Returns ``{"id": …, "favorite": …}``."""
        return (
            await self._request(
                "PATCH", f"/inventory-manager/inventories/{path_segment(inventory_id)}", json={"favorite": favorite}
            )
        ).json()

    async def get_automation(self, inventory_id: str) -> dict[str, Any]:
        """Read an inventory's DAILY-AUTOMATION config (the programmatic twin of the Automation modal):
        ``{monitoring, daily_enrichment_email, daily_report, daily_report_email,
        daily_report_template, daily_enrichment_next_run_at, custom_template_pinned}``. It is ONE pipeline
        on ONE timer: ``daily_enrichment_next_run_at`` is the epoch-ms countdown to the next run (null when
        monitoring is off); the daily report rides the same pipeline (right after the enrichment) and has no
        timer of its own. Usage-exempt."""
        return (
            await self._request(
                "GET",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/automation",
            )
        ).json()

    async def set_automation(
        self,
        inventory_id: str,
        *,
        monitoring: bool | None = None,
        daily_enrichment_email: bool | None = None,
        daily_report: bool | None = None,
        daily_report_email: bool | None = None,
        daily_report_template: str | None = None,
    ) -> dict[str, Any]:
        """Manage an inventory's daily automation — set ONLY the fields you pass (partial read-modify-write,
        preserving assets/attachments). ``monitoring`` = the daily enrichment; ``daily_report`` = ALSO
        generate a Report-Generator report from ``daily_report_template`` (a built-in template id, e.g.
        ``project_brief``) right after each daily enrichment, off its fresh findings. ONE pipeline:
        ``daily_report`` REQUIRES ``monitoring`` — enabling it while monitoring is off raises a 400
        (``UnexpectedStatus``); turning monitoring off cascades the report off. Each job's ``*_email`` toggle
        controls whether it emails the owner. The pipeline runs on the owner's key when the daily cron fires
        (the enrichment counts toward usage then). Returns ``{"id", "automation"}``. Usage-exempt (config)."""
        body: dict[str, Any] = {}
        if monitoring is not None:
            body["monitoring"] = monitoring
        if daily_enrichment_email is not None:
            body["daily_enrichment_email"] = daily_enrichment_email
        if daily_report is not None:
            body["daily_report"] = daily_report
        if daily_report_email is not None:
            body["daily_report_email"] = daily_report_email
        if daily_report_template is not None:
            body["daily_report_template"] = daily_report_template
        return (
            await self._request(
                "PUT",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/automation",
                json=body,
            )
        ).json()

    async def enrich_inventory(
        self,
        inventory_id: str,
        *,
        include: list[str] | None = None,
        poll_interval: float = 3.0,
        timeout: float = 300.0,
        on_progress: ProgressCallback | None = None,
        save: bool = False,
        enrich_attachments: bool | None = None,
    ) -> dict[str, Any]:
        """Enrich an inventory's inventory end-to-end against the /v1 engine: submit → poll → return the report.

        Reads the inventory's asset inventory (``GET /inventory-manager/inventories/{id}``), submits those
        assets to the Threat Inventory Enricher (``POST /v1/inventory-enrich``, always full depth — there is no
        fast/lite mode), polls until done, and returns the enrichment report.

        The enrichment submit is enrichment compute and **counts toward your usage** (it rides your key to
        ``/v1/inventory-enrich``); reading the inventory and polling do not.

        ``on_progress`` (optional, sync or async) is called with the live job dict on every poll —
        ``{status, progress, stages, events}`` (each ``events[]`` line carries the overall % it reached,
        streaming a ``✓ {CVE}`` line per CVE) — so you can render a live bar / feed. Polls are exempt.

        ``save=True`` files the finished enrichment into this inventory's saved history after it completes
        (the ``/v1`` engine returns the report but never persists it) — the one-call equivalent of running
        the enrichment then calling :meth:`save_enrichment`. When saved, the returned dict also carries
        ``saved`` (the ``{artifact_id}`` save response). Saving is usage-exempt.

        ``enrich_attachments`` controls the inventory's **"artifact scans"** — when on, the inventory's
        attached artifacts are resolved + projected to text and sent so the engine ALSO runs a mini Artifact
        Enrichment over them (references surface on the report's ``attachment_enrichment``). ``None`` (default)
        honors the inventory's saved toggle; pass ``True``/``False`` to force it for this run.

        Returns ``{enrichment_id, report}``. If the inventory's inventory is empty this short-circuits and
        returns ``{"enrichment_id": None, "empty": True}`` without submitting. Raises
        :class:`UnexpectedStatus` on a non-2xx (or enrichment error), or :class:`TimeoutError` if the
        enrichment doesn't finish within ``timeout`` seconds.
        """
        manifest = await self.get_inventory(inventory_id)
        items = manifest.get("inventory") or []
        if not items:
            return {"enrichment_id": None, "empty": True}
        do_attach = bool(manifest.get("enrich_attachments")) if enrich_attachments is None else enrich_attachments
        attachments_text: str | None = None
        attachments_files: list[dict[str, str]] = []
        if do_attach:
            ids = [
                attachment_id
                for attachment in (manifest.get("attached") or [])
                if isinstance(attachment, dict) and (attachment_id := attachment.get("id"))
            ]
            attachments_text, attachments_files = await self._resolve_attachments(ids)
        result = await self.enrich_items(
            items,
            include=include,
            poll_interval=poll_interval,
            timeout=timeout,
            on_progress=on_progress,
            attachments_text=attachments_text,
            attachments_files=attachments_files,
        )
        if save and result.get("enrichment_id"):
            result["saved"] = await self.save_enrichment(inventory_id, result["enrichment_id"])
        return result

    async def _resolve_attachments(self, attachment_ids: list[str]) -> tuple[str | None, list[dict[str, str]]]:
        """Fetch the inventory's attached artifacts (≤20) and split them for the engine: TEXT artifacts are
        concatenated into ``attachments_text``; BINARY ones (``X-Artifact-Format: file`` — spreadsheets, PDF,
        scan XML) are forwarded RAW (their stored base64) as ``attachments_files`` so the engine's parsers
        mine them — no SDK-side binary extraction needed. Best-effort; per-text-attachment ≤80 KB, text total
        ≤500 KB, files ≤20."""
        parts: list[str] = []
        files: list[dict[str, str]] = []
        total = 0
        for aid in attachment_ids[:20]:
            try:
                resp = await self._http.request(
                    "GET",
                    f"/artifact-manager/artifacts/{path_segment(aid)}",
                    params={"raw": "1"},
                )
                if not 200 <= resp.status_code < 300:
                    continue
                content = resp.text
                if not content:
                    continue
                name = unquote(resp.headers.get("X-Artifact-Name", "") or aid)
                if resp.headers.get("X-Artifact-Format", "") == "file":  # binary → forward to the engine's parsers
                    if len(files) < 20:
                        files.append({"filename": name, "content_b64": content})
                    continue
                chunk = content[:80_000]
                parts.append(f"--- Attached: {name} ---\n{chunk}")
                total += len(chunk)
                if total >= 400_000:
                    break
            except Exception:  # noqa: BLE001 — attachment resolution is best-effort
                continue
        text = "\n\n".join(parts)
        return (text[:500_000] if text.strip() else None, files)

    async def save_enrichment(self, inventory_id: str, enrichment_id: str) -> dict[str, Any]:
        """Persist a COMPLETED inventory enrichment into this inventory's saved history, by its engine
        ``enrichment_id``.

        The programmatic equivalent of the workbench's "Save enrichment" button. Run
        :meth:`enrich_inventory` (``POST /v1/inventory-enrich`` → poll), then pass the returned
        ``enrichment_id`` here to file the finished findings as a ``kind=inventory_enrichment`` artifact linked
        to the inventory (or use ``enrich_inventory(..., save=True)`` to do both in one call). The engine
        returns the report but never persists it — this is the only way to add it to the inventory's
        history. Idempotent (a repeat returns ``{ok: True, deduped: True}``). Usage-exempt. Returns
        ``{artifact_id}``. The completed job lives ~1 h after finishing, so save within that window. Raises
        :class:`UnexpectedStatus` (404 expired/unknown id or non-asset inventory, 409 not yet complete).
        """
        return (
            await self._request(
                "POST",
                f"/inventory-manager/inventories/{path_segment(inventory_id)}/enrichments",
                json={"enrichment_id": enrichment_id},
            )
        ).json()

    async def enrich_items(
        self,
        items: list[dict[str, Any]],
        *,
        include: list[str] | None,
        poll_interval: float,
        timeout: float,
        on_progress: ProgressCallback | None = None,
        attachments_text: str | None = None,
        attachments_files: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Submit a raw asset list to the ``/v1/inventory-enrich`` engine, poll until done, and return
        ``{enrichment_id, report}``. The shared submit→poll core behind :meth:`enrich_inventory` and the
        scan-ingest workflow. ``on_progress`` streams the live job each poll. ``attachments_text`` +
        ``attachments_files`` (optional) drive the engine's mini Artifact-Enricher stage over the inventory's
        attached artifacts (text-rendered + raw binary files the engine parses). Raises
        :class:`UnexpectedStatus` on a non-2xx / engine error, or :class:`TimeoutError` on the deadline."""
        body: dict[str, Any] = {"items": items}
        if include:
            body["include"] = include
        if attachments_text:
            body["attachments_text"] = attachments_text
        if attachments_files:
            body["attachments_files"] = attachments_files
        enrichment_id = (await self._request("POST", "/v1/inventory-enrich", json=body)).json()["enrichment_id"]
        job = await poll_until_done(
            self._request,
            enrichment_id,
            f"/v1/inventory-enrich/{path_segment(enrichment_id)}",
            poll_interval=poll_interval,
            timeout=timeout,
            on_progress=on_progress,
        )
        return {"enrichment_id": enrichment_id, "report": job.get("result")}

    async def parse_scan(self, content: str | bytes, scan_format: str) -> dict[str, Any]:
        """Parse a scan / inventory FILE into canonical asset items WITHOUT saving anything (the parse-only
        twin of :meth:`import_inventory`). You PICK the ``scan_format`` — one of ``json``/``sbom``/``csv``/
        ``nmap``/``list``/``grype``/``trivy``/``depcheck``/``nessus``/``gvm``/``xlsx`` (no auto-detect; pass
        ``bytes`` for the binary ``xlsx``). Returns ``{format, items, count, inventory_name?, truncated?}``.
        Usage-exempt — the building block for :meth:`ingest_scan`."""
        return (
            await self._request(
                "POST",
                "/inventory-manager/inventories/parse",
                json={"format": scan_format, "content": _wire_content(content)},
            )
        ).json()

    async def ingest_scan(
        self,
        content: str | bytes,
        scan_format: str,
        *,
        include: list[str] | None = None,
        poll_interval: float = 3.0,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """Scan → briefing in one call: parse the scan FILE (``parse_scan``), enrich the discovered assets
        against the ``/v1/inventory-enrich`` ranking engine, and assemble a structured briefing.

        ``scan_format`` is one of ``json``/``sbom``/``csv``/``nmap``/``list``/``grype``/``trivy``/``depcheck``/
        ``nessus``/``gvm``/``xlsx`` (pass ``bytes`` for the binary ``xlsx``).
        The parse is usage-exempt; the enrichment **submit counts toward your usage** (one
        ``/v1/inventory-enrich`` request — far cheaper than enriching each product separately). Returns
        ``{format, parsed_count, truncated?, enrichment_id, report, recommended_actions}`` where ``report`` is
        the engine's KEV-first-ranked findings + rollup and ``recommended_actions`` is the top prioritized
        CVEs. An empty parse short-circuits to ``{format, parsed_count: 0, enrichment_id: None, empty: True}``.
        Raises :class:`UnexpectedStatus` / :class:`TimeoutError` like :meth:`enrich_inventory`."""
        from .ingest import ingest_scan as _run_ingest  # the shared scan-ingest component

        return await _run_ingest(
            self,
            content,
            scan_format,
            include=include,
            poll_interval=poll_interval,
            timeout=timeout,
        )
