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
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from ._poll import ProgressCallback, poll_until_done, validate_poll_options
from ._url import path_segment
from .exceptions import UnexpectedStatus
from .tlp import Tlp, validate_tlp


def _manifest_vex_overlay(manifest: dict[str, Any]) -> str | None:
    """The inventory manifest's attached VEX overlay document text (``vex_overlay.document`` from
    ``GET /inventory-manager/inventories/{id}``), or ``None`` when no overlay is attached."""
    overlay = manifest.get("vex_overlay")
    if not isinstance(overlay, dict):
        return None
    doc = overlay.get("document")
    return doc if isinstance(doc, str) and doc.strip() else None


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


def _history_params(
    *,
    types: list[str] | str | None,
    q: str | None,
    since: str | None,
    until: str | None,
    actor: str | None,
    limit: int | None,
    cursor: str | None,
) -> dict[str, Any]:
    """Query string for ``GET …/history``. ``types`` is a list or a ready comma-separated string; ``None``
    fields are omitted so the server applies its own defaults."""
    joined = types if isinstance(types, str) else (",".join(types) if types else None)
    params = {
        "type": joined,
        "q": q,
        "since": since,
        "until": until,
        "actor": actor,
        "limit": limit,
        "cursor": cursor,
    }
    return {k: v for k, v in params.items() if v is not None}


class InventoryManagerAPI:
    """Client for the key-authed Inventory Manager API.

    Obtained via :attr:`CrawlerClient.inventory_manager` — never constructed directly.
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
        timeout: float | None = None,
    ) -> httpx.Response:
        kwargs: dict[str, Any] = {"params": params, "json": json}
        if timeout is not None:
            kwargs["timeout"] = timeout
        resp = await self._http.request(method, path, **kwargs)
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
        """An inventory as a one-shot, bounded context bundle with artifact provenance and delimiters.

        Returns ``{id, name, inventory_name, description, monitoring, stats, context}``. ``context`` starts
        with a safe prompt preamble that labels the enclosed inventory and artifact text as untrusted data.
        """
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

    async def get_history(
        self,
        inventory_id: str,
        *,
        types: list[str] | str | None = None,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """One page of an inventory's change history, newest first: ``{items, next_cursor}``.

        Covers asset, attachment, TLP, rename, settings and VEX changes, saved enrichments and generated
        reports. ``types`` filters by event type, ``q`` searches the summary, ``actor`` is ``you`` /
        ``daily monitor`` / ``api``, ``since`` / ``until`` are ISO dates, and ``cursor`` continues from a
        previous page's ``next_cursor``. Exports and Copy for AI are not logged.
        """
        resp = await self._request(
            "GET",
            f"/inventory-manager/inventories/{path_segment(inventory_id)}/history",
            params=_history_params(types=types, q=q, since=since, until=until, actor=actor, limit=limit, cursor=cursor),
        )
        return resp.json()

    async def iter_history(
        self,
        inventory_id: str,
        *,
        types: list[str] | str | None = None,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield every history item newest first, following ``next_cursor`` across pages until exhausted."""
        cursor: str | None = None
        while True:
            page = await self.get_history(
                inventory_id,
                types=types,
                q=q,
                since=since,
                until=until,
                actor=actor,
                limit=limit,
                cursor=cursor,
            )
            for item in page["items"]:
                yield item
            cursor = page.get("next_cursor")
            if not cursor:
                return

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
                "environment"?, "owner"?, "tags"?}``; optionally its OT context —
                ``{"asset_class"?, "purdue_level"?, "protocols"?, "firmware_version"?,
                "hardware_version"?, "safety_critical"?}`` (all caller-supplied, never inferred).
            monitoring: Enable scheduled re-enrichments (always full depth — there is no fast/lite mode).
            linked_artifact_ids: Attached reference-artifact ids (the inventory's context window). Each of
                these takes the new inventory's own TLP 2.0 marking.

        Returns:
            ``{"id": …, "item_count": …}``, plus ``attachment_tlp`` / ``attachment_tlp_ids`` when linked
            artifacts were passed (the marking carried onto them).
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
        ``inventory_name`` is still required by the API. Any artifact newly added through
        ``linked_artifact_ids`` takes the inventory's own TLP 2.0 marking (already-attached artifacts are
        left alone). Returns ``{"id": …, "item_count": …}``, plus ``attachment_tlp`` /
        ``attachment_tlp_ids`` (the marking carried onto newly attached artifacts).
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
                ``xlsx`` (Excel spreadsheet — pass the file as ``bytes``), or ``vex`` (a VEX
                suppression overlay — OpenVEX 0.2.0 / CSAF 2.0 VEX JSON. Unlike the asset formats it
                imports NO assets: it attaches the overlay to an existing inventory when
                ``inventory_id`` is given (or creates a bare inventory holding it), and the Inventory
                Enricher then marks matching not_affected/fixed findings suppressed instead of
                re-reporting them).
            content: The file's text content — or ``bytes`` for the binary ``xlsx`` format (base64-encoded
                for you on the wire).
            inventory_name: Optional inventory name (overrides anything the file carries).
            description: Optional description (overrides the file's).
            inventory_id: Import INTO this existing inventory instead of creating a new one.
            mode: ``replace`` (default) or ``append`` — only used with ``inventory_id``.

        Returns:
            Create → ``{"id", "item_count", "imported", "format", "truncated"?, "dropped"?}``;
            into existing → ``{"id", "item_count", "imported", "format", "replaced": True, "mode"}``.
            ``dropped`` (SBOM imports only) counts dependency edges the parser could not retain (#334).
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
            ``{"items", "count", "asset_groups", "truncated"?, "dropped"?, "per_source": [{"label", "contributed",
            "truncated"?, "dropped"?, "error"?}]}``. Usage-exempt.
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
        group: str | None = None,
    ) -> dict[str, Any]:
        """Apply a recommended upgrade — set the matched asset's version to the published fix the
        Inventory Enricher surfaced (``recommended_fix_version`` / ``recommended_fix_version_kev``),
        PRESERVING everything else on the inventory. Match is by ``product`` (case-insensitive;
        ``vendor`` disambiguates duplicate product names). This rewrites **every** asset carrying that
        product — pass ``group`` to scope the fix to one host/asset group (``group`` is the asset's own
        grouping, which host-derived imports set per host). It writes the inventory only — it does NOT
        re-enrich; the next enrichment / daily monitor confirms the CVEs cleared. Returns
        ``{"id", "product", "version", "applied", "item_count"}`` (404 when no asset matches the
        product, or no asset matches within ``group``).
        """
        body: dict[str, Any] = {"product": product, "version": version}
        if vendor is not None:
            body["vendor"] = vendor
        if group is not None:
            body["group"] = group
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

    async def export_inventory(self, inventory_id: str, fmt: str = "json", *, tlp: Tlp | None = None) -> str | bytes:
        """Export an inventory's asset inventory as a file — the returned value IS the file.

        Returns ``str`` for the text formats and ``bytes`` for the binary ``workbook`` (write it straight
        to a ``.xlsx`` file) and ``all`` (every format as one ``.zip``).

        Args:
            inventory_id: The inventory id.
            fmt: ``json`` / ``csv`` / ``list`` (CPE/purl) / ``cyclonedx`` / ``spdx`` (3.0.1) /
                ``spdx2`` (SPDX 2.3) / ``workbook`` (binary Excel .xlsx) / ``all`` (.zip of every format).
                ``json`` / ``csv`` / ``list`` round-trip back through :meth:`import_inventory`.
            tlp: Optional TLP 2.0 marking written into every format that has a marking slot —
                ``cyclonedx`` / ``spdx`` / ``spdx2`` / ``workbook`` (``CLEAR`` / ``GREEN`` / ``AMBER`` /
                ``AMBER+STRICT`` / ``RED``), overriding the inventory's stored TLP. Omit it to stamp
                the inventory's own stored TLP. ``json`` / ``csv`` / ``list`` have no
                slot and ignore it. An invalid value raises :class:`ValueError` before any request.
        """
        resp = await self._request(
            "GET",
            f"/inventory-manager/inventories/{path_segment(inventory_id)}/export/{path_segment(fmt)}",
            params={"tlp": validate_tlp(tlp)} if tlp is not None else None,
        )
        return resp.content if fmt in ("workbook", "all") else resp.text

    async def delete_inventory(self, inventory_id: str) -> bool:
        """Delete an inventory. Returns ``True`` on success (404 raises)."""
        resp = await self._request("DELETE", f"/inventory-manager/inventories/{path_segment(inventory_id)}")
        return bool(resp.json().get("deleted"))

    async def attach_to_inventory(self, inventory_id: str, artifact_id: str) -> dict[str, Any]:
        """Link an existing artifact to an inventory. The newly attached artifact takes the INVENTORY's own
        TLP 2.0 marking (it can raise or lower the artifact's marking). Returns
        ``{"ok": …, "linked": …, "already": …, "attachment_tlp": …, "attachment_tlp_ids": [...]}``."""
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
        are skipped. Deduped + capped at 100. Each newly attached artifact takes the inventory's own TLP 2.0
        marking. Returns ``{"id", "linked_count", "attached", "skipped", "mode", "attachment_tlp",
        "attachment_tlp_ids"}``.
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
        :meth:`set_attachments` — including the re-marking of the newly attached artifacts to the
        inventory's own TLP 2.0 marking."""
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
        strict_attachments: bool = False,
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

        Attachment resolution stays permissive by default for compatibility. The result carries
        ``attachment_omissions`` records (``attachment_id`` + ``reason``) for every skipped artifact.
        Set ``strict_attachments=True`` to fail before submission if any requested attachment is unavailable.

        The inventory's attached **VEX suppression overlay** (imported with ``format="vex"``) always rides along
        as the engine's ``vex_overlay``, so findings the VEX marks ``not_affected``/``fixed`` come back
        ``suppressed_by_vex`` (retained + justification, excluded from the actionable counts) instead of being
        re-reported. Nothing to pass — it is read from the inventory manifest.

        Returns ``{enrichment_id, report}``; ``report`` is the InventoryEnrichmentResult (per-asset CVEs with
        CVSS vectors, EPSS percentile, NIST LEV (``lev``), KEV detail, Metasploit / Nuclei, ``provenance``; plus
        ``technique_catalog`` and ``mitigation_catalog``). If the inventory's inventory is empty this short-circuits and
        returns ``{"enrichment_id": None, "empty": True}`` without submitting. Raises
        :class:`UnexpectedStatus` on a non-2xx (or enrichment error), or :class:`TimeoutError` if the
        enrichment doesn't finish within ``timeout`` seconds.
        """
        validate_poll_options(poll_interval, timeout)
        manifest = await self.get_inventory(inventory_id)
        items = manifest.get("inventory") or []
        if not items:
            return {"enrichment_id": None, "empty": True}
        do_attach = bool(manifest.get("enrich_attachments")) if enrich_attachments is None else enrich_attachments
        attachments_texts: list[dict[str, str]] = []
        attachments_files: list[dict[str, str]] = []
        attachment_omissions: list[dict[str, str]] = []
        if do_attach:
            ids = [
                attachment_id
                for attachment in (manifest.get("attached") or [])
                if isinstance(attachment, dict) and (attachment_id := attachment.get("id"))
            ]
            attachments_texts, attachments_files, attachment_omissions = await self._resolve_attachments(ids)
            if strict_attachments and attachment_omissions:
                omitted_ids = ", ".join(item["attachment_id"] for item in attachment_omissions)
                raise RuntimeError(
                    f"unable to resolve {len(attachment_omissions)} requested attachment(s): {omitted_ids}"
                )
        result = await self.enrich_items(
            items,
            include=include,
            poll_interval=poll_interval,
            timeout=timeout,
            on_progress=on_progress,
            attachments_texts=attachments_texts,
            attachments_files=attachments_files,
            vex_overlay=_manifest_vex_overlay(manifest),
        )
        if do_attach:
            result["attachment_omissions"] = attachment_omissions
        if save and result.get("enrichment_id"):
            result["saved"] = await self.save_enrichment(inventory_id, result["enrichment_id"])
        return result

    async def _resolve_attachments(
        self, attachment_ids: list[str]
    ) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
        """Resolve attachment evidence and return per-artifact texts, files, and structured omission records.

        Each resolved entry names the artifact it came from (``source_artifact_id``), so the engine
        attributes every reference to the artifact it actually appeared in rather than to the run as a
        whole — the caller is the only party that knows which artifact contributed which block, and that
        knowledge is captured here instead of being reconstructed from the text later.
        """
        texts: list[dict[str, str]] = []
        files: list[dict[str, str]] = []
        omissions = [
            {
                "attachment_id": attachment_id,
                "reason": "attachment limit exceeded (maximum 20)",
            }
            for attachment_id in attachment_ids[20:]
        ]
        total = 0
        for attachment_id in attachment_ids[:20]:
            try:
                resp = await self._http.request(
                    "GET",
                    f"/artifact-manager/artifacts/{path_segment(attachment_id)}",
                    params={"raw": "1"},
                )
                if not 200 <= resp.status_code < 300:
                    omissions.append(
                        {
                            "attachment_id": attachment_id,
                            "reason": f"HTTP {resp.status_code}",
                        }
                    )
                    continue
                content = resp.text
                if not content:
                    omissions.append(
                        {
                            "attachment_id": attachment_id,
                            "reason": "empty response body",
                        }
                    )
                    continue
                name = unquote(resp.headers.get("X-Artifact-Name", "") or attachment_id)
                if resp.headers.get("X-Artifact-Format", "") == "file":
                    files.append({"filename": name, "content_b64": content, "source_artifact_id": attachment_id})
                    continue
                if total >= 500_000:
                    omissions.append(
                        {
                            "attachment_id": attachment_id,
                            "reason": "combined attachment text limit exceeded",
                        }
                    )
                    continue
                chunk = content[: min(80_000, 500_000 - total)]
                texts.append({"text": chunk, "source_artifact_id": attachment_id, "filename": name})
                total += len(chunk)
            except Exception as exc:  # noqa: BLE001 — permissive mode reports each omitted attachment
                omissions.append(
                    {
                        "attachment_id": attachment_id,
                        "reason": str(exc) or type(exc).__name__,
                    }
                )
        return (texts, files, omissions)

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
        attachments_texts: list[dict[str, Any]] | None = None,
        attached_artifact_ids: list[str] | None = None,
        attachments_files: list[dict[str, str]] | None = None,
        vex_overlay: str | None = None,
    ) -> dict[str, Any]:
        """Submit a raw asset list to the ``/v1/inventory-enrich`` engine, poll until done, and return
        ``{enrichment_id, report}``. The shared submit→poll core behind :meth:`enrich_inventory` and the
        scan-ingest workflow. ``on_progress`` streams the live job each poll. ``attachments_text`` (one
        opaque blob) and ``attachments_texts`` (one entry per artifact — ``{text, source_artifact_id?,
        filename?}``) plus ``attachments_files`` (raw binary the engine parses) drive the engine's mini
        Artifact-Enricher stage over the inventory's attached artifacts; ``attached_artifact_ids`` names
        the artifacts an opaque ``attachments_text`` blob came from. ``vex_overlay`` (optional) is an
        OpenVEX 0.2.0 / CSAF 2.0 VEX document text — statements that are ``not_affected``/``fixed`` for a
        CVE on one of the submitted assets mark that finding ``suppressed_by_vex`` in the result. Raises
        :class:`UnexpectedStatus` on a non-2xx / engine error, or :class:`TimeoutError` on the deadline."""
        validate_poll_options(poll_interval, timeout)
        body: dict[str, Any] = {"items": items}
        if include:
            body["include"] = include
        if attachments_text:
            body["attachments_text"] = attachments_text
        if attachments_texts:
            body["attachments_texts"] = attachments_texts
        if attached_artifact_ids:
            body["attached_artifact_ids"] = attached_artifact_ids
        if attachments_files:
            body["attachments_files"] = attachments_files
        if vex_overlay:
            body["vex_overlay"] = {"format": "vex", "content": vex_overlay}
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
        ``nmap``/``list``/``grype``/``trivy``/``depcheck``/``nessus``/``gvm``/``xlsx``/``vex`` (no auto-detect;
        pass ``bytes`` for the binary ``xlsx``; ``vex`` is a VEX suppression overlay — OpenVEX / CSAF — that
        parses to zero assets plus a ``vex_overlay``). Returns
        ``{format, items, count, inventory_name?, truncated?, dropped?}``
        (``dropped`` — SBOM only — is the dependency edges not retained, #334). Usage-exempt — the building block
        for :meth:`ingest_scan`."""
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
        ``nessus``/``gvm``/``xlsx``/``vex`` (pass ``bytes`` for the binary ``xlsx``).
        The parse is usage-exempt; the enrichment **submit counts toward your usage** (one
        ``/v1/inventory-enrich`` request — far cheaper than enriching each product separately). Returns
        ``{format, parsed_count, truncated?, enrichment_id, report, recommended_actions,
        unverified_assets}`` where ``report`` is
        the engine's KEV-first-ranked findings + rollup, ``recommended_actions`` is the top prioritized
        CVEs, and ``unverified_assets`` names the assets whose identity never resolved. An empty parse
        short-circuits to ``{format, parsed_count: 0, enrichment_id: None, empty: True}``.
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
