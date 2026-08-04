"""Report Generator API — key-authed access to the Report Generator.

Its own section at ``/ai-reports/*`` generates and manages grounded,
cite-or-refuse intelligence reports from saved enrichments, inputs, and prior reports.
A report is built by picking a TEMPLATE + source artifacts, creating a DRAFT (the scaffold + a
list of AI sections to fill), then filling each AI section (a grounded LLM call). The
:meth:`generate_report` convenience runs the whole create → fill-all → fetch flow in one call.

Same API key, same base URL, same retry transport as every other call — **Report Generator calls never
count toward your API usage** (including the LLM generation). Reports are stored as ``kind=report``
artifacts (``format='html_report'``); browser-authored ProseMirror reports export PDF/DOCX/MD only
from the editor, but API-generated HTML reports export as ``html`` or ``md`` here.

Exposed as :attr:`CrawlerClient.ai_reports`. Responses are plain ``dict``/``list`` JSON.

Example::

    async with CrawlerClient() as client:
        out = await client.ai_reports.generate_report("exec", source_ids=[enrichment_id], name="Exec brief")
        md = await client.ai_reports.export_report(out["report"]["id"], "md")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from ._url import path_segment
from .artifact_manager import _get_buffered_raw, _safe_download_filename
from .exceptions import UnexpectedStatus

if TYPE_CHECKING:
    import httpx


class AiReportsAPI:
    """Client for the key-authed Report Generator API.

    Obtained via :attr:`CrawlerClient.ai_reports` — never constructed directly.
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
            raise UnexpectedStatus(resp.status_code, resp.content, f"Report Generator API {resp.status_code} on {path}")
        return resp

    # -- Discovery + templates --------------------------------------------- #

    async def discovery(self) -> dict[str, Any]:
        """``GET /ai-reports`` — the self-documenting endpoint map + your account context."""
        return (await self._request("GET", "/ai-reports")).json()

    async def list_templates(self) -> list[dict[str, Any]]:
        """The built-in report templates — each ``{id, name, description?, ai_sections:[{section_type,
        label}], needs?}``. Pass an ``id`` as the ``template`` to :meth:`create_draft`."""
        return (await self._request("GET", "/ai-reports/templates")).json()["templates"]

    # -- Reports ----------------------------------------------------------- #

    async def list_reports(self) -> list[dict[str, Any]]:
        """Your saved reports (newest first, no content) — ``kind=report`` artifacts."""
        return (await self._request("GET", "/ai-reports/reports")).json()["reports"]

    async def get_report(self, report_id: str) -> dict[str, Any]:
        """One report in full, including inline ``content`` (the report HTML)."""
        return (await self._request("GET", f"/ai-reports/reports/{path_segment(report_id)}")).json()["report"]

    async def get_report_raw(self, report_id: str) -> dict[str, Any]:
        """Read a report's raw HTML into a string buffer (maximum 10,000,000 bytes).

        This method does not return a streaming response. Metadata rides ``X-Artifact-*`` headers.
        Returns ``{"content": str, "id", "kind", "name", "format", "created_at"}``."""
        content, resp = await _get_buffered_raw(
            self._http,
            f"/ai-reports/reports/{path_segment(report_id)}",
            "Report Generator API",
        )
        return {
            "content": content,
            "id": resp.headers.get("x-artifact-id", report_id),
            "kind": resp.headers.get("x-artifact-kind", ""),
            "name": resp.headers.get("x-artifact-name", ""),
            "format": resp.headers.get("x-artifact-format", ""),
            "created_at": resp.headers.get("x-artifact-created", ""),
        }

    async def create_draft(
        self,
        template: str,
        *,
        source_ids: list[str] | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Create a DRAFT report from a template + source artifacts. Renders the scaffold (static +
        deterministic data sections) and returns the list of AI sections still to fill.

        Args:
            template: A template id from :meth:`list_templates` (e.g. ``"exec"``, ``"technical"``).
            source_ids: Saved artifact ids (enrichments / inputs / reports / inventories) to ground on.
            name: Optional report name (defaults to ``"<template> — <date>"``).

        Returns:
            ``{"id", "name", "html", "ai_sections": [{section_type, label, ...}], "skipped": [...]}``.
        """
        body: dict[str, Any] = {"template": template}
        if source_ids is not None:
            body["source_ids"] = source_ids
        if name is not None:
            body["name"] = name
        return (await self._request("POST", "/ai-reports/reports", json=body)).json()

    async def fill_section(self, report_id: str, section_type: str | None = None) -> dict[str, Any]:
        """Generate ONE grounded AI section of a draft (omit ``section_type`` to fill the next pending
        one). Returns ``{"section_type", "filled", "truncated", "remaining": [...], "complete": bool}``.
        Raises :class:`UnexpectedStatus` (409) when no sections remain or (502) on a copilot failure."""
        body: dict[str, Any] = {}
        if section_type is not None:
            body["section_type"] = section_type
        return (
            await self._request(
                "POST",
                f"/ai-reports/reports/{path_segment(report_id)}/sections",
                json=body,
            )
        ).json()

    async def rename_report(self, report_id: str, name: str) -> dict[str, Any]:
        """Rename a report. Returns the updated report."""
        return (
            await self._request(
                "PATCH",
                f"/ai-reports/reports/{path_segment(report_id)}",
                json={"name": name},
            )
        ).json()["report"]

    async def delete_report(self, report_id: str) -> bool:
        """Delete a report. Returns ``True`` on success (404 raises)."""
        resp = await self._request("DELETE", f"/ai-reports/reports/{path_segment(report_id)}")
        return bool(resp.json().get("deleted"))

    async def section(
        self,
        source_ids: list[str],
        *,
        section_type: str | None = None,
        instruction: str | None = None,
        selection: str | None = None,
        verbosity: Literal["concise", "standard", "detailed"] | None = None,
    ) -> dict[str, Any]:
        """Generate a single grounded section ad-hoc (NOT tied to a stored report) from ``source_ids``.

        Provide ``section_type`` (a template section) and/or a free-text ``instruction``. Returns
        ``{"text", "truncated", "grounded", "unsupported_ids"}`` — ``grounded`` is the cite-or-refuse
        check (``unsupported_ids`` lists any catalog ids not backed by the sources)."""
        body: dict[str, Any] = {"source_ids": source_ids}
        if section_type is not None:
            body["section_type"] = section_type
        if instruction is not None:
            body["instruction"] = instruction
        if selection is not None:
            body["selection"] = selection
        if verbosity is not None:
            body["verbosity"] = verbosity
        return (await self._request("POST", "/ai-reports/section", json=body)).json()

    async def export_report(self, report_id: str, fmt: Literal["html", "md"] = "html") -> dict[str, Any]:
        """Export a report as ``html`` or ``md``. The body IS the export file.

        Returns ``{"content": str, "bytes": bytes, "filename": str, "content_type": str}``. The filename
        is sanitized from ``Content-Disposition``; callers choose and validate the destination path.
        (PDF/DOCX are browser-editor-only; ProseMirror reports authored in the browser raise 422 here.)"""
        resp = await self._request("GET", f"/ai-reports/reports/{path_segment(report_id)}/export/{path_segment(fmt)}")
        filename = _safe_download_filename(
            resp.headers.get("content-disposition", ""),
            f"{report_id}.{fmt}",
        )
        return {
            "content": resp.text,
            "bytes": resp.content,
            "filename": filename,
            "content_type": resp.headers.get("content-type", ""),
        }

    async def generate_report(
        self,
        template: str,
        *,
        source_ids: list[str] | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Generate a report end-to-end: create the draft, fill every AI section, return the finished
        report. The convenience over :meth:`create_draft` + :meth:`fill_section`.

        If a section's copilot call fails (502), generation stops there and returns what filled so
        far: the report keeps the sections completed before the failure, the failed section is
        recorded in ``sections`` as ``{"error": "generation failed", "status": 502}``, and that
        section plus any after it stay unfilled cards. Re-run :meth:`generate_report` or fill the
        remaining sections individually with :meth:`fill_section` to finish.

        Returns ``{"report": <full report>, "sections": [<fill result per section>], "skipped": [...]}``
        where ``skipped`` carries draft-time unresolved source ids. Raises :class:`UnexpectedStatus`
        on a non-2xx that isn't a per-section 502.
        """
        draft = await self.create_draft(template, source_ids=source_ids, name=name)
        report_id = draft["id"]
        pending = list(draft.get("ai_sections") or [])
        sections: list[dict[str, Any]] = []
        # One fill per pending AI section (each call fills the next pending one); zero sections → no
        # fills, straight to the finished report. The complete/409/502 checks below stop early.
        for _ in range(len(pending)):
            try:
                result = await self.fill_section(report_id)
            except UnexpectedStatus as exc:
                if exc.status == 409:  # nothing left to fill
                    break
                if exc.status == 502:  # copilot blip — record + stop (the section stays a card)
                    sections.append({"error": "generation failed", "status": 502})
                    break
                raise
            sections.append(result)
            if result.get("complete"):
                break
        report = await self.get_report(report_id)
        return {"report": report, "sections": sections, "skipped": draft.get("skipped", [])}
