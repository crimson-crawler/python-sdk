"""Enricher API — key-authed access to the async enrichment engines (submit → poll).

Thin wrappers over the ``/v1/artifact-enrich`` + ``/v1/event-enrich`` engine endpoints:
``client.enricher.enrich`` stages artifacts, submits to the artifact engine, polls until done, and
returns the report; ``client.enricher.enrich_event`` submits a raw security event to the Event
Enricher, polls until done, and returns the per-indicator result + aggregate verdict. There is no
save/discard — the engine pair is submit→poll only; persistence is the portal's job, not the API's.

Same API key, same base URL, same retry transport as every other call. The enrichment submit is
enrichment compute and **counts toward your API usage** (it's a ``/v1/*-enrich`` request);
polling is the engine's own status read. Exposed as :attr:`CrawlerClient.enricher`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._poll import ProgressCallback, poll_until_done, validate_poll_options
from ._url import path_segment
from .exceptions import UnexpectedStatus
from .tlp import Tlp, validate_tlp

if TYPE_CHECKING:
    import httpx


class EnricherAPI:
    """Client for the async enrichment engines (submit→poll lifecycle: artifact + event).

    Obtained via :attr:`CrawlerClient.enricher` — never constructed directly.
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
            raise UnexpectedStatus(resp.status_code, resp.content, f"Enricher API {resp.status_code} on {path}")
        return resp

    async def enrich(
        self,
        *,
        text: str | None = None,
        texts: list[dict[str, str]] | None = None,
        files: list[dict[str, str]] | None = None,
        attached_artifact_ids: list[str] | None = None,
        formats: list[str] | None = None,
        include: list[str] | None = None,
        stakeholder: dict[str, Any] | None = None,
        tlp: Tlp | None = None,
        poll_interval: float = 3.0,
        timeout: float = 300.0,
        on_progress: ProgressCallback | None = None,
        save: bool = False,
        folder_id: str | None = None,
        new_folder_name: str | None = None,
    ) -> dict[str, Any]:
        """Run an artifact enrichment end-to-end against the /v1 engine: submit → poll → return the report.

        Stages pasted ``text`` + base64 ``files`` (``[{filename, content_b64, source_artifact_id?}]``),
        submits to ``/v1/artifact-enrich``, polls the job until done, and returns the enrichment report.

        ``texts`` is the per-artifact form of ``text`` (``[{text, source_artifact_id?, filename?}]``) —
        use it when the blocks came from several stored artifacts, so the report attributes each
        reference to the artifact it appeared in. ``attached_artifact_ids`` names the artifacts an
        opaque ``text`` blob came from; attribution is never inferred from the text itself.

        ``stakeholder`` is the optional SSVC stakeholder context applied to every reference when
        ``include`` contains ``"ssvc"`` — ``{method, exposure, human_impact, mission_prevalence,
        public_wellbeing_impact}`` (omit to use the engine's CISA-coordinator defaults).

        ``tlp`` is the optional TLP 2.0 marking applied to the exported formats that carry one
        (``CLEAR`` / ``GREEN`` / ``AMBER`` / ``AMBER+STRICT`` / ``RED``; default ``AMBER``). An invalid
        value raises :class:`ValueError` before the (billable) submit.

        Counts toward your API usage (it's ``/v1/artifact-enrich`` compute). Raises
        :class:`UnexpectedStatus` on a non-2xx or enrichment error, :class:`TimeoutError` if it doesn't
        finish within ``timeout``. Returns ``{enrichment_id, report}``. ``report`` is the ArtifactEnrichmentReport
        (``report["meta"]["schema_version"]``): each reference carries its full record — CVSS vectors, EPSS
        percentile, NIST LEV (``lev``), CWEs, the CISA KEV record, Metasploit / Nuclei, OSV fixed versions,
        ATT&CK v18 detection
        data, knowledge-base profiles, threat actors targeting a country or sector, and ``provenance``.

        ``on_progress`` (optional, sync or async) is called with the live job dict on every poll —
        ``{status, progress, stages, events}`` (each ``events[]`` line carries the overall % it reached)
        — so you can render a live progress bar / stream the per-reference feed. Polls are billing-exempt.

        ``save=True`` files the finished report into your Artifact Manager library after it completes (the
        ``/v1`` engine returns the report but never persists it) — the one-call equivalent of running the
        enrichment then calling :meth:`ArtifactManagerAPI.save_enrichment`. ``folder_id`` /
        ``new_folder_name`` optionally file it into a folder. When saved, the returned dict also carries
        ``saved`` (the ``{enrichment_artifact_id}`` / ``{already_persisted}`` save response). Saving is
        usage-exempt.
        """
        validate_poll_options(poll_interval, timeout)
        body: dict[str, Any] = {}
        for key, val in (
            ("text", text),
            ("texts", texts),
            ("files", files),
            ("attached_artifact_ids", attached_artifact_ids),
            ("formats", formats),
            ("include", include),
            ("stakeholder", stakeholder),
            ("tlp", validate_tlp(tlp)),
        ):
            if val:
                body[key] = val

        enrichment_id = (await self._request("POST", "/v1/artifact-enrich", json=body)).json()["enrichment_id"]
        job = await poll_until_done(
            self._request,
            enrichment_id,
            f"/v1/artifact-enrich/{path_segment(enrichment_id)}",
            poll_interval=poll_interval,
            timeout=timeout,
            on_progress=on_progress,
        )
        result: dict[str, Any] = {"enrichment_id": enrichment_id, "report": job.get("result")}
        if save:
            save_body: dict[str, Any] = {"enrichment_id": enrichment_id}
            if folder_id or new_folder_name:
                save_body["folder"] = {"folder_id": folder_id, "new_folder_name": new_folder_name}
            result["saved"] = (
                await self._request("POST", "/artifact-manager/artifacts/from-enrichment", json=save_body)
            ).json()
        return result

    async def enrich_event(
        self,
        *,
        event: str,
        event_id: str | None = None,
        poll_interval: float = 1.5,
        timeout: float = 1200.0,
        on_progress: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """Run an Event Enrichment end-to-end against the /v1 engine: submit → poll → return the result.

        Submits a raw security event (a Defender XDR / Sentinel alert, a SIEM/EDR log line, any JSON
        or text) to ``/v1/event-enrich``, polls the job until done, and returns
        ``{enrichment_id, result}`` — where ``result`` is the EventEnrichmentResult (per-indicator
        findings + the aggregate event threat assessment). CC extracts every indicator server-side;
        you do NOT pre-parse the alert. Each CVE indicator carries ``kev`` and ``weaponized`` (a
        Metasploit module exists, which floors its verdict at high); ``threat_assessment`` counts
        both as ``kev_count`` / ``weaponized_count``.

        Counts toward your API usage (it's ``/v1/event-enrich`` compute). Raises
        :class:`UnexpectedStatus` on a non-2xx or enrichment error, :class:`TimeoutError` if it
        doesn't finish within ``timeout``.

        ``on_progress`` (optional, sync or async) is called with the live job dict on every poll.
        Polls are billing-exempt.
        """
        validate_poll_options(poll_interval, timeout)
        body: dict[str, Any] = {"event": event}
        if event_id:
            body["event_id"] = event_id

        enrichment_id = (await self._request("POST", "/v1/event-enrich", json=body)).json()["enrichment_id"]
        job = await poll_until_done(
            self._request,
            enrichment_id,
            f"/v1/event-enrich/{path_segment(enrichment_id)}",
            poll_interval=poll_interval,
            timeout=timeout,
            on_progress=on_progress,
        )
        return {"enrichment_id": enrichment_id, "result": job.get("result")}
