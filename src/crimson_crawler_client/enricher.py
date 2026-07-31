"""Enricher API — key-authed access to the async artifact-enrichment engine (submit → poll).

A thin wrapper over the ``/v1/artifact-enrich`` engine endpoints: ``client.enricher.enrich`` stages
artifacts, submits to the engine, polls until done, and returns the report. There is no save/discard —
the engine pair is submit→poll only; persistence is the portal's job, not the API's.

Same API key, same base URL, same retry transport as every other call. The enrichment submit is
enrichment compute and **counts toward your API usage** (it's a ``/v1/artifact-enrich`` request);
polling is the engine's own status read. Exposed as :attr:`CrawlerClient.enricher`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._poll import ProgressCallback, poll_until_done
from ._url import path_segment
from .exceptions import UnexpectedStatus

if TYPE_CHECKING:
    import httpx


class EnricherAPI:
    """Client for the artifact-enrichment engine (the async submit→poll lifecycle).

    Obtained via :attr:`CrawlerClient.enricher` — never constructed directly.
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
                resp.status_code, resp.content, f"Enricher API {resp.status_code} on {path}"
            )
        return resp

    async def enrich(
        self,
        *,
        text: str | None = None,
        files: list[dict[str, str]] | None = None,
        formats: list[str] | None = None,
        include: list[str] | None = None,
        stakeholder: dict[str, Any] | None = None,
        poll_interval: float = 3.0,
        timeout: float = 300.0,
        on_progress: ProgressCallback | None = None,
        save: bool = False,
        folder_id: str | None = None,
        new_folder_name: str | None = None,
    ) -> dict[str, Any]:
        """Run an artifact enrichment end-to-end against the /v1 engine: submit → poll → return the report.

        Stages pasted ``text`` + base64 ``files`` (``[{filename, content_b64}]``), submits to
        ``/v1/artifact-enrich``, polls the job until done, and returns the enrichment report.

        ``stakeholder`` is the optional SSVC stakeholder context applied to every reference when
        ``include`` contains ``"ssvc"`` — ``{method, exposure, human_impact, mission_prevalence,
        public_wellbeing_impact}`` (omit to use the engine's CISA-coordinator defaults).

        Counts toward your API usage (it's ``/v1/artifact-enrich`` compute). Raises
        :class:`UnexpectedStatus` on a non-2xx or enrichment error, :class:`TimeoutError` if it doesn't
        finish within ``timeout``. Returns ``{enrichment_id, report}``.

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
        body: dict[str, Any] = {}
        for key, val in (("text", text), ("files", files), ("formats", formats),
                         ("include", include), ("stakeholder", stakeholder)):
            if val:
                body[key] = val

        enrichment_id = (await self._request("POST", "/v1/artifact-enrich", json=body)).json()["enrichment_id"]
        job = await poll_until_done(
            self._request, enrichment_id, f"/v1/artifact-enrich/{path_segment(enrichment_id)}",
            poll_interval=poll_interval, timeout=timeout, on_progress=on_progress,
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
