from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.artifact_enrichment_doc_request import ArtifactEnrichmentDocRequest
from ...models.enrichment_submit_response import EnrichmentSubmitResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: ArtifactEnrichmentDocRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/artifact-enrich",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichmentSubmitResponse | None:
    if response.status_code == 202:
        response_202 = EnrichmentSubmitResponse.from_dict(response.json())

        return response_202

    if response.status_code == 401:
        response_401 = cast(Any, None)
        return response_401

    if response.status_code == 422:
        response_422 = cast(Any, None)
        return response_422

    if response.status_code == 429:
        response_429 = cast(Any, None)
        return response_429

    if response.status_code == 500:
        response_500 = cast(Any, None)
        return response_500

    if response.status_code == 503:
        response_503 = cast(Any, None)
        return response_503

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | EnrichmentSubmitResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ArtifactEnrichmentDocRequest,
) -> Response[Any | EnrichmentSubmitResponse]:
    """Submit Artifact Enrichment

     Submit security text or files for asynchronous Artifact Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/artifact-enrich/{enrichment_id}` for stage progress and the finished report.

    Supply up to 1,000,000 characters in `text`, up to 20 base64-encoded files, or both. Supported
    inputs include scan exports, vulnerability reports, advisories, email, spreadsheets, and plain
    text. The report resolves detected CVEs, products, packages, weaknesses, techniques, and
    indicators into evidence, SSVC decisions, PATCH/BLOCK/WATCH/INFO actions, prioritized work,
    attack paths, defensive guidance, citations, and requested machine-readable exports.

    `include` selects report sections; it does not reduce the evidence used for core decisions.
    Decisions, scores, grades, references, and prioritized actions are always returned. The allowed
    section names and export formats are defined in the request schema.

    Submission consumes one request unit. Polling consumes none. Each API key can run 3 Artifact or
    Inventory Enrichments at once and can hold 20 running or queued jobs across both engines. Jobs
    beyond the running limit remain `queued`; a full queue returns 429. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (ArtifactEnrichmentDocRequest): Extract security references from an artifact and
            enrich them into one graded report.

            Paste ``text`` and/or upload ``files`` (nmap XML, Tenable/Qualys CSV, PDF advisory, EML).
            Every CVE, product, weakness, technique, and indicator found is enriched into a single
            report: an SSVC decision and PATCH/BLOCK/WATCH/INFO action per reference, weaponization
            scores, a prioritized worklist with KEV deadlines, ATT&CK technique mappings with
            detection
            and mitigation guidance, kill-chain attack paths, and machine-readable exports.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichmentSubmitResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: ArtifactEnrichmentDocRequest,
) -> Any | EnrichmentSubmitResponse | None:
    """Submit Artifact Enrichment

     Submit security text or files for asynchronous Artifact Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/artifact-enrich/{enrichment_id}` for stage progress and the finished report.

    Supply up to 1,000,000 characters in `text`, up to 20 base64-encoded files, or both. Supported
    inputs include scan exports, vulnerability reports, advisories, email, spreadsheets, and plain
    text. The report resolves detected CVEs, products, packages, weaknesses, techniques, and
    indicators into evidence, SSVC decisions, PATCH/BLOCK/WATCH/INFO actions, prioritized work,
    attack paths, defensive guidance, citations, and requested machine-readable exports.

    `include` selects report sections; it does not reduce the evidence used for core decisions.
    Decisions, scores, grades, references, and prioritized actions are always returned. The allowed
    section names and export formats are defined in the request schema.

    Submission consumes one request unit. Polling consumes none. Each API key can run 3 Artifact or
    Inventory Enrichments at once and can hold 20 running or queued jobs across both engines. Jobs
    beyond the running limit remain `queued`; a full queue returns 429. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (ArtifactEnrichmentDocRequest): Extract security references from an artifact and
            enrich them into one graded report.

            Paste ``text`` and/or upload ``files`` (nmap XML, Tenable/Qualys CSV, PDF advisory, EML).
            Every CVE, product, weakness, technique, and indicator found is enriched into a single
            report: an SSVC decision and PATCH/BLOCK/WATCH/INFO action per reference, weaponization
            scores, a prioritized worklist with KEV deadlines, ATT&CK technique mappings with
            detection
            and mitigation guidance, kill-chain attack paths, and machine-readable exports.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichmentSubmitResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ArtifactEnrichmentDocRequest,
) -> Response[Any | EnrichmentSubmitResponse]:
    """Submit Artifact Enrichment

     Submit security text or files for asynchronous Artifact Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/artifact-enrich/{enrichment_id}` for stage progress and the finished report.

    Supply up to 1,000,000 characters in `text`, up to 20 base64-encoded files, or both. Supported
    inputs include scan exports, vulnerability reports, advisories, email, spreadsheets, and plain
    text. The report resolves detected CVEs, products, packages, weaknesses, techniques, and
    indicators into evidence, SSVC decisions, PATCH/BLOCK/WATCH/INFO actions, prioritized work,
    attack paths, defensive guidance, citations, and requested machine-readable exports.

    `include` selects report sections; it does not reduce the evidence used for core decisions.
    Decisions, scores, grades, references, and prioritized actions are always returned. The allowed
    section names and export formats are defined in the request schema.

    Submission consumes one request unit. Polling consumes none. Each API key can run 3 Artifact or
    Inventory Enrichments at once and can hold 20 running or queued jobs across both engines. Jobs
    beyond the running limit remain `queued`; a full queue returns 429. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (ArtifactEnrichmentDocRequest): Extract security references from an artifact and
            enrich them into one graded report.

            Paste ``text`` and/or upload ``files`` (nmap XML, Tenable/Qualys CSV, PDF advisory, EML).
            Every CVE, product, weakness, technique, and indicator found is enriched into a single
            report: an SSVC decision and PATCH/BLOCK/WATCH/INFO action per reference, weaponization
            scores, a prioritized worklist with KEV deadlines, ATT&CK technique mappings with
            detection
            and mitigation guidance, kill-chain attack paths, and machine-readable exports.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichmentSubmitResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ArtifactEnrichmentDocRequest,
) -> Any | EnrichmentSubmitResponse | None:
    """Submit Artifact Enrichment

     Submit security text or files for asynchronous Artifact Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/artifact-enrich/{enrichment_id}` for stage progress and the finished report.

    Supply up to 1,000,000 characters in `text`, up to 20 base64-encoded files, or both. Supported
    inputs include scan exports, vulnerability reports, advisories, email, spreadsheets, and plain
    text. The report resolves detected CVEs, products, packages, weaknesses, techniques, and
    indicators into evidence, SSVC decisions, PATCH/BLOCK/WATCH/INFO actions, prioritized work,
    attack paths, defensive guidance, citations, and requested machine-readable exports.

    `include` selects report sections; it does not reduce the evidence used for core decisions.
    Decisions, scores, grades, references, and prioritized actions are always returned. The allowed
    section names and export formats are defined in the request schema.

    Submission consumes one request unit. Polling consumes none. Each API key can run 3 Artifact or
    Inventory Enrichments at once and can hold 20 running or queued jobs across both engines. Jobs
    beyond the running limit remain `queued`; a full queue returns 429. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (ArtifactEnrichmentDocRequest): Extract security references from an artifact and
            enrich them into one graded report.

            Paste ``text`` and/or upload ``files`` (nmap XML, Tenable/Qualys CSV, PDF advisory, EML).
            Every CVE, product, weakness, technique, and indicator found is enriched into a single
            report: an SSVC decision and PATCH/BLOCK/WATCH/INFO action per reference, weaponization
            scores, a prioritized worklist with KEV deadlines, ATT&CK technique mappings with
            detection
            and mitigation guidance, kill-chain attack paths, and machine-readable exports.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichmentSubmitResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
