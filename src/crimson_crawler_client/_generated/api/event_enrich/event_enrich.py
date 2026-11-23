from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrichment_submit_response import EnrichmentSubmitResponse
from ...models.event_enrichment_request import EventEnrichmentRequest
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EventEnrichmentRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/event-enrich",
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
    body: EventEnrichmentRequest,
) -> Response[Any | EnrichmentSubmitResponse]:
    """Submit Event Enrichment

     Submit a raw security event for an Event Enrichment and get back an enrichment ID to poll.

    Returns an `enrichment_id` right away — the enrichment runs in the background. Poll
    `GET /v1/event-enrich/{enrichment_id}` for stage-by-stage progress and the finished per-indicator
    enrichment plus the aggregate event threat verdict.

    The reactive counterpart to the Artifact + Inventory Enrichers: hand it a raw event (a Defender
    XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text) and CC extracts the indicators
    (CVEs / ATT&CK techniques / IOCs / products) the same deterministic way the Artifact Enricher
    does, enriches each against the authoritative CTI sources, and aggregates a per-event verdict —
    so a SOC platform submits one alert here instead of looping the single `/v1/enrich/*` endpoints.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact,
    Inventory, or Event Enrichments at once and can hold 20 running or queued jobs across all three
    engines. Jobs beyond the running limit remain `queued`; a full queue returns 429, and that cap is
    enforced atomically, so simultaneous submits cannot push an owner past it. If queue state cannot
    be verified, the request returns 503 and no job is created.

    Args:
        body (EventEnrichmentRequest): Event Enricher — submit a raw security/log event for async
            indicator enrichment.

            The reactive (event-driven) counterpart to the Artifact + Inventory Enrichers: hand it a
            raw
            security event (a Defender XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text)
            and the
            enrichment runs in the background — it extracts the indicators (CVEs / ATT&CK techniques /
            IOCs /
            products) the same deterministic way the Artifact Enricher does, enriches each against the
            authoritative CTI sources, and aggregates a per-event threat verdict. A SOC platform
            submits an
            alert here instead of looping the single `/v1/enrich/*` endpoints itself.

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
    body: EventEnrichmentRequest,
) -> Any | EnrichmentSubmitResponse | None:
    """Submit Event Enrichment

     Submit a raw security event for an Event Enrichment and get back an enrichment ID to poll.

    Returns an `enrichment_id` right away — the enrichment runs in the background. Poll
    `GET /v1/event-enrich/{enrichment_id}` for stage-by-stage progress and the finished per-indicator
    enrichment plus the aggregate event threat verdict.

    The reactive counterpart to the Artifact + Inventory Enrichers: hand it a raw event (a Defender
    XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text) and CC extracts the indicators
    (CVEs / ATT&CK techniques / IOCs / products) the same deterministic way the Artifact Enricher
    does, enriches each against the authoritative CTI sources, and aggregates a per-event verdict —
    so a SOC platform submits one alert here instead of looping the single `/v1/enrich/*` endpoints.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact,
    Inventory, or Event Enrichments at once and can hold 20 running or queued jobs across all three
    engines. Jobs beyond the running limit remain `queued`; a full queue returns 429, and that cap is
    enforced atomically, so simultaneous submits cannot push an owner past it. If queue state cannot
    be verified, the request returns 503 and no job is created.

    Args:
        body (EventEnrichmentRequest): Event Enricher — submit a raw security/log event for async
            indicator enrichment.

            The reactive (event-driven) counterpart to the Artifact + Inventory Enrichers: hand it a
            raw
            security event (a Defender XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text)
            and the
            enrichment runs in the background — it extracts the indicators (CVEs / ATT&CK techniques /
            IOCs /
            products) the same deterministic way the Artifact Enricher does, enriches each against the
            authoritative CTI sources, and aggregates a per-event threat verdict. A SOC platform
            submits an
            alert here instead of looping the single `/v1/enrich/*` endpoints itself.

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
    body: EventEnrichmentRequest,
) -> Response[Any | EnrichmentSubmitResponse]:
    """Submit Event Enrichment

     Submit a raw security event for an Event Enrichment and get back an enrichment ID to poll.

    Returns an `enrichment_id` right away — the enrichment runs in the background. Poll
    `GET /v1/event-enrich/{enrichment_id}` for stage-by-stage progress and the finished per-indicator
    enrichment plus the aggregate event threat verdict.

    The reactive counterpart to the Artifact + Inventory Enrichers: hand it a raw event (a Defender
    XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text) and CC extracts the indicators
    (CVEs / ATT&CK techniques / IOCs / products) the same deterministic way the Artifact Enricher
    does, enriches each against the authoritative CTI sources, and aggregates a per-event verdict —
    so a SOC platform submits one alert here instead of looping the single `/v1/enrich/*` endpoints.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact,
    Inventory, or Event Enrichments at once and can hold 20 running or queued jobs across all three
    engines. Jobs beyond the running limit remain `queued`; a full queue returns 429, and that cap is
    enforced atomically, so simultaneous submits cannot push an owner past it. If queue state cannot
    be verified, the request returns 503 and no job is created.

    Args:
        body (EventEnrichmentRequest): Event Enricher — submit a raw security/log event for async
            indicator enrichment.

            The reactive (event-driven) counterpart to the Artifact + Inventory Enrichers: hand it a
            raw
            security event (a Defender XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text)
            and the
            enrichment runs in the background — it extracts the indicators (CVEs / ATT&CK techniques /
            IOCs /
            products) the same deterministic way the Artifact Enricher does, enriches each against the
            authoritative CTI sources, and aggregates a per-event threat verdict. A SOC platform
            submits an
            alert here instead of looping the single `/v1/enrich/*` endpoints itself.

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
    body: EventEnrichmentRequest,
) -> Any | EnrichmentSubmitResponse | None:
    """Submit Event Enrichment

     Submit a raw security event for an Event Enrichment and get back an enrichment ID to poll.

    Returns an `enrichment_id` right away — the enrichment runs in the background. Poll
    `GET /v1/event-enrich/{enrichment_id}` for stage-by-stage progress and the finished per-indicator
    enrichment plus the aggregate event threat verdict.

    The reactive counterpart to the Artifact + Inventory Enrichers: hand it a raw event (a Defender
    XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text) and CC extracts the indicators
    (CVEs / ATT&CK techniques / IOCs / products) the same deterministic way the Artifact Enricher
    does, enriches each against the authoritative CTI sources, and aggregates a per-event verdict —
    so a SOC platform submits one alert here instead of looping the single `/v1/enrich/*` endpoints.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact,
    Inventory, or Event Enrichments at once and can hold 20 running or queued jobs across all three
    engines. Jobs beyond the running limit remain `queued`; a full queue returns 429, and that cap is
    enforced atomically, so simultaneous submits cannot push an owner past it. If queue state cannot
    be verified, the request returns 503 and no job is created.

    Args:
        body (EventEnrichmentRequest): Event Enricher — submit a raw security/log event for async
            indicator enrichment.

            The reactive (event-driven) counterpart to the Artifact + Inventory Enrichers: hand it a
            raw
            security event (a Defender XDR / Sentinel alert, a SIEM/EDR log line, any JSON or text)
            and the
            enrichment runs in the background — it extracts the indicators (CVEs / ATT&CK techniques /
            IOCs /
            products) the same deterministic way the Artifact Enricher does, enriches each against the
            authoritative CTI sources, and aggregates a per-event threat verdict. A SOC platform
            submits an
            alert here instead of looping the single `/v1/enrich/*` endpoints itself.

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
