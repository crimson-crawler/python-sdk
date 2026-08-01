from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_sector_request import EnrichSectorRequest
from ...models.enrich_sector_response import EnrichSectorResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichSectorRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/sector",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichSectorResponse | None:
    if response.status_code == 200:
        response_200 = EnrichSectorResponse.from_dict(response.json())

        return response_200

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

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | EnrichSectorResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichSectorRequest,
) -> Response[Any | EnrichSectorResponse]:
    r"""Enrich Sector

     Enrich the threat landscape for an industry sector.

    Returns threat groups known to target this sector and the ATT&CK techniques they employ, with full
    defensive context. Provide `sector_id` for a direct lookup (e.g. \"financial-services\") or `search`
    by name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected sector.

    **Include options**

    - `details` — sector metadata with associated groups and techniques
    - `groups` — resolved threat group profiles targeting this sector
    - `techniques` — resolved ATT&CK technique objects used against this sector
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `tie` — technique likelihood predictions for sector-relevant techniques
    - `navigator` — ATT&CK Navigator layer JSON for technique coverage
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the sector's techniques
    - `locations` — geographic regions where this sector is targeted
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for sector-specific threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the sector's threat landscape

    Args:
        body (EnrichSectorRequest): Enrich the threat landscape for an industry sector with
            groups, techniques, and defensive context.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichSectorResponse]
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
    body: EnrichSectorRequest,
) -> Any | EnrichSectorResponse | None:
    r"""Enrich Sector

     Enrich the threat landscape for an industry sector.

    Returns threat groups known to target this sector and the ATT&CK techniques they employ, with full
    defensive context. Provide `sector_id` for a direct lookup (e.g. \"financial-services\") or `search`
    by name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected sector.

    **Include options**

    - `details` — sector metadata with associated groups and techniques
    - `groups` — resolved threat group profiles targeting this sector
    - `techniques` — resolved ATT&CK technique objects used against this sector
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `tie` — technique likelihood predictions for sector-relevant techniques
    - `navigator` — ATT&CK Navigator layer JSON for technique coverage
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the sector's techniques
    - `locations` — geographic regions where this sector is targeted
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for sector-specific threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the sector's threat landscape

    Args:
        body (EnrichSectorRequest): Enrich the threat landscape for an industry sector with
            groups, techniques, and defensive context.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichSectorResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichSectorRequest,
) -> Response[Any | EnrichSectorResponse]:
    r"""Enrich Sector

     Enrich the threat landscape for an industry sector.

    Returns threat groups known to target this sector and the ATT&CK techniques they employ, with full
    defensive context. Provide `sector_id` for a direct lookup (e.g. \"financial-services\") or `search`
    by name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected sector.

    **Include options**

    - `details` — sector metadata with associated groups and techniques
    - `groups` — resolved threat group profiles targeting this sector
    - `techniques` — resolved ATT&CK technique objects used against this sector
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `tie` — technique likelihood predictions for sector-relevant techniques
    - `navigator` — ATT&CK Navigator layer JSON for technique coverage
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the sector's techniques
    - `locations` — geographic regions where this sector is targeted
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for sector-specific threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the sector's threat landscape

    Args:
        body (EnrichSectorRequest): Enrich the threat landscape for an industry sector with
            groups, techniques, and defensive context.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichSectorResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichSectorRequest,
) -> Any | EnrichSectorResponse | None:
    r"""Enrich Sector

     Enrich the threat landscape for an industry sector.

    Returns threat groups known to target this sector and the ATT&CK techniques they employ, with full
    defensive context. Provide `sector_id` for a direct lookup (e.g. \"financial-services\") or `search`
    by name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected sector.

    **Include options**

    - `details` — sector metadata with associated groups and techniques
    - `groups` — resolved threat group profiles targeting this sector
    - `techniques` — resolved ATT&CK technique objects used against this sector
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `tie` — technique likelihood predictions for sector-relevant techniques
    - `navigator` — ATT&CK Navigator layer JSON for technique coverage
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the sector's techniques
    - `locations` — geographic regions where this sector is targeted
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for sector-specific threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the sector's threat landscape

    Args:
        body (EnrichSectorRequest): Enrich the threat landscape for an industry sector with
            groups, techniques, and defensive context.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichSectorResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
