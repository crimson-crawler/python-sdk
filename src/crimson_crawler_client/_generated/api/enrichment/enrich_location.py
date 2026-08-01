from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_location_request import EnrichLocationRequest
from ...models.enrich_location_response import EnrichLocationResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichLocationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/location",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichLocationResponse | None:
    if response.status_code == 200:
        response_200 = EnrichLocationResponse.from_dict(response.json())

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
) -> Response[Any | EnrichLocationResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichLocationRequest,
) -> Response[Any | EnrichLocationResponse]:
    """Enrich Location

     Get the threat landscape for a geographic region.

    Returns active threat groups and ATT&CK techniques associated with a country or region. Provide
    `location_id` for a direct lookup (e.g. L0001) or `search` by country or region name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected location.

    **Include options**

    - `details` — location metadata and associated object counts
    - `groups` — resolved threat group objects active in this region
    - `techniques` — resolved ATT&CK technique objects used by groups in this region
    - `software` — malware and tools used by groups in this region
    - `campaigns` — threat campaigns active in this region
    - `tie` — technique likelihood predictions for regional techniques
    - `navigator` — ATT&CK Navigator layer JSON for regional technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the region's techniques
    - `sectors` — industry sectors targeted in this region
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for regional cyber threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the region's threat landscape and active groups

    Args:
        body (EnrichLocationRequest): Get the threat landscape for a geographic region: active
            groups, techniques, and sectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichLocationResponse]
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
    body: EnrichLocationRequest,
) -> Any | EnrichLocationResponse | None:
    """Enrich Location

     Get the threat landscape for a geographic region.

    Returns active threat groups and ATT&CK techniques associated with a country or region. Provide
    `location_id` for a direct lookup (e.g. L0001) or `search` by country or region name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected location.

    **Include options**

    - `details` — location metadata and associated object counts
    - `groups` — resolved threat group objects active in this region
    - `techniques` — resolved ATT&CK technique objects used by groups in this region
    - `software` — malware and tools used by groups in this region
    - `campaigns` — threat campaigns active in this region
    - `tie` — technique likelihood predictions for regional techniques
    - `navigator` — ATT&CK Navigator layer JSON for regional technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the region's techniques
    - `sectors` — industry sectors targeted in this region
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for regional cyber threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the region's threat landscape and active groups

    Args:
        body (EnrichLocationRequest): Get the threat landscape for a geographic region: active
            groups, techniques, and sectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichLocationResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichLocationRequest,
) -> Response[Any | EnrichLocationResponse]:
    """Enrich Location

     Get the threat landscape for a geographic region.

    Returns active threat groups and ATT&CK techniques associated with a country or region. Provide
    `location_id` for a direct lookup (e.g. L0001) or `search` by country or region name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected location.

    **Include options**

    - `details` — location metadata and associated object counts
    - `groups` — resolved threat group objects active in this region
    - `techniques` — resolved ATT&CK technique objects used by groups in this region
    - `software` — malware and tools used by groups in this region
    - `campaigns` — threat campaigns active in this region
    - `tie` — technique likelihood predictions for regional techniques
    - `navigator` — ATT&CK Navigator layer JSON for regional technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the region's techniques
    - `sectors` — industry sectors targeted in this region
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for regional cyber threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the region's threat landscape and active groups

    Args:
        body (EnrichLocationRequest): Get the threat landscape for a geographic region: active
            groups, techniques, and sectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichLocationResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichLocationRequest,
) -> Any | EnrichLocationResponse | None:
    """Enrich Location

     Get the threat landscape for a geographic region.

    Returns active threat groups and ATT&CK techniques associated with a country or region. Provide
    `location_id` for a direct lookup (e.g. L0001) or `search` by country or region name.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected location.

    **Include options**

    - `details` — location metadata and associated object counts
    - `groups` — resolved threat group objects active in this region
    - `techniques` — resolved ATT&CK technique objects used by groups in this region
    - `software` — malware and tools used by groups in this region
    - `campaigns` — threat campaigns active in this region
    - `tie` — technique likelihood predictions for regional techniques
    - `navigator` — ATT&CK Navigator layer JSON for regional technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the region's techniques
    - `sectors` — industry sectors targeted in this region
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for regional cyber threat landscape analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the region's threat landscape and active groups

    Args:
        body (EnrichLocationRequest): Get the threat landscape for a geographic region: active
            groups, techniques, and sectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichLocationResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
