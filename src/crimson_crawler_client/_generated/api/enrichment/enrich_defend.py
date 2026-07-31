from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_d3fend_request import EnrichD3FENDRequest
from ...models.enrich_d3fend_response import EnrichD3FENDResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichD3FENDRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/defend",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichD3FENDResponse | None:
    if response.status_code == 200:
        response_200 = EnrichD3FENDResponse.from_dict(response.json())

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
) -> Response[Any | EnrichD3FENDResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichD3FENDRequest,
) -> Response[Any | EnrichD3FENDResponse]:
    """Enrich D3FEND Technique

     Look up or search D3FEND defensive techniques and countermeasures.

    Provide `d3fend_id` for a direct lookup (e.g. D3-AL) or `search` for text-based discovery. Returns
    the D3FEND object with linked ATT&CK techniques and optional intelligence context.

    **Include options**

    - `details` — full D3FEND object with description and defensive form
    - `techniques` — ATT&CK techniques this defensive technique mitigates or detects
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for defensive technique research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the defensive technique

    Args:
        body (EnrichD3FENDRequest): Look up or search D3FEND defensive techniques and
            countermeasures.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichD3FENDResponse]
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
    body: EnrichD3FENDRequest,
) -> Any | EnrichD3FENDResponse | None:
    """Enrich D3FEND Technique

     Look up or search D3FEND defensive techniques and countermeasures.

    Provide `d3fend_id` for a direct lookup (e.g. D3-AL) or `search` for text-based discovery. Returns
    the D3FEND object with linked ATT&CK techniques and optional intelligence context.

    **Include options**

    - `details` — full D3FEND object with description and defensive form
    - `techniques` — ATT&CK techniques this defensive technique mitigates or detects
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for defensive technique research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the defensive technique

    Args:
        body (EnrichD3FENDRequest): Look up or search D3FEND defensive techniques and
            countermeasures.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichD3FENDResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichD3FENDRequest,
) -> Response[Any | EnrichD3FENDResponse]:
    """Enrich D3FEND Technique

     Look up or search D3FEND defensive techniques and countermeasures.

    Provide `d3fend_id` for a direct lookup (e.g. D3-AL) or `search` for text-based discovery. Returns
    the D3FEND object with linked ATT&CK techniques and optional intelligence context.

    **Include options**

    - `details` — full D3FEND object with description and defensive form
    - `techniques` — ATT&CK techniques this defensive technique mitigates or detects
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for defensive technique research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the defensive technique

    Args:
        body (EnrichD3FENDRequest): Look up or search D3FEND defensive techniques and
            countermeasures.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichD3FENDResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichD3FENDRequest,
) -> Any | EnrichD3FENDResponse | None:
    """Enrich D3FEND Technique

     Look up or search D3FEND defensive techniques and countermeasures.

    Provide `d3fend_id` for a direct lookup (e.g. D3-AL) or `search` for text-based discovery. Returns
    the D3FEND object with linked ATT&CK techniques and optional intelligence context.

    **Include options**

    - `details` — full D3FEND object with description and defensive form
    - `techniques` — ATT&CK techniques this defensive technique mitigates or detects
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for defensive technique research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the defensive technique

    Args:
        body (EnrichD3FENDRequest): Look up or search D3FEND defensive techniques and
            countermeasures.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichD3FENDResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
