from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_cloak_request import EnrichCloakRequest
from ...models.enrich_cloak_response import EnrichCloakResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichCloakRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/cloak",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichCloakResponse | None:
    if response.status_code == 200:
        response_200 = EnrichCloakResponse.from_dict(response.json())

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
) -> Response[Any | EnrichCloakResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCloakRequest,
) -> Response[Any | EnrichCloakResponse]:
    """Enrich CLOAK Technique

     Look up or search concealment techniques from the CLOAK framework.

    Covers concealment layers for online anonymity — encrypted DNS transports, VPN-over-Tor
    chains, traffic obfuscation. Provide `cloak_id` for a direct lookup (e.g. TTP-496, CLOAK)
    or `search` for discovery. CLOAK objects carry no ATT&CK references, so there are no
    linked techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full CLOAK object with description (the corpus has no kill-chain phases)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the concealment technique

    Args:
        body (EnrichCloakRequest): Look up or search concealment techniques from the CLOAK
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCloakResponse]
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
    body: EnrichCloakRequest,
) -> Any | EnrichCloakResponse | None:
    """Enrich CLOAK Technique

     Look up or search concealment techniques from the CLOAK framework.

    Covers concealment layers for online anonymity — encrypted DNS transports, VPN-over-Tor
    chains, traffic obfuscation. Provide `cloak_id` for a direct lookup (e.g. TTP-496, CLOAK)
    or `search` for discovery. CLOAK objects carry no ATT&CK references, so there are no
    linked techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full CLOAK object with description (the corpus has no kill-chain phases)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the concealment technique

    Args:
        body (EnrichCloakRequest): Look up or search concealment techniques from the CLOAK
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCloakResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCloakRequest,
) -> Response[Any | EnrichCloakResponse]:
    """Enrich CLOAK Technique

     Look up or search concealment techniques from the CLOAK framework.

    Covers concealment layers for online anonymity — encrypted DNS transports, VPN-over-Tor
    chains, traffic obfuscation. Provide `cloak_id` for a direct lookup (e.g. TTP-496, CLOAK)
    or `search` for discovery. CLOAK objects carry no ATT&CK references, so there are no
    linked techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full CLOAK object with description (the corpus has no kill-chain phases)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the concealment technique

    Args:
        body (EnrichCloakRequest): Look up or search concealment techniques from the CLOAK
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCloakResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichCloakRequest,
) -> Any | EnrichCloakResponse | None:
    """Enrich CLOAK Technique

     Look up or search concealment techniques from the CLOAK framework.

    Covers concealment layers for online anonymity — encrypted DNS transports, VPN-over-Tor
    chains, traffic obfuscation. Provide `cloak_id` for a direct lookup (e.g. TTP-496, CLOAK)
    or `search` for discovery. CLOAK objects carry no ATT&CK references, so there are no
    linked techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full CLOAK object with description (the corpus has no kill-chain phases)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the concealment technique

    Args:
        body (EnrichCloakRequest): Look up or search concealment techniques from the CLOAK
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCloakResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
