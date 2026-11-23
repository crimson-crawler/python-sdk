from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_disarm_request import EnrichDISARMRequest
from ...models.enrich_disarm_response import EnrichDISARMResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichDISARMRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/disarm",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichDISARMResponse | None:
    if response.status_code == 200:
        response_200 = EnrichDISARMResponse.from_dict(response.json())

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
) -> Response[Any | EnrichDISARMResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichDISARMRequest,
) -> Response[Any | EnrichDISARMResponse]:
    """Enrich DISARM Technique

     Look up or search disinformation techniques from the DISARM framework.

    Covers influence operation tactics and techniques. Provide `technique_id` for a direct lookup
    (e.g. T0002) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full DISARM technique object with description and tactic context
    - `techniques` — the DISARM parent/sub-technique family this object belongs to, resolved into
      full objects from the object's own DISARM bundle
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the disinformation technique

    DISARM has no ATT&CK-Enterprise-keyed layers: its 410-object corpus is attack-pattern (388) +
    x-mitre-tactic (20) + identity + marking-definition, so groups/software/campaigns/mitigations/
    detections/defend, TIE predictions and a Navigator layer have no source and are not declared
    (Navigator loads enterprise/mobile/ICS ATT&CK layers only).

    Args:
        body (EnrichDISARMRequest): Look up or search disinformation techniques from the DISARM
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichDISARMResponse]
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
    body: EnrichDISARMRequest,
) -> Any | EnrichDISARMResponse | None:
    """Enrich DISARM Technique

     Look up or search disinformation techniques from the DISARM framework.

    Covers influence operation tactics and techniques. Provide `technique_id` for a direct lookup
    (e.g. T0002) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full DISARM technique object with description and tactic context
    - `techniques` — the DISARM parent/sub-technique family this object belongs to, resolved into
      full objects from the object's own DISARM bundle
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the disinformation technique

    DISARM has no ATT&CK-Enterprise-keyed layers: its 410-object corpus is attack-pattern (388) +
    x-mitre-tactic (20) + identity + marking-definition, so groups/software/campaigns/mitigations/
    detections/defend, TIE predictions and a Navigator layer have no source and are not declared
    (Navigator loads enterprise/mobile/ICS ATT&CK layers only).

    Args:
        body (EnrichDISARMRequest): Look up or search disinformation techniques from the DISARM
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichDISARMResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichDISARMRequest,
) -> Response[Any | EnrichDISARMResponse]:
    """Enrich DISARM Technique

     Look up or search disinformation techniques from the DISARM framework.

    Covers influence operation tactics and techniques. Provide `technique_id` for a direct lookup
    (e.g. T0002) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full DISARM technique object with description and tactic context
    - `techniques` — the DISARM parent/sub-technique family this object belongs to, resolved into
      full objects from the object's own DISARM bundle
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the disinformation technique

    DISARM has no ATT&CK-Enterprise-keyed layers: its 410-object corpus is attack-pattern (388) +
    x-mitre-tactic (20) + identity + marking-definition, so groups/software/campaigns/mitigations/
    detections/defend, TIE predictions and a Navigator layer have no source and are not declared
    (Navigator loads enterprise/mobile/ICS ATT&CK layers only).

    Args:
        body (EnrichDISARMRequest): Look up or search disinformation techniques from the DISARM
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichDISARMResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichDISARMRequest,
) -> Any | EnrichDISARMResponse | None:
    """Enrich DISARM Technique

     Look up or search disinformation techniques from the DISARM framework.

    Covers influence operation tactics and techniques. Provide `technique_id` for a direct lookup
    (e.g. T0002) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full DISARM technique object with description and tactic context
    - `techniques` — the DISARM parent/sub-technique family this object belongs to, resolved into
      full objects from the object's own DISARM bundle
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the disinformation technique

    DISARM has no ATT&CK-Enterprise-keyed layers: its 410-object corpus is attack-pattern (388) +
    x-mitre-tactic (20) + identity + marking-definition, so groups/software/campaigns/mitigations/
    detections/defend, TIE predictions and a Navigator layer have no source and are not declared
    (Navigator loads enterprise/mobile/ICS ATT&CK layers only).

    Args:
        body (EnrichDISARMRequest): Look up or search disinformation techniques from the DISARM
            framework.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichDISARMResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
