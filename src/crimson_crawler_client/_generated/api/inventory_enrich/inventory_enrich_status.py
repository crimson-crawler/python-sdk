from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.inventory_enrichment_job_response import InventoryEnrichmentJobResponse
from ...types import UNSET, Response


def _get_kwargs(
    enrichment_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v1/inventory-enrich/{enrichment_id}".format(
            enrichment_id=quote(str(enrichment_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | InventoryEnrichmentJobResponse | None:
    if response.status_code == 200:
        response_200 = InventoryEnrichmentJobResponse.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = cast(Any, None)
        return response_401

    if response.status_code == 404:
        response_404 = cast(Any, None)
        return response_404

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
) -> Response[Any | InventoryEnrichmentJobResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    enrichment_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | InventoryEnrichmentJobResponse]:
    """Get Inventory Enrichment Status

     Poll an Inventory Enrichment until it finishes.

    Returns overall `progress`, ordered stage and substage progress, a rolling event feed, and one
    of these states:

    - `queued`: waiting for a slot; `queue_position` is the number of jobs ahead
    - `running`: enrichment is in progress
    - `done`: `result` contains per-asset findings, remediation data, and the portfolio rollup
    - `error`: `error` contains the terminal failure

    Polling consumes no request units. Use the same API key used to submit the job. A missing,
    expired, malformed, or owner-hidden identifier returns 404 or 422 as documented below.

    Args:
        enrichment_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | InventoryEnrichmentJobResponse]
    """

    kwargs = _get_kwargs(
        enrichment_id=enrichment_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    enrichment_id: str,
    *,
    client: AuthenticatedClient,
) -> Any | InventoryEnrichmentJobResponse | None:
    """Get Inventory Enrichment Status

     Poll an Inventory Enrichment until it finishes.

    Returns overall `progress`, ordered stage and substage progress, a rolling event feed, and one
    of these states:

    - `queued`: waiting for a slot; `queue_position` is the number of jobs ahead
    - `running`: enrichment is in progress
    - `done`: `result` contains per-asset findings, remediation data, and the portfolio rollup
    - `error`: `error` contains the terminal failure

    Polling consumes no request units. Use the same API key used to submit the job. A missing,
    expired, malformed, or owner-hidden identifier returns 404 or 422 as documented below.

    Args:
        enrichment_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | InventoryEnrichmentJobResponse
    """

    return sync_detailed(
        enrichment_id=enrichment_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    enrichment_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | InventoryEnrichmentJobResponse]:
    """Get Inventory Enrichment Status

     Poll an Inventory Enrichment until it finishes.

    Returns overall `progress`, ordered stage and substage progress, a rolling event feed, and one
    of these states:

    - `queued`: waiting for a slot; `queue_position` is the number of jobs ahead
    - `running`: enrichment is in progress
    - `done`: `result` contains per-asset findings, remediation data, and the portfolio rollup
    - `error`: `error` contains the terminal failure

    Polling consumes no request units. Use the same API key used to submit the job. A missing,
    expired, malformed, or owner-hidden identifier returns 404 or 422 as documented below.

    Args:
        enrichment_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | InventoryEnrichmentJobResponse]
    """

    kwargs = _get_kwargs(
        enrichment_id=enrichment_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    enrichment_id: str,
    *,
    client: AuthenticatedClient,
) -> Any | InventoryEnrichmentJobResponse | None:
    """Get Inventory Enrichment Status

     Poll an Inventory Enrichment until it finishes.

    Returns overall `progress`, ordered stage and substage progress, a rolling event feed, and one
    of these states:

    - `queued`: waiting for a slot; `queue_position` is the number of jobs ahead
    - `running`: enrichment is in progress
    - `done`: `result` contains per-asset findings, remediation data, and the portfolio rollup
    - `error`: `error` contains the terminal failure

    Polling consumes no request units. Use the same API key used to submit the job. A missing,
    expired, malformed, or owner-hidden identifier returns 404 or 422 as documented below.

    Args:
        enrichment_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | InventoryEnrichmentJobResponse
    """

    return (
        await asyncio_detailed(
            enrichment_id=enrichment_id,
            client=client,
        )
    ).parsed
