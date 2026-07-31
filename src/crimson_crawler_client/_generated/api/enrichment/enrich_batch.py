from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_batch_request import EnrichBatchRequest
from ...models.enrich_batch_response import EnrichBatchResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichBatchRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/batch",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichBatchResponse | None:
    if response.status_code == 200:
        response_200 = EnrichBatchResponse.from_dict(response.json())

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
) -> Response[Any | EnrichBatchResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichBatchRequest,
) -> Response[Any | EnrichBatchResponse]:
    r"""Enrich Mixed Batch

     Batch-run multiple enrich/* lookups in one request, preserving input order.

    Accepts 1-50 items; the 51st is rejected with HTTP 422. Each item carries a `type` discriminator
    naming the enrichment type, that type's identifier fields, and its own per-type `include` list.
    Each result follows the same response contract as its dedicated single-entity endpoint.

    There is no batch-level `include` — each item drives its own enrichment depth via the include list
    of the single-entity type it names. See that type's `/v1/enrich/*` endpoint for its include options.

    **Supported types**

    Each of the 16 maps 1:1 to a `/v1/enrich/*` endpoint:

    - `cve`, `product`, `package`, `cwe`, `capec`, `technique`, `ioc`, `group`
    - `software`, `campaign`, `atlas`, `disarm`, `location`, `sector`, `defend`, `poc_source`

    Partial failure is isolated: one item failing does not fail the batch. Each result reports
    `status=\"ok\"` (the enrichment ran — per-layer partial failures stay inside `data.errors`) or
    `status=\"error\"` (the item dispatch itself raised, with details in the item's `errors`). Results
    preserve input order.

    A batch consumes one request unit.

    Args:
        body (EnrichBatchRequest): Batch-run up to 50 enrich/* lookups in one request.

            Each item carries a `type` discriminator naming one of the 16 enrich types
            plus that type's identifier fields and its own per-type `include` list. The
            51st item is rejected with HTTP 422 via the `max_length` constraint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichBatchResponse]
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
    body: EnrichBatchRequest,
) -> Any | EnrichBatchResponse | None:
    r"""Enrich Mixed Batch

     Batch-run multiple enrich/* lookups in one request, preserving input order.

    Accepts 1-50 items; the 51st is rejected with HTTP 422. Each item carries a `type` discriminator
    naming the enrichment type, that type's identifier fields, and its own per-type `include` list.
    Each result follows the same response contract as its dedicated single-entity endpoint.

    There is no batch-level `include` — each item drives its own enrichment depth via the include list
    of the single-entity type it names. See that type's `/v1/enrich/*` endpoint for its include options.

    **Supported types**

    Each of the 16 maps 1:1 to a `/v1/enrich/*` endpoint:

    - `cve`, `product`, `package`, `cwe`, `capec`, `technique`, `ioc`, `group`
    - `software`, `campaign`, `atlas`, `disarm`, `location`, `sector`, `defend`, `poc_source`

    Partial failure is isolated: one item failing does not fail the batch. Each result reports
    `status=\"ok\"` (the enrichment ran — per-layer partial failures stay inside `data.errors`) or
    `status=\"error\"` (the item dispatch itself raised, with details in the item's `errors`). Results
    preserve input order.

    A batch consumes one request unit.

    Args:
        body (EnrichBatchRequest): Batch-run up to 50 enrich/* lookups in one request.

            Each item carries a `type` discriminator naming one of the 16 enrich types
            plus that type's identifier fields and its own per-type `include` list. The
            51st item is rejected with HTTP 422 via the `max_length` constraint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichBatchResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichBatchRequest,
) -> Response[Any | EnrichBatchResponse]:
    r"""Enrich Mixed Batch

     Batch-run multiple enrich/* lookups in one request, preserving input order.

    Accepts 1-50 items; the 51st is rejected with HTTP 422. Each item carries a `type` discriminator
    naming the enrichment type, that type's identifier fields, and its own per-type `include` list.
    Each result follows the same response contract as its dedicated single-entity endpoint.

    There is no batch-level `include` — each item drives its own enrichment depth via the include list
    of the single-entity type it names. See that type's `/v1/enrich/*` endpoint for its include options.

    **Supported types**

    Each of the 16 maps 1:1 to a `/v1/enrich/*` endpoint:

    - `cve`, `product`, `package`, `cwe`, `capec`, `technique`, `ioc`, `group`
    - `software`, `campaign`, `atlas`, `disarm`, `location`, `sector`, `defend`, `poc_source`

    Partial failure is isolated: one item failing does not fail the batch. Each result reports
    `status=\"ok\"` (the enrichment ran — per-layer partial failures stay inside `data.errors`) or
    `status=\"error\"` (the item dispatch itself raised, with details in the item's `errors`). Results
    preserve input order.

    A batch consumes one request unit.

    Args:
        body (EnrichBatchRequest): Batch-run up to 50 enrich/* lookups in one request.

            Each item carries a `type` discriminator naming one of the 16 enrich types
            plus that type's identifier fields and its own per-type `include` list. The
            51st item is rejected with HTTP 422 via the `max_length` constraint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichBatchResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichBatchRequest,
) -> Any | EnrichBatchResponse | None:
    r"""Enrich Mixed Batch

     Batch-run multiple enrich/* lookups in one request, preserving input order.

    Accepts 1-50 items; the 51st is rejected with HTTP 422. Each item carries a `type` discriminator
    naming the enrichment type, that type's identifier fields, and its own per-type `include` list.
    Each result follows the same response contract as its dedicated single-entity endpoint.

    There is no batch-level `include` — each item drives its own enrichment depth via the include list
    of the single-entity type it names. See that type's `/v1/enrich/*` endpoint for its include options.

    **Supported types**

    Each of the 16 maps 1:1 to a `/v1/enrich/*` endpoint:

    - `cve`, `product`, `package`, `cwe`, `capec`, `technique`, `ioc`, `group`
    - `software`, `campaign`, `atlas`, `disarm`, `location`, `sector`, `defend`, `poc_source`

    Partial failure is isolated: one item failing does not fail the batch. Each result reports
    `status=\"ok\"` (the enrichment ran — per-layer partial failures stay inside `data.errors`) or
    `status=\"error\"` (the item dispatch itself raised, with details in the item's `errors`). Results
    preserve input order.

    A batch consumes one request unit.

    Args:
        body (EnrichBatchRequest): Batch-run up to 50 enrich/* lookups in one request.

            Each item carries a `type` discriminator naming one of the 16 enrich types
            plus that type's identifier fields and its own per-type `include` list. The
            51st item is rejected with HTTP 422 via the `max_length` constraint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichBatchResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
