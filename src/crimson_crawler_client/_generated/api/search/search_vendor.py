from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_vendor_request import SearchVendorRequest
from ...models.search_vendor_response import SearchVendorResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchVendorRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/vendor",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchVendorResponse | None:
    if response.status_code == 200:
        response_200 = SearchVendorResponse.from_dict(response.json())

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
) -> Response[Any | SearchVendorResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchVendorRequest,
) -> Response[Any | SearchVendorResponse]:
    """Search Vendor Products

     List products from a vendor, or enumerate the vendor directory.

    Pass `vendor` for up to `limit` known products from the CPE dictionary — pass a returned CPE
    string to `/v1/search/cve` as the `cpe` filter to find vulnerabilities for that product. A
    multi-version product contributes one row per CPE entry, and `total_products` counts the
    distinct products those rows represent. Omit `vendor` (optionally with `q`) to enumerate the
    CPE vendor directory with product counts.

    The `errors` array reports any partial failures.

    Args:
        body (SearchVendorRequest): List products from a vendor, or enumerate the vendor
            directory.

            Two modes on one surface: pass `vendor` for that vendor's product catalogue; omit it
            (optionally
            with `q`) to enumerate the CPE vendor directory — 22,364 vendors with their product
            counts, the
            discovery half that had no consumer path (`search_cpe_vendors` was written and never
            called).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchVendorResponse]
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
    body: SearchVendorRequest,
) -> Any | SearchVendorResponse | None:
    """Search Vendor Products

     List products from a vendor, or enumerate the vendor directory.

    Pass `vendor` for up to `limit` known products from the CPE dictionary — pass a returned CPE
    string to `/v1/search/cve` as the `cpe` filter to find vulnerabilities for that product. A
    multi-version product contributes one row per CPE entry, and `total_products` counts the
    distinct products those rows represent. Omit `vendor` (optionally with `q`) to enumerate the
    CPE vendor directory with product counts.

    The `errors` array reports any partial failures.

    Args:
        body (SearchVendorRequest): List products from a vendor, or enumerate the vendor
            directory.

            Two modes on one surface: pass `vendor` for that vendor's product catalogue; omit it
            (optionally
            with `q`) to enumerate the CPE vendor directory — 22,364 vendors with their product
            counts, the
            discovery half that had no consumer path (`search_cpe_vendors` was written and never
            called).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchVendorResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchVendorRequest,
) -> Response[Any | SearchVendorResponse]:
    """Search Vendor Products

     List products from a vendor, or enumerate the vendor directory.

    Pass `vendor` for up to `limit` known products from the CPE dictionary — pass a returned CPE
    string to `/v1/search/cve` as the `cpe` filter to find vulnerabilities for that product. A
    multi-version product contributes one row per CPE entry, and `total_products` counts the
    distinct products those rows represent. Omit `vendor` (optionally with `q`) to enumerate the
    CPE vendor directory with product counts.

    The `errors` array reports any partial failures.

    Args:
        body (SearchVendorRequest): List products from a vendor, or enumerate the vendor
            directory.

            Two modes on one surface: pass `vendor` for that vendor's product catalogue; omit it
            (optionally
            with `q`) to enumerate the CPE vendor directory — 22,364 vendors with their product
            counts, the
            discovery half that had no consumer path (`search_cpe_vendors` was written and never
            called).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchVendorResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchVendorRequest,
) -> Any | SearchVendorResponse | None:
    """Search Vendor Products

     List products from a vendor, or enumerate the vendor directory.

    Pass `vendor` for up to `limit` known products from the CPE dictionary — pass a returned CPE
    string to `/v1/search/cve` as the `cpe` filter to find vulnerabilities for that product. A
    multi-version product contributes one row per CPE entry, and `total_products` counts the
    distinct products those rows represent. Omit `vendor` (optionally with `q`) to enumerate the
    CPE vendor directory with product counts.

    The `errors` array reports any partial failures.

    Args:
        body (SearchVendorRequest): List products from a vendor, or enumerate the vendor
            directory.

            Two modes on one surface: pass `vendor` for that vendor's product catalogue; omit it
            (optionally
            with `q`) to enumerate the CPE vendor directory — 22,364 vendors with their product
            counts, the
            discovery half that had no consumer path (`search_cpe_vendors` was written and never
            called).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchVendorResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
