from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_csaf_request import SearchCSAFRequest
from ...models.search_csaf_response import SearchCSAFResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchCSAFRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/csaf",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchCSAFResponse | None:
    if response.status_code == 200:
        response_200 = SearchCSAFResponse.from_dict(response.json())

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
) -> Response[Any | SearchCSAFResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchCSAFRequest,
) -> Response[Any | SearchCSAFResponse]:
    """Search Csaf

     Search the seeded CSAF vendor-advisory corpus.

    Filters combine with AND; omitted filters are ignored. This is the consumer door for
    CVE-less advisories (vendor/product/sector search), which `enrich/cve` cannot reach.

    **Filters**

    - `cve_id`, `advisory_id`, `publisher`, `sector`, `product`, `cpe`, `tlp`
    - `sort` (`newest`/`oldest`), `limit` (1-100), `page`

    A present, empty corpus returns `200` with `advisories: []`; a missing or unreadable table returns
    the same empty body plus an `errors[]` entry. The `advisories[]` list is paginated, while
    `total` is the unpaginated match count.

    Args:
        body (SearchCSAFRequest): Search the seeded CSAF advisory corpus (vendor/product/sector,
            including CVE-less advisories).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchCSAFResponse]
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
    body: SearchCSAFRequest,
) -> Any | SearchCSAFResponse | None:
    """Search Csaf

     Search the seeded CSAF vendor-advisory corpus.

    Filters combine with AND; omitted filters are ignored. This is the consumer door for
    CVE-less advisories (vendor/product/sector search), which `enrich/cve` cannot reach.

    **Filters**

    - `cve_id`, `advisory_id`, `publisher`, `sector`, `product`, `cpe`, `tlp`
    - `sort` (`newest`/`oldest`), `limit` (1-100), `page`

    A present, empty corpus returns `200` with `advisories: []`; a missing or unreadable table returns
    the same empty body plus an `errors[]` entry. The `advisories[]` list is paginated, while
    `total` is the unpaginated match count.

    Args:
        body (SearchCSAFRequest): Search the seeded CSAF advisory corpus (vendor/product/sector,
            including CVE-less advisories).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchCSAFResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchCSAFRequest,
) -> Response[Any | SearchCSAFResponse]:
    """Search Csaf

     Search the seeded CSAF vendor-advisory corpus.

    Filters combine with AND; omitted filters are ignored. This is the consumer door for
    CVE-less advisories (vendor/product/sector search), which `enrich/cve` cannot reach.

    **Filters**

    - `cve_id`, `advisory_id`, `publisher`, `sector`, `product`, `cpe`, `tlp`
    - `sort` (`newest`/`oldest`), `limit` (1-100), `page`

    A present, empty corpus returns `200` with `advisories: []`; a missing or unreadable table returns
    the same empty body plus an `errors[]` entry. The `advisories[]` list is paginated, while
    `total` is the unpaginated match count.

    Args:
        body (SearchCSAFRequest): Search the seeded CSAF advisory corpus (vendor/product/sector,
            including CVE-less advisories).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchCSAFResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchCSAFRequest,
) -> Any | SearchCSAFResponse | None:
    """Search Csaf

     Search the seeded CSAF vendor-advisory corpus.

    Filters combine with AND; omitted filters are ignored. This is the consumer door for
    CVE-less advisories (vendor/product/sector search), which `enrich/cve` cannot reach.

    **Filters**

    - `cve_id`, `advisory_id`, `publisher`, `sector`, `product`, `cpe`, `tlp`
    - `sort` (`newest`/`oldest`), `limit` (1-100), `page`

    A present, empty corpus returns `200` with `advisories: []`; a missing or unreadable table returns
    the same empty body plus an `errors[]` entry. The `advisories[]` list is paginated, while
    `total` is the unpaginated match count.

    Args:
        body (SearchCSAFRequest): Search the seeded CSAF advisory corpus (vendor/product/sector,
            including CVE-less advisories).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchCSAFResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
