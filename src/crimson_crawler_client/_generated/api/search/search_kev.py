from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_kev_request import SearchKEVRequest
from ...models.search_kev_response import SearchKEVResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchKEVRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/kev",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchKEVResponse | None:
    if response.status_code == 200:
        response_200 = SearchKEVResponse.from_dict(response.json())

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
) -> Response[Any | SearchKEVResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchKEVRequest,
) -> Response[Any | SearchKEVResponse]:
    """Search CISA KEV

     Search the Known Exploited Vulnerabilities catalog.

    Look up a specific CVE by ID, or browse KEV entries. Each result carries an EPSS score, a public-
    exploit
    count, and a weaponization score.

    **Filters**

    - `cve_id` — check one CVE against the KEV catalog
    - `ransomware_status` — `Known` (confirmed ransomware campaign use) or `Unknown` (unconfirmed)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchKEVRequest): Search the Known Exploited Vulnerabilities catalog for actively
            exploited CVEs.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchKEVResponse]
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
    body: SearchKEVRequest,
) -> Any | SearchKEVResponse | None:
    """Search CISA KEV

     Search the Known Exploited Vulnerabilities catalog.

    Look up a specific CVE by ID, or browse KEV entries. Each result carries an EPSS score, a public-
    exploit
    count, and a weaponization score.

    **Filters**

    - `cve_id` — check one CVE against the KEV catalog
    - `ransomware_status` — `Known` (confirmed ransomware campaign use) or `Unknown` (unconfirmed)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchKEVRequest): Search the Known Exploited Vulnerabilities catalog for actively
            exploited CVEs.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchKEVResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchKEVRequest,
) -> Response[Any | SearchKEVResponse]:
    """Search CISA KEV

     Search the Known Exploited Vulnerabilities catalog.

    Look up a specific CVE by ID, or browse KEV entries. Each result carries an EPSS score, a public-
    exploit
    count, and a weaponization score.

    **Filters**

    - `cve_id` — check one CVE against the KEV catalog
    - `ransomware_status` — `Known` (confirmed ransomware campaign use) or `Unknown` (unconfirmed)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchKEVRequest): Search the Known Exploited Vulnerabilities catalog for actively
            exploited CVEs.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchKEVResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchKEVRequest,
) -> Any | SearchKEVResponse | None:
    """Search CISA KEV

     Search the Known Exploited Vulnerabilities catalog.

    Look up a specific CVE by ID, or browse KEV entries. Each result carries an EPSS score, a public-
    exploit
    count, and a weaponization score.

    **Filters**

    - `cve_id` — check one CVE against the KEV catalog
    - `ransomware_status` — `Known` (confirmed ransomware campaign use) or `Unknown` (unconfirmed)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchKEVRequest): Search the Known Exploited Vulnerabilities catalog for actively
            exploited CVEs.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchKEVResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
