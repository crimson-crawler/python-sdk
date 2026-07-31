from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_d3fend_request import SearchD3FENDRequest
from ...models.search_d3fend_response import SearchD3FENDResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchD3FENDRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/d3fend",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchD3FENDResponse | None:
    if response.status_code == 200:
        response_200 = SearchD3FENDResponse.from_dict(response.json())

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
) -> Response[Any | SearchD3FENDResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchD3FENDRequest,
) -> Response[Any | SearchD3FENDResponse]:
    """Search D3FEND

     Search D3FEND defensive techniques and countermeasures.

    Find defensive techniques by name or description. Each result carries a count of the ATT&CK
    techniques it
    counters.

    **Form filters**

    - `tactic` — defensive tactic
    - `mitigation` — defensive mitigation
    - `sub-mitigation` — defensive sub-mitigation
    - `artifact` — digital artifact

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchD3FENDRequest): Search D3FEND defensive techniques by text.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchD3FENDResponse]
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
    body: SearchD3FENDRequest,
) -> Any | SearchD3FENDResponse | None:
    """Search D3FEND

     Search D3FEND defensive techniques and countermeasures.

    Find defensive techniques by name or description. Each result carries a count of the ATT&CK
    techniques it
    counters.

    **Form filters**

    - `tactic` — defensive tactic
    - `mitigation` — defensive mitigation
    - `sub-mitigation` — defensive sub-mitigation
    - `artifact` — digital artifact

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchD3FENDRequest): Search D3FEND defensive techniques by text.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchD3FENDResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchD3FENDRequest,
) -> Response[Any | SearchD3FENDResponse]:
    """Search D3FEND

     Search D3FEND defensive techniques and countermeasures.

    Find defensive techniques by name or description. Each result carries a count of the ATT&CK
    techniques it
    counters.

    **Form filters**

    - `tactic` — defensive tactic
    - `mitigation` — defensive mitigation
    - `sub-mitigation` — defensive sub-mitigation
    - `artifact` — digital artifact

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchD3FENDRequest): Search D3FEND defensive techniques by text.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchD3FENDResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchD3FENDRequest,
) -> Any | SearchD3FENDResponse | None:
    """Search D3FEND

     Search D3FEND defensive techniques and countermeasures.

    Find defensive techniques by name or description. Each result carries a count of the ATT&CK
    techniques it
    counters.

    **Form filters**

    - `tactic` — defensive tactic
    - `mitigation` — defensive mitigation
    - `sub-mitigation` — defensive sub-mitigation
    - `artifact` — digital artifact

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchD3FENDRequest): Search D3FEND defensive techniques by text.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchD3FENDResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
