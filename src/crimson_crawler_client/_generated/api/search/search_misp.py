from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_misp_request import SearchMISPRequest
from ...models.search_misp_response import SearchMISPResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchMISPRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/misp",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchMISPResponse | None:
    if response.status_code == 200:
        response_200 = SearchMISPResponse.from_dict(response.json())

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
) -> Response[Any | SearchMISPResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Response[Any | SearchMISPResponse]:
    """Search MISP

     Search your organization's threat intelligence feed.

    Query by indicator value (IP, hash, domain), event description, or event ID. Returns matching threat
    events and associated indicators with actor and malware context. Available on self-hosted
    deployments
    with a connected threat intelligence feed.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — return only attributes flagged for IDS detection (high-confidence indicators)
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search your threat intelligence feed by indicator value, event
            info, or event ID.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchMISPResponse]
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
    body: SearchMISPRequest,
) -> Any | SearchMISPResponse | None:
    """Search MISP

     Search your organization's threat intelligence feed.

    Query by indicator value (IP, hash, domain), event description, or event ID. Returns matching threat
    events and associated indicators with actor and malware context. Available on self-hosted
    deployments
    with a connected threat intelligence feed.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — return only attributes flagged for IDS detection (high-confidence indicators)
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search your threat intelligence feed by indicator value, event
            info, or event ID.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchMISPResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Response[Any | SearchMISPResponse]:
    """Search MISP

     Search your organization's threat intelligence feed.

    Query by indicator value (IP, hash, domain), event description, or event ID. Returns matching threat
    events and associated indicators with actor and malware context. Available on self-hosted
    deployments
    with a connected threat intelligence feed.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — return only attributes flagged for IDS detection (high-confidence indicators)
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search your threat intelligence feed by indicator value, event
            info, or event ID.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchMISPResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchMISPRequest,
) -> Any | SearchMISPResponse | None:
    """Search MISP

     Search your organization's threat intelligence feed.

    Query by indicator value (IP, hash, domain), event description, or event ID. Returns matching threat
    events and associated indicators with actor and malware context. Available on self-hosted
    deployments
    with a connected threat intelligence feed.

    **Filters**

    - `value` — indicator value to match (IP, hash, domain, etc.)
    - `eventinfo` — search events by title or description text
    - `event_id` — look up one event directly by ID
    - `type_attribute` — restrict to one attribute type (e.g. `ip-dst`, `md5`, `domain`)
    - `category` — restrict to one MISP attribute category (e.g. `Network activity`, `Payload delivery`)
    - `tags` — match any of the given tags (supports `tlp:` prefixes and galaxy cluster names)
    - `to_ids` — return only attributes flagged for IDS detection (high-confidence indicators)
    - `threat_level_id` — event threat level: `1` (high), `2` (medium), `3` (low), `4` (undefined)
    - `date_from` / `date_to` — restrict to an event date range (`YYYY-MM-DD`)
    - `published` — restrict to events published by their owning org (excludes analyst drafts)

    Omitted filters are ignored. The `errors` array reports any partial failures.

    Args:
        body (SearchMISPRequest): Search your threat intelligence feed by indicator value, event
            info, or event ID.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchMISPResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
