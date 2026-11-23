from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_f3_request import EnrichF3Request
from ...models.enrich_f3_response import EnrichF3Response
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichF3Request,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/f3",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | EnrichF3Response | None:
    if response.status_code == 200:
        response_200 = EnrichF3Response.from_dict(response.json())

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
) -> Response[Any | EnrichF3Response]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichF3Request,
) -> Response[Any | EnrichF3Response]:
    """Enrich F3 Technique

     Look up or search fraud techniques from the MITRE Fight Fraud Framework (F3).

    Covers financial-crime techniques — impersonation, account takeover, payment fraud,
    money-mule recruitment. Provide `f3_id` for a direct lookup (e.g. F1031) or `search` for
    discovery. 43 of the 132 F3 objects borrow a real ATT&CK `T####` id, so `techniques`
    resolves those into full Enterprise ATT&CK techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full F3 object with description and kill-chain tactics
    - `techniques` — linked ATT&CK Enterprise techniques for the F3 objects that borrow a `T####` id
    - `knowledgebase` — related intelligence from the knowledge base
    - `versions` — the object's KB revision history (`revision_history`)
    - `summary` — AI-generated executive brief covering the fraud technique and its kill-chain position

    Args:
        body (EnrichF3Request): Look up or search fraud techniques from the MITRE Fight Fraud
            Framework (F3).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichF3Response]
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
    body: EnrichF3Request,
) -> Any | EnrichF3Response | None:
    """Enrich F3 Technique

     Look up or search fraud techniques from the MITRE Fight Fraud Framework (F3).

    Covers financial-crime techniques — impersonation, account takeover, payment fraud,
    money-mule recruitment. Provide `f3_id` for a direct lookup (e.g. F1031) or `search` for
    discovery. 43 of the 132 F3 objects borrow a real ATT&CK `T####` id, so `techniques`
    resolves those into full Enterprise ATT&CK techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full F3 object with description and kill-chain tactics
    - `techniques` — linked ATT&CK Enterprise techniques for the F3 objects that borrow a `T####` id
    - `knowledgebase` — related intelligence from the knowledge base
    - `versions` — the object's KB revision history (`revision_history`)
    - `summary` — AI-generated executive brief covering the fraud technique and its kill-chain position

    Args:
        body (EnrichF3Request): Look up or search fraud techniques from the MITRE Fight Fraud
            Framework (F3).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichF3Response
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichF3Request,
) -> Response[Any | EnrichF3Response]:
    """Enrich F3 Technique

     Look up or search fraud techniques from the MITRE Fight Fraud Framework (F3).

    Covers financial-crime techniques — impersonation, account takeover, payment fraud,
    money-mule recruitment. Provide `f3_id` for a direct lookup (e.g. F1031) or `search` for
    discovery. 43 of the 132 F3 objects borrow a real ATT&CK `T####` id, so `techniques`
    resolves those into full Enterprise ATT&CK techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full F3 object with description and kill-chain tactics
    - `techniques` — linked ATT&CK Enterprise techniques for the F3 objects that borrow a `T####` id
    - `knowledgebase` — related intelligence from the knowledge base
    - `versions` — the object's KB revision history (`revision_history`)
    - `summary` — AI-generated executive brief covering the fraud technique and its kill-chain position

    Args:
        body (EnrichF3Request): Look up or search fraud techniques from the MITRE Fight Fraud
            Framework (F3).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichF3Response]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichF3Request,
) -> Any | EnrichF3Response | None:
    """Enrich F3 Technique

     Look up or search fraud techniques from the MITRE Fight Fraud Framework (F3).

    Covers financial-crime techniques — impersonation, account takeover, payment fraud,
    money-mule recruitment. Provide `f3_id` for a direct lookup (e.g. F1031) or `search` for
    discovery. 43 of the 132 F3 objects borrow a real ATT&CK `T####` id, so `techniques`
    resolves those into full Enterprise ATT&CK techniques.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full F3 object with description and kill-chain tactics
    - `techniques` — linked ATT&CK Enterprise techniques for the F3 objects that borrow a `T####` id
    - `knowledgebase` — related intelligence from the knowledge base
    - `versions` — the object's KB revision history (`revision_history`)
    - `summary` — AI-generated executive brief covering the fraud technique and its kill-chain position

    Args:
        body (EnrichF3Request): Look up or search fraud techniques from the MITRE Fight Fraud
            Framework (F3).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichF3Response
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
