from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_knowledgebase_request import SearchKnowledgebaseRequest
from ...models.search_knowledgebase_response import SearchKnowledgebaseResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchKnowledgebaseRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/knowledgebase",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchKnowledgebaseResponse | None:
    if response.status_code == 200:
        response_200 = SearchKnowledgebaseResponse.from_dict(response.json())

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
) -> Response[Any | SearchKnowledgebaseResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchKnowledgebaseRequest,
) -> Response[Any | SearchKnowledgebaseResponse]:
    """Search Knowledge Base

     Search the knowledge base using natural language queries.

    Find relevant threat intelligence, research, and analysis across the knowledge base. Adjust `alpha`
    to tune search relevance from `0.0` (keyword-only) to `1.0` (semantic-only).

    **Collections**

    - `red_team` — adversarial tradecraft playbooks (default)
    - `main` — general knowledge base content
    - `large` — extended corpus
    - `user` — user-uploaded content

    Each result carries a relevance score. The `errors` array reports any partial failures.

    Args:
        body (SearchKnowledgebaseRequest): Search the knowledge base using natural language
            queries.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchKnowledgebaseResponse]
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
    body: SearchKnowledgebaseRequest,
) -> Any | SearchKnowledgebaseResponse | None:
    """Search Knowledge Base

     Search the knowledge base using natural language queries.

    Find relevant threat intelligence, research, and analysis across the knowledge base. Adjust `alpha`
    to tune search relevance from `0.0` (keyword-only) to `1.0` (semantic-only).

    **Collections**

    - `red_team` — adversarial tradecraft playbooks (default)
    - `main` — general knowledge base content
    - `large` — extended corpus
    - `user` — user-uploaded content

    Each result carries a relevance score. The `errors` array reports any partial failures.

    Args:
        body (SearchKnowledgebaseRequest): Search the knowledge base using natural language
            queries.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchKnowledgebaseResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchKnowledgebaseRequest,
) -> Response[Any | SearchKnowledgebaseResponse]:
    """Search Knowledge Base

     Search the knowledge base using natural language queries.

    Find relevant threat intelligence, research, and analysis across the knowledge base. Adjust `alpha`
    to tune search relevance from `0.0` (keyword-only) to `1.0` (semantic-only).

    **Collections**

    - `red_team` — adversarial tradecraft playbooks (default)
    - `main` — general knowledge base content
    - `large` — extended corpus
    - `user` — user-uploaded content

    Each result carries a relevance score. The `errors` array reports any partial failures.

    Args:
        body (SearchKnowledgebaseRequest): Search the knowledge base using natural language
            queries.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchKnowledgebaseResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchKnowledgebaseRequest,
) -> Any | SearchKnowledgebaseResponse | None:
    """Search Knowledge Base

     Search the knowledge base using natural language queries.

    Find relevant threat intelligence, research, and analysis across the knowledge base. Adjust `alpha`
    to tune search relevance from `0.0` (keyword-only) to `1.0` (semantic-only).

    **Collections**

    - `red_team` — adversarial tradecraft playbooks (default)
    - `main` — general knowledge base content
    - `large` — extended corpus
    - `user` — user-uploaded content

    Each result carries a relevance score. The `errors` array reports any partial failures.

    Args:
        body (SearchKnowledgebaseRequest): Search the knowledge base using natural language
            queries.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchKnowledgebaseResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
