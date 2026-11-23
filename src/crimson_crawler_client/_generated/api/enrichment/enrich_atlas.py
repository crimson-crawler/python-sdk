from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_atlas_request import EnrichATLASRequest
from ...models.enrich_atlas_response import EnrichATLASResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichATLASRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/atlas",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichATLASResponse | None:
    if response.status_code == 200:
        response_200 = EnrichATLASResponse.from_dict(response.json())

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
) -> Response[Any | EnrichATLASResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichATLASRequest,
) -> Response[Any | EnrichATLASResponse]:
    """Enrich ATLAS Technique

     Look up or search adversarial machine learning techniques from the ATLAS knowledge base.

    Covers AI/ML-specific attack techniques including model evasion, data poisoning, and model theft.
    Provide `technique_id` for a direct lookup (e.g. AML.T0043) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full ATLAS technique object with description and procedure examples
    - `techniques` — the ATLAS parent/sub-technique family this object belongs to, resolved
      into full objects from the object's own ATLAS bundle
    - `mitigations` — the ATLAS-native course-of-action objects (AML.M####) this technique is
      joined to, read from the same bundle. Self-sufficient: it does not require `details`
      or `techniques` to be requested alongside it.
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the AI/ML attack

    ATLAS has no ATT&CK-Enterprise-keyed layers: the imported corpus carries no
    ATLAS-to-Enterprise edge, so none are declared on the response.

    Args:
        body (EnrichATLASRequest): Look up or search adversarial machine learning techniques from
            the ATLAS knowledge base.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichATLASResponse]
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
    body: EnrichATLASRequest,
) -> Any | EnrichATLASResponse | None:
    """Enrich ATLAS Technique

     Look up or search adversarial machine learning techniques from the ATLAS knowledge base.

    Covers AI/ML-specific attack techniques including model evasion, data poisoning, and model theft.
    Provide `technique_id` for a direct lookup (e.g. AML.T0043) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full ATLAS technique object with description and procedure examples
    - `techniques` — the ATLAS parent/sub-technique family this object belongs to, resolved
      into full objects from the object's own ATLAS bundle
    - `mitigations` — the ATLAS-native course-of-action objects (AML.M####) this technique is
      joined to, read from the same bundle. Self-sufficient: it does not require `details`
      or `techniques` to be requested alongside it.
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the AI/ML attack

    ATLAS has no ATT&CK-Enterprise-keyed layers: the imported corpus carries no
    ATLAS-to-Enterprise edge, so none are declared on the response.

    Args:
        body (EnrichATLASRequest): Look up or search adversarial machine learning techniques from
            the ATLAS knowledge base.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichATLASResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichATLASRequest,
) -> Response[Any | EnrichATLASResponse]:
    """Enrich ATLAS Technique

     Look up or search adversarial machine learning techniques from the ATLAS knowledge base.

    Covers AI/ML-specific attack techniques including model evasion, data poisoning, and model theft.
    Provide `technique_id` for a direct lookup (e.g. AML.T0043) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full ATLAS technique object with description and procedure examples
    - `techniques` — the ATLAS parent/sub-technique family this object belongs to, resolved
      into full objects from the object's own ATLAS bundle
    - `mitigations` — the ATLAS-native course-of-action objects (AML.M####) this technique is
      joined to, read from the same bundle. Self-sufficient: it does not require `details`
      or `techniques` to be requested alongside it.
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the AI/ML attack

    ATLAS has no ATT&CK-Enterprise-keyed layers: the imported corpus carries no
    ATLAS-to-Enterprise edge, so none are declared on the response.

    Args:
        body (EnrichATLASRequest): Look up or search adversarial machine learning techniques from
            the ATLAS knowledge base.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichATLASResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichATLASRequest,
) -> Any | EnrichATLASResponse | None:
    """Enrich ATLAS Technique

     Look up or search adversarial machine learning techniques from the ATLAS knowledge base.

    Covers AI/ML-specific attack techniques including model evasion, data poisoning, and model theft.
    Provide `technique_id` for a direct lookup (e.g. AML.T0043) or `search` for discovery.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected technique.

    **Include options**

    - `details` — full ATLAS technique object with description and procedure examples
    - `techniques` — the ATLAS parent/sub-technique family this object belongs to, resolved
      into full objects from the object's own ATLAS bundle
    - `mitigations` — the ATLAS-native course-of-action objects (AML.M####) this technique is
      joined to, read from the same bundle. Self-sufficient: it does not require `details`
      or `techniques` to be requested alongside it.
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated executive brief covering the AI/ML attack

    ATLAS has no ATT&CK-Enterprise-keyed layers: the imported corpus carries no
    ATLAS-to-Enterprise edge, so none are declared on the response.

    Args:
        body (EnrichATLASRequest): Look up or search adversarial machine learning techniques from
            the ATLAS knowledge base.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichATLASResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
