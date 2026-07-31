from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_technique_request import EnrichTechniqueRequest
from ...models.enrich_technique_response import EnrichTechniqueResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichTechniqueRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/technique",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichTechniqueResponse | None:
    if response.status_code == 200:
        response_200 = EnrichTechniqueResponse.from_dict(response.json())

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
) -> Response[Any | EnrichTechniqueResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichTechniqueRequest,
) -> Response[Any | EnrichTechniqueResponse]:
    """Enrich ATT&CK Technique

     Retrieve ATT&CK technique details with threat predictions and related intelligence.

    Supports a single ID (`technique_id`), batch IDs (`technique_ids`), or text search (`search`),
    across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`). Each technique is
    enriched with threat predictions (TIE) and optionally related intelligence from the knowledge base.
    If all three lookup fields are omitted, the endpoint returns HTTP 200 with an empty technique list.

    **Include options**

    - `details` — full technique object with tactics, mitigations, and detection guidance
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON for visualization
    - `groups` — threat actor groups using the technique
    - `software` — malware and tools using the technique
    - `campaigns` — threat campaigns using the technique
    - `mitigations` — defensive courses of action for the technique
    - `detections` — detection data sources for the technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the technique
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for technique-related research and analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the technique's usage and detection priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the technique,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichTechniqueRequest): Retrieve ATT&CK technique details with threat predictions
            and related intelligence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichTechniqueResponse]
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
    body: EnrichTechniqueRequest,
) -> Any | EnrichTechniqueResponse | None:
    """Enrich ATT&CK Technique

     Retrieve ATT&CK technique details with threat predictions and related intelligence.

    Supports a single ID (`technique_id`), batch IDs (`technique_ids`), or text search (`search`),
    across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`). Each technique is
    enriched with threat predictions (TIE) and optionally related intelligence from the knowledge base.
    If all three lookup fields are omitted, the endpoint returns HTTP 200 with an empty technique list.

    **Include options**

    - `details` — full technique object with tactics, mitigations, and detection guidance
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON for visualization
    - `groups` — threat actor groups using the technique
    - `software` — malware and tools using the technique
    - `campaigns` — threat campaigns using the technique
    - `mitigations` — defensive courses of action for the technique
    - `detections` — detection data sources for the technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the technique
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for technique-related research and analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the technique's usage and detection priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the technique,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichTechniqueRequest): Retrieve ATT&CK technique details with threat predictions
            and related intelligence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichTechniqueResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichTechniqueRequest,
) -> Response[Any | EnrichTechniqueResponse]:
    """Enrich ATT&CK Technique

     Retrieve ATT&CK technique details with threat predictions and related intelligence.

    Supports a single ID (`technique_id`), batch IDs (`technique_ids`), or text search (`search`),
    across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`). Each technique is
    enriched with threat predictions (TIE) and optionally related intelligence from the knowledge base.
    If all three lookup fields are omitted, the endpoint returns HTTP 200 with an empty technique list.

    **Include options**

    - `details` — full technique object with tactics, mitigations, and detection guidance
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON for visualization
    - `groups` — threat actor groups using the technique
    - `software` — malware and tools using the technique
    - `campaigns` — threat campaigns using the technique
    - `mitigations` — defensive courses of action for the technique
    - `detections` — detection data sources for the technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the technique
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for technique-related research and analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the technique's usage and detection priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the technique,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichTechniqueRequest): Retrieve ATT&CK technique details with threat predictions
            and related intelligence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichTechniqueResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichTechniqueRequest,
) -> Any | EnrichTechniqueResponse | None:
    """Enrich ATT&CK Technique

     Retrieve ATT&CK technique details with threat predictions and related intelligence.

    Supports a single ID (`technique_id`), batch IDs (`technique_ids`), or text search (`search`),
    across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`). Each technique is
    enriched with threat predictions (TIE) and optionally related intelligence from the knowledge base.
    If all three lookup fields are omitted, the endpoint returns HTTP 200 with an empty technique list.

    **Include options**

    - `details` — full technique object with tactics, mitigations, and detection guidance
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON for visualization
    - `groups` — threat actor groups using the technique
    - `software` — malware and tools using the technique
    - `campaigns` — threat campaigns using the technique
    - `mitigations` — defensive courses of action for the technique
    - `detections` — detection data sources for the technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the technique
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for technique-related research and analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the technique's usage and detection priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the technique,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichTechniqueRequest): Retrieve ATT&CK technique details with threat predictions
            and related intelligence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichTechniqueResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
