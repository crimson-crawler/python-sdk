from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_software_request import EnrichSoftwareRequest
from ...models.enrich_software_response import EnrichSoftwareResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichSoftwareRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/software",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichSoftwareResponse | None:
    if response.status_code == 200:
        response_200 = EnrichSoftwareResponse.from_dict(response.json())

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
) -> Response[Any | EnrichSoftwareResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichSoftwareRequest,
) -> Response[Any | EnrichSoftwareResponse]:
    """Enrich Malware or Tool

     Look up or search malware and tools with their techniques and associated groups.

    Provide `software_id` for a direct lookup (e.g. S0154 for Cobalt Strike) or `search` for text-based
    discovery by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default
    `enterprise`). Returns the software profile with ATT&CK techniques and known user groups.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected software.

    **Include options**

    - `details` — full software profile (type, description, associated groups, techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `groups` — threat actor groups that use this software
    - `campaigns` — threat campaigns that used this software
    - `tie` — technique likelihood predictions for this software's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the software's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the software's techniques
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for malware analysis reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the software's capabilities and detection
    priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the software's
    techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichSoftwareRequest): Look up or search malware and tools with their techniques
            and associated groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichSoftwareResponse]
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
    body: EnrichSoftwareRequest,
) -> Any | EnrichSoftwareResponse | None:
    """Enrich Malware or Tool

     Look up or search malware and tools with their techniques and associated groups.

    Provide `software_id` for a direct lookup (e.g. S0154 for Cobalt Strike) or `search` for text-based
    discovery by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default
    `enterprise`). Returns the software profile with ATT&CK techniques and known user groups.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected software.

    **Include options**

    - `details` — full software profile (type, description, associated groups, techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `groups` — threat actor groups that use this software
    - `campaigns` — threat campaigns that used this software
    - `tie` — technique likelihood predictions for this software's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the software's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the software's techniques
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for malware analysis reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the software's capabilities and detection
    priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the software's
    techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichSoftwareRequest): Look up or search malware and tools with their techniques
            and associated groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichSoftwareResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichSoftwareRequest,
) -> Response[Any | EnrichSoftwareResponse]:
    """Enrich Malware or Tool

     Look up or search malware and tools with their techniques and associated groups.

    Provide `software_id` for a direct lookup (e.g. S0154 for Cobalt Strike) or `search` for text-based
    discovery by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default
    `enterprise`). Returns the software profile with ATT&CK techniques and known user groups.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected software.

    **Include options**

    - `details` — full software profile (type, description, associated groups, techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `groups` — threat actor groups that use this software
    - `campaigns` — threat campaigns that used this software
    - `tie` — technique likelihood predictions for this software's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the software's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the software's techniques
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for malware analysis reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the software's capabilities and detection
    priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the software's
    techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichSoftwareRequest): Look up or search malware and tools with their techniques
            and associated groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichSoftwareResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichSoftwareRequest,
) -> Any | EnrichSoftwareResponse | None:
    """Enrich Malware or Tool

     Look up or search malware and tools with their techniques and associated groups.

    Provide `software_id` for a direct lookup (e.g. S0154 for Cobalt Strike) or `search` for text-based
    discovery by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default
    `enterprise`). Returns the software profile with ATT&CK techniques and known user groups.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected software.

    **Include options**

    - `details` — full software profile (type, description, associated groups, techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `groups` — threat actor groups that use this software
    - `campaigns` — threat campaigns that used this software
    - `tie` — technique likelihood predictions for this software's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the software's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the software's techniques
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for malware analysis reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the software's capabilities and detection
    priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the software's
    techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichSoftwareRequest): Look up or search malware and tools with their techniques
            and associated groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichSoftwareResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
