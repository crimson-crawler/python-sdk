from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_ioc_request import EnrichIOCRequest
from ...models.enrich_ioc_response import EnrichIOCResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichIOCRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/ioc",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichIOCResponse | None:
    if response.status_code == 200:
        response_200 = EnrichIOCResponse.from_dict(response.json())

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
) -> Response[Any | EnrichIOCResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichIOCRequest,
) -> Response[Any | EnrichIOCResponse]:
    """Enrich IOC

     Enrich an indicator of compromise with linked threat events, techniques, and predictions.

    Searches threat intelligence feeds for the indicator (by `value` + `type` — e.g. `ip-dst`, `domain`,
    `sha256`, `url`, `email-src`), extracts linked threat actors and malware, maps to ATT&CK techniques,
    and generates threat predictions. Technique mappings return even when the indicator has sparse data.

    **Include options**

    - `misp_attributes` — matching threat event attributes with event metadata
    - `galaxies` — linked threat actor and malware context, resolved into full Galaxy cluster profiles
    - `techniques` — ATT&CK techniques linked to this indicator
    - `tie` — technique likelihood predictions for resolved techniques
    - `warninglist` — false-positive check against known safe-list entries
    - `sightings` — sighting count across linked events
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per linked technique
    - `detections` — detection data sources per linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `poc` — proof-of-concept exploits from GitHub for any linked CVEs
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat indicator analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the indicator's threat context
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      IOC relationships yield no techniques. These low-confidence analyst hints are never authoritative.
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichIOCRequest): Enrich an indicator of compromise with linked threat events,
            techniques, and predictions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichIOCResponse]
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
    body: EnrichIOCRequest,
) -> Any | EnrichIOCResponse | None:
    """Enrich IOC

     Enrich an indicator of compromise with linked threat events, techniques, and predictions.

    Searches threat intelligence feeds for the indicator (by `value` + `type` — e.g. `ip-dst`, `domain`,
    `sha256`, `url`, `email-src`), extracts linked threat actors and malware, maps to ATT&CK techniques,
    and generates threat predictions. Technique mappings return even when the indicator has sparse data.

    **Include options**

    - `misp_attributes` — matching threat event attributes with event metadata
    - `galaxies` — linked threat actor and malware context, resolved into full Galaxy cluster profiles
    - `techniques` — ATT&CK techniques linked to this indicator
    - `tie` — technique likelihood predictions for resolved techniques
    - `warninglist` — false-positive check against known safe-list entries
    - `sightings` — sighting count across linked events
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per linked technique
    - `detections` — detection data sources per linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `poc` — proof-of-concept exploits from GitHub for any linked CVEs
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat indicator analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the indicator's threat context
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      IOC relationships yield no techniques. These low-confidence analyst hints are never authoritative.
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichIOCRequest): Enrich an indicator of compromise with linked threat events,
            techniques, and predictions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichIOCResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichIOCRequest,
) -> Response[Any | EnrichIOCResponse]:
    """Enrich IOC

     Enrich an indicator of compromise with linked threat events, techniques, and predictions.

    Searches threat intelligence feeds for the indicator (by `value` + `type` — e.g. `ip-dst`, `domain`,
    `sha256`, `url`, `email-src`), extracts linked threat actors and malware, maps to ATT&CK techniques,
    and generates threat predictions. Technique mappings return even when the indicator has sparse data.

    **Include options**

    - `misp_attributes` — matching threat event attributes with event metadata
    - `galaxies` — linked threat actor and malware context, resolved into full Galaxy cluster profiles
    - `techniques` — ATT&CK techniques linked to this indicator
    - `tie` — technique likelihood predictions for resolved techniques
    - `warninglist` — false-positive check against known safe-list entries
    - `sightings` — sighting count across linked events
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per linked technique
    - `detections` — detection data sources per linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `poc` — proof-of-concept exploits from GitHub for any linked CVEs
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat indicator analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the indicator's threat context
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      IOC relationships yield no techniques. These low-confidence analyst hints are never authoritative.
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichIOCRequest): Enrich an indicator of compromise with linked threat events,
            techniques, and predictions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichIOCResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichIOCRequest,
) -> Any | EnrichIOCResponse | None:
    """Enrich IOC

     Enrich an indicator of compromise with linked threat events, techniques, and predictions.

    Searches threat intelligence feeds for the indicator (by `value` + `type` — e.g. `ip-dst`, `domain`,
    `sha256`, `url`, `email-src`), extracts linked threat actors and malware, maps to ATT&CK techniques,
    and generates threat predictions. Technique mappings return even when the indicator has sparse data.

    **Include options**

    - `misp_attributes` — matching threat event attributes with event metadata
    - `galaxies` — linked threat actor and malware context, resolved into full Galaxy cluster profiles
    - `techniques` — ATT&CK techniques linked to this indicator
    - `tie` — technique likelihood predictions for resolved techniques
    - `warninglist` — false-positive check against known safe-list entries
    - `sightings` — sighting count across linked events
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per linked technique
    - `detections` — detection data sources per linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `poc` — proof-of-concept exploits from GitHub for any linked CVEs
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat indicator analysis
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the indicator's threat context
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      IOC relationships yield no techniques. These low-confidence analyst hints are never authoritative.
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichIOCRequest): Enrich an indicator of compromise with linked threat events,
            techniques, and predictions.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichIOCResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
