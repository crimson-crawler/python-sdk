from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_group_request import EnrichGroupRequest
from ...models.enrich_group_response import EnrichGroupResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichGroupRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/group",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichGroupResponse | None:
    if response.status_code == 200:
        response_200 = EnrichGroupResponse.from_dict(response.json())

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
) -> Response[Any | EnrichGroupResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichGroupRequest,
) -> Response[Any | EnrichGroupResponse]:
    """Enrich Threat Group

     Look up or search threat actor groups with their techniques and tooling.

    Provide `group_id` for a direct lookup (e.g. G0016 for APT28) or `search` for text-based discovery
    by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`).
    Returns the group profile with associated ATT&CK techniques and software.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected group.

    **Include options**

    - `details` — full group profile (aliases, description, references, attributed techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `software` — malware and tools used by this group
    - `campaigns` — threat campaigns attributed to this group
    - `tie` — technique likelihood predictions for the group's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the group's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the group's techniques
    - `misp` — matching threat intelligence events
    - `sectors` — industry sectors this group is known to target
    - `locations` — geographic regions this group is known to target
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat group analysis and reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the group's profile and technique priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the group's techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichGroupRequest): Look up or search threat actor groups with their techniques and
            tooling.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichGroupResponse]
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
    body: EnrichGroupRequest,
) -> Any | EnrichGroupResponse | None:
    """Enrich Threat Group

     Look up or search threat actor groups with their techniques and tooling.

    Provide `group_id` for a direct lookup (e.g. G0016 for APT28) or `search` for text-based discovery
    by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`).
    Returns the group profile with associated ATT&CK techniques and software.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected group.

    **Include options**

    - `details` — full group profile (aliases, description, references, attributed techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `software` — malware and tools used by this group
    - `campaigns` — threat campaigns attributed to this group
    - `tie` — technique likelihood predictions for the group's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the group's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the group's techniques
    - `misp` — matching threat intelligence events
    - `sectors` — industry sectors this group is known to target
    - `locations` — geographic regions this group is known to target
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat group analysis and reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the group's profile and technique priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the group's techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichGroupRequest): Look up or search threat actor groups with their techniques and
            tooling.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichGroupResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichGroupRequest,
) -> Response[Any | EnrichGroupResponse]:
    """Enrich Threat Group

     Look up or search threat actor groups with their techniques and tooling.

    Provide `group_id` for a direct lookup (e.g. G0016 for APT28) or `search` for text-based discovery
    by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`).
    Returns the group profile with associated ATT&CK techniques and software.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected group.

    **Include options**

    - `details` — full group profile (aliases, description, references, attributed techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `software` — malware and tools used by this group
    - `campaigns` — threat campaigns attributed to this group
    - `tie` — technique likelihood predictions for the group's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the group's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the group's techniques
    - `misp` — matching threat intelligence events
    - `sectors` — industry sectors this group is known to target
    - `locations` — geographic regions this group is known to target
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat group analysis and reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the group's profile and technique priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the group's techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichGroupRequest): Look up or search threat actor groups with their techniques and
            tooling.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichGroupResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichGroupRequest,
) -> Any | EnrichGroupResponse | None:
    """Enrich Threat Group

     Look up or search threat actor groups with their techniques and tooling.

    Provide `group_id` for a direct lookup (e.g. G0016 for APT28) or `search` for text-based discovery
    by name or alias, across the `enterprise`, `ics`, or `mobile` framework (default `enterprise`).
    Returns the group profile with associated ATT&CK techniques and software.
    If both lookup fields are omitted, the endpoint returns HTTP 200 with no selected group.

    **Include options**

    - `details` — full group profile (aliases, description, references, attributed techniques)
    - `techniques` — resolved ATT&CK technique objects with mitigations and detection guidance
    - `software` — malware and tools used by this group
    - `campaigns` — threat campaigns attributed to this group
    - `tie` — technique likelihood predictions for the group's known techniques
    - `navigator` — ATT&CK Navigator layer JSON for the group's technique coverage
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the group's techniques
    - `misp` — matching threat intelligence events
    - `sectors` — industry sectors this group is known to target
    - `locations` — geographic regions this group is known to target
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for threat group analysis and reports
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated executive brief covering the group's profile and technique priorities
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the group's techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichGroupRequest): Look up or search threat actor groups with their techniques and
            tooling.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichGroupResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
