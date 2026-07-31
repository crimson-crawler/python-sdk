from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.assess_ioc_portfolio_request import AssessIOCPortfolioRequest
from ...models.assess_ioc_portfolio_response import AssessIOCPortfolioResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: AssessIOCPortfolioRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/assess/ioc-portfolio",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | AssessIOCPortfolioResponse | None:
    if response.status_code == 200:
        response_200 = AssessIOCPortfolioResponse.from_dict(response.json())

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
) -> Response[Any | AssessIOCPortfolioResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: AssessIOCPortfolioRequest,
) -> Response[Any | AssessIOCPortfolioResponse]:
    """Assess IOC Portfolio

     Assess the combined threat picture across multiple indicators of compromise.

    Takes up to 50 IOCs (IPs, hashes, domains), correlates each through your threat intelligence
    feed, deduplicates events and techniques across all indicators, and returns a unified threat
    assessment with predictions and defensive context.

    **Include options**

    - `misp_attributes` — per-IOC matching threat-event attributes
    - `techniques` — ATT&CK techniques surfaced from any IOC's events / galaxies
    - `tie` — per-technique likelihood predictions
    - `groups` — threat-actor groups linked to the surfaced techniques
    - `software` — malware / tools linked to the surfaced techniques
    - `campaigns` — campaigns linked to the surfaced techniques
    - `mitigations` — ATT&CK course-of-action items for the surfaced techniques
    - `detections` — data sources and components for the surfaced techniques
    - `defend` — D3FEND defensive techniques and countermeasures
    - `galaxies` — resolve referenced MISP Galaxy clusters into full actor / malware / tool profiles
      (synonyms, source, relations); the multi-IOC sibling of enrich/ioc's galaxies include
    - `warninglist` — flag portfolio IOCs that match a MISP warninglist (likely false positives or
      known-benign values)
    - `sightings` — aggregate MISP sighting counts (`total_sightings`) across the matched attributes
    - `summary` — AI-generated portfolio threat narrative
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the surfaced
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    The response also carries `misp_feed_hits` from supplemental threat feeds automatically; no
    `include` value is needed.

    Args:
        body (AssessIOCPortfolioRequest): Assess the combined threat picture across multiple
            indicators of compromise.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | AssessIOCPortfolioResponse]
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
    body: AssessIOCPortfolioRequest,
) -> Any | AssessIOCPortfolioResponse | None:
    """Assess IOC Portfolio

     Assess the combined threat picture across multiple indicators of compromise.

    Takes up to 50 IOCs (IPs, hashes, domains), correlates each through your threat intelligence
    feed, deduplicates events and techniques across all indicators, and returns a unified threat
    assessment with predictions and defensive context.

    **Include options**

    - `misp_attributes` — per-IOC matching threat-event attributes
    - `techniques` — ATT&CK techniques surfaced from any IOC's events / galaxies
    - `tie` — per-technique likelihood predictions
    - `groups` — threat-actor groups linked to the surfaced techniques
    - `software` — malware / tools linked to the surfaced techniques
    - `campaigns` — campaigns linked to the surfaced techniques
    - `mitigations` — ATT&CK course-of-action items for the surfaced techniques
    - `detections` — data sources and components for the surfaced techniques
    - `defend` — D3FEND defensive techniques and countermeasures
    - `galaxies` — resolve referenced MISP Galaxy clusters into full actor / malware / tool profiles
      (synonyms, source, relations); the multi-IOC sibling of enrich/ioc's galaxies include
    - `warninglist` — flag portfolio IOCs that match a MISP warninglist (likely false positives or
      known-benign values)
    - `sightings` — aggregate MISP sighting counts (`total_sightings`) across the matched attributes
    - `summary` — AI-generated portfolio threat narrative
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the surfaced
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    The response also carries `misp_feed_hits` from supplemental threat feeds automatically; no
    `include` value is needed.

    Args:
        body (AssessIOCPortfolioRequest): Assess the combined threat picture across multiple
            indicators of compromise.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | AssessIOCPortfolioResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AssessIOCPortfolioRequest,
) -> Response[Any | AssessIOCPortfolioResponse]:
    """Assess IOC Portfolio

     Assess the combined threat picture across multiple indicators of compromise.

    Takes up to 50 IOCs (IPs, hashes, domains), correlates each through your threat intelligence
    feed, deduplicates events and techniques across all indicators, and returns a unified threat
    assessment with predictions and defensive context.

    **Include options**

    - `misp_attributes` — per-IOC matching threat-event attributes
    - `techniques` — ATT&CK techniques surfaced from any IOC's events / galaxies
    - `tie` — per-technique likelihood predictions
    - `groups` — threat-actor groups linked to the surfaced techniques
    - `software` — malware / tools linked to the surfaced techniques
    - `campaigns` — campaigns linked to the surfaced techniques
    - `mitigations` — ATT&CK course-of-action items for the surfaced techniques
    - `detections` — data sources and components for the surfaced techniques
    - `defend` — D3FEND defensive techniques and countermeasures
    - `galaxies` — resolve referenced MISP Galaxy clusters into full actor / malware / tool profiles
      (synonyms, source, relations); the multi-IOC sibling of enrich/ioc's galaxies include
    - `warninglist` — flag portfolio IOCs that match a MISP warninglist (likely false positives or
      known-benign values)
    - `sightings` — aggregate MISP sighting counts (`total_sightings`) across the matched attributes
    - `summary` — AI-generated portfolio threat narrative
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the surfaced
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    The response also carries `misp_feed_hits` from supplemental threat feeds automatically; no
    `include` value is needed.

    Args:
        body (AssessIOCPortfolioRequest): Assess the combined threat picture across multiple
            indicators of compromise.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | AssessIOCPortfolioResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AssessIOCPortfolioRequest,
) -> Any | AssessIOCPortfolioResponse | None:
    """Assess IOC Portfolio

     Assess the combined threat picture across multiple indicators of compromise.

    Takes up to 50 IOCs (IPs, hashes, domains), correlates each through your threat intelligence
    feed, deduplicates events and techniques across all indicators, and returns a unified threat
    assessment with predictions and defensive context.

    **Include options**

    - `misp_attributes` — per-IOC matching threat-event attributes
    - `techniques` — ATT&CK techniques surfaced from any IOC's events / galaxies
    - `tie` — per-technique likelihood predictions
    - `groups` — threat-actor groups linked to the surfaced techniques
    - `software` — malware / tools linked to the surfaced techniques
    - `campaigns` — campaigns linked to the surfaced techniques
    - `mitigations` — ATT&CK course-of-action items for the surfaced techniques
    - `detections` — data sources and components for the surfaced techniques
    - `defend` — D3FEND defensive techniques and countermeasures
    - `galaxies` — resolve referenced MISP Galaxy clusters into full actor / malware / tool profiles
      (synonyms, source, relations); the multi-IOC sibling of enrich/ioc's galaxies include
    - `warninglist` — flag portfolio IOCs that match a MISP warninglist (likely false positives or
      known-benign values)
    - `sightings` — aggregate MISP sighting counts (`total_sightings`) across the matched attributes
    - `summary` — AI-generated portfolio threat narrative
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the surfaced
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    The response also carries `misp_feed_hits` from supplemental threat feeds automatically; no
    `include` value is needed.

    Args:
        body (AssessIOCPortfolioRequest): Assess the combined threat picture across multiple
            indicators of compromise.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | AssessIOCPortfolioResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
