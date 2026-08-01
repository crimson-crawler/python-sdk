from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.assess_technique_coverage_request import AssessTechniqueCoverageRequest
from ...models.assess_technique_coverage_response import AssessTechniqueCoverageResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: AssessTechniqueCoverageRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/assess/technique-coverage",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | AssessTechniqueCoverageResponse | None:
    if response.status_code == 200:
        response_200 = AssessTechniqueCoverageResponse.from_dict(response.json())

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
) -> Response[Any | AssessTechniqueCoverageResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: AssessTechniqueCoverageRequest,
) -> Response[Any | AssessTechniqueCoverageResponse]:
    """Assess ATT&CK Technique Coverage

     Batch-assess ATT&CK techniques for mitigations, detections, and threat predictions in one call.

    More efficient than individual technique lookups. Returns aggregated mitigations and detection
    methods across all assessed techniques, plus per-technique threat predictions.

    **Include options**

    - `mitigations` — ATT&CK course-of-action items for each technique
    - `detections` — data sources and components per technique
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON across the assessed technique surface
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs known to map to any of the assessed techniques (reverse lookup, capped)
    - `coverage_score` — mitigation/detection coverage percentages plus uncovered technique list
    - `summary` — AI-generated coverage-gap brief covering mitigations and high-priority gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the assessed
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessTechniqueCoverageRequest): Batch-assess ATT&CK techniques: mitigations,
            detections, and threat predictions in one call.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | AssessTechniqueCoverageResponse]
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
    body: AssessTechniqueCoverageRequest,
) -> Any | AssessTechniqueCoverageResponse | None:
    """Assess ATT&CK Technique Coverage

     Batch-assess ATT&CK techniques for mitigations, detections, and threat predictions in one call.

    More efficient than individual technique lookups. Returns aggregated mitigations and detection
    methods across all assessed techniques, plus per-technique threat predictions.

    **Include options**

    - `mitigations` — ATT&CK course-of-action items for each technique
    - `detections` — data sources and components per technique
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON across the assessed technique surface
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs known to map to any of the assessed techniques (reverse lookup, capped)
    - `coverage_score` — mitigation/detection coverage percentages plus uncovered technique list
    - `summary` — AI-generated coverage-gap brief covering mitigations and high-priority gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the assessed
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessTechniqueCoverageRequest): Batch-assess ATT&CK techniques: mitigations,
            detections, and threat predictions in one call.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | AssessTechniqueCoverageResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AssessTechniqueCoverageRequest,
) -> Response[Any | AssessTechniqueCoverageResponse]:
    """Assess ATT&CK Technique Coverage

     Batch-assess ATT&CK techniques for mitigations, detections, and threat predictions in one call.

    More efficient than individual technique lookups. Returns aggregated mitigations and detection
    methods across all assessed techniques, plus per-technique threat predictions.

    **Include options**

    - `mitigations` — ATT&CK course-of-action items for each technique
    - `detections` — data sources and components per technique
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON across the assessed technique surface
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs known to map to any of the assessed techniques (reverse lookup, capped)
    - `coverage_score` — mitigation/detection coverage percentages plus uncovered technique list
    - `summary` — AI-generated coverage-gap brief covering mitigations and high-priority gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the assessed
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessTechniqueCoverageRequest): Batch-assess ATT&CK techniques: mitigations,
            detections, and threat predictions in one call.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | AssessTechniqueCoverageResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AssessTechniqueCoverageRequest,
) -> Any | AssessTechniqueCoverageResponse | None:
    """Assess ATT&CK Technique Coverage

     Batch-assess ATT&CK techniques for mitigations, detections, and threat predictions in one call.

    More efficient than individual technique lookups. Returns aggregated mitigations and detection
    methods across all assessed techniques, plus per-technique threat predictions.

    **Include options**

    - `mitigations` — ATT&CK course-of-action items for each technique
    - `detections` — data sources and components per technique
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON across the assessed technique surface
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs known to map to any of the assessed techniques (reverse lookup, capped)
    - `coverage_score` — mitigation/detection coverage percentages plus uncovered technique list
    - `summary` — AI-generated coverage-gap brief covering mitigations and high-priority gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the assessed
      techniques, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessTechniqueCoverageRequest): Batch-assess ATT&CK techniques: mitigations,
            detections, and threat predictions in one call.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | AssessTechniqueCoverageResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
