from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.assess_group_exposure_request import AssessGroupExposureRequest
from ...models.assess_group_exposure_response import AssessGroupExposureResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: AssessGroupExposureRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/assess/group-exposure",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | AssessGroupExposureResponse | None:
    if response.status_code == 200:
        response_200 = AssessGroupExposureResponse.from_dict(response.json())

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
) -> Response[Any | AssessGroupExposureResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: AssessGroupExposureRequest,
) -> Response[Any | AssessGroupExposureResponse]:
    """Assess Threat Group Exposure

     Assess the combined technique surface across multiple threat groups.

    Takes a list of group IDs and/or group names, deduplicates their combined ATT&CK technique
    footprint, and returns the unified result with predictions.

    **Include options**

    - `details` — resolved threat-actor group profiles (aliases, first/last seen, software)
    - `techniques` — deduplicated technique surface across the group set
    - `tie` — per-technique likelihood predictions
    - `cves` — CVEs known to map to any technique in the combined set
    - `sectors` — sector context aggregated across the groups
    - `locations` — geographic context aggregated across the groups
    - `defend` — D3FEND defensive techniques and countermeasures
    - `navigator` — ATT&CK Navigator layer JSON
    - `summary` — AI-generated narrative covering shared techniques and coverage gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the combined
      technique surface, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessGroupExposureRequest): Assess the combined technique surface across multiple
            threat groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | AssessGroupExposureResponse]
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
    body: AssessGroupExposureRequest,
) -> Any | AssessGroupExposureResponse | None:
    """Assess Threat Group Exposure

     Assess the combined technique surface across multiple threat groups.

    Takes a list of group IDs and/or group names, deduplicates their combined ATT&CK technique
    footprint, and returns the unified result with predictions.

    **Include options**

    - `details` — resolved threat-actor group profiles (aliases, first/last seen, software)
    - `techniques` — deduplicated technique surface across the group set
    - `tie` — per-technique likelihood predictions
    - `cves` — CVEs known to map to any technique in the combined set
    - `sectors` — sector context aggregated across the groups
    - `locations` — geographic context aggregated across the groups
    - `defend` — D3FEND defensive techniques and countermeasures
    - `navigator` — ATT&CK Navigator layer JSON
    - `summary` — AI-generated narrative covering shared techniques and coverage gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the combined
      technique surface, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessGroupExposureRequest): Assess the combined technique surface across multiple
            threat groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | AssessGroupExposureResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AssessGroupExposureRequest,
) -> Response[Any | AssessGroupExposureResponse]:
    """Assess Threat Group Exposure

     Assess the combined technique surface across multiple threat groups.

    Takes a list of group IDs and/or group names, deduplicates their combined ATT&CK technique
    footprint, and returns the unified result with predictions.

    **Include options**

    - `details` — resolved threat-actor group profiles (aliases, first/last seen, software)
    - `techniques` — deduplicated technique surface across the group set
    - `tie` — per-technique likelihood predictions
    - `cves` — CVEs known to map to any technique in the combined set
    - `sectors` — sector context aggregated across the groups
    - `locations` — geographic context aggregated across the groups
    - `defend` — D3FEND defensive techniques and countermeasures
    - `navigator` — ATT&CK Navigator layer JSON
    - `summary` — AI-generated narrative covering shared techniques and coverage gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the combined
      technique surface, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessGroupExposureRequest): Assess the combined technique surface across multiple
            threat groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | AssessGroupExposureResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AssessGroupExposureRequest,
) -> Any | AssessGroupExposureResponse | None:
    """Assess Threat Group Exposure

     Assess the combined technique surface across multiple threat groups.

    Takes a list of group IDs and/or group names, deduplicates their combined ATT&CK technique
    footprint, and returns the unified result with predictions.

    **Include options**

    - `details` — resolved threat-actor group profiles (aliases, first/last seen, software)
    - `techniques` — deduplicated technique surface across the group set
    - `tie` — per-technique likelihood predictions
    - `cves` — CVEs known to map to any technique in the combined set
    - `sectors` — sector context aggregated across the groups
    - `locations` — geographic context aggregated across the groups
    - `defend` — D3FEND defensive techniques and countermeasures
    - `navigator` — ATT&CK Navigator layer JSON
    - `summary` — AI-generated narrative covering shared techniques and coverage gaps
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the combined
      technique surface, based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (AssessGroupExposureRequest): Assess the combined technique surface across multiple
            threat groups.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | AssessGroupExposureResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
