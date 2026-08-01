from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_capec_request import EnrichCAPECRequest
from ...models.enrich_capec_response import EnrichCAPECResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichCAPECRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/capec",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichCAPECResponse | None:
    if response.status_code == 200:
        response_200 = EnrichCAPECResponse.from_dict(response.json())

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
) -> Response[Any | EnrichCAPECResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCAPECRequest,
) -> Response[Any | EnrichCAPECResponse]:
    """Enrich CAPEC

     Look up or search attack patterns and resolve linked adversary techniques.

    Provide `capec_id` for a direct lookup or `search` for text-based discovery. Linked ATT&CK
    techniques are resolved into full objects with mitigations and detection guidance, returned even
    when the attack pattern has sparse data.
    If both fields are omitted, the endpoint returns HTTP 200 with no selected pattern and empty search
    results.

    **Include options**

    - `details` — full CAPEC object with description, prerequisites, and related weaknesses
    - `techniques` — ATT&CK techniques linked to this attack pattern
    - `tie` — technique likelihood predictions for linked techniques
    - `navigator` — ATT&CK Navigator layer JSON for linked techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for attack pattern research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the attack pattern
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCAPECRequest): Look up or search attack patterns and resolve linked adversary
            techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCAPECResponse]
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
    body: EnrichCAPECRequest,
) -> Any | EnrichCAPECResponse | None:
    """Enrich CAPEC

     Look up or search attack patterns and resolve linked adversary techniques.

    Provide `capec_id` for a direct lookup or `search` for text-based discovery. Linked ATT&CK
    techniques are resolved into full objects with mitigations and detection guidance, returned even
    when the attack pattern has sparse data.
    If both fields are omitted, the endpoint returns HTTP 200 with no selected pattern and empty search
    results.

    **Include options**

    - `details` — full CAPEC object with description, prerequisites, and related weaknesses
    - `techniques` — ATT&CK techniques linked to this attack pattern
    - `tie` — technique likelihood predictions for linked techniques
    - `navigator` — ATT&CK Navigator layer JSON for linked techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for attack pattern research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the attack pattern
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCAPECRequest): Look up or search attack patterns and resolve linked adversary
            techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCAPECResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCAPECRequest,
) -> Response[Any | EnrichCAPECResponse]:
    """Enrich CAPEC

     Look up or search attack patterns and resolve linked adversary techniques.

    Provide `capec_id` for a direct lookup or `search` for text-based discovery. Linked ATT&CK
    techniques are resolved into full objects with mitigations and detection guidance, returned even
    when the attack pattern has sparse data.
    If both fields are omitted, the endpoint returns HTTP 200 with no selected pattern and empty search
    results.

    **Include options**

    - `details` — full CAPEC object with description, prerequisites, and related weaknesses
    - `techniques` — ATT&CK techniques linked to this attack pattern
    - `tie` — technique likelihood predictions for linked techniques
    - `navigator` — ATT&CK Navigator layer JSON for linked techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for attack pattern research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the attack pattern
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCAPECRequest): Look up or search attack patterns and resolve linked adversary
            techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCAPECResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichCAPECRequest,
) -> Any | EnrichCAPECResponse | None:
    """Enrich CAPEC

     Look up or search attack patterns and resolve linked adversary techniques.

    Provide `capec_id` for a direct lookup or `search` for text-based discovery. Linked ATT&CK
    techniques are resolved into full objects with mitigations and detection guidance, returned even
    when the attack pattern has sparse data.
    If both fields are omitted, the endpoint returns HTTP 200 with no selected pattern and empty search
    results.

    **Include options**

    - `details` — full CAPEC object with description, prerequisites, and related weaknesses
    - `techniques` — ATT&CK techniques linked to this attack pattern
    - `tie` — technique likelihood predictions for linked techniques
    - `navigator` — ATT&CK Navigator layer JSON for linked techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for attack pattern research
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the attack pattern
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCAPECRequest): Look up or search attack patterns and resolve linked adversary
            techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCAPECResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
