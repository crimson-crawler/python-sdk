from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_cwe_request import EnrichCWERequest
from ...models.enrich_cwe_response import EnrichCWEResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichCWERequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/cwe",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichCWEResponse | None:
    if response.status_code == 200:
        response_200 = EnrichCWEResponse.from_dict(response.json())

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
) -> Response[Any | EnrichCWEResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCWERequest,
) -> Response[Any | EnrichCWEResponse]:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and adversary techniques.

    Returns the weakness with associated attack patterns and ATT&CK techniques, connecting root cause
    to adversary behavior. Technique mappings come with full mitigations and detection guidance even
    when the weakness has sparse data.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for weakness-related research and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            adversary techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCWEResponse]
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
    body: EnrichCWERequest,
) -> Any | EnrichCWEResponse | None:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and adversary techniques.

    Returns the weakness with associated attack patterns and ATT&CK techniques, connecting root cause
    to adversary behavior. Technique mappings come with full mitigations and detection guidance even
    when the weakness has sparse data.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for weakness-related research and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            adversary techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCWEResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCWERequest,
) -> Response[Any | EnrichCWEResponse]:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and adversary techniques.

    Returns the weakness with associated attack patterns and ATT&CK techniques, connecting root cause
    to adversary behavior. Technique mappings come with full mitigations and detection guidance even
    when the weakness has sparse data.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for weakness-related research and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            adversary techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCWEResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichCWERequest,
) -> Any | EnrichCWEResponse | None:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and adversary techniques.

    Returns the weakness with associated attack patterns and ATT&CK techniques, connecting root cause
    to adversary behavior. Technique mappings come with full mitigations and detection guidance even
    when the weakness has sparse data.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs mapped to the linked techniques
    - `knowledgebase` — related intelligence from the knowledge base
    - `web` — live web search for weakness-related research and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            adversary techniques.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCWEResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
