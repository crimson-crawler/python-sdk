from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_product_request import EnrichProductRequest
from ...models.enrich_product_response import EnrichProductResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichProductRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/product",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichProductResponse | None:
    if response.status_code == 200:
        response_200 = EnrichProductResponse.from_dict(response.json())

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
) -> Response[Any | EnrichProductResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichProductRequest,
) -> Response[Any | EnrichProductResponse]:
    """Enrich Product

     Find vulnerabilities affecting a product and enrich each matched CVE.

    Searches by product name, version, and vendor using CPE matching, then runs every matched CVE
    through the same multi-source chain as `/v1/enrich/cve`. Supply `vendor` to narrow CPE matches
    and `version` to hard-filter discovered CVEs to those affecting that release.

    The include options drive the per-CVE enrichment depth (each value behaves exactly as it does on
    `/v1/enrich/cve`); the product-level extras roll those results up across the matched set.

    **Include options**

    Per-CVE enrichment (applied to each matched CVE):

    - `details` — core CVE data (CVSS, severity, description, references)
    - `epss` — EPSS exploit probability score and percentile
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification
    - `capec` — attack patterns for the weakness
    - `techniques` — linked ATT&CK techniques
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related knowledge-base context
    - `web` — live web search for exploits and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with CPE strings
    - `poc` — proof-of-concept exploits from GitHub
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques
    - `exploits` — authoritative exploit objects per CVE (real evidence, not the heuristic
      `has_public_exploit` boolean)
    - `ssvc` — SSVC vulnerability-prioritisation decision per CVE (CERT/CC Deployer tree,
      worst-reasonable-case defaults)
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques
      (MITRE CTID mapping)
    - `osv` — OSV.dev advisories and fixed versions aliased to each matched CVE

    Product-level rollup:

    - `summary` — AI-generated product-level brief over the matched CVE set
    - `risk_summary` — aggregate risk statistics across the matched CVEs

    The response also carries `likely_tactics`, an always-on set of ATT&CK tactic-class hints based on
    the requested vendor. These hints are useful when matched CVEs have sparse technique coverage.
    Returns up to 20 enriched CVEs per request.

    Args:
        body (EnrichProductRequest): Find vulnerabilities affecting a specific product and enrich
            each CVE.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichProductResponse]
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
    body: EnrichProductRequest,
) -> Any | EnrichProductResponse | None:
    """Enrich Product

     Find vulnerabilities affecting a product and enrich each matched CVE.

    Searches by product name, version, and vendor using CPE matching, then runs every matched CVE
    through the same multi-source chain as `/v1/enrich/cve`. Supply `vendor` to narrow CPE matches
    and `version` to hard-filter discovered CVEs to those affecting that release.

    The include options drive the per-CVE enrichment depth (each value behaves exactly as it does on
    `/v1/enrich/cve`); the product-level extras roll those results up across the matched set.

    **Include options**

    Per-CVE enrichment (applied to each matched CVE):

    - `details` — core CVE data (CVSS, severity, description, references)
    - `epss` — EPSS exploit probability score and percentile
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification
    - `capec` — attack patterns for the weakness
    - `techniques` — linked ATT&CK techniques
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related knowledge-base context
    - `web` — live web search for exploits and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with CPE strings
    - `poc` — proof-of-concept exploits from GitHub
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques
    - `exploits` — authoritative exploit objects per CVE (real evidence, not the heuristic
      `has_public_exploit` boolean)
    - `ssvc` — SSVC vulnerability-prioritisation decision per CVE (CERT/CC Deployer tree,
      worst-reasonable-case defaults)
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques
      (MITRE CTID mapping)
    - `osv` — OSV.dev advisories and fixed versions aliased to each matched CVE

    Product-level rollup:

    - `summary` — AI-generated product-level brief over the matched CVE set
    - `risk_summary` — aggregate risk statistics across the matched CVEs

    The response also carries `likely_tactics`, an always-on set of ATT&CK tactic-class hints based on
    the requested vendor. These hints are useful when matched CVEs have sparse technique coverage.
    Returns up to 20 enriched CVEs per request.

    Args:
        body (EnrichProductRequest): Find vulnerabilities affecting a specific product and enrich
            each CVE.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichProductResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichProductRequest,
) -> Response[Any | EnrichProductResponse]:
    """Enrich Product

     Find vulnerabilities affecting a product and enrich each matched CVE.

    Searches by product name, version, and vendor using CPE matching, then runs every matched CVE
    through the same multi-source chain as `/v1/enrich/cve`. Supply `vendor` to narrow CPE matches
    and `version` to hard-filter discovered CVEs to those affecting that release.

    The include options drive the per-CVE enrichment depth (each value behaves exactly as it does on
    `/v1/enrich/cve`); the product-level extras roll those results up across the matched set.

    **Include options**

    Per-CVE enrichment (applied to each matched CVE):

    - `details` — core CVE data (CVSS, severity, description, references)
    - `epss` — EPSS exploit probability score and percentile
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification
    - `capec` — attack patterns for the weakness
    - `techniques` — linked ATT&CK techniques
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related knowledge-base context
    - `web` — live web search for exploits and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with CPE strings
    - `poc` — proof-of-concept exploits from GitHub
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques
    - `exploits` — authoritative exploit objects per CVE (real evidence, not the heuristic
      `has_public_exploit` boolean)
    - `ssvc` — SSVC vulnerability-prioritisation decision per CVE (CERT/CC Deployer tree,
      worst-reasonable-case defaults)
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques
      (MITRE CTID mapping)
    - `osv` — OSV.dev advisories and fixed versions aliased to each matched CVE

    Product-level rollup:

    - `summary` — AI-generated product-level brief over the matched CVE set
    - `risk_summary` — aggregate risk statistics across the matched CVEs

    The response also carries `likely_tactics`, an always-on set of ATT&CK tactic-class hints based on
    the requested vendor. These hints are useful when matched CVEs have sparse technique coverage.
    Returns up to 20 enriched CVEs per request.

    Args:
        body (EnrichProductRequest): Find vulnerabilities affecting a specific product and enrich
            each CVE.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichProductResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichProductRequest,
) -> Any | EnrichProductResponse | None:
    """Enrich Product

     Find vulnerabilities affecting a product and enrich each matched CVE.

    Searches by product name, version, and vendor using CPE matching, then runs every matched CVE
    through the same multi-source chain as `/v1/enrich/cve`. Supply `vendor` to narrow CPE matches
    and `version` to hard-filter discovered CVEs to those affecting that release.

    The include options drive the per-CVE enrichment depth (each value behaves exactly as it does on
    `/v1/enrich/cve`); the product-level extras roll those results up across the matched set.

    **Include options**

    Per-CVE enrichment (applied to each matched CVE):

    - `details` — core CVE data (CVSS, severity, description, references)
    - `epss` — EPSS exploit probability score and percentile
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification
    - `capec` — attack patterns for the weakness
    - `techniques` — linked ATT&CK techniques
    - `tie` — technique likelihood predictions
    - `navigator` — ATT&CK Navigator layer JSON
    - `misp` — matching threat intelligence events
    - `knowledgebase` — related knowledge-base context
    - `web` — live web search for exploits and advisories
    - `web_scrape` — scraped article text on the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with CPE strings
    - `poc` — proof-of-concept exploits from GitHub
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques
    - `exploits` — authoritative exploit objects per CVE (real evidence, not the heuristic
      `has_public_exploit` boolean)
    - `ssvc` — SSVC vulnerability-prioritisation decision per CVE (CERT/CC Deployer tree,
      worst-reasonable-case defaults)
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques
      (MITRE CTID mapping)
    - `osv` — OSV.dev advisories and fixed versions aliased to each matched CVE

    Product-level rollup:

    - `summary` — AI-generated product-level brief over the matched CVE set
    - `risk_summary` — aggregate risk statistics across the matched CVEs

    The response also carries `likely_tactics`, an always-on set of ATT&CK tactic-class hints based on
    the requested vendor. These hints are useful when matched CVEs have sparse technique coverage.
    Returns up to 20 enriched CVEs per request.

    Args:
        body (EnrichProductRequest): Find vulnerabilities affecting a specific product and enrich
            each CVE.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichProductResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
