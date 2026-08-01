from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_cve_request import EnrichCVERequest
from ...models.enrich_cve_response import EnrichCVEResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichCVERequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/cve",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichCVEResponse | None:
    if response.status_code == 200:
        response_200 = EnrichCVEResponse.from_dict(response.json())

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
) -> Response[Any | EnrichCVEResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCVERequest,
) -> Response[Any | EnrichCVEResponse]:
    """Enrich CVE

     Enrich a CVE into a full attack narrative.

    Returns severity scoring, exploit intelligence, weakness analysis, adversary techniques,
    threat predictions, and an AI-generated executive summary. Control depth with `include`.

    ATT&CK mappings follow published CVE, CWE, and CAPEC relationships. If those relationships yield
    no techniques, `techniques[]` stays empty rather than returning an unsupported match.

    **Include options**

    - `details` — core CVE data including CVSS, severity, description, dates, and references
    - `epss` — EPSS exploit probability score and percentile ranking
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification with descriptions
    - `capec` — attack patterns describing how the weakness is exploited
    - `techniques` — ATT&CK techniques linked through published vulnerability relationships
    - `tie` — technique likelihood predictions (probability per technique)
    - `misp` — matching threat intelligence events from your threat feed
    - `knowledgebase` — related context from the intelligence knowledge base
    - `web` — live web search for exploit PoCs, advisories, and security research
    - `web_scrape` — scraped article text added to the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with vendor, product, version, and CPE string
    - `poc` — proof-of-concept exploits from GitHub (count + repo metadata)
    - `poc_source` — AI-assisted analysis of selected PoC repositories (trigger, affected path,
      preconditions, and mitigation); raw source code is never returned
    - `exploits` — confirmed exploit records from the KEV exploit feed (real evidence, not the
      heuristic `has_public_exploit` boolean)
    - `osv` — OSV.dev advisories aliased to this CVE (GHSA/PYSEC/RUSTSEC records plus per-ecosystem
      fixed versions; the same advisory source used by `/v1/enrich/package`)
    - `groups` — threat actor groups known to use the linked ATT&CK techniques
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `similar_cves` — up to 15 CVEs with overlapping weakness/technique fingerprint, ranked by
      weighted Jaccard similarity (signal-by-signal breakdown included)
    - `sector_context` — evidence-based industry sector detection from threat group targeting patterns
    - `timeline` — EPSS score history for trend visualisation (pair with `epss_velocity`)
    - `navigator` — ATT&CK Navigator layer JSON for MITRE's Navigator tool
    - `summary` — AI-generated 3-5 sentence executive brief covering severity, exploitation
      status, and key attack techniques
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      mappings yield no techniques. These low-confidence analyst hints are never treated as
    authoritative.
    - `nist_controls` *(default-on)* — NIST SP 800-53 rev 5 controls that mitigate the CVE's mapped
      techniques, based on MITRE Center for Threat-Informed Defense mappings
    - `ssvc` — SSVC vulnerability-prioritisation decision (CERT/CC Deployer tree by default, or CISA
      Coordinator tree). Stakeholder context comes from the optional `stakeholder` request field;
      defaults to the worst-reasonable case for an unknown environment.

    Several extra fields always populate regardless of `include`: `techniques_provenance` (precision
    class of `techniques[]`), `likely_tactics` (vendor tactic-class hints when the chain walk is
    empty), `confidence` (importance-weighted completeness indicator), `weaponization_score` (0-100
    composite).

    Omitted include values return as `null` or empty arrays. The `errors` array reports any partial
    failures.

    Args:
        body (EnrichCVERequest): Enrich a CVE with severity, exploit intelligence, attack
            patterns, and AI analysis.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCVEResponse]
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
    body: EnrichCVERequest,
) -> Any | EnrichCVEResponse | None:
    """Enrich CVE

     Enrich a CVE into a full attack narrative.

    Returns severity scoring, exploit intelligence, weakness analysis, adversary techniques,
    threat predictions, and an AI-generated executive summary. Control depth with `include`.

    ATT&CK mappings follow published CVE, CWE, and CAPEC relationships. If those relationships yield
    no techniques, `techniques[]` stays empty rather than returning an unsupported match.

    **Include options**

    - `details` — core CVE data including CVSS, severity, description, dates, and references
    - `epss` — EPSS exploit probability score and percentile ranking
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification with descriptions
    - `capec` — attack patterns describing how the weakness is exploited
    - `techniques` — ATT&CK techniques linked through published vulnerability relationships
    - `tie` — technique likelihood predictions (probability per technique)
    - `misp` — matching threat intelligence events from your threat feed
    - `knowledgebase` — related context from the intelligence knowledge base
    - `web` — live web search for exploit PoCs, advisories, and security research
    - `web_scrape` — scraped article text added to the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with vendor, product, version, and CPE string
    - `poc` — proof-of-concept exploits from GitHub (count + repo metadata)
    - `poc_source` — AI-assisted analysis of selected PoC repositories (trigger, affected path,
      preconditions, and mitigation); raw source code is never returned
    - `exploits` — confirmed exploit records from the KEV exploit feed (real evidence, not the
      heuristic `has_public_exploit` boolean)
    - `osv` — OSV.dev advisories aliased to this CVE (GHSA/PYSEC/RUSTSEC records plus per-ecosystem
      fixed versions; the same advisory source used by `/v1/enrich/package`)
    - `groups` — threat actor groups known to use the linked ATT&CK techniques
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `similar_cves` — up to 15 CVEs with overlapping weakness/technique fingerprint, ranked by
      weighted Jaccard similarity (signal-by-signal breakdown included)
    - `sector_context` — evidence-based industry sector detection from threat group targeting patterns
    - `timeline` — EPSS score history for trend visualisation (pair with `epss_velocity`)
    - `navigator` — ATT&CK Navigator layer JSON for MITRE's Navigator tool
    - `summary` — AI-generated 3-5 sentence executive brief covering severity, exploitation
      status, and key attack techniques
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      mappings yield no techniques. These low-confidence analyst hints are never treated as
    authoritative.
    - `nist_controls` *(default-on)* — NIST SP 800-53 rev 5 controls that mitigate the CVE's mapped
      techniques, based on MITRE Center for Threat-Informed Defense mappings
    - `ssvc` — SSVC vulnerability-prioritisation decision (CERT/CC Deployer tree by default, or CISA
      Coordinator tree). Stakeholder context comes from the optional `stakeholder` request field;
      defaults to the worst-reasonable case for an unknown environment.

    Several extra fields always populate regardless of `include`: `techniques_provenance` (precision
    class of `techniques[]`), `likely_tactics` (vendor tactic-class hints when the chain walk is
    empty), `confidence` (importance-weighted completeness indicator), `weaponization_score` (0-100
    composite).

    Omitted include values return as `null` or empty arrays. The `errors` array reports any partial
    failures.

    Args:
        body (EnrichCVERequest): Enrich a CVE with severity, exploit intelligence, attack
            patterns, and AI analysis.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCVEResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCVERequest,
) -> Response[Any | EnrichCVEResponse]:
    """Enrich CVE

     Enrich a CVE into a full attack narrative.

    Returns severity scoring, exploit intelligence, weakness analysis, adversary techniques,
    threat predictions, and an AI-generated executive summary. Control depth with `include`.

    ATT&CK mappings follow published CVE, CWE, and CAPEC relationships. If those relationships yield
    no techniques, `techniques[]` stays empty rather than returning an unsupported match.

    **Include options**

    - `details` — core CVE data including CVSS, severity, description, dates, and references
    - `epss` — EPSS exploit probability score and percentile ranking
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification with descriptions
    - `capec` — attack patterns describing how the weakness is exploited
    - `techniques` — ATT&CK techniques linked through published vulnerability relationships
    - `tie` — technique likelihood predictions (probability per technique)
    - `misp` — matching threat intelligence events from your threat feed
    - `knowledgebase` — related context from the intelligence knowledge base
    - `web` — live web search for exploit PoCs, advisories, and security research
    - `web_scrape` — scraped article text added to the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with vendor, product, version, and CPE string
    - `poc` — proof-of-concept exploits from GitHub (count + repo metadata)
    - `poc_source` — AI-assisted analysis of selected PoC repositories (trigger, affected path,
      preconditions, and mitigation); raw source code is never returned
    - `exploits` — confirmed exploit records from the KEV exploit feed (real evidence, not the
      heuristic `has_public_exploit` boolean)
    - `osv` — OSV.dev advisories aliased to this CVE (GHSA/PYSEC/RUSTSEC records plus per-ecosystem
      fixed versions; the same advisory source used by `/v1/enrich/package`)
    - `groups` — threat actor groups known to use the linked ATT&CK techniques
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `similar_cves` — up to 15 CVEs with overlapping weakness/technique fingerprint, ranked by
      weighted Jaccard similarity (signal-by-signal breakdown included)
    - `sector_context` — evidence-based industry sector detection from threat group targeting patterns
    - `timeline` — EPSS score history for trend visualisation (pair with `epss_velocity`)
    - `navigator` — ATT&CK Navigator layer JSON for MITRE's Navigator tool
    - `summary` — AI-generated 3-5 sentence executive brief covering severity, exploitation
      status, and key attack techniques
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      mappings yield no techniques. These low-confidence analyst hints are never treated as
    authoritative.
    - `nist_controls` *(default-on)* — NIST SP 800-53 rev 5 controls that mitigate the CVE's mapped
      techniques, based on MITRE Center for Threat-Informed Defense mappings
    - `ssvc` — SSVC vulnerability-prioritisation decision (CERT/CC Deployer tree by default, or CISA
      Coordinator tree). Stakeholder context comes from the optional `stakeholder` request field;
      defaults to the worst-reasonable case for an unknown environment.

    Several extra fields always populate regardless of `include`: `techniques_provenance` (precision
    class of `techniques[]`), `likely_tactics` (vendor tactic-class hints when the chain walk is
    empty), `confidence` (importance-weighted completeness indicator), `weaponization_score` (0-100
    composite).

    Omitted include values return as `null` or empty arrays. The `errors` array reports any partial
    failures.

    Args:
        body (EnrichCVERequest): Enrich a CVE with severity, exploit intelligence, attack
            patterns, and AI analysis.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCVEResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichCVERequest,
) -> Any | EnrichCVEResponse | None:
    """Enrich CVE

     Enrich a CVE into a full attack narrative.

    Returns severity scoring, exploit intelligence, weakness analysis, adversary techniques,
    threat predictions, and an AI-generated executive summary. Control depth with `include`.

    ATT&CK mappings follow published CVE, CWE, and CAPEC relationships. If those relationships yield
    no techniques, `techniques[]` stays empty rather than returning an unsupported match.

    **Include options**

    - `details` — core CVE data including CVSS, severity, description, dates, and references
    - `epss` — EPSS exploit probability score and percentile ranking
    - `kev` — Known Exploited Vulnerabilities catalog status
    - `cwe` — root cause weakness classification with descriptions
    - `capec` — attack patterns describing how the weakness is exploited
    - `techniques` — ATT&CK techniques linked through published vulnerability relationships
    - `tie` — technique likelihood predictions (probability per technique)
    - `misp` — matching threat intelligence events from your threat feed
    - `knowledgebase` — related context from the intelligence knowledge base
    - `web` — live web search for exploit PoCs, advisories, and security research
    - `web_scrape` — scraped article text added to the top web results (requires `web`)
    - `affected_products` — confirmed vulnerable software with vendor, product, version, and CPE string
    - `poc` — proof-of-concept exploits from GitHub (count + repo metadata)
    - `poc_source` — AI-assisted analysis of selected PoC repositories (trigger, affected path,
      preconditions, and mitigation); raw source code is never returned
    - `exploits` — confirmed exploit records from the KEV exploit feed (real evidence, not the
      heuristic `has_public_exploit` boolean)
    - `osv` — OSV.dev advisories aliased to this CVE (GHSA/PYSEC/RUSTSEC records plus per-ecosystem
      fixed versions; the same advisory source used by `/v1/enrich/package`)
    - `groups` — threat actor groups known to use the linked ATT&CK techniques
    - `software` — malware and tools that employ the linked techniques
    - `campaigns` — threat campaigns that used the linked techniques
    - `mitigations` — defensive courses of action for each linked technique
    - `detections` — data sources and components for detecting each linked technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `similar_cves` — up to 15 CVEs with overlapping weakness/technique fingerprint, ranked by
      weighted Jaccard similarity (signal-by-signal breakdown included)
    - `sector_context` — evidence-based industry sector detection from threat group targeting patterns
    - `timeline` — EPSS score history for trend visualisation (pair with `epss_velocity`)
    - `navigator` — ATT&CK Navigator layer JSON for MITRE's Navigator tool
    - `summary` — AI-generated 3-5 sentence executive brief covering severity, exploitation
      status, and key attack techniques
    - `inferred_chain` — quarantined AI-assisted technique candidates, returned only when published
      mappings yield no techniques. These low-confidence analyst hints are never treated as
    authoritative.
    - `nist_controls` *(default-on)* — NIST SP 800-53 rev 5 controls that mitigate the CVE's mapped
      techniques, based on MITRE Center for Threat-Informed Defense mappings
    - `ssvc` — SSVC vulnerability-prioritisation decision (CERT/CC Deployer tree by default, or CISA
      Coordinator tree). Stakeholder context comes from the optional `stakeholder` request field;
      defaults to the worst-reasonable case for an unknown environment.

    Several extra fields always populate regardless of `include`: `techniques_provenance` (precision
    class of `techniques[]`), `likely_tactics` (vendor tactic-class hints when the chain walk is
    empty), `confidence` (importance-weighted completeness indicator), `weaponization_score` (0-100
    composite).

    Omitted include values return as `null` or empty arrays. The `errors` array reports any partial
    failures.

    Args:
        body (EnrichCVERequest): Enrich a CVE with severity, exploit intelligence, attack
            patterns, and AI analysis.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCVEResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
