from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_package_request import EnrichPackageRequest
from ...models.enrich_package_response import EnrichPackageResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichPackageRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/package",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichPackageResponse | None:
    if response.status_code == 200:
        response_200 = EnrichPackageResponse.from_dict(response.json())

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
) -> Response[Any | EnrichPackageResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichPackageRequest,
) -> Response[Any | EnrichPackageResponse]:
    """Enrich Package

     Enrich an open-source package — OSV.dev advisories plus full multi-source CVE enrichment.

    The package-ecosystem sibling of `/v1/enrich/product`. Keyed by **ecosystem + name (+ optional
    version)**, it covers the dependency-vulnerability surface (npm, PyPI, Go, Maven, crates.io,
    NuGet, RubyGems, …) that the CPE-keyed product endpoint cannot reach.

    OSV.dev supplies the advisories (id, cross-database aliases CVE/GHSA, fixed versions, severity,
    affected ranges, references — CVE-aliased first). The CVEs those advisories alias are then
    enriched through the **same multi-source enrichment chain** (CWE → CAPEC → ATT&CK techniques, EPSS,
    KEV, mitigations, …) as `enrich/product`'s nested CVEs, returned under `cves[]`. Supplying a
    `version` filters advisories to that version.

    **Include options**

    OSV-advisory verbosity:

    - `details` — full advisory description and metadata
    - `severity` — CVSS vectors and labels
    - `affected` — affected/fixed version ranges
    - `references` — advisory reference URLs

    Nested CVE enrichment accepts every CVE layer listed in the request schema, including exploit
    probability and exploitation evidence, weakness and ATT&CK mappings, related groups and software,
    defensive guidance, source research, SSVC decisions, NIST controls, timeline and similarity context,
    and AI-assisted summaries.

    The advisory core is always returned. `cves[]` populates only when at least one CVE-chain option
    is requested (the fan-out is bounded and deduped per request).

    Args:
        body (EnrichPackageRequest): Find vulnerabilities affecting an open-source package via
            OSV.dev.

            Keyed by package **ecosystem + name (+ optional version)** — the dependency-vuln
            surface (npm / PyPI / Go / Maven / crates.io / …) that the CPE-keyed `enrich/product`
            can't reach. With a version, results are filtered to advisories whose affected ranges
            include it; without one, every advisory for the package is returned.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichPackageResponse]
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
    body: EnrichPackageRequest,
) -> Any | EnrichPackageResponse | None:
    """Enrich Package

     Enrich an open-source package — OSV.dev advisories plus full multi-source CVE enrichment.

    The package-ecosystem sibling of `/v1/enrich/product`. Keyed by **ecosystem + name (+ optional
    version)**, it covers the dependency-vulnerability surface (npm, PyPI, Go, Maven, crates.io,
    NuGet, RubyGems, …) that the CPE-keyed product endpoint cannot reach.

    OSV.dev supplies the advisories (id, cross-database aliases CVE/GHSA, fixed versions, severity,
    affected ranges, references — CVE-aliased first). The CVEs those advisories alias are then
    enriched through the **same multi-source enrichment chain** (CWE → CAPEC → ATT&CK techniques, EPSS,
    KEV, mitigations, …) as `enrich/product`'s nested CVEs, returned under `cves[]`. Supplying a
    `version` filters advisories to that version.

    **Include options**

    OSV-advisory verbosity:

    - `details` — full advisory description and metadata
    - `severity` — CVSS vectors and labels
    - `affected` — affected/fixed version ranges
    - `references` — advisory reference URLs

    Nested CVE enrichment accepts every CVE layer listed in the request schema, including exploit
    probability and exploitation evidence, weakness and ATT&CK mappings, related groups and software,
    defensive guidance, source research, SSVC decisions, NIST controls, timeline and similarity context,
    and AI-assisted summaries.

    The advisory core is always returned. `cves[]` populates only when at least one CVE-chain option
    is requested (the fan-out is bounded and deduped per request).

    Args:
        body (EnrichPackageRequest): Find vulnerabilities affecting an open-source package via
            OSV.dev.

            Keyed by package **ecosystem + name (+ optional version)** — the dependency-vuln
            surface (npm / PyPI / Go / Maven / crates.io / …) that the CPE-keyed `enrich/product`
            can't reach. With a version, results are filtered to advisories whose affected ranges
            include it; without one, every advisory for the package is returned.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichPackageResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichPackageRequest,
) -> Response[Any | EnrichPackageResponse]:
    """Enrich Package

     Enrich an open-source package — OSV.dev advisories plus full multi-source CVE enrichment.

    The package-ecosystem sibling of `/v1/enrich/product`. Keyed by **ecosystem + name (+ optional
    version)**, it covers the dependency-vulnerability surface (npm, PyPI, Go, Maven, crates.io,
    NuGet, RubyGems, …) that the CPE-keyed product endpoint cannot reach.

    OSV.dev supplies the advisories (id, cross-database aliases CVE/GHSA, fixed versions, severity,
    affected ranges, references — CVE-aliased first). The CVEs those advisories alias are then
    enriched through the **same multi-source enrichment chain** (CWE → CAPEC → ATT&CK techniques, EPSS,
    KEV, mitigations, …) as `enrich/product`'s nested CVEs, returned under `cves[]`. Supplying a
    `version` filters advisories to that version.

    **Include options**

    OSV-advisory verbosity:

    - `details` — full advisory description and metadata
    - `severity` — CVSS vectors and labels
    - `affected` — affected/fixed version ranges
    - `references` — advisory reference URLs

    Nested CVE enrichment accepts every CVE layer listed in the request schema, including exploit
    probability and exploitation evidence, weakness and ATT&CK mappings, related groups and software,
    defensive guidance, source research, SSVC decisions, NIST controls, timeline and similarity context,
    and AI-assisted summaries.

    The advisory core is always returned. `cves[]` populates only when at least one CVE-chain option
    is requested (the fan-out is bounded and deduped per request).

    Args:
        body (EnrichPackageRequest): Find vulnerabilities affecting an open-source package via
            OSV.dev.

            Keyed by package **ecosystem + name (+ optional version)** — the dependency-vuln
            surface (npm / PyPI / Go / Maven / crates.io / …) that the CPE-keyed `enrich/product`
            can't reach. With a version, results are filtered to advisories whose affected ranges
            include it; without one, every advisory for the package is returned.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichPackageResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichPackageRequest,
) -> Any | EnrichPackageResponse | None:
    """Enrich Package

     Enrich an open-source package — OSV.dev advisories plus full multi-source CVE enrichment.

    The package-ecosystem sibling of `/v1/enrich/product`. Keyed by **ecosystem + name (+ optional
    version)**, it covers the dependency-vulnerability surface (npm, PyPI, Go, Maven, crates.io,
    NuGet, RubyGems, …) that the CPE-keyed product endpoint cannot reach.

    OSV.dev supplies the advisories (id, cross-database aliases CVE/GHSA, fixed versions, severity,
    affected ranges, references — CVE-aliased first). The CVEs those advisories alias are then
    enriched through the **same multi-source enrichment chain** (CWE → CAPEC → ATT&CK techniques, EPSS,
    KEV, mitigations, …) as `enrich/product`'s nested CVEs, returned under `cves[]`. Supplying a
    `version` filters advisories to that version.

    **Include options**

    OSV-advisory verbosity:

    - `details` — full advisory description and metadata
    - `severity` — CVSS vectors and labels
    - `affected` — affected/fixed version ranges
    - `references` — advisory reference URLs

    Nested CVE enrichment accepts every CVE layer listed in the request schema, including exploit
    probability and exploitation evidence, weakness and ATT&CK mappings, related groups and software,
    defensive guidance, source research, SSVC decisions, NIST controls, timeline and similarity context,
    and AI-assisted summaries.

    The advisory core is always returned. `cves[]` populates only when at least one CVE-chain option
    is requested (the fan-out is bounded and deduped per request).

    Args:
        body (EnrichPackageRequest): Find vulnerabilities affecting an open-source package via
            OSV.dev.

            Keyed by package **ecosystem + name (+ optional version)** — the dependency-vuln
            surface (npm / PyPI / Go / Maven / crates.io / …) that the CPE-keyed `enrich/product`
            can't reach. With a version, results are filtered to advisories whose affected ranges
            include it; without one, every advisory for the package is returned.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichPackageResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
