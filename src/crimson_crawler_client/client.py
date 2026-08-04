"""High-level wrapper around the generated Crimson Crawler API client.

Configures API-key authentication (``apikey`` header), reads connection details
from environment variables when not supplied, and provides convenience methods
that encode the most common ``include=[...]`` enrichment chains.

Every method sends one request to the configured public API. The wrapper adds no
caching, proxying, or extra network hops.

Example:
    Basic usage as an async context manager::

        async with CrawlerClient() as client:
            result = await client.enrich_cve_full("CVE-2024-3400")
            print(result.cve.cvss_score)
            for technique in result.techniques:
                print(technique.technique_id)

    Every one of the 33 ``/v1`` operations has a named method; the generated layer
    stays reachable for hand-built request models and sync callers::

        async with CrawlerClient() as client:
            from crimson_crawler_client._generated.api.search import search_cve
            from crimson_crawler_client._generated.models import SearchCVERequest
            result = await search_cve.asyncio(
                client=client.api,
                body=SearchCVERequest(kev=True, epss_min=0.9),
            )
"""

from __future__ import annotations

import os
import warnings
from ipaddress import ip_address
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, TypeVar
from urllib.parse import urlsplit

import httpx

from . import presets
from ._generated import AuthenticatedClient
from ._generated.api.artifact_enrich import artifact_enrich, artifact_enrich_status
from ._generated.api.assess import (
    assess_group_exposure,
    assess_ioc_portfolio,
    assess_technique_coverage,
    assess_vulnerability_exposure,
)
from ._generated.api.enrichment import (
    enrich_atlas,
    enrich_batch,
    enrich_campaign,
    enrich_capec,
    enrich_cve,
    enrich_cwe,
    enrich_defend,
    enrich_disarm,
    enrich_group,
    enrich_ioc,
    enrich_location,
    enrich_package,
    enrich_poc_source,
    enrich_product,
    enrich_sector,
    enrich_software,
    enrich_technique,
)
from ._generated.api.inventory_enrich import inventory_enrich, inventory_enrich_status
from ._generated.api.search import (
    search_cti,
    search_cve,
    search_d3fend,
    search_kev,
    search_knowledgebase,
    search_misp,
    search_poc,
    search_vendor,
)
from ._generated.models import (
    ArtifactEnrichmentDocRequest,
    ArtifactEnrichmentDocRequestFormatsItem,
    ArtifactEnrichmentFileInput,
    ArtifactEnrichmentJobResponse,
    ArtifactEnrichmentStakeholder,
    AssessGroupExposureRequest,
    AssessGroupExposureRequestFramework,
    AssessGroupExposureResponse,
    AssessIOCPortfolioRequest,
    AssessIOCPortfolioRequestIndicatorsItem,
    AssessIOCPortfolioResponse,
    AssessTechniqueCoverageRequest,
    AssessTechniqueCoverageRequestFramework,
    AssessTechniqueCoverageResponse,
    AssessVulnerabilityExposureRequest,
    AssessVulnerabilityExposureResponse,
    EnrichATLASRequest,
    EnrichATLASResponse,
    EnrichBatchRequest,
    EnrichBatchResponse,
    EnrichCampaignRequest,
    EnrichCampaignRequestFramework,
    EnrichCampaignResponse,
    EnrichCAPECRequest,
    EnrichCAPECResponse,
    EnrichCVERequest,
    EnrichCVEResponse,
    EnrichCWERequest,
    EnrichCWEResponse,
    EnrichD3FENDRequest,
    EnrichD3FENDResponse,
    EnrichDISARMRequest,
    EnrichDISARMResponse,
    EnrichGroupRequest,
    EnrichGroupRequestFramework,
    EnrichGroupResponse,
    EnrichIOCRequest,
    EnrichIOCResponse,
    EnrichLocationRequest,
    EnrichLocationResponse,
    EnrichmentSubmitResponse,
    EnrichPackageRequest,
    EnrichPackageResponse,
    EnrichProductRequest,
    EnrichProductResponse,
    EnrichSectorRequest,
    EnrichSectorResponse,
    EnrichSoftwareRequest,
    EnrichSoftwareRequestFramework,
    EnrichSoftwareResponse,
    EnrichTechniqueRequest,
    EnrichTechniqueResponse,
    FetchPoCSourceRequest,
    FetchPoCSourceResponse,
    InventoryAsset,
    InventoryEnrichmentJobResponse,
    InventoryEnrichmentRequest,
    SearchCTIRequest,
    SearchCTIRequestTypesType0Item,
    SearchCTIResponse,
    SearchCVERequest,
    SearchCVERequestSortType0,
    SearchCVERequestVulnStatusType0,
    SearchCVEResponse,
    SearchD3FENDRequest,
    SearchD3FENDRequestD3FendFormType0,
    SearchD3FENDResponse,
    SearchKEVRequest,
    SearchKEVRequestRansomwareStatusType0,
    SearchKEVResponse,
    SearchKnowledgebaseRequest,
    SearchKnowledgebaseRequestCollectionsItem,
    SearchKnowledgebaseResponse,
    SearchMISPRequest,
    SearchMISPResponse,
    SearchPoCRequest,
    SearchPoCResponse,
    SearchVendorRequest,
    SearchVendorResponse,
)
from ._generated.types import UNSET, Response
from ._retry import RetryTransport
from .ai_reports import AiReportsAPI
from .artifact_manager import ArtifactManagerAPI
from .enricher import EnricherAPI
from .exceptions import MissingCredentials, UnexpectedStatus
from .inventory_manager import InventoryManagerAPI

if TYPE_CHECKING:
    from typing import Self


BASE_URL: str = "https://crimsoncrawler.com"
"""Default Crimson Crawler endpoint. ``base_url=`` or
``CRIMSON_CRAWLER_BASE_URL`` selects a custom, self-hosted, or local
deployment."""

DEFAULT_TIMEOUT_SECONDS: float = 90.0
"""Sized for cold-cache full-chain enrich; reduce for fast-preset workloads."""

DEFAULT_MAX_RETRIES: int = 2
"""Default retry count → 3 total attempts (1 initial + 2 retries). Matches
the OpenAI/Anthropic SDK defaults. Override via ``max_retries=`` constructor
arg; ``0`` disables retries entirely."""

ENV_API_KEY = "CRIMSON_CRAWLER_API_KEY"
ENV_BASE_URL = "CRIMSON_CRAWLER_BASE_URL"
ENV_VERIFY_SSL = "CRIMSON_CRAWLER_VERIFY_SSL"


def _resolve_verify_ssl(verify_ssl: bool | None) -> bool:
    """Resolve the verify_ssl flag from constructor arg or env var.

    Constructor arg wins. Env-var fallback accepts ``false``/``0``/``no``
    (case-insensitive) to disable TLS verification; any other value (or
    unset) keeps verification on. Defaulting to ``True`` is intentional —
    self-signed-cert deployments (e.g. internal preview environments) must
    opt out explicitly.
    """
    if verify_ssl is not None:
        return verify_ssl
    raw = os.environ.get(ENV_VERIFY_SSL, "true").strip().lower()
    return raw not in {"false", "0", "no"}


def _validate_base_url(base_url: str) -> None:
    """Reject malformed or credential-unsafe API origins."""
    if not base_url or base_url != base_url.strip() or any(character.isspace() for character in base_url):
        raise ValueError("base_url must be a valid HTTPS URL or an HTTP loopback URL")

    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("base_url must be a valid HTTPS URL or an HTTP loopback URL") from exc

    if not hostname or not parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must be a valid HTTPS URL or an HTTP loopback URL")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("base_url must contain only an origin, without a path, query, or fragment")

    loopback = hostname.lower() == "localhost"
    if not loopback:
        try:
            loopback = ip_address(hostname).is_loopback
        except ValueError:
            pass

    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("base_url must use HTTPS unless its host is loopback")


def _warn_connection_override(
    *,
    base_url: str,
    base_url_source: str,
    verify_ssl: bool,
    verify_ssl_source: str,
) -> None:
    if base_url != BASE_URL:
        warnings.warn(
            f"Crimson Crawler API origin override is active (source: {base_url_source}); "
            "inspect client.base_url explicitly for the configured origin",
            RuntimeWarning,
            stacklevel=3,
        )
    if not verify_ssl:
        warnings.warn(
            f"TLS certificate and hostname verification disabled by {verify_ssl_source}",
            RuntimeWarning,
            stacklevel=3,
        )


class CrawlerClient:
    """Typed wrapper around the generated Crimson Crawler API client.

    Args:
        api_key: API key. Sent as ``apikey`` header on every request.
            Falls back to the ``CRIMSON_CRAWLER_API_KEY`` env var. Required.
        base_url: API endpoint. Falls back to the
            ``CRIMSON_CRAWLER_BASE_URL`` env var, then the hosted
            ``https://crimsoncrawler.com`` default. The API key is sent to
            this origin, so use a local/development key for custom endpoints.
        verify_ssl: TLS certificate verification toggle. Falls back to the
            ``CRIMSON_CRAWLER_VERIFY_SSL`` env var (accepts ``false``/``0``/
            ``no`` to disable), then to ``True``. Prefer trusting the
            deployment's CA. Set to ``False`` only for local or isolated
            self-signed development endpoints.
        max_retries: Number of automatic retries on transient failures
            (HTTP 429/502/503/504 and connect/read/write transport errors)
            for safe HTTP methods (``GET``/``HEAD``/``OPTIONS``) only.
            Defaults to ``2`` (3 total attempts). Set to ``0`` to disable.
            Retries use exponential backoff with jitter and honor a
            ``Retry-After`` header when present. Mutating requests —
            including Platform writes and deletes — always make exactly
            one attempt regardless of this setting.

    Raises:
        MissingCredentials: ``api_key`` not provided and ``CRIMSON_CRAWLER_API_KEY``
            env var is unset.
        ValueError: ``base_url`` is malformed or not HTTPS (except for loopback), or ``max_retries`` is negative.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        verify_ssl: bool | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        resolved_api_key = api_key if api_key is not None else os.environ.get(ENV_API_KEY)
        if not resolved_api_key:
            raise MissingCredentials(f"Set {ENV_API_KEY} or pass api_key= explicitly.")
        resolved_base_url = base_url if base_url is not None else os.environ.get(ENV_BASE_URL, BASE_URL)
        _validate_base_url(resolved_base_url)
        self._base_url = resolved_base_url
        self._verify_ssl = _resolve_verify_ssl(verify_ssl)
        _warn_connection_override(
            base_url=resolved_base_url,
            base_url_source="constructor argument" if base_url is not None else f"{ENV_BASE_URL} environment variable",
            verify_ssl=self._verify_ssl,
            verify_ssl_source=(
                "constructor argument" if verify_ssl is not None else f"{ENV_VERIFY_SSL} environment variable"
            ),
        )
        if max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {max_retries}")
        self._max_retries = max_retries

        self._artifact_manager: ArtifactManagerAPI | None = None
        self._inventory_manager: InventoryManagerAPI | None = None
        self._enricher: EnricherAPI | None = None
        self._ai_reports: AiReportsAPI | None = None
        self._inner = AuthenticatedClient(
            base_url=resolved_base_url,
            token=resolved_api_key,
            prefix="",
            auth_header_name="apikey",
            verify_ssl=self._verify_ssl,
            timeout=httpx.Timeout(DEFAULT_TIMEOUT_SECONDS),
            # We surface non-2xx as UnexpectedStatus from convenience methods
            # ourselves (carrying status + body, matching the TS wrapper).
            raise_on_unexpected_status=False,
            # Install a retry transport so all convenience methods AND the
            # client.api escape hatch get transparent backoff. Once we supply
            # our own transport, the AuthenticatedClient verify_ssl arg above
            # no longer governs TLS — the inner transport must be built with
            # verify=self._verify_ssl explicitly (done here).
            httpx_args={
                "transport": RetryTransport(
                    max_retries=self._max_retries,
                    verify=self._verify_ssl,
                ),
            },
        )

    @property
    def api(self) -> AuthenticatedClient:
        """Underlying generated client. An escape hatch for hand-built request models and
        sync callers — every one of the 33 endpoints also has a named method on this class."""
        return self._inner

    @property
    def artifact_manager(self) -> ArtifactManagerAPI:
        """The Artifact Manager API (Artifact Manager) — your stored artifacts, enrichment exports,
        ratings, enrichment-compare, and folders over the same key. Hand-written (the
        ``/artifact-manager/*`` surface lives outside the ``/v1`` OpenAPI contract) and
        **usage-exempt** — artifact_manager calls never count toward your API usage."""
        if self._artifact_manager is None:
            self._artifact_manager = ArtifactManagerAPI(self._inner.get_async_httpx_client())
        return self._artifact_manager

    @property
    def inventory_manager(self) -> InventoryManagerAPI:
        """The Inventory Manager API — your monitored inventory context windows (asset inventory +
        attached artifacts + saved enrichment history) over the same key. Its own section at
        ``/inventory-manager/inventories/*`` (outside the ``/v1`` OpenAPI contract). **Usage-exempt**
        except ``enrich_inventory``'s submit, which is enrichment compute and counts toward your usage."""
        if self._inventory_manager is None:
            self._inventory_manager = InventoryManagerAPI(self._inner.get_async_httpx_client())
        return self._inventory_manager

    @property
    def enricher(self) -> EnricherAPI:
        """The Enricher API — the async artifact-enrichment lifecycle (submit → poll → report) over the same
        key, straight against the ``/v1/artifact-enrich`` engine. The enrichment submit counts toward usage;
        polling is the engine's own status read."""
        if self._enricher is None:
            self._enricher = EnricherAPI(self._inner.get_async_httpx_client())
        return self._enricher

    @property
    def ai_reports(self) -> AiReportsAPI:
        """The Report Generator API — generate + manage grounded intelligence reports
        from your saved artifacts, at ``/ai-reports/*`` (its own section, outside the ``/v1`` OpenAPI
        contract). **Usage-exempt**, including the LLM generation."""
        if self._ai_reports is None:
            self._ai_reports = AiReportsAPI(self._inner.get_async_httpx_client())
        return self._ai_reports

    @property
    def base_url(self) -> str:
        """The resolved Crimson Crawler API base URL for this client instance."""
        return self._base_url

    @property
    def max_retries(self) -> int:
        """Number of automatic retries on transient failures (read-only)."""
        return self._max_retries

    async def __aenter__(self) -> Self:
        await self._inner.get_async_httpx_client().__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._inner.get_async_httpx_client().__aexit__(exc_type, exc, tb)

    async def aclose(self) -> None:
        """Close the underlying httpx client. Prefer ``async with`` for normal use."""
        await self._inner.get_async_httpx_client().aclose()

    # -- Convenience methods for the most common enrichment chains --------- #

    async def enrich_cve_full(
        self,
        cve_id: str,
        *,
        include: list[str] | None = None,
    ) -> EnrichCVEResponse:
        """Walk the full CVE → CWE → CAPEC → ATT&CK → TIE chain plus MISP/knowledge base/web.

        Args:
            cve_id: CVE identifier (e.g. ``CVE-2024-3400``).
            include: Override the default :data:`presets.CVE_FULL_WALK` chain.

        Returns:
            Fully enriched response with all chain layers populated.

        Raises:
            UnexpectedStatus: Server returned a non-success status or an
                unparseable body. ``status`` and ``body`` carry the response.
        """
        body = EnrichCVERequest(
            cve_id=cve_id,
            include=include if include is not None else presets.CVE_FULL_WALK,
        )
        result = await enrich_cve.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichCVEResponse)

    async def enrich_ioc_full(
        self,
        value: str,
        ioc_type: str = "ip-dst",
        *,
        include: list[str] | None = None,
    ) -> EnrichIOCResponse:
        """Enrich an IOC against MISP, link to ATT&CK, and add knowledge base/web context.

        Args:
            value: Indicator value (hash, IP, domain, URL).
            ioc_type: MISP-style attribute type — ``ip-dst``, ``ip-src``, ``domain``,
                ``hostname``, ``md5``, ``sha1``, ``sha256``, ``url``, etc. Defaults
                to ``ip-dst`` matching the API default.
            include: Override the default :data:`presets.IOC_FULL_WALK` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichIOCRequest(
            value=value,
            type_=ioc_type,
            include=include if include is not None else presets.IOC_FULL_WALK,
        )
        result = await enrich_ioc.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichIOCResponse)

    async def enrich_cwe_full(
        self,
        cwe_id: str,
        *,
        include: list[str] | None = None,
    ) -> EnrichCWEResponse:
        """Walk CWE → CAPEC → ATT&CK with TIE predictions.

        Args:
            cwe_id: CWE identifier (e.g. ``CWE-79``).
            include: Override the default :data:`presets.CWE_FULL_WALK` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichCWERequest(
            cwe_id=cwe_id,
            include=include if include is not None else presets.CWE_FULL_WALK,
        )
        result = await enrich_cwe.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichCWEResponse)

    async def enrich_technique_full(
        self,
        technique_ids: list[str],
        *,
        framework: Literal["enterprise", "ics", "mobile"] = "enterprise",
        include: list[str] | None = None,
    ) -> EnrichTechniqueResponse:
        """Enrich one or more ATT&CK techniques with TIE, adversary attribution, Navigator JSON.

        Args:
            technique_ids: ATT&CK technique IDs (e.g. ``["T1190", "T1059.001"]``).
            framework: ATT&CK matrix variant — ``enterprise``, ``ics``, or ``mobile``.
            include: Override the default :data:`presets.TECHNIQUE_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        # Regression from the API's Literal["enterprise","ics","mobile"]
        # migration: openapi-python-client codegen now emits an
        # EnrichTechniqueRequestFramework Enum for that field (because the
        # OpenAPI schema gained an `enum: [...]` constraint). The generated
        # request model's `to_dict()` calls `.value` on it, so passing a
        # plain str raises AttributeError. Convert here so the public
        # convenience-method signature stays string-typed.
        from ._generated.models.enrich_technique_request_framework import (
            EnrichTechniqueRequestFramework,
        )

        body = EnrichTechniqueRequest(
            technique_ids=technique_ids,
            framework=EnrichTechniqueRequestFramework(framework),
            include=include if include is not None else presets.TECHNIQUE_FULL,
        )
        result = await enrich_technique.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichTechniqueResponse)

    async def enrich_product_full(
        self,
        product: str,
        *,
        version: str | None = None,
        vendor: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichProductResponse:
        """Find vulnerabilities affecting a product/version and enrich each matched CVE.

        Args:
            product: Product name (e.g. ``"Apache HTTP Server"``, ``"nginx"``).
            version: Optional specific version (e.g. ``"2.4.51"``).
            vendor: Optional vendor name to narrow results (e.g. ``"apache"``).
            include: Override the default :data:`presets.PRODUCT_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichProductRequest(
            product=product,
            version=version if version is not None else UNSET,
            vendor=vendor if vendor is not None else UNSET,
            include=include if include is not None else presets.PRODUCT_FULL,
        )
        result = await enrich_product.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichProductResponse)

    async def enrich_package_full(
        self,
        ecosystem: str,
        package: str,
        *,
        version: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichPackageResponse:
        """Enrich an open-source package — OSV.dev advisories + full CVE enrichment.

        The package-ecosystem sibling of :meth:`enrich_product_full`: OSV.dev supplies the package's
        advisories, and the CVEs they alias are enriched through the same CWE→CAPEC→ATT&CK + EPSS/KEV
        chain. Covers the dependency-vuln surface (npm / PyPI / Go / Maven / crates.io / …) the
        CPE-keyed product endpoint can't reach.

        Args:
            ecosystem: Package ecosystem (e.g. ``"PyPI"``, ``"npm"``, ``"Go"``; loose spellings normalized).
            package: Package name as published in its ecosystem registry (e.g. ``"django"``).
            version: Optional installed version to filter advisories to.
            include: Override the default :data:`presets.PACKAGE_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichPackageRequest(
            ecosystem=ecosystem,
            package=package,
            version=version if version is not None else UNSET,
            include=include if include is not None else presets.PACKAGE_FULL,
        )
        result = await enrich_package.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichPackageResponse)

    async def search_techniques(
        self,
        keyword: str,
        *,
        limit: int = 20,
    ) -> SearchCTIResponse:
        """Keyword-search the ATT&CK knowledge base for matching techniques.

        A convenience wrapper over the generated ``search_cti`` endpoint, scoped
        to ATT&CK attack-patterns. Replaces the raw ``client.api`` escape hatch
        callers previously used to hand-build the request: the generated
        ``types`` field is an enum whose ``to_dict()`` calls ``.value``, so
        passing a plain string raises ``AttributeError`` at serialisation time.
        This method passes the enum, killing that footgun.

        Args:
            keyword: Free-text query (e.g. ``"phishing"``, ``"credential dumping"``).
            limit: Maximum number of results to return (1-100). Default 20.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchCTIRequest(
            query=keyword,
            sources=["attack"],
            types=[SearchCTIRequestTypesType0Item.ATTACK_PATTERN],
            limit=limit,
        )
        result = await search_cti.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchCTIResponse)

    # -- Remaining enrichment endpoints ------------------------------------ #

    async def enrich_capec_full(
        self,
        capec_id: str | None = None,
        *,
        search: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichCAPECResponse:
        """Walk CAPEC → ATT&CK with TIE predictions, exploiting CVEs, and adversary attribution.

        Args:
            capec_id: CAPEC identifier for direct lookup (e.g. ``CAPEC-66``).
            search: Text query to search attack patterns by name or description. Supply
                this or ``capec_id``; the server rejects a request carrying neither.
            include: Override the default :data:`presets.CAPEC_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichCAPECRequest(
            capec_id=capec_id if capec_id is not None else UNSET,
            search=search if search is not None else UNSET,
            include=include if include is not None else presets.CAPEC_FULL,
        )
        result = await enrich_capec.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichCAPECResponse)

    async def enrich_atlas_full(
        self,
        technique_id: str | None = None,
        *,
        search: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichATLASResponse:
        """Enrich an adversarial-ML (MITRE ATLAS) technique and map it onto ATT&CK.

        Args:
            technique_id: ATLAS technique ID for direct lookup (e.g. ``AML.T0043``).
            search: Text query to search AI/ML attack techniques. Supply this or
                ``technique_id``; the server rejects a request carrying neither.
            include: Override the default :data:`presets.ATLAS_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichATLASRequest(
            technique_id=technique_id if technique_id is not None else UNSET,
            search=search if search is not None else UNSET,
            include=include if include is not None else presets.ATLAS_FULL,
        )
        result = await enrich_atlas.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichATLASResponse)

    async def enrich_disarm_full(
        self,
        technique_id: str | None = None,
        *,
        search: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichDISARMResponse:
        """Enrich a DISARM disinformation technique with its countermeasures and ATT&CK mapping.

        Args:
            technique_id: DISARM technique ID for direct lookup (e.g. ``T0001``).
            search: Text query to search disinformation techniques. Supply this or
                ``technique_id``; the server rejects a request carrying neither.
            include: Override the default :data:`presets.DISARM_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichDISARMRequest(
            technique_id=technique_id if technique_id is not None else UNSET,
            search=search if search is not None else UNSET,
            include=include if include is not None else presets.DISARM_FULL,
        )
        result = await enrich_disarm.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichDISARMResponse)

    async def enrich_defend_full(
        self,
        d3fend_id: str | None = None,
        *,
        search: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichD3FENDResponse:
        """Enrich a D3FEND defensive technique with the ATT&CK techniques it counters.

        Args:
            d3fend_id: D3FEND identifier for direct lookup (e.g. ``D3-AL``).
            search: Text query to search defensive techniques. Supply this or
                ``d3fend_id``; the server rejects a request carrying neither.
            include: Override the default :data:`presets.DEFEND_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichD3FENDRequest(
            d3fend_id=d3fend_id if d3fend_id is not None else UNSET,
            search=search if search is not None else UNSET,
            include=include if include is not None else presets.DEFEND_FULL,
        )
        result = await enrich_defend.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichD3FENDResponse)

    async def enrich_group_full(
        self,
        group_id: str | None = None,
        *,
        search: str | None = None,
        framework: Literal["enterprise", "ics", "mobile"] = "enterprise",
        include: list[str] | None = None,
    ) -> EnrichGroupResponse:
        """Enrich a threat actor with its techniques, tooling, campaigns, and target profile.

        Args:
            group_id: ATT&CK group ID for direct lookup (e.g. ``G0016``).
            search: Group name or alias to search (e.g. ``"APT28"``). Supply this or
                ``group_id``; the server rejects a request carrying neither.
            framework: ATT&CK matrix variant — ``enterprise``, ``ics``, or ``mobile``.
            include: Override the default :data:`presets.GROUP_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichGroupRequest(
            group_id=group_id if group_id is not None else UNSET,
            search=search if search is not None else UNSET,
            framework=EnrichGroupRequestFramework(framework),
            include=include if include is not None else presets.GROUP_FULL,
        )
        result = await enrich_group.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichGroupResponse)

    async def enrich_software_full(
        self,
        software_id: str | None = None,
        *,
        search: str | None = None,
        framework: Literal["enterprise", "ics", "mobile"] = "enterprise",
        include: list[str] | None = None,
    ) -> EnrichSoftwareResponse:
        """Enrich malware or a tool with the techniques it implements and the actors wielding it.

        Args:
            software_id: ATT&CK software ID for direct lookup (e.g. ``S0154``).
            search: Name or alias to search (e.g. ``"Cobalt Strike"``). Supply this or
                ``software_id``; the server rejects a request carrying neither.
            framework: ATT&CK matrix variant — ``enterprise``, ``ics``, or ``mobile``.
            include: Override the default :data:`presets.SOFTWARE_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichSoftwareRequest(
            software_id=software_id if software_id is not None else UNSET,
            search=search if search is not None else UNSET,
            framework=EnrichSoftwareRequestFramework(framework),
            include=include if include is not None else presets.SOFTWARE_FULL,
        )
        result = await enrich_software.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichSoftwareResponse)

    async def enrich_campaign_full(
        self,
        campaign_id: str | None = None,
        *,
        search: str | None = None,
        framework: Literal["enterprise", "ics", "mobile"] = "enterprise",
        include: list[str] | None = None,
    ) -> EnrichCampaignResponse:
        """Enrich a threat campaign with its techniques, attributed groups, tooling, and CVEs.

        Args:
            campaign_id: ATT&CK campaign ID for direct lookup (e.g. ``C0028``).
            search: Text query to search campaigns by name or description. Supply this
                or ``campaign_id``; the server rejects a request carrying neither.
            framework: ATT&CK matrix variant — ``enterprise``, ``ics``, or ``mobile``.
            include: Override the default :data:`presets.CAMPAIGN_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichCampaignRequest(
            campaign_id=campaign_id if campaign_id is not None else UNSET,
            search=search if search is not None else UNSET,
            framework=EnrichCampaignRequestFramework(framework),
            include=include if include is not None else presets.CAMPAIGN_FULL,
        )
        result = await enrich_campaign.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichCampaignResponse)

    async def enrich_location_full(
        self,
        location_id: str | None = None,
        *,
        search: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichLocationResponse:
        """Enrich a region's threat landscape — active groups, their techniques, targeted sectors.

        Args:
            location_id: ATT&CK location ID for direct lookup.
            search: Country or region name to search (e.g. ``"United States"``). Supply
                this or ``location_id``; the server rejects a request carrying neither.
            include: Override the default :data:`presets.LOCATION_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichLocationRequest(
            location_id=location_id if location_id is not None else UNSET,
            search=search if search is not None else UNSET,
            include=include if include is not None else presets.LOCATION_FULL,
        )
        result = await enrich_location.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichLocationResponse)

    async def enrich_sector_full(
        self,
        sector_id: str | None = None,
        *,
        search: str | None = None,
        include: list[str] | None = None,
    ) -> EnrichSectorResponse:
        """Enrich an industry sector's threat landscape — groups targeting it and how.

        Args:
            sector_id: Sector identifier for direct lookup.
            search: Sector name to search (e.g. ``"healthcare"``). Supply this or
                ``sector_id``; the server rejects a request carrying neither.
            include: Override the default :data:`presets.SECTOR_FULL` chain.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichSectorRequest(
            sector_id=sector_id if sector_id is not None else UNSET,
            search=search if search is not None else UNSET,
            include=include if include is not None else presets.SECTOR_FULL,
        )
        result = await enrich_sector.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichSectorResponse)

    async def enrich_batch(self, items: list[dict[str, Any]]) -> EnrichBatchResponse:
        """Run up to 50 heterogeneous ``enrich/*`` lookups in one request.

        No preset: each item carries its own ``include``, so the list is passed through
        untouched. Every item needs a ``type`` discriminator naming one of the 16 enrich
        kinds (``cve``, ``product``, ``package``, ``cwe``, ``capec``, ``technique``,
        ``ioc``, ``group``, ``software``, ``campaign``, ``atlas``, ``disarm``,
        ``location``, ``sector``, ``d3fend``, ``poc_source``) plus that kind's
        identifier fields.

        Args:
            items: 1-50 item dicts, e.g. ``[{"type": "cve", "cve_id": "CVE-2024-3400"}]``.
                The 51st is rejected with HTTP 422.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = EnrichBatchRequest.from_dict({"items": items})
        result = await enrich_batch.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichBatchResponse)

    async def enrich_poc_source(self, repo_url: str) -> FetchPoCSourceResponse:
        """Fetch the source of a proof-of-concept exploit repository.

        Args:
            repo_url: GitHub repository URL.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = FetchPoCSourceRequest(repo_url=repo_url)
        result = await enrich_poc_source.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, FetchPoCSourceResponse)

    # -- Search endpoints --------------------------------------------------- #

    async def search_cti(
        self,
        query: str,
        *,
        sources: list[str] | None = None,
        types: list[
            Literal[
                "attack-pattern",
                "intrusion-set",
                "malware",
                "tool",
                "campaign",
                "weakness",
                "course-of-action",
            ]
        ]
        | None = None,
        limit: int = 20,
        page: int = 1,
        deprecated: bool | None = None,
        revoked: bool | None = None,
    ) -> SearchCTIResponse:
        """Search ATT&CK, CWE, CAPEC, ATLAS, DISARM and friends in one query.

        The unscoped form of :meth:`search_techniques`, which pins ``sources`` and
        ``types`` to ATT&CK attack-patterns.

        Args:
            query: Text search query.
            sources: Knowledge bases to search — ``attack``, ``attack-enterprise``,
                ``attack-ics``, ``attack-mobile``, ``cwe``, ``capec``, ``atlas``,
                ``disarm``, ``location``, ``sector``. Defaults to the server's
                ``["attack", "cwe", "capec"]``.
            types: Restrict results to these STIX object types.
            limit: Maximum number of results to return (1-100).
            page: Page number for pagination (1-indexed, max 100).
            deprecated: Set to ``False`` to exclude objects the source marked deprecated.
            revoked: Set to ``False`` to exclude objects the source marked revoked.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchCTIRequest(
            query=query,
            sources=sources if sources is not None else UNSET,
            # The generated request's ``to_dict()`` calls ``.value`` on each item, so a
            # plain string raises AttributeError at serialisation — same footgun the
            # ``framework`` conversions kill.
            types=[SearchCTIRequestTypesType0Item(t) for t in types] if types is not None else UNSET,
            limit=limit,
            page=page,
            deprecated=deprecated if deprecated is not None else UNSET,
            revoked=revoked if revoked is not None else UNSET,
        )
        result = await search_cti.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchCTIResponse)

    async def search_cve(
        self,
        query: str | None = None,
        *,
        cve_id: str | None = None,
        stix_id: str | None = None,
        cwe_id: str | None = None,
        capec_id: str | None = None,
        attack_id: str | None = None,
        cpe: str | None = None,
        cpes_not_vulnerable: str | None = None,
        created_by_ref: str | None = None,
        created_min: str | None = None,
        created_max: str | None = None,
        modified_min: str | None = None,
        modified_max: str | None = None,
        cvss_min: float | None = None,
        cvss_v2_min: float | None = None,
        cvss_v4_min: float | None = None,
        epss_min: float | None = None,
        epss_percentile_min: float | None = None,
        kev_only: bool = False,
        vuln_status: Literal["Analyzed", "Awaiting Analysis", "Modified", "Received", "Rejected"] | None = None,
        sort: Literal[
            "created_ascending",
            "created_descending",
            "modified_ascending",
            "modified_descending",
            "epss_score_descending",
            "x_opencti_cvss_base_score_descending",
        ]
        | None = None,
        limit: int = 50,
        page: int = 1,
        include: list[str] | None = None,
    ) -> SearchCVEResponse:
        """Search vulnerabilities by severity, exploit status, technique, weakness, or date.

        Args:
            query: Compatibility field for a future description search. It does not
                currently filter and is rejected unless another filter or a sort is given.
            cve_id: Direct CVE ID lookup.
            stix_id: Filter by exact vulnerability STIX ID.
            cwe_id: Filter CVEs by weakness type.
            capec_id: Filter CVEs linked to a CAPEC attack pattern (e.g. ``CAPEC-665``).
            attack_id: Filter CVEs linked to an ATT&CK technique (e.g. ``T1190``).
            cpe: Filter CVEs by affected product (CPE string).
            cpes_not_vulnerable: Exclude CVEs whose configuration requires — but is not
                vulnerable in — this CPE 2.3 string.
            created_by_ref: Filter by CNA / numbering-authority identity STIX ID.
            created_min: Earliest creation date (``YYYY-MM-DDThh:mm:ss.sssZ``).
            created_max: Latest creation date.
            modified_min: Earliest modification date.
            modified_max: Latest modification date.
            cvss_min: Minimum CVSS v3.1 base score (0.0-10.0).
            cvss_v2_min: Minimum CVSS v2 base score (0.0-10.0).
            cvss_v4_min: Minimum CVSS v4 base score (0.0-10.0).
            epss_min: Minimum EPSS score (0.0-1.0).
            epss_percentile_min: Minimum EPSS percentile (0.0-1.0).
            kev_only: Only return CVEs in the Known Exploited Vulnerabilities catalog.
            vuln_status: Filter by NVD vulnerability status.
            sort: Result ordering.
            limit: Maximum number of results to return (1-100).
            page: Page number for pagination (1-indexed, max 100).
            include: Result layers. ``["details"]`` is the only allowed value; pass ``[]``
                for summaries. No preset — omitted entirely when ``None``.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchCVERequest(
            query=query if query is not None else UNSET,
            cve_id=cve_id if cve_id is not None else UNSET,
            stix_id=stix_id if stix_id is not None else UNSET,
            cwe_id=cwe_id if cwe_id is not None else UNSET,
            capec_id=capec_id if capec_id is not None else UNSET,
            attack_id=attack_id if attack_id is not None else UNSET,
            cpe=cpe if cpe is not None else UNSET,
            cpes_not_vulnerable=cpes_not_vulnerable if cpes_not_vulnerable is not None else UNSET,
            created_by_ref=created_by_ref if created_by_ref is not None else UNSET,
            created_min=created_min if created_min is not None else UNSET,
            created_max=created_max if created_max is not None else UNSET,
            modified_min=modified_min if modified_min is not None else UNSET,
            modified_max=modified_max if modified_max is not None else UNSET,
            cvss_min=cvss_min if cvss_min is not None else UNSET,
            cvss_v2_min=cvss_v2_min if cvss_v2_min is not None else UNSET,
            cvss_v4_min=cvss_v4_min if cvss_v4_min is not None else UNSET,
            epss_min=epss_min if epss_min is not None else UNSET,
            epss_percentile_min=epss_percentile_min if epss_percentile_min is not None else UNSET,
            kev_only=kev_only,
            vuln_status=SearchCVERequestVulnStatusType0(vuln_status) if vuln_status is not None else UNSET,
            sort=SearchCVERequestSortType0(sort) if sort is not None else UNSET,
            limit=limit,
            page=page,
            include=include if include is not None else UNSET,
        )
        result = await search_cve.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchCVEResponse)

    async def search_kev(
        self,
        *,
        cve_id: str | None = None,
        ransomware_status: Literal["Known", "Unknown"] | None = None,
        limit: int = 50,
        page: int = 1,
    ) -> SearchKEVResponse:
        """Search the CISA Known Exploited Vulnerabilities catalog.

        Args:
            cve_id: CVE ID to check against the catalog.
            ransomware_status: Filter by ransomware campaign use — ``Known`` (confirmed)
                or ``Unknown`` (unconfirmed).
            limit: Maximum number of results to return (1-100).
            page: Page number for pagination (1-indexed, max 100).

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchKEVRequest(
            cve_id=cve_id if cve_id is not None else UNSET,
            ransomware_status=(
                SearchKEVRequestRansomwareStatusType0(ransomware_status) if ransomware_status is not None else UNSET
            ),
            limit=limit,
            page=page,
        )
        result = await search_kev.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchKEVResponse)

    async def search_d3fend(
        self,
        query: str,
        *,
        d3fend_form: Literal["tactic", "mitigation", "sub-mitigation", "artifact"] | None = None,
        limit: int = 20,
        page: int = 1,
    ) -> SearchD3FENDResponse:
        """Text-search D3FEND defensive techniques.

        Args:
            query: Search query.
            d3fend_form: Restrict to one D3FEND form.
            limit: Maximum results (1-100).
            page: Page number for pagination (1-indexed, max 100).

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchD3FENDRequest(
            query=query,
            d3fend_form=SearchD3FENDRequestD3FendFormType0(d3fend_form) if d3fend_form is not None else UNSET,
            limit=limit,
            page=page,
        )
        result = await search_d3fend.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchD3FENDResponse)

    async def search_knowledgebase(
        self,
        query: str,
        *,
        collections: list[Literal["main", "large", "user", "red_team"]] | None = None,
        alpha: float = 0.7,
        limit: int = 10,
    ) -> SearchKnowledgebaseResponse:
        """Natural-language search over the knowledge base corpora.

        Args:
            query: Natural language search query.
            collections: Corpora to search. Defaults to the server's ``["red_team"]`` —
                the only collection seeded with substantial content.
            alpha: Search relevance tuning parameter (0.0-1.0).
            limit: Maximum number of results to return (1-100).

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchKnowledgebaseRequest(
            query=query,
            collections=(
                [SearchKnowledgebaseRequestCollectionsItem(c) for c in collections]
                if collections is not None
                else UNSET
            ),
            alpha=alpha,
            limit=limit,
        )
        result = await search_knowledgebase.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchKnowledgebaseResponse)

    async def search_misp(
        self,
        *,
        value: str | None = None,
        type_attribute: str | None = None,
        category: str | None = None,
        event_id: str | None = None,
        eventinfo: str | None = None,
        tags: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        published: bool | None = None,
        to_ids: bool | None = None,
        threat_level_id: str | None = None,
        limit: int = 50,
        page: int = 1,
    ) -> SearchMISPResponse:
        """Search the MISP threat intelligence feed by indicator, event, or tag.

        Args:
            value: Indicator value to search (IP, hash, domain, etc.).
            type_attribute: Filter attributes by type (e.g. ``ip-dst``, ``md5``).
            category: MISP attribute category (e.g. ``"Network activity"``).
            event_id: Direct event ID lookup.
            eventinfo: Search events by title/description text.
            tags: Filter by MISP tag(s), any match. Supports ``tlp:`` prefixes.
            date_from: Earliest event date (``YYYY-MM-DD``).
            date_to: Latest event date (``YYYY-MM-DD``).
            published: Restrict to events published by their owning org.
            to_ids: Return only attributes flagged for IDS detection.
            threat_level_id: ``1`` high, ``2`` medium, ``3`` low, ``4`` undefined.
            limit: Maximum number of results to return (1-100).
            page: Page number for pagination (1-indexed, max 100).

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchMISPRequest(
            value=value if value is not None else UNSET,
            type_attribute=type_attribute if type_attribute is not None else UNSET,
            category=category if category is not None else UNSET,
            event_id=event_id if event_id is not None else UNSET,
            eventinfo=eventinfo if eventinfo is not None else UNSET,
            tags=tags if tags is not None else UNSET,
            date_from=date_from if date_from is not None else UNSET,
            date_to=date_to if date_to is not None else UNSET,
            published=published if published is not None else UNSET,
            to_ids=to_ids if to_ids is not None else UNSET,
            threat_level_id=threat_level_id if threat_level_id is not None else UNSET,
            limit=limit,
            page=page,
        )
        result = await search_misp.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchMISPResponse)

    async def search_poc(self, cve_id: str, *, limit: int = 25) -> SearchPoCResponse:
        """List known proof-of-concept exploits for a CVE.

        Args:
            cve_id: CVE identifier.
            limit: Maximum results (1-100).

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchPoCRequest(cve_id=cve_id, limit=limit)
        result = await search_poc.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchPoCResponse)

    async def search_vendor(self, vendor: str, *, limit: int = 50) -> SearchVendorResponse:
        """List a vendor's products with their CPE identifiers.

        The CPE strings returned here are what :meth:`search_cve`'s ``cpe`` filter and
        :meth:`enrich_product_full` match against.

        Args:
            vendor: Vendor name to search (e.g. ``"apache"``, ``"microsoft"``).
            limit: Maximum number of products to return (1-100).

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = SearchVendorRequest(vendor=vendor, limit=limit)
        result = await search_vendor.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, SearchVendorResponse)

    # -- Portfolio assessments ---------------------------------------------- #

    async def assess_vulnerability_exposure(
        self,
        cve_ids: list[str],
        *,
        stakeholder: dict[str, Any] | None = None,
        include: list[str] | None = None,
    ) -> AssessVulnerabilityExposureResponse:
        """Assess the aggregate technique surface across a set of CVEs.

        Args:
            cve_ids: CVE IDs to analyze (max 50).
            stakeholder: SSVC deployment context applied to every CVE when ``ssvc`` is in
                ``include`` — e.g. ``{"exposure": "controlled", "method": "deployer"}``.
            include: Assessment layers. No preset — omitted entirely when ``None``, so the
                server's ``["techniques", "tie", "nist_controls"]`` default applies.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = AssessVulnerabilityExposureRequest(
            cve_ids=cve_ids,
            stakeholder=ArtifactEnrichmentStakeholder.from_dict(stakeholder) if stakeholder is not None else UNSET,
            include=include if include is not None else UNSET,
        )
        result = await assess_vulnerability_exposure.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, AssessVulnerabilityExposureResponse)

    async def assess_technique_coverage(
        self,
        technique_ids: list[str],
        *,
        framework: Literal["enterprise", "ics", "mobile"] = "enterprise",
        include: list[str] | None = None,
    ) -> AssessTechniqueCoverageResponse:
        """Batch-assess ATT&CK techniques for mitigations, detections, and threat predictions.

        Args:
            technique_ids: ATT&CK technique IDs to assess (max 50).
            framework: ATT&CK matrix variant — ``enterprise``, ``ics``, or ``mobile``.
            include: Assessment layers. No preset — omitted entirely when ``None``, so the
                server's ``["mitigations", "detections", "tie"]`` default applies.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = AssessTechniqueCoverageRequest(
            technique_ids=technique_ids,
            framework=AssessTechniqueCoverageRequestFramework(framework),
            include=include if include is not None else UNSET,
        )
        result = await assess_technique_coverage.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, AssessTechniqueCoverageResponse)

    async def assess_ioc_portfolio(
        self,
        indicators: list[dict[str, Any]],
        *,
        include: list[str] | None = None,
    ) -> AssessIOCPortfolioResponse:
        """Assess the combined threat picture across a set of indicators.

        Args:
            indicators: IOC dicts, each with ``value`` and ``type`` keys — e.g.
                ``[{"value": "8.8.8.8", "type": "ip-dst"}]``.
            include: Assessment layers. No preset — omitted entirely when ``None``, so the
                server's ``["misp_attributes", "techniques", "tie"]`` default applies.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = AssessIOCPortfolioRequest(
            indicators=[AssessIOCPortfolioRequestIndicatorsItem.from_dict(i) for i in indicators],
            include=include if include is not None else UNSET,
        )
        result = await assess_ioc_portfolio.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, AssessIOCPortfolioResponse)

    async def assess_group_exposure(
        self,
        *,
        group_ids: list[str] | None = None,
        search: list[str] | None = None,
        framework: Literal["enterprise", "ics", "mobile"] = "enterprise",
        include: list[str] | None = None,
    ) -> AssessGroupExposureResponse:
        """Assess the combined technique surface across several threat groups.

        Args:
            group_ids: ATT&CK group IDs (e.g. ``["G0016", "G0032"]``).
            search: Group names to search (e.g. ``["APT28", "Lazarus Group"]``). Supply
                this or ``group_ids``; the server rejects a request carrying neither.
            framework: ATT&CK matrix variant — ``enterprise``, ``ics``, or ``mobile``.
            include: Assessment layers. No preset — omitted entirely when ``None``, so the
                server's ``["details", "techniques", "tie"]`` default applies.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = AssessGroupExposureRequest(
            group_ids=group_ids if group_ids is not None else UNSET,
            search=search if search is not None else UNSET,
            framework=AssessGroupExposureRequestFramework(framework),
            include=include if include is not None else UNSET,
        )
        result = await assess_group_exposure.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, AssessGroupExposureResponse)

    # -- Async enrichment engines (submit → poll) --------------------------- #

    async def artifact_enrich(
        self,
        *,
        text: str | None = None,
        files: list[dict[str, Any]] | None = None,
        formats: list[
            Literal[
                "report",
                "json",
                "stix",
                "vex",
                "csaf",
                "navigator",
                "kev_remediation",
                "oscal_poam",
                "misp",
                "csv",
            ]
        ]
        | None = None,
        stakeholder: dict[str, Any] | None = None,
        include: list[str] | None = None,
    ) -> EnrichmentSubmitResponse:
        """Submit an artifact for asynchronous enrichment; returns the job handle.

        Poll the returned ``enrichment_id`` with :meth:`artifact_enrich_status`. The
        ``client.enricher`` namespace wraps the same engine with submit-and-wait helpers.

        Args:
            text: Pasted text — an IR note, advisory, or raw indicators.
            files: Uploaded artifacts (max 20), each ``{"content_b64": ..., "filename": ...}``.
            formats: Export formats to serialize from the assembled report.
            stakeholder: SSVC deployment context, e.g. ``{"exposure": "controlled"}``.
            include: Report sections. No preset — omitted entirely when ``None``.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = ArtifactEnrichmentDocRequest(
            text=text if text is not None else UNSET,
            files=[ArtifactEnrichmentFileInput.from_dict(f) for f in files] if files is not None else UNSET,
            formats=[ArtifactEnrichmentDocRequestFormatsItem(f) for f in formats] if formats is not None else UNSET,
            stakeholder=ArtifactEnrichmentStakeholder.from_dict(stakeholder) if stakeholder is not None else UNSET,
            include=include if include is not None else UNSET,
        )
        result = await artifact_enrich.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichmentSubmitResponse)

    async def artifact_enrich_status(self, enrichment_id: str) -> ArtifactEnrichmentJobResponse:
        """Read the status (and, once finished, the report) of an artifact-enrichment job.

        Args:
            enrichment_id: The 32-character hex ID returned by :meth:`artifact_enrich`.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        result = await artifact_enrich_status.asyncio_detailed(enrichment_id, client=self._inner)
        return _ensure_ok(result, ArtifactEnrichmentJobResponse)

    async def inventory_enrich(
        self,
        items: list[dict[str, Any]],
        *,
        include: list[str] | None = None,
        attachments_text: str | None = None,
        attachments_files: list[dict[str, Any]] | None = None,
    ) -> EnrichmentSubmitResponse:
        """Submit an asset inventory for asynchronous CVE findings; returns the job handle.

        Poll the returned ``enrichment_id`` with :meth:`inventory_enrich_status`.

        Args:
            items: Asset dicts (1-200), each at least ``{"product": ...}``. An asset with
                ``ecosystem`` set is matched as an open-source package instead of a CPE.
            include: Per-asset CVE layers. No preset — omitted entirely when ``None``.
            attachments_text: Text extracted from artifacts attached to the inventory.
            attachments_files: Attached files (max 20), each
                ``{"content_b64": ..., "filename": ...}``.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        body = InventoryEnrichmentRequest(
            items=[InventoryAsset.from_dict(i) for i in items],
            include=include if include is not None else UNSET,
            attachments_text=attachments_text if attachments_text is not None else UNSET,
            attachments_files=(
                [ArtifactEnrichmentFileInput.from_dict(f) for f in attachments_files]
                if attachments_files is not None
                else UNSET
            ),
        )
        result = await inventory_enrich.asyncio_detailed(client=self._inner, body=body)
        return _ensure_ok(result, EnrichmentSubmitResponse)

    async def inventory_enrich_status(self, enrichment_id: str) -> InventoryEnrichmentJobResponse:
        """Read the status (and, once finished, the findings) of an inventory-enrichment job.

        Args:
            enrichment_id: The 32-character hex ID returned by :meth:`inventory_enrich`.

        Raises:
            UnexpectedStatus: See :meth:`enrich_cve_full`.
        """
        result = await inventory_enrich_status.asyncio_detailed(enrichment_id, client=self._inner)
        return _ensure_ok(result, InventoryEnrichmentJobResponse)


_T = TypeVar("_T")


def _ensure_ok(response: Response[Any], expected: type[_T]) -> _T:
    """Return ``response.parsed`` when the server returned a 2xx and the body
    matched the expected schema. Otherwise raise :class:`UnexpectedStatus`
    carrying the status and raw body. Mirrors the TS wrapper's ``ensureOk``.
    """
    if 200 <= response.status_code < 300 and isinstance(response.parsed, expected):
        return response.parsed
    raise UnexpectedStatus(
        response.status_code,
        response.content,
        f"Crimson Crawler API {response.status_code} (expected {expected.__name__})",
    )
