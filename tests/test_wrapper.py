"""Wrapper-layer unit tests for crimson_crawler_client.

Covers the hand-written code in `client.py`, `exceptions.py`, `presets.py`,
and `__init__.py`, plus security-sensitive patches applied to the generated
layer by `scripts/codegen.py`.
"""

from __future__ import annotations

import warnings
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from crimson_crawler_client import (
    BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_VERIFY_SSL,
    AuthenticatedClient,
    CrawlerClient,
    CrawlerClientError,
    MissingCredentials,
    UnexpectedStatus,
    __version__,
    presets,
)
from crimson_crawler_client._auth import ApiKeyAuth
from crimson_crawler_client._generated.errors import UnexpectedStatus as GeneratedUnexpectedStatus
from crimson_crawler_client._generated.models import (
    ArtifactEnrichmentJobResponse,
    ArtifactEnrichmentJobResponseStatus,
    AssessGroupExposureRequestFramework,
    AssessGroupExposureResponse,
    AssessIOCPortfolioResponse,
    AssessTechniqueCoverageRequestFramework,
    AssessTechniqueCoverageResponse,
    AssessVulnerabilityExposureResponse,
    EnrichATLASResponse,
    EnrichBatchResponse,
    EnrichCampaignRequestFramework,
    EnrichCampaignResponse,
    EnrichCAPECResponse,
    EnrichD3FENDResponse,
    EnrichDISARMResponse,
    EnrichGroupRequestFramework,
    EnrichGroupResponse,
    EnrichLocationResponse,
    EnrichmentSubmitResponse,
    EnrichSectorResponse,
    EnrichSoftwareRequestFramework,
    EnrichSoftwareResponse,
    FetchPoCSourceResponse,
    InventoryEnrichmentJobResponse,
    InventoryEnrichmentJobResponseStatus,
    SearchCTIRequestTypesType0Item,
    SearchCTIResponse,
    SearchCVEResponse,
    SearchD3FENDResponse,
    SearchKEVResponse,
    SearchKnowledgebaseResponse,
    SearchMISPResponse,
    SearchPoCResponse,
    SearchVendorResponse,
)
from crimson_crawler_client._generated.types import UNSET, Response

# --------------------------------------------------------------------------- #
# Module-level constants and exports
# --------------------------------------------------------------------------- #


class TestModuleSurface:
    def test_default_base_url(self) -> None:
        assert BASE_URL == "https://crimsoncrawler.com"

    def test_env_var_names(self) -> None:
        assert ENV_API_KEY == "CRIMSON_CRAWLER_API_KEY"
        assert ENV_BASE_URL == "CRIMSON_CRAWLER_BASE_URL"
        assert ENV_VERIFY_SSL == "CRIMSON_CRAWLER_VERIFY_SSL"

    def test_default_timeout_seconds_is_positive(self) -> None:
        assert DEFAULT_TIMEOUT_SECONDS > 0

    def test_version_string(self) -> None:
        assert isinstance(__version__, str)
        assert __version__.count(".") >= 2  # X.Y.Z

    def test_presets_are_non_empty_lists(self) -> None:
        for name in presets.__all__:
            value = getattr(presets, name)
            assert isinstance(value, list)
            assert value, f"preset {name} is empty"
            assert all(isinstance(item, str) for item in value)

    def test_preset_exports_match_module_constants(self) -> None:
        """``__all__`` is the published preset surface — a constant that never reaches it
        is invisible to ``from presets import *`` and to the docs generated off it."""
        defined = {n for n in vars(presets) if n.isupper() and isinstance(getattr(presets, n), list)}
        assert defined == set(presets.__all__)

    def test_every_full_walk_preset_is_deduplicated(self) -> None:
        """A repeated layer is silently accepted by the API but doubles the work for it."""
        for name in presets.__all__:
            value = getattr(presets, name)
            assert len(value) == len(set(value)), f"preset {name} repeats a layer"


# --------------------------------------------------------------------------- #
# Exception hierarchy
# --------------------------------------------------------------------------- #


class TestExceptions:
    def test_missing_credentials_inherits_from_base(self) -> None:
        assert issubclass(MissingCredentials, CrawlerClientError)
        assert issubclass(CrawlerClientError, Exception)

    def test_unexpected_status_inherits_from_base(self) -> None:
        assert issubclass(UnexpectedStatus, CrawlerClientError)

    def test_unexpected_status_carries_status_and_body(self) -> None:
        exc = UnexpectedStatus(503, b"upstream down", "boom")
        assert exc.status == 503
        assert exc.body == b"upstream down"
        assert "boom" in str(exc)

    def test_unexpected_status_default_message(self) -> None:
        exc = UnexpectedStatus(418, {"error": "teapot"})
        assert exc.status == 418
        assert "418" in str(exc)


# --------------------------------------------------------------------------- #
# Constructor: api_key + base_url resolution
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with no SDK env vars set."""
    monkeypatch.delenv(ENV_API_KEY, raising=False)
    monkeypatch.delenv(ENV_BASE_URL, raising=False)
    monkeypatch.delenv(ENV_VERIFY_SSL, raising=False)


class TestConstructor:
    def test_missing_api_key_raises(self) -> None:
        with pytest.raises(MissingCredentials) as exc_info:
            CrawlerClient()
        assert ENV_API_KEY in str(exc_info.value)

    def test_empty_string_api_key_treated_as_missing(self) -> None:
        with pytest.raises(MissingCredentials):
            CrawlerClient(api_key="")

    def test_constructor_arg_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_API_KEY, "from-env")
        client = CrawlerClient(api_key="from-arg")
        assert client.api.token == "from-arg"

    def test_falls_back_to_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_API_KEY, "env-key")
        client = CrawlerClient()
        assert client.api.token == "env-key"

    def test_default_base_url(self) -> None:
        client = CrawlerClient(api_key="k")
        assert client.base_url == BASE_URL

    def test_base_url_constructor_arg_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_BASE_URL, "https://env.example")
        client = CrawlerClient(api_key="k", base_url="https://arg.example")
        assert client.base_url == "https://arg.example"

    def test_base_url_falls_back_to_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_BASE_URL, "https://env.example")
        client = CrawlerClient(api_key="k")
        assert client.base_url == "https://env.example"

    def test_insecure_remote_base_url_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="HTTPS"):
            CrawlerClient(api_key="k", base_url="http://evil.example")

    def test_http_loopback_base_url_is_allowed_and_warns(self) -> None:
        with pytest.warns(RuntimeWarning, match="origin override is active"):
            client = CrawlerClient(api_key="k", base_url="http://localhost:8000")
        assert client.base_url == "http://localhost:8000"

    def test_non_default_origin_warning_names_constructor_source_without_hostname(self) -> None:
        with pytest.warns(RuntimeWarning) as captured:
            CrawlerClient(api_key="k", base_url="https://api.example")
        message = str(captured[0].message)
        assert "origin override is active" in message
        assert "constructor argument" in message
        assert "api.example" not in message

    def test_non_default_origin_warning_names_environment_source_without_hostname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_BASE_URL, "https://internal.example")
        with pytest.warns(RuntimeWarning) as captured:
            CrawlerClient(api_key="k")
        message = str(captured[0].message)
        assert "origin override is active" in message
        assert f"{ENV_BASE_URL} environment variable" in message
        assert "internal.example" not in message

    def test_default_verify_ssl_is_true(self) -> None:
        client = CrawlerClient(api_key="k")
        assert client._verify_ssl is True
        assert client.api._verify_ssl is True

    def test_default_connection_emits_no_warning(self) -> None:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            CrawlerClient(api_key="k")
        assert not captured

    def test_verify_ssl_constructor_false_disables_verification(self) -> None:
        client = CrawlerClient(api_key="k", verify_ssl=False)
        assert client._verify_ssl is False
        assert client.api._verify_ssl is False

    def test_verify_ssl_constructor_warning_names_source(self) -> None:
        with pytest.warns(RuntimeWarning, match="disabled by constructor argument"):
            CrawlerClient(api_key="k", verify_ssl=False)

    def test_verify_ssl_env_warning_names_source(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VERIFY_SSL, "false")
        with pytest.warns(RuntimeWarning, match=f"disabled by {ENV_VERIFY_SSL} environment variable"):
            CrawlerClient(api_key="k")

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("false", False),
            ("0", False),
            ("no", False),
            ("FALSE", False),
            (" No ", False),
            ("true", True),
            ("1", True),
            ("yes", True),
            ("", True),
            ("garbage", True),
        ],
    )
    def test_verify_ssl_env_var_parsing(self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool) -> None:
        monkeypatch.setenv(ENV_VERIFY_SSL, raw)
        client = CrawlerClient(api_key="k")
        assert client._verify_ssl is expected

    def test_verify_ssl_constructor_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VERIFY_SSL, "false")
        client = CrawlerClient(api_key="k", verify_ssl=True)
        assert client._verify_ssl is True

    def test_inner_client_configured(self) -> None:
        client = CrawlerClient(api_key="abc")
        inner = client.api
        assert isinstance(inner, AuthenticatedClient)
        assert inner.token == "abc"
        # apikey injection is the whole point of the wrapper, but it happens per
        # request now (see _auth.ApiKeyAuth) rather than as a header parked on the
        # client — httpx does not redact an `apikey` header, so parking it there
        # meant repr(client.headers) printed the key. Assert the wire, not the
        # container: the container being empty is the fix.
        http = inner.get_async_httpx_client()
        assert "apikey" not in http.headers
        request = httpx.Request("GET", f"{BASE_URL}/health")
        auth = http.auth
        assert isinstance(auth, ApiKeyAuth)
        next(auth.auth_flow(request))
        assert request.headers["apikey"] == "abc"


# --------------------------------------------------------------------------- #
# Convenience methods: preset + delegation
# --------------------------------------------------------------------------- #


def _ok_response(parsed: object) -> Response[object]:
    """Build a Response object that mimics a 200 OK detailed response."""
    return Response(
        status_code=200,
        content=b"{}",
        headers={},
        parsed=parsed,
    )


def _err_response(status: int, body: bytes = b"err") -> Response[None]:
    return Response(status_code=status, content=body, headers={}, parsed=None)


class TestCredentialDisclosure:
    # scripts/codegen.py patches repr=False onto the generated client's token and
    # _headers fields. attrs @define would otherwise put both in __repr__, so any
    # traceback rendering locals would print a live API key. These tests fail if
    # that patch stops applying after an openapi-python-client upgrade.
    def test_generated_unexpected_status_keeps_body_out_of_message(self) -> None:
        content = b"arbitrary sensitive response content"
        exc = GeneratedUnexpectedStatus(502, content)

        assert exc.status_code == 502
        assert exc.content is content
        assert "502" in str(exc)
        assert str(len(content)) in str(exc)
        assert content.decode() not in str(exc)

    def test_repr_does_not_disclose_api_key(self) -> None:
        client = CrawlerClient(api_key="ck_live_repr_probe")
        assert "ck_live_repr_probe" not in repr(client.api)

    def test_str_does_not_disclose_api_key(self) -> None:
        client = CrawlerClient(api_key="ck_live_str_probe")
        assert "ck_live_str_probe" not in str(client.api)

    def test_repr_does_not_disclose_caller_supplied_headers(self) -> None:
        client = CrawlerClient(api_key="k")
        client.api._headers["x-downstream-token"] = "ck_live_header_probe"
        assert "ck_live_header_probe" not in repr(client.api)

    def test_token_stays_readable_by_code(self) -> None:
        # Redaction must not break auth: the wrapper and the generated request
        # layer both read this attribute to build the apikey header.
        client = CrawlerClient(api_key="ck_live_readable")
        assert client.api.token == "ck_live_readable"

    # The three above cover attrs' __repr__. The key also used to reach httpx's
    # own persistent header container, which redacts only authorization/
    # proxy-authorization — so repr() of it printed the key in full, one
    # attribute access from the documented client.api escape hatch. It is now
    # injected per request by _auth.ApiKeyAuth instead; these fail if that
    # regresses to a header on the client.
    def test_async_httpx_headers_do_not_disclose_api_key(self) -> None:
        client = CrawlerClient(api_key="ck_live_async_headers")
        headers = client.api.get_async_httpx_client().headers
        assert "ck_live_async_headers" not in repr(headers)
        assert "ck_live_async_headers" not in str(headers)

    def test_sync_httpx_headers_do_not_disclose_api_key(self) -> None:
        # The escape hatch serves sync callers too, via a separate accessor.
        client = CrawlerClient(api_key="ck_live_sync_headers")
        headers = client.api.get_httpx_client().headers
        assert "ck_live_sync_headers" not in repr(headers)
        assert "ck_live_sync_headers" not in str(headers)

    def test_auth_flow_still_sends_api_key_header(self) -> None:
        # Moving the key off the client must not stop it reaching the wire. The
        # URL has to be our own origin — the key is deliberately withheld from
        # any other host, which the origin test below covers.
        client = CrawlerClient(api_key="ck_live_flow")
        auth = client.api.get_async_httpx_client().auth
        assert isinstance(auth, ApiKeyAuth)
        request = httpx.Request("GET", f"{BASE_URL}/health")
        next(auth.auth_flow(request))
        assert request.headers["apikey"] == "ck_live_flow"

    async def test_transport_error_does_not_disclose_api_key(self) -> None:
        # httpx attaches the outgoing request to any transport failure as
        # exc.request, and httpx.Headers redacts only authorization/
        # proxy-authorization — so this printed the live key on an ordinary
        # connect error, timeout or TLS failure, from the primary documented call
        # path rather than the client.api escape hatch. Port 9 (discard) refuses.
        client = CrawlerClient(api_key="ck_live_transport", base_url="https://127.0.0.1:9")
        with pytest.raises(httpx.TransportError) as exc_info:
            await client.enrich_cve_full("CVE-2000-0001")
        request = exc_info.value.request
        assert "ck_live_transport" not in repr(request.headers)
        assert "ck_live_transport" not in str(request.headers)
        # Redaction is for accidental disclosure only — reading the value
        # deliberately still works, and auth still went out correctly.
        assert request.headers["apikey"] == "ck_live_transport"

    def test_key_is_withheld_from_another_origin(self) -> None:
        # client.api is a documented escape hatch, so a caller can hand its httpx
        # client an absolute URL for a different host. The header name `apikey`
        # gets none of the protection httpx gives `authorization`, so without an
        # origin check that request carried the key.
        client = CrawlerClient(api_key="ck_live_origin", base_url="https://localhost:8443")
        auth = client.api.get_async_httpx_client().auth
        assert isinstance(auth, ApiKeyAuth)

        ours = httpx.Request("GET", "https://localhost:8443/v1/enrich/cve")
        next(auth.auth_flow(ours))
        assert ours.headers["apikey"] == "ck_live_origin"

        theirs = httpx.Request("GET", "https://attacker.example/collect")
        next(auth.auth_flow(theirs))
        assert "apikey" not in theirs.headers


class TestEnrichCveFull:
    @patch("crimson_crawler_client.client.enrich_cve.asyncio_detailed", new_callable=AsyncMock)
    async def test_default_preset_used(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichCVEResponse

        expected = EnrichCVEResponse()
        mock_call.return_value = _ok_response(expected)

        client = CrawlerClient(api_key="k")
        result = await client.enrich_cve_full("CVE-2024-3400")

        assert result is expected
        body = mock_call.call_args.kwargs["body"]
        assert body.cve_id == "CVE-2024-3400"
        assert list(body.include) == presets.CVE_FULL_WALK

    @patch("crimson_crawler_client.client.enrich_cve.asyncio_detailed", new_callable=AsyncMock)
    async def test_custom_include_overrides_preset(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichCVEResponse

        mock_call.return_value = _ok_response(EnrichCVEResponse())
        client = CrawlerClient(api_key="k")
        await client.enrich_cve_full("CVE-2024-1", include=["details"])
        body = mock_call.call_args.kwargs["body"]
        assert list(body.include) == ["details"]

    @patch("crimson_crawler_client.client.enrich_cve.asyncio_detailed", new_callable=AsyncMock)
    async def test_non_2xx_raises_unexpected_status(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _err_response(503, b"upstream")
        client = CrawlerClient(api_key="k")
        with pytest.raises(UnexpectedStatus) as exc_info:
            await client.enrich_cve_full("CVE-2024-3400")
        assert exc_info.value.status == 503
        assert exc_info.value.body == b"upstream"


class TestOtherConvenienceMethods:
    @patch("crimson_crawler_client.client.enrich_ioc.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_ioc_full_passes_type_and_preset(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichIOCResponse

        mock_call.return_value = _ok_response(EnrichIOCResponse(value="8.8.8.8", type_="ip-dst"))
        client = CrawlerClient(api_key="k")
        await client.enrich_ioc_full("8.8.8.8", "ip-dst")
        body = mock_call.call_args.kwargs["body"]
        assert body.value == "8.8.8.8"
        assert body.type_ == "ip-dst"
        assert list(body.include) == presets.IOC_FULL_WALK

    @patch("crimson_crawler_client.client.enrich_cwe.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_cwe_full_passes_id(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichCWEResponse

        mock_call.return_value = _ok_response(EnrichCWEResponse())
        client = CrawlerClient(api_key="k")
        await client.enrich_cwe_full("CWE-79")
        body = mock_call.call_args.kwargs["body"]
        assert body.cwe_id == "CWE-79"
        assert list(body.include) == presets.CWE_FULL_WALK

    @patch("crimson_crawler_client.client.enrich_technique.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_technique_full_passes_framework(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichTechniqueResponse
        from crimson_crawler_client._generated.models.enrich_technique_request_framework import (
            EnrichTechniqueRequestFramework,
        )

        mock_call.return_value = _ok_response(EnrichTechniqueResponse())
        client = CrawlerClient(api_key="k")
        await client.enrich_technique_full(["T1190"], framework="ics")
        body = mock_call.call_args.kwargs["body"]
        assert body.technique_ids == ["T1190"]
        # The convenience method converts the string ``framework`` to the
        # codegen-generated enum BEFORE constructing the request body — without
        # this, the request's ``to_dict()`` calls ``.value`` on a plain string
        # and the SDK raises AttributeError at serialisation time. Regression
        # guard against the live-smoke failure seen in pipeline #25785.
        assert isinstance(body.framework, EnrichTechniqueRequestFramework)
        assert body.framework == EnrichTechniqueRequestFramework.ICS
        assert list(body.include) == presets.TECHNIQUE_FULL
        # And the request's own serialiser must succeed end-to-end.
        body.to_dict()

    @patch("crimson_crawler_client.client.enrich_product.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_product_full_optional_fields_unset_by_default(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichProductResponse
        from crimson_crawler_client._generated.types import UNSET

        mock_call.return_value = _ok_response(EnrichProductResponse(product="nginx"))
        client = CrawlerClient(api_key="k")
        await client.enrich_product_full("nginx")
        body = mock_call.call_args.kwargs["body"]
        assert body.product == "nginx"
        assert body.version is UNSET
        assert body.vendor is UNSET

    @patch("crimson_crawler_client.client.enrich_product.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_product_full_passes_optional_fields(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichProductResponse

        mock_call.return_value = _ok_response(EnrichProductResponse(product="nginx"))
        client = CrawlerClient(api_key="k")
        await client.enrich_product_full("nginx", version="1.25", vendor="nginx")
        body = mock_call.call_args.kwargs["body"]
        assert body.version == "1.25"
        assert body.vendor == "nginx"

    @patch("crimson_crawler_client.client.enrich_package.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_package_full_defaults_and_preset(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client import presets
        from crimson_crawler_client._generated.models import EnrichPackageResponse
        from crimson_crawler_client._generated.types import UNSET

        mock_call.return_value = _ok_response(EnrichPackageResponse(ecosystem="PyPI", package="django"))
        client = CrawlerClient(api_key="k")
        await client.enrich_package_full("PyPI", "django")
        body = mock_call.call_args.kwargs["body"]
        assert body.ecosystem == "PyPI" and body.package == "django"
        assert body.version is UNSET
        assert body.include == presets.PACKAGE_FULL  # default preset wired in

    @patch("crimson_crawler_client.client.enrich_package.asyncio_detailed", new_callable=AsyncMock)
    async def test_enrich_package_full_passes_version_and_include(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import EnrichPackageResponse

        mock_call.return_value = _ok_response(EnrichPackageResponse(ecosystem="npm", package="lodash"))
        client = CrawlerClient(api_key="k")
        await client.enrich_package_full("npm", "lodash", version="4.17.20", include=["epss"])
        body = mock_call.call_args.kwargs["body"]
        assert body.version == "4.17.20"
        assert body.include == ["epss"]  # explicit include overrides the preset

    @patch("crimson_crawler_client.client.enrich_ioc.asyncio_detailed", new_callable=AsyncMock)
    async def test_unexpected_payload_raises(self, mock_call: AsyncMock) -> None:
        # 200 status but no parsed body of the right shape
        mock_call.return_value = Response(
            status_code=200,
            content=b"{}",
            headers={},
            parsed=None,
        )
        client = CrawlerClient(api_key="k")
        with pytest.raises(UnexpectedStatus) as exc_info:
            await client.enrich_ioc_full("8.8.8.8")
        assert exc_info.value.status == 200

    @patch("crimson_crawler_client.client.search_cti.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_techniques_wires_request(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import SearchCTIResponse
        from crimson_crawler_client._generated.models.search_cti_request_types_type_0_item import (
            SearchCTIRequestTypesType0Item,
        )

        mock_call.return_value = _ok_response(SearchCTIResponse(results=[]))
        client = CrawlerClient(api_key="k")
        await client.search_techniques("credential dumping", limit=5)
        body = mock_call.call_args.kwargs["body"]
        assert body.query == "credential dumping"
        assert body.sources == ["attack"]
        assert body.limit == 5
        # The convenience method passes the codegen-generated enum, NOT a raw
        # string — the generated request's ``to_dict()`` calls ``.value`` on the
        # types items, so a plain string raises AttributeError at serialisation
        # (the raw-string escape-hatch footgun this wrapper exists to kill).
        assert body.types == [SearchCTIRequestTypesType0Item.ATTACK_PATTERN]
        assert isinstance(body.types[0], SearchCTIRequestTypesType0Item)
        # And the request's own serialiser must succeed end-to-end.
        body.to_dict()

    @patch("crimson_crawler_client.client.search_cti.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_techniques_default_limit(self, mock_call: AsyncMock) -> None:
        from crimson_crawler_client._generated.models import SearchCTIResponse

        mock_call.return_value = _ok_response(SearchCTIResponse(results=[]))
        client = CrawlerClient(api_key="k")
        await client.search_techniques("phishing")
        assert mock_call.call_args.kwargs["body"].limit == 20

    @patch("crimson_crawler_client.client.search_cti.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_techniques_raises_on_non_2xx(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _err_response(503)
        client = CrawlerClient(api_key="k")
        with pytest.raises(UnexpectedStatus):
            await client.search_techniques("phishing")


# --------------------------------------------------------------------------- #
# Full-33 parity surface — the 27 operations wrapped for CLI/SDK parity
# --------------------------------------------------------------------------- #


def _submit_response() -> EnrichmentSubmitResponse:
    return EnrichmentSubmitResponse(enrichment_id="a" * 32)


def _artifact_job() -> ArtifactEnrichmentJobResponse:
    return ArtifactEnrichmentJobResponse(
        enrichment_id="a" * 32,
        status=ArtifactEnrichmentJobResponseStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:01Z",
        stages=[],
        progress=1.0,
    )


def _inventory_job() -> InventoryEnrichmentJobResponse:
    return InventoryEnrichmentJobResponse(
        enrichment_id="b" * 32,
        status=InventoryEnrichmentJobResponseStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:01Z",
        stages=[],
        progress=1.0,
    )


# (method, patched generated module, parsed response, args, kwargs, expected body attrs).
# ``expected`` of None marks a path-parameter GET, which sends no body.
_PARITY_CASES = [
    pytest.param(
        "enrich_capec_full",
        "enrich_capec",
        EnrichCAPECResponse(),
        ("CAPEC-66",),
        {},
        {"capec_id": "CAPEC-66", "search": UNSET, "include": presets.CAPEC_FULL},
        id="enrich_capec_full",
    ),
    pytest.param(
        "enrich_atlas_full",
        "enrich_atlas",
        EnrichATLASResponse(),
        ("AML.T0043",),
        {},
        {"technique_id": "AML.T0043", "search": UNSET, "include": presets.ATLAS_FULL},
        id="enrich_atlas_full",
    ),
    pytest.param(
        "enrich_disarm_full",
        "enrich_disarm",
        EnrichDISARMResponse(),
        (),
        {"search": "narrative"},
        {"technique_id": UNSET, "search": "narrative", "include": presets.DISARM_FULL},
        id="enrich_disarm_full",
    ),
    pytest.param(
        "enrich_defend_full",
        "enrich_defend",
        EnrichD3FENDResponse(),
        ("D3-AL",),
        {},
        {"d3fend_id": "D3-AL", "search": UNSET, "include": presets.DEFEND_FULL},
        id="enrich_defend_full",
    ),
    pytest.param(
        "enrich_group_full",
        "enrich_group",
        EnrichGroupResponse(),
        ("G0016",),
        {},
        {"group_id": "G0016", "search": UNSET, "include": presets.GROUP_FULL},
        id="enrich_group_full",
    ),
    pytest.param(
        "enrich_software_full",
        "enrich_software",
        EnrichSoftwareResponse(),
        ("S0154",),
        {},
        {"software_id": "S0154", "search": UNSET, "include": presets.SOFTWARE_FULL},
        id="enrich_software_full",
    ),
    pytest.param(
        "enrich_campaign_full",
        "enrich_campaign",
        EnrichCampaignResponse(),
        ("C0028",),
        {},
        {"campaign_id": "C0028", "search": UNSET, "include": presets.CAMPAIGN_FULL},
        id="enrich_campaign_full",
    ),
    pytest.param(
        "enrich_location_full",
        "enrich_location",
        EnrichLocationResponse(),
        (),
        {"search": "United States"},
        {"location_id": UNSET, "search": "United States", "include": presets.LOCATION_FULL},
        id="enrich_location_full",
    ),
    pytest.param(
        "enrich_sector_full",
        "enrich_sector",
        EnrichSectorResponse(),
        (),
        {"search": "healthcare"},
        {"sector_id": UNSET, "search": "healthcare", "include": presets.SECTOR_FULL},
        id="enrich_sector_full",
    ),
    pytest.param(
        "enrich_poc_source",
        "enrich_poc_source",
        FetchPoCSourceResponse(repo_url="https://github.com/x/y"),
        ("https://github.com/x/y",),
        {},
        {"repo_url": "https://github.com/x/y"},
        id="enrich_poc_source",
    ),
    pytest.param(
        "search_cti",
        "search_cti",
        SearchCTIResponse(),
        ("lateral movement",),
        {"sources": ["attack", "capec"], "limit": 5, "page": 2},
        {"query": "lateral movement", "sources": ["attack", "capec"], "limit": 5, "page": 2, "types": UNSET},
        id="search_cti",
    ),
    pytest.param(
        "search_cve",
        "search_cve",
        SearchCVEResponse(),
        (),
        {"cwe_id": "CWE-79", "epss_min": 0.9, "kev_only": True},
        {"cwe_id": "CWE-79", "epss_min": 0.9, "kev_only": True, "query": UNSET, "include": UNSET, "limit": 50},
        id="search_cve",
    ),
    pytest.param(
        "search_kev",
        "search_kev",
        SearchKEVResponse(),
        (),
        {"cve_id": "CVE-2000-0001"},
        {"cve_id": "CVE-2000-0001", "ransomware_status": UNSET, "limit": 50, "page": 1},
        id="search_kev",
    ),
    pytest.param(
        "search_d3fend",
        "search_d3fend",
        SearchD3FENDResponse(),
        ("credential hardening",),
        {},
        {"query": "credential hardening", "d3fend_form": UNSET, "limit": 20, "page": 1},
        id="search_d3fend",
    ),
    pytest.param(
        "search_knowledgebase",
        "search_knowledgebase",
        SearchKnowledgebaseResponse(),
        ("how do I pivot",),
        {"alpha": 0.4},
        {"query": "how do I pivot", "alpha": 0.4, "collections": UNSET, "limit": 10},
        id="search_knowledgebase",
    ),
    pytest.param(
        "search_misp",
        "search_misp",
        SearchMISPResponse(),
        (),
        {"value": "8.8.8.8", "tags": ["tlp:white"], "to_ids": True},
        {"value": "8.8.8.8", "tags": ["tlp:white"], "to_ids": True, "event_id": UNSET, "limit": 50},
        id="search_misp",
    ),
    pytest.param(
        "search_poc",
        "search_poc",
        SearchPoCResponse(cve_id="CVE-2000-0001"),
        ("CVE-2000-0001",),
        {"limit": 5},
        {"cve_id": "CVE-2000-0001", "limit": 5},
        id="search_poc",
    ),
    pytest.param(
        "search_vendor",
        "search_vendor",
        SearchVendorResponse(vendor="apache"),
        ("apache",),
        {},
        {"vendor": "apache", "limit": 50},
        id="search_vendor",
    ),
    pytest.param(
        "assess_vulnerability_exposure",
        "assess_vulnerability_exposure",
        AssessVulnerabilityExposureResponse(),
        (["CVE-2000-0001", "CVE-2000-0002"],),
        {},
        {"cve_ids": ["CVE-2000-0001", "CVE-2000-0002"], "include": UNSET, "stakeholder": UNSET},
        id="assess_vulnerability_exposure",
    ),
    pytest.param(
        "assess_technique_coverage",
        "assess_technique_coverage",
        AssessTechniqueCoverageResponse(),
        (["T1190"],),
        {},
        {"technique_ids": ["T1190"], "include": UNSET},
        id="assess_technique_coverage",
    ),
    pytest.param(
        "assess_group_exposure",
        "assess_group_exposure",
        AssessGroupExposureResponse(),
        (),
        {"group_ids": ["G0016"]},
        {"group_ids": ["G0016"], "search": UNSET, "include": UNSET},
        id="assess_group_exposure",
    ),
    pytest.param(
        "artifact_enrich",
        "artifact_enrich",
        _submit_response(),
        (),
        {"text": "CVE-2000-0001 seen in prod"},
        {"text": "CVE-2000-0001 seen in prod", "files": UNSET, "formats": UNSET, "include": UNSET},
        id="artifact_enrich",
    ),
    pytest.param(
        "artifact_enrich_status",
        "artifact_enrich_status",
        _artifact_job(),
        ("a" * 32,),
        {},
        None,
        id="artifact_enrich_status",
    ),
    pytest.param(
        "inventory_enrich_status",
        "inventory_enrich_status",
        _inventory_job(),
        ("b" * 32,),
        {},
        None,
        id="inventory_enrich_status",
    ),
]


class TestParitySurface:
    """One case per operation that gained a wrapper: request wiring and the shared
    non-2xx contract. Structured-input and enum coercion get their own classes below."""

    @pytest.mark.parametrize(("method", "module", "parsed", "args", "kwargs", "expected"), _PARITY_CASES)
    async def test_request_is_wired(
        self,
        method: str,
        module: str,
        parsed: object,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        expected: dict[str, object] | None,
    ) -> None:
        with patch(f"crimson_crawler_client.client.{module}.asyncio_detailed", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _ok_response(parsed)
            client = CrawlerClient(api_key="k")
            result = await getattr(client, method)(*args, **kwargs)

        assert result is parsed
        if expected is None:
            # Path-parameter GET: the id travels positionally, there is no body.
            assert mock_call.call_args.args == args
            assert "body" not in mock_call.call_args.kwargs
            return
        body = mock_call.call_args.kwargs["body"]
        for field, value in expected.items():
            assert getattr(body, field) == value, f"{method}.{field}"
        # Whatever we built must survive the generated serialiser.
        body.to_dict()

    @pytest.mark.parametrize(("method", "module", "parsed", "args", "kwargs", "expected"), _PARITY_CASES)
    async def test_non_2xx_raises_unexpected_status(
        self,
        method: str,
        module: str,
        parsed: object,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        expected: dict[str, object] | None,
    ) -> None:
        with patch(f"crimson_crawler_client.client.{module}.asyncio_detailed", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _err_response(503, b"upstream")
            client = CrawlerClient(api_key="k")
            with pytest.raises(UnexpectedStatus) as exc_info:
                await getattr(client, method)(*args, **kwargs)
        assert exc_info.value.status == 503
        assert exc_info.value.body == b"upstream"

    @pytest.mark.parametrize(
        ("method", "module", "parsed", "args"),
        [
            pytest.param("enrich_capec_full", "enrich_capec", EnrichCAPECResponse(), ("CAPEC-66",), id="capec"),
            pytest.param("enrich_atlas_full", "enrich_atlas", EnrichATLASResponse(), ("AML.T0043",), id="atlas"),
            pytest.param("enrich_disarm_full", "enrich_disarm", EnrichDISARMResponse(), ("T0001",), id="disarm"),
            pytest.param("enrich_defend_full", "enrich_defend", EnrichD3FENDResponse(), ("D3-AL",), id="defend"),
            pytest.param("enrich_group_full", "enrich_group", EnrichGroupResponse(), ("G0016",), id="group"),
            pytest.param(
                "enrich_software_full", "enrich_software", EnrichSoftwareResponse(), ("S0154",), id="software"
            ),
            pytest.param(
                "enrich_campaign_full", "enrich_campaign", EnrichCampaignResponse(), ("C0028",), id="campaign"
            ),
            pytest.param("enrich_location_full", "enrich_location", EnrichLocationResponse(), ("L1",), id="location"),
            pytest.param("enrich_sector_full", "enrich_sector", EnrichSectorResponse(), ("S1",), id="sector"),
        ],
    )
    async def test_explicit_include_overrides_preset(
        self, method: str, module: str, parsed: object, args: tuple[object, ...]
    ) -> None:
        with patch(f"crimson_crawler_client.client.{module}.asyncio_detailed", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _ok_response(parsed)
            client = CrawlerClient(api_key="k")
            await getattr(client, method)(*args, include=["details"])
        assert mock_call.call_args.kwargs["body"].include == ["details"]

    @pytest.mark.parametrize(
        ("method", "module", "parsed", "args"),
        [
            pytest.param("search_cve", "search_cve", SearchCVEResponse(), (), id="search_cve"),
            pytest.param(
                "assess_vulnerability_exposure",
                "assess_vulnerability_exposure",
                AssessVulnerabilityExposureResponse(),
                (["CVE-2000-0001"],),
                id="assess_vulnerability_exposure",
            ),
            pytest.param(
                "assess_technique_coverage",
                "assess_technique_coverage",
                AssessTechniqueCoverageResponse(),
                (["T1190"],),
                id="assess_technique_coverage",
            ),
            pytest.param(
                "assess_group_exposure",
                "assess_group_exposure",
                AssessGroupExposureResponse(),
                (),
                id="assess_group_exposure",
            ),
        ],
    )
    async def test_include_passthrough_has_no_preset(
        self, method: str, module: str, parsed: object, args: tuple[object, ...]
    ) -> None:
        """search/assess carry no preset: ``include`` is dropped from the body entirely
        when unset, so the server's own default applies rather than a client-side guess."""
        with patch(f"crimson_crawler_client.client.{module}.asyncio_detailed", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _ok_response(parsed)
            client = CrawlerClient(api_key="k")
            await getattr(client, method)(*args)
            assert "include" not in mock_call.call_args.kwargs["body"].to_dict()

            await getattr(client, method)(*args, include=["tie"])
            assert mock_call.call_args.kwargs["body"].to_dict()["include"] == ["tie"]


class TestParityEnumCoercion:
    """The generated request models call ``.value`` on enum-typed fields in ``to_dict()``,
    so a raw string raises AttributeError at serialisation. Every wrapper that accepts one
    of these as a plain string must convert it first — the pipeline #25785 footgun."""

    @pytest.mark.parametrize(
        ("method", "module", "parsed", "args", "enum_cls"),
        [
            pytest.param(
                "enrich_group_full",
                "enrich_group",
                EnrichGroupResponse(),
                ("G0016",),
                EnrichGroupRequestFramework,
                id="enrich_group_full",
            ),
            pytest.param(
                "enrich_software_full",
                "enrich_software",
                EnrichSoftwareResponse(),
                ("S0154",),
                EnrichSoftwareRequestFramework,
                id="enrich_software_full",
            ),
            pytest.param(
                "enrich_campaign_full",
                "enrich_campaign",
                EnrichCampaignResponse(),
                ("C0028",),
                EnrichCampaignRequestFramework,
                id="enrich_campaign_full",
            ),
            pytest.param(
                "assess_technique_coverage",
                "assess_technique_coverage",
                AssessTechniqueCoverageResponse(),
                (["T1190"],),
                AssessTechniqueCoverageRequestFramework,
                id="assess_technique_coverage",
            ),
            pytest.param(
                "assess_group_exposure",
                "assess_group_exposure",
                AssessGroupExposureResponse(),
                (),
                AssessGroupExposureRequestFramework,
                id="assess_group_exposure",
            ),
        ],
    )
    async def test_framework_string_becomes_enum(
        self, method: str, module: str, parsed: object, args: tuple[object, ...], enum_cls: type
    ) -> None:
        with patch(f"crimson_crawler_client.client.{module}.asyncio_detailed", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _ok_response(parsed)
            client = CrawlerClient(api_key="k")
            await getattr(client, method)(*args, framework="ics")
        body = mock_call.call_args.kwargs["body"]
        assert isinstance(body.framework, enum_cls)
        assert body.to_dict()["framework"] == "ics"

    @patch("crimson_crawler_client.client.search_cti.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_cti_types_become_enums(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(SearchCTIResponse())
        client = CrawlerClient(api_key="k")
        await client.search_cti("apt", types=["intrusion-set", "malware"])
        body = mock_call.call_args.kwargs["body"]
        assert body.types == [
            SearchCTIRequestTypesType0Item.INTRUSION_SET,
            SearchCTIRequestTypesType0Item.MALWARE,
        ]
        assert body.to_dict()["types"] == ["intrusion-set", "malware"]

    @patch("crimson_crawler_client.client.search_cve.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_cve_sort_and_status_become_enums(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(SearchCVEResponse())
        client = CrawlerClient(api_key="k")
        await client.search_cve(sort="epss_score_descending", vuln_status="Analyzed")
        serialized = mock_call.call_args.kwargs["body"].to_dict()
        assert serialized["sort"] == "epss_score_descending"
        assert serialized["vuln_status"] == "Analyzed"

    @patch("crimson_crawler_client.client.search_kev.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_kev_ransomware_status_becomes_enum(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(SearchKEVResponse())
        client = CrawlerClient(api_key="k")
        await client.search_kev(ransomware_status="Known")
        assert mock_call.call_args.kwargs["body"].to_dict()["ransomware_status"] == "Known"

    @patch("crimson_crawler_client.client.search_d3fend.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_d3fend_form_becomes_enum(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(SearchD3FENDResponse())
        client = CrawlerClient(api_key="k")
        await client.search_d3fend("isolation", d3fend_form="sub-mitigation")
        assert mock_call.call_args.kwargs["body"].to_dict()["d3fend_form"] == "sub-mitigation"

    @patch("crimson_crawler_client.client.search_knowledgebase.asyncio_detailed", new_callable=AsyncMock)
    async def test_search_knowledgebase_collections_become_enums(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(SearchKnowledgebaseResponse())
        client = CrawlerClient(api_key="k")
        await client.search_knowledgebase("pivot", collections=["main", "red_team"])
        assert mock_call.call_args.kwargs["body"].to_dict()["collections"] == ["main", "red_team"]

    @patch("crimson_crawler_client.client.artifact_enrich.asyncio_detailed", new_callable=AsyncMock)
    async def test_artifact_enrich_formats_become_enums(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(_submit_response())
        client = CrawlerClient(api_key="k")
        await client.artifact_enrich(text="note", formats=["stix", "navigator"])
        assert mock_call.call_args.kwargs["body"].to_dict()["formats"] == ["stix", "navigator"]


class TestParityStructuredInputs:
    """Nested request models are accepted as plain dicts so callers never import
    anything out of ``_generated`` to reach an endpoint."""

    @patch("crimson_crawler_client.client.assess_ioc_portfolio.asyncio_detailed", new_callable=AsyncMock)
    async def test_indicator_dicts_survive_serialisation(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(AssessIOCPortfolioResponse())
        client = CrawlerClient(api_key="k")
        await client.assess_ioc_portfolio([{"value": "8.8.8.8", "type": "ip-dst"}])
        assert mock_call.call_args.kwargs["body"].to_dict()["indicators"] == [{"value": "8.8.8.8", "type": "ip-dst"}]

    @patch("crimson_crawler_client.client.artifact_enrich.asyncio_detailed", new_callable=AsyncMock)
    async def test_file_and_stakeholder_dicts_survive_serialisation(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(_submit_response())
        client = CrawlerClient(api_key="k")
        await client.artifact_enrich(
            files=[{"content_b64": "QUJD", "filename": "scan.xml"}],
            stakeholder={"exposure": "controlled", "method": "cisa_coordinator"},
        )
        serialized = mock_call.call_args.kwargs["body"].to_dict()
        assert serialized["files"] == [{"content_b64": "QUJD", "filename": "scan.xml"}]
        assert serialized["stakeholder"] == {"exposure": "controlled", "method": "cisa_coordinator"}

    @patch("crimson_crawler_client.client.inventory_enrich.asyncio_detailed", new_callable=AsyncMock)
    async def test_inventory_assets_survive_serialisation(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(_submit_response())
        client = CrawlerClient(api_key="k")
        result = await client.inventory_enrich(
            [{"product": "nginx", "version": "1.24.0", "environment": "production"}],
            attachments_text="prior report",
        )
        assert result.enrichment_id == "a" * 32
        serialized = mock_call.call_args.kwargs["body"].to_dict()
        assert serialized["items"] == [{"product": "nginx", "version": "1.24.0", "environment": "production"}]
        assert serialized["attachments_text"] == "prior report"

    @patch("crimson_crawler_client.client.inventory_enrich.asyncio_detailed", new_callable=AsyncMock)
    async def test_inventory_enrich_non_2xx_raises(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _err_response(429, b"slow down")
        client = CrawlerClient(api_key="k")
        with pytest.raises(UnexpectedStatus) as exc_info:
            await client.inventory_enrich([{"product": "nginx"}])
        assert exc_info.value.status == 429

    @patch("crimson_crawler_client.client.assess_vulnerability_exposure.asyncio_detailed", new_callable=AsyncMock)
    async def test_assess_stakeholder_dict_survives_serialisation(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(AssessVulnerabilityExposureResponse())
        client = CrawlerClient(api_key="k")
        await client.assess_vulnerability_exposure(["CVE-2000-0001"], stakeholder={"exposure": "small"})
        assert mock_call.call_args.kwargs["body"].to_dict()["stakeholder"] == {"exposure": "small"}


class TestEnrichBatch:
    """``enrich_batch`` passes heterogeneous items through untouched — the per-item
    ``include`` is deliberately not presetted. The generated union dispatches on the
    ``type`` discriminator, so every one of the 16 kinds must round-trip unchanged."""

    _ITEMS = [
        {"type": "cve", "cve_id": "CVE-2000-0001", "include": ["details", "kev"]},
        {"type": "product", "product": "nginx", "version": "1.24.0"},
        {"type": "package", "ecosystem": "PyPI", "package": "django"},
        {"type": "cwe", "cwe_id": "CWE-79"},
        {"type": "capec", "capec_id": "CAPEC-66"},
        {"type": "technique", "technique_ids": ["T1190"], "framework": "ics"},
        # The batch union owns ``type`` as its discriminator, so the IOC indicator type
        # is spelled ``value_type`` here — NOT the ``ioc_type`` of enrich_ioc_full.
        {"type": "ioc", "value": "1.2.3.4", "value_type": "ip-dst"},
        {"type": "group", "group_id": "G0016"},
        {"type": "software", "software_id": "S0154"},
        {"type": "campaign", "campaign_id": "C0028"},
        {"type": "atlas", "search": "prompt injection"},
        {"type": "disarm", "technique_id": "T0001"},
        {"type": "location", "location_id": "L1"},
        {"type": "sector", "sector_id": "S1"},
        {"type": "defend", "d3fend_id": "D3-AL"},
        {"type": "poc_source", "repo_url": "https://github.com/x/y"},
    ]

    @patch("crimson_crawler_client.client.enrich_batch.asyncio_detailed", new_callable=AsyncMock)
    async def test_every_item_kind_round_trips(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(EnrichBatchResponse())
        client = CrawlerClient(api_key="k")
        await client.enrich_batch(self._ITEMS)
        serialized = mock_call.call_args.kwargs["body"].to_dict()["items"]
        assert serialized == self._ITEMS

    @patch("crimson_crawler_client.client.enrich_batch.asyncio_detailed", new_callable=AsyncMock)
    async def test_no_include_preset_is_applied(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _ok_response(EnrichBatchResponse())
        client = CrawlerClient(api_key="k")
        await client.enrich_batch([{"type": "cve", "cve_id": "CVE-2000-0001"}])
        assert mock_call.call_args.kwargs["body"].to_dict()["items"] == [
            {"type": "cve", "cve_id": "CVE-2000-0001"},
        ]

    @patch("crimson_crawler_client.client.enrich_batch.asyncio_detailed", new_callable=AsyncMock)
    async def test_unknown_discriminator_fails_before_the_request(self, mock_call: AsyncMock) -> None:
        client = CrawlerClient(api_key="k")
        with pytest.raises((KeyError, ValueError, TypeError)):
            await client.enrich_batch([{"type": "d3fend", "d3fend_id": "D3-AL"}])
        mock_call.assert_not_awaited()

    @patch("crimson_crawler_client.client.enrich_batch.asyncio_detailed", new_callable=AsyncMock)
    async def test_non_2xx_raises(self, mock_call: AsyncMock) -> None:
        mock_call.return_value = _err_response(422, b"51 items")
        client = CrawlerClient(api_key="k")
        with pytest.raises(UnexpectedStatus) as exc_info:
            await client.enrich_batch([{"type": "cve", "cve_id": "CVE-2000-0001"}])
        assert exc_info.value.status == 422


# --------------------------------------------------------------------------- #
# Async context manager lifecycle
# --------------------------------------------------------------------------- #


class TestLifecycle:
    async def test_aenter_aexit_returns_self(self) -> None:
        async with CrawlerClient(api_key="k") as client:
            assert isinstance(client, CrawlerClient)

    async def test_aclose_is_idempotent(self) -> None:
        client = CrawlerClient(api_key="k")
        await client.aclose()
        await client.aclose()  # second call should not raise
