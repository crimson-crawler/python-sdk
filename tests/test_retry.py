"""Unit tests for the RetryTransport + backoff helpers.

Drives ``RetryTransport.handle_async_request`` directly with a fake inner
transport (``httpx.MockTransport``) and injected sleep + RNG so tests never
wait and jitter is reproducible. Also covers the constructor knob
(``max_retries`` validation/default) and the verify_ssl-preserved path.

These tests mock at the httpx transport layer — no network, no real upstream.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from crimson_crawler_client import (
    DEFAULT_MAX_RETRIES,
    CrawlerClient,
)
from crimson_crawler_client._retry import (
    RETRY_AFTER_MAX,
    RETRY_BASE_DELAY,
    RetryTransport,
    _compute_backoff,
    _parse_retry_after,
)


def _zero_rng(_a: float, _b: float) -> float:
    """Deterministic RNG that kills jitter — backoff equals the raw delay."""
    return 0.0


class _RecordingSleep:
    """Async sleep stub that records the durations it was asked to wait."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)


class _RecordingSyncSleep:
    """Sync sleep stub that records the durations it was asked to wait."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, delay: float) -> None:
        self.calls.append(delay)


def _make_request(method: str = "GET") -> httpx.Request:
    return httpx.Request(method, "https://test.local/v1/enrich/cve")


def _response(status: int, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status_code=status, headers=headers or {}, content=b"body")


class _ScriptedTransport(httpx.AsyncBaseTransport):
    """Inner transport that replays a scripted list of responses/exceptions."""

    def __init__(self, script: list[object]) -> None:
        self._script = list(script)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]


class _ScriptedSyncTransport(httpx.BaseTransport):
    """Sync inner transport that replays a scripted list of responses/exceptions."""

    def __init__(self, script: list[object]) -> None:
        self._script = list(script)
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]


class _FailingSyncStream(httpx.SyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        raise httpx.ReadError("response body reset")

    def close(self) -> None:
        self.closed = True


class _FailingAsyncStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        raise httpx.ReadError("response body reset")
        yield b""  # pragma: no cover

    async def aclose(self) -> None:
        self.closed = True


class _UncloseableAsyncStream(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        raise httpx.ReadError("response body reset")
        yield b""  # pragma: no cover

    async def aclose(self) -> None:
        raise RuntimeError("close failed")


class _RecordingAsyncStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.read = False
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.read = True
        yield b"retry body"

    async def aclose(self) -> None:
        self.closed = True


def _build(
    script: list[object], *, max_retries: int = 2, sleep=None, rng=None
) -> tuple[RetryTransport, _ScriptedTransport]:
    inner = _ScriptedTransport(script)
    transport = RetryTransport(
        max_retries=max_retries,
        wrapped=inner,
        sleep=sleep,
        rng=rng or _zero_rng,
    )
    return transport, inner


def _build_sync(
    script: list[object], *, max_retries: int = 2, sleep=None, rng=None
) -> tuple[RetryTransport, _ScriptedSyncTransport, _RecordingSyncSleep]:
    inner = _ScriptedSyncTransport(script)
    recorder = sleep or _RecordingSyncSleep()
    transport = RetryTransport(
        max_retries=max_retries,
        sync_wrapped=inner,
        sync_sleep=recorder,
        rng=rng or _zero_rng,
    )
    return transport, inner, recorder


# --------------------------------------------------------------------------- #
# Backoff + Retry-After helpers
# --------------------------------------------------------------------------- #


class TestBackoffHelpers:
    def test_compute_backoff_exponential_no_jitter(self) -> None:
        assert _compute_backoff(0, _zero_rng) == RETRY_BASE_DELAY  # 0.5
        assert _compute_backoff(1, _zero_rng) == 1.0
        assert _compute_backoff(2, _zero_rng) == 2.0
        assert _compute_backoff(3, _zero_rng) == 4.0

    def test_compute_backoff_caps_at_max(self) -> None:
        # attempt=10 → raw 512s, must clamp to 8.0
        assert _compute_backoff(10, _zero_rng) == 8.0

    def test_compute_backoff_never_negative(self) -> None:
        # Max negative jitter at attempt 0: 0.5 + 0.5*0.25*(-1) = 0.375 (still > 0),
        # but the clamp guards pathological RNG returning < -1.
        assert _compute_backoff(0, lambda _a, _b: -10.0) == 0.0

    def test_compute_backoff_jitter_within_band(self) -> None:
        # Full positive jitter at attempt 0: 0.5 + 0.5*0.25 = 0.625
        assert _compute_backoff(0, lambda _a, _b: 1.0) == pytest.approx(0.625)

    def test_parse_retry_after_none(self) -> None:
        assert _parse_retry_after(None) is None

    def test_parse_retry_after_blank(self) -> None:
        assert _parse_retry_after("   ") is None

    def test_parse_retry_after_delta_seconds(self) -> None:
        assert _parse_retry_after("2") == 2.0

    def test_parse_retry_after_delta_clamped(self) -> None:
        assert _parse_retry_after("600") == RETRY_AFTER_MAX  # 60.0

    def test_parse_retry_after_http_date(self) -> None:
        now = 1_000_000.0
        future = datetime.fromtimestamp(now, tz=timezone.utc) + timedelta(seconds=5)
        value = format_datetime(future)
        assert _parse_retry_after(value, now=now) == pytest.approx(5.0, abs=1.0)

    def test_parse_retry_after_http_date_clamped(self) -> None:
        now = 1_000_000.0
        future = datetime.fromtimestamp(now, tz=timezone.utc) + timedelta(seconds=600)
        value = format_datetime(future)
        assert _parse_retry_after(value, now=now) == RETRY_AFTER_MAX

    def test_parse_retry_after_past_date_is_zero(self) -> None:
        now = 1_000_000.0
        past = datetime.fromtimestamp(now, tz=timezone.utc) - timedelta(seconds=30)
        value = format_datetime(past)
        assert _parse_retry_after(value, now=now) == 0.0

    def test_parse_retry_after_unparseable(self) -> None:
        assert _parse_retry_after("not-a-date") is None


# --------------------------------------------------------------------------- #
# RetryTransport behavior (spec §6.1)
# --------------------------------------------------------------------------- #


class TestRetryTransport:
    async def test_retry_then_succeed_on_503(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([_response(503), _response(200)], sleep=sleep)
        resp = await transport.handle_async_request(_make_request())
        assert resp.status_code == 200
        assert inner.calls == 2
        assert len(sleep.calls) == 1
        assert sleep.calls[0] == RETRY_BASE_DELAY  # 0.5, no jitter

    async def test_retryable_status_body_read_failure_uses_retry_budget(self) -> None:
        sleep = _RecordingSleep()
        failed_stream = _FailingAsyncStream()
        retryable = httpx.Response(503, stream=failed_stream)
        transport, inner = _build([retryable, _response(200)], sleep=sleep)

        response = await transport.handle_async_request(_make_request())

        assert response.status_code == 200
        assert inner.calls == 2
        assert sleep.calls == [RETRY_BASE_DELAY]
        assert failed_stream.closed

    async def test_response_cleanup_failure_does_not_mask_retry(self) -> None:
        sleep = _RecordingSleep()
        retryable = httpx.Response(503, stream=_UncloseableAsyncStream())
        transport, inner = _build([retryable, _response(200)], sleep=sleep)

        response = await transport.handle_async_request(_make_request())

        assert response.status_code == 200
        assert inner.calls == 2

    async def test_every_discarded_retry_response_is_consumed_and_closed(self) -> None:
        sleep = _RecordingSleep()
        first_stream = _RecordingAsyncStream()
        second_stream = _RecordingAsyncStream()
        transport, _ = _build(
            [
                httpx.Response(503, stream=first_stream),
                httpx.Response(429, stream=second_stream),
                _response(200),
            ],
            sleep=sleep,
        )

        response = await transport.handle_async_request(_make_request())

        assert response.status_code == 200
        assert first_stream.read and first_stream.closed
        assert second_stream.read and second_stream.closed

    async def test_exhaust_then_return_final_503(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([_response(503), _response(503), _response(503)], sleep=sleep)
        resp = await transport.handle_async_request(_make_request())
        # Transport does NOT swallow — returns the final 503 for _ensure_ok to raise.
        assert resp.status_code == 503
        assert inner.calls == 3
        assert sleep.calls == [0.5, 1.0]  # two sleeps, exponential, no jitter

    async def test_transport_error_retry_then_succeed(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([httpx.ConnectError("boom"), _response(200)], sleep=sleep)
        resp = await transport.handle_async_request(_make_request())
        assert resp.status_code == 200
        assert inner.calls == 2
        assert len(sleep.calls) == 1

    async def test_post_status_is_not_retried(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([_response(503)], sleep=sleep)
        response = await transport.handle_async_request(_make_request("POST"))
        assert response.status_code == 503
        assert inner.calls == 1
        assert sleep.calls == []

    async def test_post_transport_error_is_not_retried(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([httpx.ReadTimeout("t")], sleep=sleep)
        with pytest.raises(httpx.ReadTimeout):
            await transport.handle_async_request(_make_request("POST"))
        assert inner.calls == 1
        assert sleep.calls == []

    async def test_transport_error_exhaust_reraises(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build(
            [httpx.ReadTimeout("t"), httpx.ReadTimeout("t"), httpx.ReadTimeout("t")],
            sleep=sleep,
        )
        with pytest.raises(httpx.ReadTimeout):
            await transport.handle_async_request(_make_request())
        assert inner.calls == 3
        assert sleep.calls == [0.5, 1.0]

    async def test_retry_after_delta_seconds_honored(self) -> None:
        sleep = _RecordingSleep()
        transport, _ = _build([_response(503, {"retry-after": "2"}), _response(200)], sleep=sleep)
        await transport.handle_async_request(_make_request())
        assert sleep.calls == [2.0]  # honored, not computed 0.5

    async def test_retry_after_http_date_honored(self) -> None:
        sleep = _RecordingSleep()
        future = datetime.now(tz=timezone.utc) + timedelta(seconds=5)
        transport, _ = _build(
            [_response(503, {"retry-after": format_datetime(future)}), _response(200)],
            sleep=sleep,
        )
        await transport.handle_async_request(_make_request())
        assert sleep.calls[0] == pytest.approx(5.0, abs=2.0)

    async def test_retry_after_clamped_to_60(self) -> None:
        sleep = _RecordingSleep()
        transport, _ = _build([_response(503, {"retry-after": "600"}), _response(200)], sleep=sleep)
        await transport.handle_async_request(_make_request())
        assert sleep.calls == [60.0]

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 500])
    async def test_non_retryable_not_retried(self, status: int) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([_response(status)], sleep=sleep)
        resp = await transport.handle_async_request(_make_request())
        assert resp.status_code == status
        assert inner.calls == 1
        assert sleep.calls == []

    @pytest.mark.parametrize("status", [429, 502, 503, 504])
    async def test_retryable_statuses(self, status: int) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([_response(status), _response(200)], sleep=sleep)
        resp = await transport.handle_async_request(_make_request())
        assert resp.status_code == 200
        assert inner.calls == 2

    async def test_max_retries_zero_disables(self) -> None:
        sleep = _RecordingSleep()
        transport, inner = _build([_response(503)], max_retries=0, sleep=sleep)
        resp = await transport.handle_async_request(_make_request())
        assert resp.status_code == 503
        assert inner.calls == 1
        assert sleep.calls == []

    async def test_default_inner_transports_are_real_http(self) -> None:
        # No wrapped transports supplied → builds an httpx.AsyncHTTPTransport
        # for the async client AND an httpx.HTTPTransport for the sync client
        # (the generated AuthenticatedClient hands the same instance to both).
        transport = RetryTransport(max_retries=2, verify=False)
        assert isinstance(transport._wrapped, httpx.AsyncHTTPTransport)
        assert isinstance(transport._sync_wrapped, httpx.HTTPTransport)
        transport.close()
        await transport.aclose()


class TestSyncRetryTransport:
    """Sync twin of TestRetryTransport — driven through a real httpx.Client.

    Regression for the sync escape hatch: RetryTransport used to subclass only
    AsyncBaseTransport, so httpx.Client(transport=RetryTransport(...)) — what
    the generated AuthenticatedClient builds — blew up on the missing
    ``handle_request`` before any request was sent.
    """

    def test_sync_client_request_reaches_sync_inner_transport(self) -> None:
        transport, inner, sleep = _build_sync([_response(200)])
        with httpx.Client(transport=transport) as client:
            resp = client.get("https://test.local/v1/enrich/cve")
        assert resp.status_code == 200
        assert inner.calls == 1
        assert sleep.calls == []

    def test_sync_retry_then_succeed_on_503(self) -> None:
        transport, inner, sleep = _build_sync([_response(503), _response(200)])
        with httpx.Client(transport=transport) as client:
            resp = client.get("https://test.local/v1/enrich/cve")
        assert resp.status_code == 200
        assert inner.calls == 2
        assert sleep.calls == [RETRY_BASE_DELAY]  # 0.5, no jitter

    def test_sync_retryable_status_body_read_failure_uses_retry_budget(self) -> None:
        failed_stream = _FailingSyncStream()
        retryable = httpx.Response(503, stream=failed_stream)
        transport, inner, sleep = _build_sync([retryable, _response(200)])

        with httpx.Client(transport=transport) as client:
            response = client.get("https://test.local/v1/enrich/cve")

        assert response.status_code == 200
        assert inner.calls == 2
        assert sleep.calls == [RETRY_BASE_DELAY]
        assert failed_stream.closed

    def test_sync_exhaust_then_return_final_503(self) -> None:
        transport, inner, sleep = _build_sync([_response(503), _response(503), _response(503)])
        with httpx.Client(transport=transport) as client:
            resp = client.get("https://test.local/v1/enrich/cve")
        assert resp.status_code == 503
        assert inner.calls == 3
        assert sleep.calls == [0.5, 1.0]

    def test_sync_retry_after_delta_seconds_honored(self) -> None:
        transport, _, sleep = _build_sync([_response(503, {"retry-after": "2"}), _response(200)])
        with httpx.Client(transport=transport) as client:
            client.get("https://test.local/v1/enrich/cve")
        assert sleep.calls == [2.0]  # honored, not computed 0.5

    def test_sync_post_status_at_most_once(self) -> None:
        transport, inner, sleep = _build_sync([_response(503)])
        with httpx.Client(transport=transport) as client:
            resp = client.post("https://test.local/v1/enrich/cve", json={})
        assert resp.status_code == 503
        assert inner.calls == 1
        assert sleep.calls == []

    def test_sync_post_transport_error_at_most_once(self) -> None:
        transport, inner, sleep = _build_sync([httpx.ReadTimeout("t")])
        with httpx.Client(transport=transport) as client:
            with pytest.raises(httpx.ReadTimeout):
                client.post("https://test.local/v1/enrich/cve", json={})
        assert inner.calls == 1
        assert sleep.calls == []

    def test_sync_transport_error_exhaust_reraises(self) -> None:
        transport, inner, sleep = _build_sync([httpx.ReadTimeout("t"), httpx.ReadTimeout("t"), httpx.ReadTimeout("t")])
        with httpx.Client(transport=transport) as client:
            with pytest.raises(httpx.ReadTimeout):
                client.get("https://test.local/v1/enrich/cve")
        assert inner.calls == 3
        assert sleep.calls == [0.5, 1.0]


# --------------------------------------------------------------------------- #
# CrawlerClient integration: constructor knob + end-to-end via MockTransport
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRIMSON_CRAWLER_API_KEY", raising=False)
    monkeypatch.delenv("CRIMSON_CRAWLER_BASE_URL", raising=False)
    monkeypatch.delenv("CRIMSON_CRAWLER_VERIFY_SSL", raising=False)


class TestConstructorKnob:
    def test_default_max_retries(self) -> None:
        client = CrawlerClient(api_key="k")
        assert client.max_retries == DEFAULT_MAX_RETRIES == 2

    def test_max_retries_zero_valid(self) -> None:
        client = CrawlerClient(api_key="k", max_retries=0)
        assert client.max_retries == 0

    def test_max_retries_negative_raises(self) -> None:
        with pytest.raises(ValueError):
            CrawlerClient(api_key="k", max_retries=-1)

    def test_retry_transport_installed(self) -> None:
        client = CrawlerClient(api_key="k", max_retries=3)
        httpx_client = client.api.get_async_httpx_client()
        # httpx wraps the transport; the mounted default transport is ours.
        transport = httpx_client._transport
        assert isinstance(transport, RetryTransport)
        assert transport._max_retries == 3

    def test_verify_ssl_false_threads_into_inner_transport(self) -> None:
        # §6.1 #11 — verify_ssl=False must build the inner transport with
        # verify=False even though the AuthenticatedClient verify_ssl arg no
        # longer governs TLS once we install our own transport.
        client = CrawlerClient(api_key="k", verify_ssl=False)
        assert client.api._verify_ssl is False
        transport = client.api.get_async_httpx_client()._transport
        assert isinstance(transport, RetryTransport)
        inner = transport._wrapped
        assert isinstance(inner, httpx.AsyncHTTPTransport)
        # The inner AsyncHTTPTransport holds an httpx._config.SSLConfig /
        # ssl context built from verify=False. A verify=False transport's
        # pool ssl_context disables hostname checking + cert verification.
        ssl_ctx = inner._pool._ssl_context
        assert ssl_ctx.check_hostname is False
        import ssl as _ssl

        assert ssl_ctx.verify_mode == _ssl.CERT_NONE


class TestEndToEndRetry:
    """Prove generated POST requests never replay through the shared transport."""

    @staticmethod
    def _install_mock_transport(client: CrawlerClient, responses: list[httpx.Response]) -> _RecordingSleep:
        sleep = _RecordingSleep()
        iterator = iter(responses)

        def handler(_request: httpx.Request) -> httpx.Response:
            return next(iterator)

        retry = RetryTransport(
            max_retries=client.max_retries,
            wrapped=httpx.MockTransport(handler),
            sleep=sleep,
            rng=_zero_rng,
        )
        client.api.set_async_httpx_client(
            httpx.AsyncClient(
                base_url=client.base_url,
                headers={"apikey": client.api.token},
                transport=retry,
            )
        )
        return sleep

    async def test_post_status_fails_after_first_response(self) -> None:
        from crimson_crawler_client import UnexpectedStatus

        client = CrawlerClient(api_key="k")
        sleep = self._install_mock_transport(
            client,
            [httpx.Response(503, content=b"down")],
        )
        with pytest.raises(UnexpectedStatus) as exc_info:
            await client.enrich_cve_full("CVE-2024-3400")
        assert exc_info.value.status == 503
        assert sleep.calls == []
        await client.aclose()

    async def test_post_transport_error_propagates_immediately(self) -> None:
        client = CrawlerClient(api_key="k")
        sleep = _RecordingSleep()

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        retry = RetryTransport(
            max_retries=client.max_retries,
            wrapped=httpx.MockTransport(handler),
            sleep=sleep,
            rng=_zero_rng,
        )
        client.api.set_async_httpx_client(
            httpx.AsyncClient(
                base_url=client.base_url,
                headers={"apikey": client.api.token},
                transport=retry,
            )
        )
        with pytest.raises(httpx.ConnectError):
            await client.enrich_cve_full("CVE-2024-3400")
        assert sleep.calls == []
        await client.aclose()


class TestSyncEscapeHatch:
    """Regression: the constructor-installed RetryTransport must serve the sync
    ``client.api`` escape hatch too.

    The generated AuthenticatedClient spreads the same ``httpx_args`` into both
    ``httpx.Client`` and ``httpx.AsyncClient``; before RetryTransport grew a
    sync side, ``client.api.get_httpx_client()`` requests died on the missing
    ``handle_request``. These tests exercise the REAL installed transport with
    only its sync inner swapped for a mock.
    """

    @staticmethod
    def _mock_sync_inner(client: CrawlerClient, handler) -> RetryTransport:
        transport = client.api.get_httpx_client()._transport
        assert isinstance(transport, RetryTransport)
        transport._sync_wrapped.close()  # discard the real HTTPTransport
        transport._sync_wrapped = httpx.MockTransport(handler)
        transport._sync_sleep = _RecordingSyncSleep()
        return transport

    def test_sync_escape_hatch_reaches_mock_sync_transport(self) -> None:
        client = CrawlerClient(api_key="k")
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"ok": True})

        self._mock_sync_inner(client, handler)
        resp = client.api.get_httpx_client().get("/v1/enrich/cve")
        assert resp.status_code == 200
        assert len(seen) == 1
        assert seen[0].headers["apikey"] == "k"
        client.api.get_httpx_client().close()

    def test_sync_escape_hatch_mutation_at_most_once(self) -> None:
        client = CrawlerClient(api_key="k")
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(503, content=b"down")

        transport = self._mock_sync_inner(client, handler)
        resp = client.api.get_httpx_client().post("/v1/enrich/cve", json={"cve_id": "CVE-2000-0001"})
        assert resp.status_code == 503
        assert len(seen) == 1  # mutation → exactly one attempt, no replay
        assert transport._sync_sleep.calls == []
        client.api.get_httpx_client().close()
