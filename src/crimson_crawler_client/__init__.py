"""Crimson Crawler API client.

Typed async Python wrapper for the Crimson Crawler v1 API. Built on top of an
``openapi-python-client`` codegen layer; adds API key auth, sensible defaults,
and convenience methods for the most common enrichment chains.

Usage:
    Standard async context manager — recommended::

        from crimson_crawler_client import CrawlerClient

        async with CrawlerClient() as client:
            result = await client.enrich_cve_full("CVE-2024-3400")
            print(result.cve.cvss_score)

    Configuration:

    - ``CRIMSON_CRAWLER_API_KEY`` env var, or pass ``api_key=`` to the
      constructor. Required.
    - ``CRIMSON_CRAWLER_BASE_URL`` env var, or pass ``base_url=`` to the
      constructor, to select a custom, self-hosted, or local deployment.
      Defaults to ``https://crimsoncrawler.com``.

See ``presets`` for the default ``include=[...]`` chains. Every one of the 33 ``/v1``
operations has a named method on ``CrawlerClient``; ``_generated`` stays available as an
escape hatch for hand-built request models and sync callers.
"""

from __future__ import annotations

from . import presets
from ._generated import AuthenticatedClient, Client
from .ai_reports import AiReportsAPI
from .artifact_manager import ArtifactManagerAPI
from .client import (
    BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_VERIFY_SSL,
    CrawlerClient,
)
from .enricher import EnricherAPI
from .exceptions import (
    CrawlerClientError,
    MissingCredentials,
    UnexpectedStatus,
)
from .ingest import assemble_briefing, ingest_scan
from .inventory_manager import InventoryManagerAPI

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("crimson-crawler-client")
except Exception:  # noqa: BLE001  # pragma: no cover — fall back when running from source without metadata
    __version__ = "0.0.0+unknown"

__all__ = [
    "AuthenticatedClient",
    "BASE_URL",
    "Client",
    "CrawlerClient",
    "CrawlerClientError",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "MissingCredentials",
    "ENV_VERIFY_SSL",
    "UnexpectedStatus",
    "AiReportsAPI",
    "ArtifactManagerAPI",
    "InventoryManagerAPI",
    "EnricherAPI",
    "assemble_briefing",
    "ingest_scan",
    "__version__",
    "presets",
]
