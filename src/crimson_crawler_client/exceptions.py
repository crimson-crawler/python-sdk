"""Exception types for the Crimson Crawler client.

Callers should catch :class:`CrawlerClientError` to handle any client-raised
problem. Mirrors the TypeScript wrapper (`@crimson-crawler/crimson-crawler-client`)
shape so the two SDKs raise the same hierarchy with the same attributes.
"""

from __future__ import annotations

from typing import Any


class CrawlerClientError(Exception):
    """Base class for all client-side errors raised by this wrapper."""


class MissingCredentials(CrawlerClientError):
    """Raised when neither an explicit api_key nor CRIMSON_CRAWLER_API_KEY is set."""


class UnexpectedStatus(CrawlerClientError):
    """Raised when the server returns a non-success status or an unparseable body.

    Mirrors the TS wrapper's ``UnexpectedStatus`` (status + body + message) so
    callers can write portable error-handling against either SDK.
    """

    def __init__(self, status: int, body: Any, message: str | None = None) -> None:
        self.status = status
        self.body = body
        super().__init__(message or f"Unexpected response status {status}")


__all__ = [
    "CrawlerClientError",
    "MissingCredentials",
    "UnexpectedStatus",
]
