"""Internal URL construction helpers."""

from __future__ import annotations

from urllib.parse import quote


def path_segment(value: str) -> str:
    """Encode one caller-provided URL path segment."""
    return quote(value, safe="")
