"""Expand page-local CVE context catalogues for SDK consumers."""

from typing import Any

_FIELDS = {"attack_patterns", "techniques", "mitigations", "weaknesses"}


def expand_cve_context(data: dict[str, Any]) -> None:
    """Restore each CVE's context rows, rejecting missing or malformed references."""
    if "cve_context_catalog" not in data:
        if any(row.get("catalog_refs") for row in data.get("cves") or []):
            raise ValueError("Invalid CVE context catalogue reference")
        return
    catalog = data.get("cve_context_catalog") or {}
    for row in data.get("cves") or []:
        for field, keys in (row.get("catalog_refs") or {}).items():
            if field not in _FIELDS or not isinstance(keys, list):
                raise ValueError("Invalid CVE context catalogue reference")
            entries = catalog.get(field) or {}
            if any(not isinstance(key, str) or key not in entries for key in keys):
                raise ValueError("Invalid CVE context catalogue reference")
            row[field] = [entries[key] for key in keys]
        row["catalog_refs"] = {}
    data["cve_context_catalog"] = {}
