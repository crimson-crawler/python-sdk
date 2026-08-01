#!/usr/bin/env python3
"""Normalize a CycloneDX JSON SBOM for reproducible release assets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class SbomError(ValueError):
    """Raised when an SBOM cannot be normalized safely."""


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def normalize_sbom(document: dict[str, Any]) -> dict[str, Any]:
    """Remove per-run metadata and put unordered content in a stable order."""
    if document.get("bomFormat") != "CycloneDX":
        raise SbomError("expected a CycloneDX JSON SBOM")
    if not isinstance(document.get("specVersion"), str):
        raise SbomError("CycloneDX specVersion is missing")

    normalized = dict(document)
    normalized.pop("serialNumber", None)
    metadata = normalized.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise SbomError("CycloneDX metadata must be an object")
        metadata = dict(metadata)
        metadata.pop("timestamp", None)
        normalized["metadata"] = metadata
    return _normalize(normalized)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("input and output paths must differ")

    try:
        document = json.loads(args.input.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"unable to read SBOM: {exc}") from exc
    if not isinstance(document, dict):
        raise SystemExit("SBOM root must be a JSON object")

    try:
        normalized = normalize_sbom(document)
    except SbomError as exc:
        raise SystemExit(str(exc)) from exc
    args.output.write_text(json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
