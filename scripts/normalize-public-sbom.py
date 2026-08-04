#!/usr/bin/env python3
"""Normalize and validate a CycloneDX JSON SBOM for public release assets.

Two defects reached production through this script and both are guarded here now.

The first was fatal to the release: it deleted ``serialNumber``. ``actions/attest``
identifies a CycloneDX document by ``bomFormat`` **and** ``serialNumber`` **and**
``specVersion`` together, so an SBOM without a serial is rejected outright as
"Unsupported SBOM format" — in the ``attest`` job, *after* the package has already
published to an immutable registry. The generator's serial is now preserved and
validated rather than removed; nothing compares SBOMs across builds, so its
per-run randomness costs nothing.

The second was quieter and worse: Syft was pointed at ``dist/``, which holds opaque
archives, so it emitted an SBOM whose only component was ``dist`` itself and whose
``components`` array was empty. That would have produced a *signed attestation over
an empty inventory* — an assertion that says nothing while looking authoritative.
Callers now declare the package they expect and the runtime dependencies that must
appear, and this script fails closed when the inventory does not contain them.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

# CycloneDX requires `serialNumber` to be a URN UUID when present.
_SERIAL_PATTERN = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Names a scanner reports when it was aimed at a directory instead of package contents.
# `dist` is the exact value that shipped an empty inventory; the others are the staging
# directories the workflows use, which must never end up as the released component.
_SCAN_ROOT_NAMES = frozenset({"dist", "sbom-root", "distribution", "."})

# Only these keys are removed. Everything else the generator produced is preserved —
# deleting identity or inventory fields is what caused both production defects.
_NONDETERMINISTIC_METADATA_KEYS = ("timestamp",)


class SbomError(ValueError):
    """Raised when an SBOM cannot be normalized or fails its release contract."""


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def _component_names(document: dict[str, Any]) -> set[str]:
    components = document.get("components")
    if not isinstance(components, list):
        return set()
    return {c["name"] for c in components if isinstance(c, dict) and isinstance(c.get("name"), str)}


def normalize_sbom(
    document: dict[str, Any],
    *,
    expect_component: str | None = None,
    require_dependencies: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return the document with per-run metadata dropped and ordering stabilized.

    ``expect_component`` and ``require_dependencies`` turn this into the release gate
    Crux requires: without them a caller can still normalize, but the release
    workflows always pass them so an empty or misidentified inventory fails closed.
    """
    if document.get("bomFormat") != "CycloneDX":
        raise SbomError("expected a CycloneDX JSON SBOM")
    if not isinstance(document.get("specVersion"), str) or not document["specVersion"]:
        raise SbomError("CycloneDX specVersion is missing")

    serial = document.get("serialNumber")
    if not isinstance(serial, str) or not _SERIAL_PATTERN.match(serial):
        raise SbomError(
            "CycloneDX serialNumber must be a urn:uuid value; "
            "actions/attest rejects a document without it as an unsupported SBOM format"
        )

    normalized = dict(document)
    metadata = normalized.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise SbomError("CycloneDX metadata must be an object")
        metadata = dict(metadata)
        for key in _NONDETERMINISTIC_METADATA_KEYS:
            metadata.pop(key, None)
        normalized["metadata"] = metadata

    subject = (metadata or {}).get("component")
    subject_name = subject.get("name") if isinstance(subject, dict) else None
    if not isinstance(subject_name, str) or not subject_name:
        raise SbomError("CycloneDX metadata.component must identify the released package")
    if subject_name in _SCAN_ROOT_NAMES:
        raise SbomError(
            f"metadata.component names the scan directory {subject_name!r}, not a package — "
            "generate the SBOM from extracted package contents, not from the archive directory"
        )
    if expect_component is not None and subject_name != expect_component:
        raise SbomError(f"metadata.component is {subject_name!r}, expected {expect_component!r}")

    names = _component_names(normalized)
    if not names:
        raise SbomError("CycloneDX components is empty — an attestation over an empty inventory asserts nothing")
    missing = sorted(dep for dep in require_dependencies if dep not in names)
    if missing:
        raise SbomError(f"CycloneDX components is missing required runtime dependencies: {', '.join(missing)}")

    return _normalize(normalized)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--expect-component",
        help="package name metadata.component must carry (rejects a scan-directory SBOM)",
    )
    parser.add_argument(
        "--require-dependency",
        action="append",
        default=[],
        metavar="NAME",
        help="runtime dependency that must appear in components; repeatable",
    )
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
        normalized = normalize_sbom(
            document,
            expect_component=args.expect_component,
            require_dependencies=tuple(args.require_dependency),
        )
    except SbomError as exc:
        raise SystemExit(str(exc)) from exc
    args.output.write_text(json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
