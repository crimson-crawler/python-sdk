#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for a built public client package, hermetically.

Why this exists instead of a scanner. The release previously ran Syft over ``dist/``,
which holds opaque archives, so it emitted a document whose only component was the
directory ``dist`` itself and whose ``components`` array was empty. Pointing Syft at
the *extracted* package is better but still insufficient: it then reports the package
plus every file, and none of the declared runtime dependencies, because a wheel does
not vendor its dependencies — they live in ``Requires-Dist`` metadata. An attestation
over that inventory asserts nothing.

So the SBOM is built from what the package actually declares, and the concrete
versions come from the committed lockfile. That keeps generation offline and
deterministic: no resolver runs at release time, and the same inputs always produce
the same bytes.

The ``serialNumber`` is derived from the document's own content. CycloneDX requires a
URN UUID and ``actions/attest`` refuses a document without one, while a random value
would make two runs over identical content differ. Deriving it satisfies both and is
the "documented, tested process" a generated identifier needs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import uuid
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.6"
CYCLONEDX_SCHEMA = f"http://cyclonedx.org/schema/bom-{CYCLONEDX_SPEC_VERSION}.schema.json"
_SERIAL_NAMESPACE = b"crimson-crawler/public-client-sbom/v1"

# `Requires-Dist: attrs>=24.0` / `httpx<1,>=0.28` / `mypy<2,>=1.19; extra == 'dev'`
_REQUIRES_DIST = re.compile(r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<rest>.*)$")


class SbomGenerationError(RuntimeError):
    """Raised when a package's metadata cannot produce a complete SBOM."""


def _content_serial(document: dict[str, Any]) -> str:
    """Return a `urn:uuid:` serial derived from the document's own content."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(_SERIAL_NAMESPACE + canonical).digest()
    # SHA-256 rather than `uuid.uuid5`, which is SHA-1 based. `version=5` only rewrites
    # the version/variant bits so the result is a syntactically valid RFC 4122 UUID.
    return f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=5)}"


def read_wheel_metadata(wheel: Path) -> tuple[str, str, list[str]]:
    """Return ``(name, version, runtime_dependency_names)`` from a wheel's METADATA.

    Dependencies carrying an ``extra ==`` marker are development-only and are excluded:
    the public package's SBOM describes what a consumer installs.
    """
    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise SbomGenerationError(f"{wheel}: expected exactly one dist-info/METADATA, found {len(names)}")
        raw = archive.read(names[0]).decode("utf-8", errors="replace")

    message = Parser().parsestr(raw)
    name = message.get("Name")
    version = message.get("Version")
    if not name or not version:
        raise SbomGenerationError(f"{wheel}: METADATA is missing Name or Version")

    dependencies: list[str] = []
    for requirement in message.get_all("Requires-Dist") or []:
        if "extra ==" in requirement:
            continue
        match = _REQUIRES_DIST.match(requirement)
        if match:
            dependencies.append(match.group("name"))
    return name, version, dependencies


def read_npm_metadata(tarball: Path) -> tuple[str, str, list[str]]:
    """Return ``(name, version, runtime_dependency_names)`` from a packed npm tarball."""
    with tarfile.open(tarball, "r:gz") as archive:
        member = next((m for m in archive.getmembers() if m.name == "package/package.json"), None)
        if member is None:
            raise SbomGenerationError(f"{tarball}: package/package.json is missing")
        handle = archive.extractfile(member)
        if handle is None:
            raise SbomGenerationError(f"{tarball}: package/package.json is not a regular file")
        manifest = json.loads(handle.read().decode("utf-8"))

    name = manifest.get("name")
    version = manifest.get("version")
    if not name or not version:
        raise SbomGenerationError(f"{tarball}: package.json is missing name or version")
    # `dependencies` only — devDependencies are not installed by a consumer.
    return name, version, sorted(manifest.get("dependencies") or {})


def resolve_uv_lock_versions(lock: Path, wanted: list[str]) -> dict[str, str]:
    """Map dependency name to the concrete version pinned in a `uv.lock`."""
    text = lock.read_text()
    resolved: dict[str, str] = {}
    for name in wanted:
        match = re.search(rf'\[\[package\]\]\nname = "{re.escape(name)}"\nversion = "([^"]+)"', text)
        if match:
            resolved[name] = match.group(1)
    return resolved


def resolve_npm_lock_versions(lock: Path, wanted: list[str]) -> dict[str, str]:
    """Map dependency name to the concrete version pinned in a `package-lock.json`."""
    packages = (json.loads(lock.read_text()).get("packages") or {}).items()
    resolved: dict[str, str] = {}
    for name in wanted:
        entry = dict(packages).get(f"node_modules/{name}")
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            resolved[name] = entry["version"]
    return resolved


def build_sbom(
    ecosystem: str,
    name: str,
    version: str,
    dependencies: list[str],
    resolved: dict[str, str],
) -> dict[str, Any]:
    """Assemble the CycloneDX document, then stamp its content-derived serial."""
    missing = sorted(set(dependencies) - set(resolved))
    if missing:
        raise SbomGenerationError(
            f"lockfile does not pin declared runtime dependencies: {', '.join(missing)}. "
            "The SBOM must carry concrete versions, so refusing to emit an incomplete inventory."
        )

    subject_ref = f"pkg:{ecosystem}/{name}@{version}"
    components = [
        {
            "type": "library",
            "bom-ref": f"pkg:{ecosystem}/{dep}@{resolved[dep]}",
            "name": dep,
            "version": resolved[dep],
            "purl": f"pkg:{ecosystem}/{dep}@{resolved[dep]}",
        }
        for dep in sorted(dependencies)
    ]
    document: dict[str, Any] = {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": subject_ref,
                "name": name,
                "version": version,
                "purl": subject_ref,
            },
            "tools": {
                "components": [{"type": "application", "author": "crimson-crawler", "name": "generate-public-sbom.py"}]
            },
        },
        "components": components,
        "dependencies": [
            {"ref": subject_ref, "dependsOn": [c["bom-ref"] for c in components]},
            *({"ref": c["bom-ref"], "dependsOn": []} for c in components),
        ],
    }
    document["serialNumber"] = _content_serial(document)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--wheel", type=Path, help="built Python wheel")
    source.add_argument("--npm-tarball", type=Path, help="packed npm tarball")
    parser.add_argument("--lock", type=Path, required=True, help="uv.lock or package-lock.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.wheel is not None:
            ecosystem = "pypi"
            name, version, dependencies = read_wheel_metadata(args.wheel)
            resolved = resolve_uv_lock_versions(args.lock, dependencies)
        else:
            ecosystem = "npm"
            name, version, dependencies = read_npm_metadata(args.npm_tarball)
            resolved = resolve_npm_lock_versions(args.lock, dependencies)
        document = build_sbom(ecosystem, name, version, dependencies, resolved)
    except (SbomGenerationError, OSError, json.JSONDecodeError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise SystemExit(f"unable to generate SBOM: {exc}") from exc

    args.output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"{name} {version}: {len(document['components'])} runtime component(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
