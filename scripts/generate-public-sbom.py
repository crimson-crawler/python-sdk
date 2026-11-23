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
import tomllib
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


def _walk(roots: list[str], edges: dict[str, list[str]], known: set[str]) -> set[str]:
    """Return the transitive closure of ``roots`` over ``edges``, restricted to ``known``.

    Iterative, and guarded by the visited set: dependency graphs contain cycles
    (dev tooling especially), and a recursive walk would blow the stack on one.
    """
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node in seen or node not in known:
            continue
        seen.add(node)
        stack.extend(edges.get(node, ()))
    return seen


def resolve_uv_lock_graph(lock: Path, root: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Return ``(name -> version, name -> runtime deps)`` for a `uv.lock` runtime closure.

    Parsed with ``tomllib`` rather than a regex over the raw text. The previous
    regex could only answer "what version is package X pinned at"; the edges are
    what make the closure and the CycloneDX ``dependencies`` graph possible.

    **Dev exclusion is structural, not a filter.** Only ``[[package]].dependencies``
    edges are traversed, and dev tooling is reachable exclusively through
    ``dev-dependencies`` / ``metadata.requires-dev``, so it can never enter the
    closure. That is stronger than name-matching a denylist: a new dev dependency
    is excluded automatically, with nothing to keep in sync.

    Marker-gated dependencies (``sys_platform``, ``python_full_version``) ARE
    included. An SBOM describes what the package may install, and resolving
    markers would require choosing a target platform the document does not have.
    """
    data = tomllib.loads(lock.read_text())
    packages = data.get("package") or []

    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    for entry in packages:
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        if isinstance(entry.get("version"), str):
            versions[name] = entry["version"]
        deps = entry.get("dependencies") or []
        edges[name] = sorted({d["name"] for d in deps if isinstance(d, dict) and isinstance(d.get("name"), str)})

    if root not in versions:
        raise SbomGenerationError(f"{lock}: no [[package]] entry named {root!r} — cannot root the runtime closure")

    reachable = _walk(edges.get(root, []), edges, set(versions))
    return {n: versions[n] for n in reachable}, {n: edges.get(n, []) for n in reachable}


def resolve_npm_lock_graph(lock: Path, root: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Return ``(name -> version, name -> runtime deps)`` for a `package-lock.json` closure.

    npm marks every entry reachable only from ``devDependencies`` with ``dev: true``,
    so that flag *is* the runtime projection — computed by npm's own resolver, which
    is more trustworthy than re-deriving it here. Entries are additionally reachable
    from the root's ``dependencies`` to catch a stale flag.

    The vast majority of a front-end lock is dev tooling: at the time this was
    written 306 of 308 entries in `client-ts/package-lock.json` carried ``dev: true``.
    Emitting those would assert that `vitest` and `eslint` ship inside the published
    package — affirmatively false, and worse than under-reporting.
    """
    packages = json.loads(lock.read_text()).get("packages") or {}

    versions: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict) or entry.get("dev"):
            continue
        name = key.split("node_modules/")[-1]
        if isinstance(entry.get("version"), str):
            versions[name] = entry["version"]
        edges[name] = sorted(entry.get("dependencies") or {})

    root_entry = packages.get("") or {}
    roots = sorted(root_entry.get("dependencies") or {})
    reachable = _walk(roots, edges, set(versions))
    return {n: versions[n] for n in reachable}, {n: edges.get(n, []) for n in reachable}


def build_sbom(
    ecosystem: str,
    name: str,
    version: str,
    dependencies: list[str],
    resolved: dict[str, str],
    edges: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Assemble the CycloneDX document, then stamp its content-derived serial.

    ``dependencies`` are the package's DIRECT runtime requirements (from wheel
    METADATA / package.json); ``resolved`` is the full runtime closure from the
    lockfile. The direct set must be a subset of the closure — if it is not, the
    lockfile does not describe the artifact being shipped, and emitting anyway
    would attest to an inventory that never existed.
    """
    missing = sorted(set(dependencies) - set(resolved))
    if missing:
        raise SbomGenerationError(
            f"lockfile does not pin declared runtime dependencies: {', '.join(missing)}. "
            "The SBOM must carry concrete versions, so refusing to emit an incomplete inventory."
        )

    edges = edges or {}
    subject_ref = f"pkg:{ecosystem}/{name}@{version}"

    def ref(dep: str) -> str:
        return f"pkg:{ecosystem}/{dep}@{resolved[dep]}"

    components = [
        {
            "type": "library",
            "bom-ref": ref(dep),
            "name": dep,
            "version": resolved[dep],
            "purl": ref(dep),
        }
        for dep in sorted(resolved)
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
        # Real edges, so an SCA tool can tell a direct dependency from a transitive
        # one. The root depends on the DIRECT set only; every other edge comes from
        # the lockfile. A flat "root dependsOn everything" graph would make the
        # larger document merely bigger, not more useful.
        "dependencies": [
            {"ref": subject_ref, "dependsOn": [ref(d) for d in sorted(dependencies)]},
            *(
                {"ref": ref(dep), "dependsOn": [ref(d) for d in sorted(edges.get(dep, [])) if d in resolved]}
                for dep in sorted(resolved)
            ),
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
            # Root the closure at the package's own [[package]] entry. uv.lock uses
            # normalised (hyphenated) names, which is what the wheel METADATA
            # `Name:` field already carries for these packages.
            resolved, edges = resolve_uv_lock_graph(args.lock, name)
        else:
            ecosystem = "npm"
            name, version, dependencies = read_npm_metadata(args.npm_tarball)
            resolved, edges = resolve_npm_lock_graph(args.lock, name)
        document = build_sbom(ecosystem, name, version, dependencies, resolved, edges)
    except (
        SbomGenerationError,
        OSError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as exc:
        raise SystemExit(f"unable to generate SBOM: {exc}") from exc

    args.output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"{name} {version}: {len(document['components'])} runtime component(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
