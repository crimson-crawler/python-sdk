#!/usr/bin/env python3
"""Compare release artifacts with immutable public registry metadata."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MISSING = 10
RETRY_ATTEMPTS = 3
TRANSIENT_HTTP_STATUS = {408, 429, 500, 502, 503, 504}


def retry_delay(error: BaseException, attempt: int) -> float:
    if isinstance(error, urllib.error.HTTPError):
        retry_after = error.headers.get("Retry-After")
        if retry_after:
            try:
                return min(30.0, max(0.0, float(retry_after)))
            except ValueError:
                pass
    return float(2**attempt)


class RegistryError(RuntimeError):
    """Registry metadata does not match the local release."""


def wait_to_retry(error: BaseException, message: str, attempt: int, *, transient: bool) -> None:
    if not transient or attempt == RETRY_ATTEMPTS - 1:
        raise RegistryError(message) from error
    time.sleep(retry_delay(error, attempt))


def fetch_json(url: str) -> dict | None:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "crimson-client-release"},
    )
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 -- URL is built from fixed registry origins
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            wait_to_retry(
                exc,
                f"registry metadata request failed with HTTP {exc.code}",
                attempt,
                transient=exc.code in TRANSIENT_HTTP_STATUS,
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            wait_to_retry(exc, f"registry metadata request failed: {exc}", attempt, transient=True)
    raise AssertionError("registry retry loop exhausted without returning")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sha512_integrity(path: Path) -> str:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha512").digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def checked_files(names: list[str]) -> list[Path]:
    paths = [Path(name) for name in names]
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise RegistryError(f"local artifact is not a regular file: {path}")
    if len({path.name for path in paths}) != len(paths):
        raise RegistryError("local artifact filenames are ambiguous")
    return paths


def check_pypi(project: str, version: str, paths: list[Path]) -> list[Path]:
    url = (
        "https://pypi.org/pypi/"
        f"{urllib.parse.quote(project, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    )
    metadata = fetch_json(url)
    if metadata is None:
        return paths
    if metadata.get("info", {}).get("name", "").lower().replace("_", "-") != project.lower().replace("_", "-"):
        raise RegistryError("PyPI project metadata identity does not match")
    if metadata.get("info", {}).get("version") != version:
        raise RegistryError("PyPI version metadata does not match")

    entries = metadata.get("urls", [])
    remote: dict[str, str | None] = {}
    for entry in entries:
        filename = entry.get("filename")
        if not isinstance(filename, str) or filename in remote:
            raise RegistryError("PyPI version metadata contains ambiguous filenames")
        remote[filename] = entry.get("digests", {}).get("sha256")
    expected_names = {path.name for path in paths}
    unexpected = sorted(set(remote) - expected_names)
    if unexpected:
        raise RegistryError(f"PyPI version contains unexpected files: {', '.join(unexpected)}")

    missing: list[Path] = []
    for path in paths:
        if path.name not in remote:
            missing.append(path)
        elif remote[path.name] != sha256(path):
            raise RegistryError(f"PyPI digest differs for {path.name}")
    return missing


def check_npm(package: str, version: str, path: Path) -> list[Path]:
    url = (
        "https://registry.npmjs.org/"
        f"{urllib.parse.quote(package, safe='')}/{urllib.parse.quote(version, safe='')}"
    )
    metadata = fetch_json(url)
    if metadata is None:
        return [path]
    if metadata.get("name") != package or metadata.get("version") != version:
        raise RegistryError("npm package metadata identity does not match")
    integrity = metadata.get("dist", {}).get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise RegistryError("npm metadata has no sha512 integrity digest")
    if integrity != sha512_integrity(path):
        raise RegistryError(f"npm digest differs for {path.name}")
    return []


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="registry", required=True)
    pypi = subparsers.add_parser("pypi")
    pypi.add_argument("project")
    pypi.add_argument("version")
    pypi.add_argument("files", nargs="+")
    npm = subparsers.add_parser("npm")
    npm.add_argument("package")
    npm.add_argument("version")
    npm.add_argument("file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.registry == "pypi":
        missing = check_pypi(args.project, args.version, checked_files(args.files))
    else:
        missing = check_npm(args.package, args.version, checked_files([args.file])[0])
    for path in missing:
        print(path)
    return MISSING if missing else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
