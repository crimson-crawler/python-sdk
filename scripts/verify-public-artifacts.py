#!/usr/bin/env python3
"""Validate release artifacts built in a public client repository."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import re
import stat
import sys
import tarfile
import tomllib
import unicodedata
import zipfile
from collections.abc import Iterator
from email.message import Message
from pathlib import Path, PurePosixPath
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"(?i)(?:api[_-]?key|token|password|secret)\s*[=:]\s*['\"][A-Za-z0-9_./+=-]{24,}['\"]"),
)
WORKSTATION_PATH_PATTERNS = (
    re.compile(rb"(?:^|[\s\"'(=])/(?:Users|home)/[^/\s]+/"),
    re.compile(rb"(?i)(?:^|[\s\"'(=])[a-z]:\\Users\\[^\\\s]+\\"),
)
UNICODE_TEXT_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")
FORBIDDEN_ARTIFACT_PARTS = {".env", ".git", ".npmrc", "__pycache__", "node_modules", "tests", "examples"}
CANONICAL_SPIDER_SHA256 = "d25864a14deb269490c01832bc7ed92a6d2134bdaa6b779822b6937cc4324e0c"
CANONICAL_WORDMARK_SHA256 = {
    "python": "bfa605463d55abcd60670e50bd773bde72c8606466e442490bb81405ce66f934",
    "typescript": "cfd25573bc9ea7accc5766e5f9806804e8079b6043f79a86b9992e03d9865aaf",
    "cli": "8137afe49c6ada2d8c67315f03ca21b69f12931a205f1ecb49b50ab5e27f1b8c",
}


class VerificationError(RuntimeError):
    """Artifact failed a release invariant."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def python_project(path: Path) -> dict:
    with path.open("rb") as stream:
        return tomllib.load(stream)["project"]


def archive_members(path: Path) -> Iterator[tuple[str, bytes]]:
    seen: dict[str, str] = {}

    def validate_name(name: str, *, is_dir: bool) -> None:
        source_name = name[:-1] if is_dir and name.endswith("/") else name
        member_path = PurePosixPath(source_name)
        if (
            not source_name
            or "\0" in source_name
            or "\\" in source_name
            or member_path.is_absolute()
            or any(part in {"", ".", ".."} for part in source_name.split("/"))
        ):
            fail(f"{path}: unsafe archive member {name}")
        key = unicodedata.normalize("NFC", member_path.as_posix()).casefold()
        if previous := seen.get(key):
            fail(f"{path}: duplicate normalized archive member {name} conflicts with {previous}")
        seen[key] = name

    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            for info in members:
                validate_name(info.filename, is_dir=info.is_dir())
                if stat.S_ISLNK(info.external_attr >> 16):
                    fail(f"{path}: symlink member {info.filename}")
            if bad := archive.testzip():
                fail(f"{path}: corrupt wheel member {bad}")
            for info in members:
                if not info.is_dir():
                    yield info.filename, archive.read(info)
        return

    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            validate_name(member.name, is_dir=member.isdir())
            if not member.isdir() and not member.isfile():
                fail(f"{path}: non-file member {member.name}")
        for member in members:
            if member.isdir():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                fail(f"{path}: unreadable member {member.name}")
            yield member.name, stream.read()


def scan_content(location: str, content: bytes) -> None:
    if content.startswith(UNICODE_TEXT_BOMS):
        fail(f"{location}: UTF-16/UTF-32 content is not allowed")
    for pattern in SECRET_PATTERNS:
        if pattern.search(content):
            fail(f"{location}: credential-like value present")
    for pattern in WORKSTATION_PATH_PATTERNS:
        if pattern.search(content):
            fail(f"{location}: absolute workstation path present")


def scan_member(artifact: Path, name: str, content: bytes) -> None:
    parts = set(PurePosixPath(name).parts)
    if parts & FORBIDDEN_ARTIFACT_PARTS or name.endswith((".pyc", ".pyo")):
        fail(f"{artifact}: forbidden member {name}")
    if ".gitignore" in parts and not artifact.name.endswith(".tar.gz"):
        fail(f"{artifact}: forbidden member {name}")
    scan_content(f"{artifact}:{name}", content)


def one_artifact(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        fail(f"{directory}: expected one {pattern} artifact, found {len(matches)}")
    return matches[0]


def verify_dist_entries(directory: Path, expected: set[Path]) -> None:
    if directory.is_symlink() or not directory.is_dir():
        fail(f"{directory}: dist must be a real directory")
    entries = set(directory.iterdir())
    if entries != expected:
        names = ", ".join(sorted(path.name for path in entries ^ expected))
        fail(f"{directory}: unexpected or missing dist entries: {names}")
    for path in entries:
        if path.is_symlink() or not path.is_file():
            fail(f"{directory}: dist entry must be a regular file: {path.name}")


def metadata_from_wheel(path: Path) -> Message:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            fail(f"{path}: expected one METADATA file")
        return email.parser.BytesParser().parsebytes(archive.read(names[0]))


def requirement_covers_major(requirement: str, package: str, major: int) -> bool:
    normalized = requirement.replace(" ", "")
    match = re.fullmatch(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<specifiers>[<>=!~].*)", normalized)
    if match is None or match.group("name") != package:
        return False
    specifiers = set(match.group("specifiers").split(","))
    return {f">={major}.0", f"<{major + 1}.0"}.issubset(specifiers)


def verify_python_package(directory: Path, expected_name: str, *, cli: bool = False) -> None:
    project = python_project(directory / "pyproject.toml")
    version = project["version"]
    wheel = one_artifact(directory / "dist", f"{expected_name.replace('-', '_')}-{version}-*.whl")
    sdist = one_artifact(directory / "dist", f"{expected_name.replace('-', '_')}-{version}.tar.gz")
    verify_dist_entries(directory / "dist", {wheel, sdist})
    wheel_names: set[str] = set()
    for artifact in (wheel, sdist):
        for name, content in archive_members(artifact):
            scan_member(artifact, name, content)
            if artifact == wheel:
                wheel_names.add(name)
    metadata = metadata_from_wheel(wheel)
    if metadata["Name"] != expected_name or metadata["Version"] != version:
        fail(f"{wheel}: core metadata does not match {expected_name} {version}")
    if metadata["License-Expression"] != "Apache-2.0":
        fail(f"{wheel}: expected Apache-2.0 license expression")
    repository = "https://github.com/crimson-crawler/ccc" if cli else "https://github.com/crimson-crawler/python-sdk"
    if repository not in "\n".join(metadata.get_all("Project-URL", [])):
        fail(f"{wheel}: public repository URL missing")
    if not any(name.endswith("/py.typed") for name in wheel_names):
        fail(f"{wheel}: py.typed marker missing")
    if not any("licenses/LICENSE" in name or name.endswith("/LICENSE") for name in wheel_names):
        fail(f"{wheel}: Apache license file missing")
    # Apache-2.0 section 4(d) requires a redistributed NOTICE to travel with the
    # artifact. Both Python packages carry it via PEP 639 `license-files`, which
    # hatchling resolves silently -- a glob that matches nothing is not an error,
    # so dropping the entry produces a package that builds green and violates the
    # license. This assertion is the only thing that would catch that.
    if not any("licenses/NOTICE" in name or name.endswith("/NOTICE") for name in wheel_names):
        fail(f"{wheel}: Apache NOTICE file missing")
    if cli:
        dependency_name = "crimson-crawler-client"
        declared = next((item for item in project.get("dependencies", []) if item.startswith(dependency_name)), "")
        built = [
            item for item in metadata.get_all("Requires-Dist", []) if item.replace(" ", "").startswith(dependency_name)
        ]
        major = int(version.partition(".")[0])
        if (
            len(built) != 1
            or not requirement_covers_major(declared, dependency_name, major)
            or not requirement_covers_major(built[0], dependency_name, major)
        ):
            fail(f"{wheel}: CLI does not require the co-released {major}.x SDK")


def export_condition_targets(value: object, path: str = "") -> Iterator[tuple[str, str]]:
    """Every (condition path, target) pair under one exports entry.

    Conditions nest once types are resolved per format — `{"require": {"types": ..., "default": ...}}` —
    so a flat walk would treat the inner object as a target and miss the real files.
    """
    if isinstance(value, str):
        yield path or "default", value
    elif isinstance(value, dict):
        for condition, child in value.items():
            yield from export_condition_targets(child, f"{path}.{condition}" if path else condition)


def verify_npm_package(directory: Path) -> None:
    manifest = json.loads((directory / "package.json").read_text())
    version = manifest["version"]
    tarball = one_artifact(directory / "dist", f"crimson-crawler-crimson-crawler-client-{version}.tgz")
    verify_dist_entries(directory / "dist", {tarball})
    members = dict(archive_members(tarball))
    for name, content in members.items():
        scan_member(tarball, name, content)
        if name.endswith(".map"):
            fail(f"{tarball}: source map shipped ({name})")
    package = json.loads(members["package/package.json"])
    if package.get("name") != "@crimson-crawler/crimson-crawler-client" or package.get("version") != version:
        fail(f"{tarball}: npm package identity does not match manifest")
    if package["license"] != "Apache-2.0" or package.get("publishConfig", {}).get("access") != "public":
        fail(f"{tarball}: npm license/access is not public Apache-2.0")
    repository = package.get("repository", {})
    if repository.get("url", "").removeprefix("git+") != "https://github.com/crimson-crawler/typescript-sdk.git":
        fail(f"{tarball}: public repository URL missing")
    for lifecycle in ("preinstall", "install", "postinstall", "prepare"):
        if lifecycle in package.get("scripts", {}):
            fail(f"{tarball}: consumer lifecycle hook {lifecycle} is forbidden")
    for export_name, conditions in package["exports"].items():
        for condition, target in export_condition_targets(conditions):
            if f"package/{target.removeprefix('./')}" not in members:
                fail(f"{tarball}: export {export_name} {condition} target missing: {target}")
    if "package/LICENSE" not in members:
        fail(f"{tarball}: Apache license file missing")
    # Same section 4(d) requirement as the wheels. npm has no `license-files`
    # equivalent: inclusion depends entirely on the `files` allowlist, so an
    # omission here is invisible until someone inspects a published tarball.
    if "package/NOTICE" not in members:
        fail(f"{tarball}: Apache NOTICE file missing")


def verify_brand_asset_digests(directory: Path, kind: str) -> None:
    expected = {
        "assets/spider.png": CANONICAL_SPIDER_SHA256,
        "assets/crimson-crawler-logo.svg": CANONICAL_WORDMARK_SHA256[kind],
    }
    for relative, digest in expected.items():
        path = directory / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            fail(f"{directory}: canonical brand asset content mismatch: {relative}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--py-only", action="store_true")
    parser.add_argument("--ts-only", action="store_true")
    parser.add_argument("--cli-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    selected = sum((args.py_only, args.ts_only, args.cli_only))
    if selected > 1:
        fail("artifact filters are mutually exclusive")
    if args.py_only or selected == 0:
        verify_python_package(ROOT, "crimson-crawler-client")
        verify_brand_asset_digests(ROOT, "python")
    if args.ts_only or selected == 0:
        verify_npm_package(ROOT)
        verify_brand_asset_digests(ROOT, "typescript")
    if args.cli_only or selected == 0:
        verify_python_package(ROOT, "crimson-crawler-cli", cli=True)
        verify_brand_asset_digests(ROOT, "cli")
    print("Client release input verified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
