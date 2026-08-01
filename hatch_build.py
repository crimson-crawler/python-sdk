"""Custom Hatch hooks for validating the generated tree and packaging README metadata.

`_generated/` is gitignored in the monorepo and produced by codegen; the published
export and every sdist/wheel carry it so consumers get a self-contained archive.
The guard blocks a build that would otherwise ship an importable-but-empty package
— an incomplete archive, an accidental removal, or a monorepo build run before
codegen.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.metadata.plugin.interface import MetadataHookInterface


class GeneratedTreeGuard(BuildHookInterface):
    """Block builds when the codegen output is missing."""

    PLUGIN_NAME = "generated-tree-guard"

    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ARG002
        sentinel = Path(self.root) / "src" / "crimson_crawler_client" / "_generated" / "__init__.py"
        if not sentinel.exists():
            raise SystemExit(
                "crimson-crawler-client: _generated/ tree is missing. Regenerate it from "
                "openapi.snapshot.json (../scripts/regenerate_clients.sh, or "
                "scripts/codegen.py in a public checkout) before building."
            )


class PackagedReadmeUrls(MetadataHookInterface):
    """Point the packaged README's brand images at absolute URLs.

    The README in the repository references the art the tree ships (`assets/...`), so a repository
    renders its own header with nothing deployed. PyPI renders that same README standalone, with no
    repository for a relative path to resolve against, and it does not rewrite them. So the packaged
    metadata gets absolute URLs while the file on disk stays relative. Nothing is mutated; each
    surface gets the form that works there.

    `readme` is declared `dynamic` in pyproject.toml because PEP 621 only lets a hook supply a field
    that is not already static.
    """

    PLUGIN_NAME = "packaged-readme-urls"

    #: relative repository references -> absolute URLs for the packaged copy
    PACKAGED_URLS = {
        'src="assets/spider.png"': 'src="https://crimsoncrawler.com/logo-icon.png"',
        'src="assets/crimson-crawler-logo.svg"': ('src="https://crimsoncrawler.com/crimson-crawler-logo-python.svg"'),
        "[Apache License 2.0](LICENSE)": (
            "[Apache License 2.0](https://github.com/crimson-crawler/python-sdk/blob/main/LICENSE)"
        ),
    }

    @classmethod
    def rewrite(cls, text: str) -> str:
        for relative, absolute in cls.PACKAGED_URLS.items():
            text = text.replace(relative, absolute)
        return text

    def update(self, metadata: dict) -> None:
        readme = Path(self.root) / "README.md"
        if not readme.exists():
            return
        metadata["readme"] = {
            "content-type": "text/markdown",
            "text": self.rewrite(readme.read_text(encoding="utf-8")),
        }
