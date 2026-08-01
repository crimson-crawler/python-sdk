"""Regenerate the committed Python client from ``openapi.snapshot.json``.

Run from the package root:
    uv run python scripts/codegen.py

The snapshot ships with the source export, so regeneration never imports the
private server package.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

CLIENT_DIR = Path(__file__).resolve().parent.parent
GENERATED_DIR = CLIENT_DIR / "src" / "crimson_crawler_client" / "_generated"
CONFIG_FILE = CLIENT_DIR / "openapi_python_client_config.yaml"
SNAPSHOT = Path.cwd() / "openapi.snapshot.json"


def _load_snapshot() -> dict:
    if not SNAPSHOT.exists():
        raise SystemExit(f"Snapshot {SNAPSHOT} is missing.")
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


# openapi-python-client emits both client classes as plain attrs ``@define``
# classes, so every field lands in the generated ``__repr__``. ``token`` holds
# the API key (the wrapper passes it as ``token=`` with ``auth_header_name=
# "apikey"``), and ``_headers`` holds whatever auth material a caller supplies
# directly, so ``repr(client.api)`` would print live credentials — including
# inside any traceback that renders locals. The generator has no option for
# this, so patch its output here rather than asking callers to remember.
#
# Each entry must match exactly ``count`` times. A generator upgrade that
# reshapes these declarations fails the build instead of silently dropping the
# redaction, which is the failure mode that matters: nobody reads a diff of
# generated code closely enough to notice a missing ``repr=False``.
_REPR_REDACTIONS: tuple[tuple[str, str, int], ...] = (
    (
        "    token: str\n",
        "    token: str = field(repr=False)\n",
        1,
    ),
    (
        '    _headers: dict[str, str] = field(factory=dict, kw_only=True, alias="headers")\n',
        '    _headers: dict[str, str] = field(factory=dict, kw_only=True, alias="headers", repr=False)\n',
        2,
    ),
)


# The generator authenticates by writing the key into ``_headers``, which httpx
# then keeps on the persistent ``Client``/``AsyncClient``. ``httpx.Headers``
# redacts only ``authorization``/``proxy-authorization``, so with our ``apikey``
# header ``repr(client.api.get_async_httpx_client().headers)`` printed the live
# key. Rewrite both accessors to authenticate per request instead, via the
# hand-written ``ApiKeyAuth`` in ``crimson_crawler_client._auth``.
#
# ``_headers`` is left alone: a caller may still pass their own headers through
# ``headers=`` and expect them on the client.
_HEADER_AUTH_IMPORT: tuple[str, str, int] = (
    "import httpx\nfrom attrs import define, evolve, field\n",
    "import httpx\nfrom attrs import define, evolve, field\n\nfrom .._auth import ApiKeyAuth\n",
    1,
)

_HEADER_AUTH_REWRITES: tuple[tuple[str, str, int], ...] = (
    (
        "            self._headers[self.auth_header_name] = "
        'f"{self.prefix} {self.token}" if self.prefix else self.token\n'
        "            self._client = httpx.Client(\n",
        "            self._client = httpx.Client(\n"
        "                auth=ApiKeyAuth(self.auth_header_name, self.prefix, self.token, self._base_url),\n",
        1,
    ),
    (
        "            self._headers[self.auth_header_name] = "
        'f"{self.prefix} {self.token}" if self.prefix else self.token\n'
        "            self._async_client = httpx.AsyncClient(\n",
        "            self._async_client = httpx.AsyncClient(\n"
        "                auth=ApiKeyAuth(self.auth_header_name, self.prefix, self.token, self._base_url),\n",
        1,
    ),
)


def _apply(source: str, target: Path, patches: tuple[tuple[str, str, int], ...]) -> str:
    for old, new, count in patches:
        found = source.count(old)
        if found != count:
            raise SystemExit(
                f"codegen: expected {count} occurrence(s) of {old.strip()[:60]!r} in "
                f"{target.relative_to(CLIENT_DIR)}, found {found}. The generator's "
                "output shape changed - re-point the credential patch before shipping, "
                "or the published client will disclose API keys."
            )
        source = source.replace(old, new)
    return source


def _redact_credentials_in_repr() -> None:
    """Keep the generated clients from disclosing credentials via ``repr`` or headers."""
    target = GENERATED_DIR / "client.py"
    source = target.read_text(encoding="utf-8")
    original = source

    # Each group is guarded independently so adding one later still applies to a
    # tree that already carries the others.
    if "repr=False" not in source:
        source = _apply(source, target, _REPR_REDACTIONS)
    if "ApiKeyAuth" not in source:
        source = _apply(source, target, (_HEADER_AUTH_IMPORT, *_HEADER_AUTH_REWRITES))

    if source != original:
        target.write_text(source, encoding="utf-8")


def main() -> int:
    snapshot = _load_snapshot()

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(snapshot, handle)
        schema_path = Path(handle.name)

    try:
        if GENERATED_DIR.exists():
            shutil.rmtree(GENERATED_DIR)

        subprocess.check_call(
            [
                "uv",
                "sync",
                "--locked",
                "--project",
                str(CLIENT_DIR),
                "--extra",
                "dev",
                "--no-install-project",
            ],
            cwd=CLIENT_DIR,
        )

        cmd = [
            "uv",
            "run",
            "--locked",
            "--project",
            str(CLIENT_DIR),
            "--no-sync",
            "python",
            "-m",
            "openapi_python_client",
            "generate",
            "--path",
            str(schema_path),
            "--output-path",
            str(GENERATED_DIR),
            "--meta",
            "none",
            "--config",
            str(CONFIG_FILE),
            "--overwrite",
        ]
        print(f"Running: {' '.join(cmd)}")
        subprocess.check_call(cmd, cwd=CLIENT_DIR)
        _redact_credentials_in_repr()
    finally:
        schema_path.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
