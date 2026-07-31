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
    finally:
        schema_path.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
