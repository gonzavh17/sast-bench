#!/usr/bin/env python3
"""Baja el bundle de CodeQL (CLI + packs de JS/TS precompilados) a una carpeta local.

La CLI de CodeQL NO es open source: se usa bajo los "GitHub CodeQL Terms and
Conditions", que permiten analizar un "Open Source Codebase" (un codebase
publicado bajo licencia aprobada por la OSI), testear queries OSI y hacer
academic research, pero *prohiben redistribuir la CLI*. Por eso el bundle no se
commitea: se versiona la etiqueta exacta (BUNDLE_TAG) y este script lo baja.

Este repo esta bajo MIT, asi que el corpus califica como Open Source Codebase.

    https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md

Las queries (github/codeql) son MIT y si podrian redistribuirse; igual viajan
dentro del bundle, que no.
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import shutil
import tarfile
import urllib.request
from compression import zstd
from pathlib import Path

BUNDLE_REPO = "github/codeql-action"
BUNDLE_TAG = "codeql-bundle-v2.27.1"
BUNDLE_ASSET = "codeql-bundle-javascript-linux64.tar.zst"
LANGUAGE = "javascript-typescript"
SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEST = REPO_ROOT / "runners" / "tools" / "codeql"
PROVENANCE = ".provenance.json"


def fetch(dest: Path, tag: str = BUNDLE_TAG) -> Path:
    """Extrae el bundle en `dest`. Idempotente: reemplaza lo que haya."""
    url = f"https://github.com/{BUNDLE_REPO}/releases/download/{tag}/{BUNDLE_ASSET}"
    print(f"bajando {url}")
    with urllib.request.urlopen(url) as response:  # noqa: S310 - URL fija
        blob = zstd.decompress(response.read())

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    # El tar trae todo bajo `codeql/`; se aplana para que el binario quede en
    # `dest/codeql` y no en `dest/codeql/codeql`.
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tar:
        tar.extractall(dest.parent, filter="tar")

    binary = dest / "codeql"
    if not binary.is_file():
        raise RuntimeError(f"el bundle no dejo un ejecutable en {binary}")
    binary.chmod(0o755)

    (dest / PROVENANCE).write_text(
        json.dumps(
            {
                "repo": BUNDLE_REPO,
                "tag": tag,
                "asset": BUNDLE_ASSET,
                "language": LANGUAGE,
                "suite": SUITE,
                "fetched_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                "license": "GitHub CodeQL Terms - solo sobre Open Source Codebase, sin redistribuir",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"bundle {tag} en {dest}")
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument("--tag", default=BUNDLE_TAG)
    args = parser.parse_args()
    fetch(args.dest, args.tag)


if __name__ == "__main__":
    main()
