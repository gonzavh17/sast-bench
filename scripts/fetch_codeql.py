#!/usr/bin/env python3
"""Download the CodeQL bundle (CLI + precompiled JS/TS packs) into a local directory.

The CodeQL CLI is NOT open source: it is used under the "GitHub CodeQL Terms and
Conditions", which allow analyzing an "Open Source Codebase" (a codebase
released under an OSI-approved license), testing OSI queries and doing academic
research, but *forbid redistributing the CLI*. So the bundle is not committed:
the exact tag (BUNDLE_TAG) is versioned and this script downloads it.

This repo is MIT-licensed, so the corpus qualifies as an Open Source Codebase.

    https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md

The queries (github/codeql) are MIT and could be redistributed; they ship
inside the bundle anyway, which cannot.
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
    """Extract the bundle into `dest`. Idempotent: replaces whatever is there."""
    url = f"https://github.com/{BUNDLE_REPO}/releases/download/{tag}/{BUNDLE_ASSET}"
    print(f"downloading {url}")
    with urllib.request.urlopen(url) as response:  # noqa: S310 - fixed URL
        blob = zstd.decompress(response.read())

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    # The tar has everything under `codeql/`; it is flattened so the binary
    # ends up at `dest/codeql` and not `dest/codeql/codeql`.
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tar:
        tar.extractall(dest.parent, filter="tar")

    binary = dest / "codeql"
    if not binary.is_file():
        raise RuntimeError(f"the bundle left no executable at {binary}")
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
                "license": "GitHub CodeQL Terms - Open Source Codebase only, no redistribution",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"bundle {tag} in {dest}")
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument("--tag", default=BUNDLE_TAG)
    args = parser.parse_args()
    fetch(args.dest, args.tag)


if __name__ == "__main__":
    main()
