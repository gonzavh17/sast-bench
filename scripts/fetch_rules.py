#!/usr/bin/env python3
"""Baja las reglas oficiales de Semgrep a una carpeta local.

Las reglas estan bajo la Semgrep Rules License v1.0, que permite usarlas para
fines internos propios pero *prohibe redistribuirlas*. Por eso no se commitean:
lo que se versiona es el commit exacto (RULES_COMMIT), asi cualquiera reproduce
el mismo conjunto corriendo este script.

    https://semgrep.dev/legal/rules-license
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import shutil
import tarfile
import urllib.request
from pathlib import Path

RULES_REPO = "semgrep/semgrep-rules"
RULES_COMMIT = "40b8c63f75dc7c22c8a77482d73bfb864b146f7e"
RULES_PATHS = ("javascript", "typescript")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEST = REPO_ROOT / "runners" / "rules" / "semgrep"
PROVENANCE = ".provenance.json"


def fetch(dest: Path, commit: str = RULES_COMMIT) -> int:
    """Extrae los .yaml de RULES_PATHS en `dest`. Idempotente: reemplaza."""
    url = f"https://github.com/{RULES_REPO}/archive/{commit}.tar.gz"
    print(f"bajando {url}")
    with urllib.request.urlopen(url) as response:  # noqa: S310 - URL fija
        blob = response.read()

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    count = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            relative = _wanted(member.name)
            if relative is None or not member.isfile():
                continue
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            target.write_bytes(extracted.read())
            count += 1

    (dest / PROVENANCE).write_text(
        json.dumps(
            {
                "repo": RULES_REPO,
                "commit": commit,
                "paths": list(RULES_PATHS),
                "rule_files": count,
                "fetched_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                "license": "Semgrep Rules License v1.0 - uso local, sin redistribuir",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"{count} archivos de reglas en {dest}")
    return count


def _wanted(member_name: str) -> str | None:
    """`semgrep-rules-<sha>/javascript/.../x.yaml` -> `javascript/.../x.yaml`."""
    parts = Path(member_name).parts
    if len(parts) < 3 or parts[1] not in RULES_PATHS:
        return None
    if not member_name.endswith((".yaml", ".yml")):
        return None
    return str(Path(*parts[1:]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument("--commit", default=RULES_COMMIT)
    args = parser.parse_args()
    fetch(args.dest, args.commit)


if __name__ == "__main__":
    main()
