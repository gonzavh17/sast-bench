"""Corre Semgrep sobre el corpus, una corrida por variante.

Una corrida por variante evita tener que atribuir hallazgos por prefijo de ruta
y garantiza que ningun gemelo contamine al otro.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any

from scoring.models import VARIANT_LABELS, Case, discover_cases
from scoring.normalize import from_semgrep
from scripts.fetch_rules import (
    DEFAULT_DEST,
    PROVENANCE,
    RULES_COMMIT,
    RULES_PATHS,
    RULES_REPO,
)


def run_variant(variant_dir: Path, rules: Path) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            "semgrep",
            "--json",
            "--no-git-ignore",
            "--metrics=off",
            "--quiet",
            "--config",
            str(rules),
            str(variant_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if not completed.stdout.strip():
        raise RuntimeError(f"semgrep no devolvio JSON para {variant_dir}:\n{completed.stderr}")
    payload = json.loads(completed.stdout)
    if payload.get("errors"):
        print(f"  aviso: semgrep reporto {len(payload['errors'])} errores en {variant_dir}")
    return [f.model_dump() for f in from_semgrep(payload, variant_dir)]


def rules_provenance(rules: Path) -> dict[str, Any]:
    """De donde salieron las reglas, para que el resultado diga contra que se midio."""
    if rules.resolve() == DEFAULT_DEST.resolve():
        recorded = json.loads((rules / PROVENANCE).read_text(encoding="utf-8"))
        return {
            "kind": "official",
            "repo": RULES_REPO,
            "commit": recorded.get("commit", RULES_COMMIT),
            "paths": list(RULES_PATHS),
            "fetched_at": recorded.get("fetched_at"),
        }
    return {"kind": "custom", "path": str(rules)}


def semgrep_version() -> str:
    completed = subprocess.run(
        ["semgrep", "--version"], capture_output=True, text=True, check=False
    )
    return completed.stdout.strip() or "unknown"


def scan(cases: list[Case], rules: Path) -> dict[str, Any]:
    variants: list[dict[str, Any]] = []
    for case in cases:
        for label in VARIANT_LABELS:
            variant_dir = case.variant_dir(label)
            findings = run_variant(variant_dir, rules)
            print(f"  {case.meta.id} {label}: {len(findings)} hallazgos")
            variants.append(
                {
                    "case_id": case.meta.id,
                    "case_dir": str(case.directory),
                    "variant": label,
                    "findings": findings,
                }
            )
    return {
        "tool": "semgrep",
        "tool_version": semgrep_version(),
        "run_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "rules": rules_provenance(rules),
        "variants": variants,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_DEST,
        help="carpeta de reglas; apuntala a otra para correr reglas propias",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if not (args.rules / PROVENANCE).exists() and args.rules.resolve() == DEFAULT_DEST.resolve():
        parser.error("faltan las reglas oficiales; corre primero scripts/fetch_rules.py")

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no se encontro ningun meta.yaml bajo {args.corpus}")
    print(f"{len(cases)} casos en {args.corpus}")

    report = scan(cases, args.rules)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"escrito {args.out}")


if __name__ == "__main__":
    main()
