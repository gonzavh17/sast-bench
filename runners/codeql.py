"""Corre CodeQL sobre el corpus, una base de datos por variante.

Misma logica que el runner de Semgrep: una corrida por variante, para que
ningun gemelo contamine al otro y no haya que atribuir hallazgos por prefijo
de ruta. La diferencia es que CodeQL necesita construir una base por cada una,
lo que lo hace bastante mas lento.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console

from scoring.console import log_event, make_console, progress_bar
from scoring.models import VARIANT_LABELS, Case, discover_cases
from scoring.normalize import from_codeql
from scripts.fetch_codeql import (
    BUNDLE_REPO,
    BUNDLE_TAG,
    DEFAULT_DEST,
    LANGUAGE,
    PROVENANCE,
    SUITE,
)


def run_variant(variant_dir: Path, binary: Path, suite: str) -> list[dict[str, Any]]:
    """Construye la base de la variante, la analiza y devuelve Findings."""
    with tempfile.TemporaryDirectory(prefix="codeql-") as tmp:
        database = Path(tmp) / "db"
        sarif = Path(tmp) / "results.sarif"

        _run(
            [
                str(binary),
                "database",
                "create",
                str(database),
                f"--language={LANGUAGE}",
                f"--source-root={variant_dir}",
                "--overwrite",
                "--quiet",
            ],
            f"crear la base de {variant_dir}",
        )
        _run(
            [
                str(binary),
                "database",
                "analyze",
                str(database),
                suite,
                "--format=sarif-latest",
                f"--output={sarif}",
                "--threads=0",
                "--quiet",
            ],
            f"analizar {variant_dir}",
        )

        payload = json.loads(sarif.read_text(encoding="utf-8"))
        return [f.model_dump() for f in from_codeql(payload)]


def _run(command: list[str], what: str) -> None:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"codeql fallo al {what}:\n{completed.stderr.strip()}")


def bundle_provenance(bundle: Path, suite: str) -> dict[str, Any]:
    """De donde salio el bundle, para que el resultado diga contra que se midio."""
    if bundle.resolve() == DEFAULT_DEST.resolve():
        recorded = json.loads((bundle / PROVENANCE).read_text(encoding="utf-8"))
        return {
            "kind": "bundle",
            "bundle": f"{BUNDLE_REPO}@{recorded.get('tag', BUNDLE_TAG)}",
            "suite": suite,
            "fetched_at": recorded.get("fetched_at"),
        }
    return {"kind": "custom", "path": str(bundle)}


def codeql_version(binary: Path) -> str:
    completed = subprocess.run(
        [str(binary), "version", "--format=terse"], capture_output=True, text=True, check=False
    )
    return completed.stdout.strip() or "unknown"


def scan(
    cases: list[Case], bundle: Path, suite: str, console: Console, tool: str = "codeql"
) -> dict[str, Any]:
    binary = bundle / "codeql"
    variants: list[dict[str, Any]] = []
    todo = [(case, label) for case in cases for label in VARIANT_LABELS]
    with progress_bar(console) as bar:
        task = bar.add_task("construyendo bases", total=len(todo))
        for case, label in todo:
            variant_dir = case.variant_dir(label)
            bar.update(task, description=f"{case.meta.id} {label}")
            findings = run_variant(variant_dir, binary, suite)
            log_event(
                console, "codeql", f"{case.meta.id} {label:10} {len(findings)} hallazgos"
            )
            bar.advance(task)
            variants.append(
                {
                    "case_id": case.meta.id,
                    "case_dir": str(case.directory),
                    "variant": label,
                    "findings": findings,
                }
            )
    report: dict[str, Any] = {
        "tool": tool,
        "tool_version": codeql_version(binary),
        "run_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "rules": bundle_provenance(bundle, suite),
        "variants": variants,
    }
    if tool != "codeql":
        # Misma herramienta con otra suite: los rule_id siguen siendo de CodeQL.
        report["rule_map"] = "codeql"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=DEFAULT_DEST,
        help="carpeta del bundle; apuntala a otra para correr otra version",
    )
    parser.add_argument("--suite", default=SUITE, help="suite de queries a correr")
    parser.add_argument(
        "--tool",
        default="codeql",
        help="nombre de la fila en los reportes; p. ej. codeql+ext con la suite extendida",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if not (args.bundle / "codeql").is_file():
        parser.error(f"falta el bundle en {args.bundle}; corre primero scripts/fetch_codeql.py")

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no se encontro ningun meta.yaml bajo {args.corpus}")
    console = make_console()
    log_event(console, "codeql", f"{len(cases)} casos en {args.corpus}")

    report = scan(cases, args.bundle, args.suite, console, args.tool)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    log_event(console, "codeql", f"escrito {args.out}")


if __name__ == "__main__":
    main()
