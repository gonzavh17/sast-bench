"""Chequeo del entorno: que hay, que falta y como se arregla.

Cada chequeo dice si lo que falta es bloqueante (sin eso no corre ningun engine
que lo use) o un aviso (algo opcional, o desactualizado).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from runners.codeql import CACHE_DIR, codeql_version
from sast_bench.corpus import validate
from scripts import fetch_codeql, fetch_rules
from scripts.fetch_codeql import REPO_ROOT

OK, WARN, MISSING = "ok", "aviso", "falta"
EXT_PACK = REPO_ROOT / "runners" / "codeql-ext" / "qlpack.yml"


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # ok | aviso | falta
    detail: str
    fix: str = ""


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def check_semgrep() -> Check:
    binary = shutil.which("semgrep")
    if binary is None:
        return Check("semgrep", MISSING, "no esta en el PATH", "uv sync")
    completed = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
    return Check("semgrep", OK, completed.stdout.strip() or "version desconocida")


def check_semgrep_rules() -> Check:
    provenance = _read_json(fetch_rules.DEFAULT_DEST / fetch_rules.PROVENANCE)
    fix = "uv run python -m scripts.fetch_rules"
    if not provenance:
        return Check("reglas de semgrep", MISSING, f"no hay reglas en {fetch_rules.DEFAULT_DEST}", fix)
    commit = provenance.get("commit", "?")
    detail = f"{fetch_rules.RULES_REPO}@{commit[:12]} · {provenance.get('rule_files', '?')} archivos"
    if commit != fetch_rules.RULES_COMMIT:
        return Check(
            "reglas de semgrep",
            WARN,
            f"{detail}; el pin es {fetch_rules.RULES_COMMIT[:12]}",
            fix,
        )
    return Check("reglas de semgrep", OK, detail)


def check_codeql() -> Check:
    binary = fetch_codeql.DEFAULT_DEST / "codeql"
    fix = "uv run python -m scripts.fetch_codeql"
    if not binary.is_file():
        return Check("CLI de CodeQL", MISSING, f"no esta en {binary}", fix)
    provenance = _read_json(fetch_codeql.DEFAULT_DEST / fetch_codeql.PROVENANCE)
    tag = provenance.get("tag", "?")
    detail = f"{codeql_version(binary)} · {tag}"
    if tag != fetch_codeql.BUNDLE_TAG:
        return Check("CLI de CodeQL", WARN, f"{detail}; el pin es {fetch_codeql.BUNDLE_TAG}", fix)
    return Check("CLI de CodeQL", OK, detail)


def check_codeql_ext() -> Check:
    if EXT_PACK.is_file():
        return Check("extension codeql+ext", OK, str(EXT_PACK.parent.relative_to(REPO_ROOT)))
    return Check(
        "extension codeql+ext",
        WARN,
        "no esta el qlpack; `run --codeql-ext` no va a andar",
        "git checkout -- runners/codeql-ext",
    )


def check_cache() -> Check:
    if not CACHE_DIR.is_dir():
        return Check("cache de CodeQL", OK, "vacia; se llena con la primera corrida")
    bases = [p for p in CACHE_DIR.iterdir() if (p / "codeql-database.yml").is_file()]
    size = sum(f.stat().st_size for f in CACHE_DIR.rglob("*") if f.is_file())
    return Check("cache de CodeQL", OK, f"{len(bases)} bases · {size / 1e6:.0f} MB en {CACHE_DIR.relative_to(REPO_ROOT)}")


def check_api_key() -> Check:
    load_dotenv(REPO_ROOT / ".env")
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    fix = "cp .env.example .env y completar ANTHROPIC_API_KEY (o `ant auth login`)"
    if key and not key.endswith("..."):
        return Check("clave de API", OK, "ANTHROPIC_API_KEY cargada; solo la usa el hibrido")
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return Check("clave de API", OK, "ANTHROPIC_AUTH_TOKEN cargado; solo lo usa el hibrido")
    detail = "ANTHROPIC_API_KEY es el placeholder" if key else "no hay ANTHROPIC_API_KEY"
    return Check("clave de API", WARN, f"{detail}; el hibrido no va a correr", fix)


def check_corpus(corpus: Path) -> Check:
    cases, problems = validate(corpus)
    if problems:
        return Check(
            "corpus", MISSING, f"{len(cases)} casos, {len(problems)} problemas", "sast-bench corpus validate"
        )
    return Check("corpus", OK, f"{len(cases)} pares validos en {corpus}")


def run_checks(corpus: Path) -> list[Check]:
    return [
        check_semgrep(),
        check_semgrep_rules(),
        check_codeql(),
        check_codeql_ext(),
        check_cache(),
        check_api_key(),
        check_corpus(corpus),
    ]
