"""Environment check: what is there, what is missing and how to fix it.

Each check says whether what is missing is blocking (no engine that needs it
can run) or a warning (something optional, or out of date).
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

OK, WARN, MISSING = "ok", "warning", "missing"
EXT_PACK = REPO_ROOT / "runners" / "codeql-ext" / "qlpack.yml"


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # ok | warning | missing
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
        return Check("semgrep", MISSING, "not on PATH", "uv sync")
    completed = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
    return Check("semgrep", OK, completed.stdout.strip() or "unknown version")


def check_semgrep_rules() -> Check:
    provenance = _read_json(fetch_rules.DEFAULT_DEST / fetch_rules.PROVENANCE)
    fix = "uv run python -m scripts.fetch_rules"
    if not provenance:
        return Check("semgrep rules", MISSING, f"no rules in {fetch_rules.DEFAULT_DEST}", fix)
    commit = provenance.get("commit", "?")
    detail = f"{fetch_rules.RULES_REPO}@{commit[:12]} · {provenance.get('rule_files', '?')} files"
    if commit != fetch_rules.RULES_COMMIT:
        return Check(
            "semgrep rules",
            WARN,
            f"{detail}; the pin is {fetch_rules.RULES_COMMIT[:12]}",
            fix,
        )
    return Check("semgrep rules", OK, detail)


def check_codeql() -> Check:
    binary = fetch_codeql.DEFAULT_DEST / "codeql"
    fix = "uv run python -m scripts.fetch_codeql"
    if not binary.is_file():
        return Check("CodeQL CLI", MISSING, f"not at {binary}", fix)
    provenance = _read_json(fetch_codeql.DEFAULT_DEST / fetch_codeql.PROVENANCE)
    tag = provenance.get("tag", "?")
    detail = f"{codeql_version(binary)} · {tag}"
    if tag != fetch_codeql.BUNDLE_TAG:
        return Check("CodeQL CLI", WARN, f"{detail}; the pin is {fetch_codeql.BUNDLE_TAG}", fix)
    return Check("CodeQL CLI", OK, detail)


def check_codeql_ext() -> Check:
    if EXT_PACK.is_file():
        return Check("codeql+ext extension", OK, str(EXT_PACK.parent.relative_to(REPO_ROOT)))
    return Check(
        "codeql+ext extension",
        WARN,
        "the qlpack is missing; `run --codeql-ext` will not work",
        "git checkout -- runners/codeql-ext",
    )


def check_cache() -> Check:
    if not CACHE_DIR.is_dir():
        return Check("CodeQL cache", OK, "empty; the first run fills it")
    bases = [p for p in CACHE_DIR.iterdir() if (p / "codeql-database.yml").is_file()]
    size = sum(f.stat().st_size for f in CACHE_DIR.rglob("*") if f.is_file())
    return Check("CodeQL cache", OK, f"{len(bases)} databases · {size / 1e6:.0f} MB in {CACHE_DIR.relative_to(REPO_ROOT)}")


def check_api_key() -> Check:
    load_dotenv(REPO_ROOT / ".env")
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    fix = "cp .env.example .env and fill in ANTHROPIC_API_KEY (or `ant auth login`)"
    if key and not key.endswith("..."):
        return Check("API key", OK, "ANTHROPIC_API_KEY loaded; only the hybrid uses it")
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return Check("API key", OK, "ANTHROPIC_AUTH_TOKEN loaded; only the hybrid uses it")
    detail = "ANTHROPIC_API_KEY is the placeholder" if key else "no ANTHROPIC_API_KEY"
    return Check("API key", WARN, f"{detail}; the hybrid will not run", fix)


def check_corpus(corpus: Path) -> Check:
    cases, problems = validate(corpus)
    if problems:
        return Check(
            "corpus", MISSING, f"{len(cases)} cases, {len(problems)} problems", "sast-bench corpus validate"
        )
    return Check("corpus", OK, f"{len(cases)} valid pairs in {corpus}")


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
