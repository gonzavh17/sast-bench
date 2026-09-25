"""Run CodeQL over the corpus, one database per variant.

Same logic as the Semgrep runner: one scan per variant, so neither twin
contaminates the other and findings need no attribution by path prefix. The
difference is that CodeQL has to build a database for each one, which makes it
much slower.

Databases are cached in .cache/codeql-db/, keyed by a hash of the variant's
content and the CodeQL version. If none of that changed, the database is
reused and only the analysis runs. `--no-cache` rebuilds everything.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
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
    REPO_ROOT,
    SUITE,
)

CACHE_DIR = REPO_ROOT / ".cache" / "codeql-db"


def variant_fingerprint(variant_dir: Path, version: str) -> str:
    """Cache key for a database: language, CodeQL version and every file.

    It hashes each file's relative path and content, not the variant's absolute
    path: moving the repo does not invalidate the cache, editing a file does.
    """
    digest = hashlib.sha256(f"{LANGUAGE}\0{version}\0".encode())
    for path in sorted(p for p in variant_dir.rglob("*") if p.is_file()):
        digest.update(path.relative_to(variant_dir).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()[:24]


def _create_database(database: Path, variant_dir: Path, binary: Path) -> None:
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
        f"create the database for {variant_dir}",
    )


def cached_database(
    variant_dir: Path, binary: Path, cache_dir: Path, version: str
) -> tuple[Path, bool]:
    """The variant's database, built or taken from the cache. The bool says whether it was a hit."""
    database = cache_dir / variant_fingerprint(variant_dir, version)
    if (database / "codeql-database.yml").is_file():
        return database, True
    # Built to the side and renamed at the end: a run cut halfway does not
    # leave an incomplete database that looks valid.
    staging = cache_dir / f"{database.name}.tmp"
    shutil.rmtree(staging, ignore_errors=True)
    shutil.rmtree(database, ignore_errors=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    _create_database(staging, variant_dir, binary)
    staging.rename(database)
    return database, False


def run_variant(
    variant_dir: Path,
    binary: Path,
    suite: str,
    *,
    cache_dir: Path | None = None,
    version: str = "",
) -> tuple[list[dict[str, Any]], bool]:
    """Analyze the variant and return (Findings, whether the database came from the cache)."""
    with tempfile.TemporaryDirectory(prefix="codeql-") as tmp:
        sarif = Path(tmp) / "results.sarif"
        if cache_dir is None:
            database, hit = Path(tmp) / "db", False
            _create_database(database, variant_dir, binary)
        else:
            database, hit = cached_database(variant_dir, binary, cache_dir, version)

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
            f"analyze {variant_dir}",
        )

        payload = json.loads(sarif.read_text(encoding="utf-8"))
        return [f.model_dump() for f in from_codeql(payload)], hit


def _run(command: list[str], what: str) -> None:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"codeql failed to {what}:\n{completed.stderr.strip()}")


def bundle_provenance(bundle: Path, suite: str) -> dict[str, Any]:
    """Where the bundle came from, so the result says what it was measured against."""
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
    cases: list[Case],
    bundle: Path,
    suite: str,
    console: Console,
    tool: str = "codeql",
    *,
    cache_dir: Path | None = None,
    stats: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Run CodeQL over the cases. `stats`, if given, collects cache hits and misses.

    The stats live outside the result on purpose: the results JSON keeps its
    format.
    """
    binary = bundle / "codeql"
    version = codeql_version(binary)
    if stats is not None:
        stats.setdefault("hits", 0)
        stats.setdefault("misses", 0)
    variants: list[dict[str, Any]] = []
    todo = [(case, label) for case in cases for label in VARIANT_LABELS]
    with progress_bar(console) as bar:
        task = bar.add_task("building databases", total=len(todo))
        for case, label in todo:
            variant_dir = case.variant_dir(label)
            bar.update(task, description=f"{case.meta.id} {label}")
            findings, hit = run_variant(
                variant_dir, binary, suite, cache_dir=cache_dir, version=version
            )
            if stats is not None:
                stats["hits" if hit else "misses"] += 1
            cached = " [dim](cached database)[/dim]" if hit else ""
            log_event(
                console, "codeql", f"{case.meta.id} {label:10} {len(findings)} findings{cached}"
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
        "tool_version": version,
        "run_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "rules": bundle_provenance(bundle, suite),
        "variants": variants,
    }
    if tool != "codeql":
        # Same tool with another suite: the rule_ids are still CodeQL's.
        report["rule_map"] = "codeql"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=DEFAULT_DEST,
        help="bundle directory; point it elsewhere to run another version",
    )
    parser.add_argument("--suite", default=SUITE, help="query suite to run")
    parser.add_argument(
        "--tool",
        default="codeql",
        help="row name in the reports, e.g. codeql+ext with the extended suite",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--no-cache", action="store_true", help="build every database even if it is cached"
    )
    args = parser.parse_args()

    if not (args.bundle / "codeql").is_file():
        parser.error(f"missing bundle at {args.bundle}; run scripts/fetch_codeql.py first")

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no meta.yaml found under {args.corpus}")
    console = make_console()
    log_event(console, "codeql", f"{len(cases)} cases in {args.corpus}")

    report = scan(
        cases,
        args.bundle,
        args.suite,
        console,
        args.tool,
        cache_dir=None if args.no_cache else CACHE_DIR,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    log_event(console, "codeql", f"wrote {args.out}")


if __name__ == "__main__":
    main()
