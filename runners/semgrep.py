"""Run Semgrep over the corpus, one scan per variant.

One scan per variant avoids attributing findings by path prefix and guarantees
that neither twin contaminates the other.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

from scoring.console import log_event, make_console, progress_bar
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
        raise RuntimeError(f"semgrep returned no JSON for {variant_dir}:\n{completed.stderr}")
    payload = json.loads(completed.stdout)
    if payload.get("errors"):
        print(f"  warning: semgrep reported {len(payload['errors'])} errors in {variant_dir}")
    return [f.model_dump() for f in from_semgrep(payload, variant_dir)]


def rules_provenance(rules: Path) -> dict[str, Any]:
    """Where the rules came from, so the result says what it was measured against."""
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


def scan(cases: list[Case], rules: Path, console: Console) -> dict[str, Any]:
    variants: list[dict[str, Any]] = []
    todo = [(case, label) for case in cases for label in VARIANT_LABELS]
    with progress_bar(console) as bar:
        task = bar.add_task("scanning", total=len(todo))
        for case, label in todo:
            variant_dir = case.variant_dir(label)
            bar.update(task, description=f"{case.meta.id} {label}")
            findings = run_variant(variant_dir, rules)
            log_event(
                console, "semgrep", f"{case.meta.id} {label:10} {len(findings)} findings"
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
        help="rules directory; point it elsewhere to run your own rules",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if not (args.rules / PROVENANCE).exists() and args.rules.resolve() == DEFAULT_DEST.resolve():
        parser.error("the official rules are missing; run scripts/fetch_rules.py first")

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no meta.yaml found under {args.corpus}")
    console = make_console()
    log_event(console, "semgrep", f"{len(cases)} cases in {args.corpus}")

    report = scan(cases, args.rules, console)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    log_event(console, "semgrep", f"wrote {args.out}")


if __name__ == "__main__":
    main()
