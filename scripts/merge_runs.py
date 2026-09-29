#!/usr/bin/env python3
"""Combine a base results file with a later re-run of some of its cases.

When a few cases are fixed and re-run, the table for the family needs the
base run for the untouched cases and the re-run for the fixed ones. This
writes that combination, in the usual results format, so every number in the
README can be traced to files in the repo:

    uv run python -m scripts.merge_runs \\
        --base results/runs/<old>/codeql.json \\
        --override results/runs/<new>/codeql.json \\
        --family broken-authorization \\
        --out results/merged/broken-authorization-codeql.json

Only the `variants` change. Everything else comes from the override, the most
recent run, and the sources are listed next to the output in a .sources.txt.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def merge(base: dict[str, Any], override: dict[str, Any], family: str | None) -> dict[str, Any]:
    if base["tool"] != override["tool"]:
        raise ValueError(f"different tools: {base['tool']} and {override['tool']}")
    replaced = {entry["case_id"] for entry in override["variants"]}
    kept = [
        entry
        for entry in base["variants"]
        if entry["case_id"] not in replaced and (family is None or f"/{family}/" in entry["case_dir"])
    ]
    variants = sorted(kept + override["variants"], key=lambda e: (e["case_id"], e["variant"]))
    return {**override, "variants": variants}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--override", type=Path, required=True)
    parser.add_argument("--family", help="keep only this family's cases from the base")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    base = json.loads(args.base.read_text(encoding="utf-8"))
    override = json.loads(args.override.read_text(encoding="utf-8"))
    merged = merge(base, override, args.family)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    replaced = sorted({e["case_id"] for e in override["variants"]})
    args.out.with_suffix(".sources.txt").write_text(
        f"base:     {args.base}\noverride: {args.override}\nreplaced: {', '.join(replaced)}\n",
        encoding="utf-8",
    )
    print(f"wrote {args.out} ({len(merged['variants']) // 2} pairs, {len(replaced)} from the override)")


if __name__ == "__main__":
    main()
