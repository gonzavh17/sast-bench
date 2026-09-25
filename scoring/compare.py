"""CLI: several results + corpus -> side-by-side table across tools.

`report.py` looks at one tool at a time. This one looks at several together,
which is what the benchmark question needs: not which scores higher, but
whether they measure the same thing. So besides each tool's headline it shows
the overlap: pairs both solve, pairs only one solves, and pairs none solves.

Each results.json says which tool it is (`tool`), and the rule_map is looked
up by convention in scoring/rule_map/<tool>.yaml.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scoring.console import (
    cases_table,
    export_svg,
    glossary,
    header,
    make_console,
    metrics_table,
)
from scoring.metrics import Score, tally
from scoring.models import Case, discover_cases, load_rule_map

RULE_MAP_DIR = Path(__file__).resolve().parent / "rule_map"

CELL = {True: "yes", False: "no"}


def load(results_path: Path, cases: list[Case], rule_map_dir: Path) -> tuple[str, dict, Score]:
    results = json.loads(results_path.read_text(encoding="utf-8"))
    tool = results["tool"]
    # A derived runner (the phase 3 filter) reuses the rule_map of its input:
    # filtering does not change rule_ids.
    rule_map_path = rule_map_dir / f"{results.get('rule_map', tool)}.yaml"
    if not rule_map_path.is_file():
        raise SystemExit(f"missing rule_map for {tool}: {rule_map_path}")
    return tool, results, tally(cases, results, load_rule_map(rule_map_path))


def render(runs: list[tuple[str, dict, Score]], cases: list[Case]) -> str:
    tools = [tool for tool, _, _ in runs]
    difficulties = {case.meta.id: case.meta.difficulty.value for case in cases}

    lines = [
        f"# Comparison — {', '.join(tools)}",
        "",
        "## Headline",
        "",
        "| tool | pair score | recall | FPR | precision | F1 | localization | noise |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for tool, results, score in runs:
        solved = sum(p.solved for p in score.pairs)
        lines.append(
            f"| `{tool} {results['tool_version']}` | "
            f"**{score.pair_score:.2f}** ({solved}/{len(score.pairs)}) | "
            f"{score.recall:.2f} | {score.fpr:.2f} | {score.precision:.2f} | "
            f"{score.f1:.2f} | {score.localization:.2f} | {score.noise:.2f} |"
        )

    lines += ["", "## Per pair", "", "| case | difficulty | " + " | ".join(tools) + " |"]
    lines.append("|---|---|" + "---|" * len(tools))

    solved_by: dict[str, set[str]] = {tool: set() for tool, _, _ in runs}
    by_case = {tool: {p.case_id: p for p in score.pairs} for tool, _, score in runs}

    for case_id in sorted(difficulties):
        row = [f"`{case_id}`", difficulties[case_id]]
        for tool in tools:
            pair = by_case[tool][case_id]
            if pair.solved:
                solved_by[tool].add(case_id)
            row.append(f"{pair.vulnerable.cell}/{pair.safe.cell} · {CELL[pair.solved]}")
        lines.append("| " + " | ".join(row) + " |")

    lines += ["", "## Overlap", ""]
    everyone = set.intersection(*solved_by.values()) if solved_by else set()
    union = set.union(*solved_by.values()) if solved_by else set()
    total = len(next(iter(by_case.values())))

    lines.append(f"- solved by **all**: {_ids(everyone)}")
    for tool in tools:
        only = solved_by[tool] - set.union(
            *[solved_by[other] for other in tools if other != tool]
        ) if len(tools) > 1 else solved_by[tool]
        lines.append(f"- only `{tool}`: {_ids(only)}")
    lines.append(f"- **solved by none**: {_ids(set(by_case[tools[0]]) - union)}")
    lines.append("")
    lines.append(
        f"Union = {len(union)}/{total} pairs ({len(union) / total:.2f}). "
        "That is the ceiling of running them all together."
    )

    return "\n".join(lines) + "\n"


def _ids(case_ids: set[str]) -> str:
    return ", ".join(f"`{c}`" for c in sorted(case_ids)) or "—"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--results", type=Path, nargs="+", required=True)
    parser.add_argument("--rule-map-dir", type=Path, default=RULE_MAP_DIR)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--svg", type=Path, help="export the console to SVG for the README")
    args = parser.parse_args()

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no meta.yaml found under {args.corpus}")

    runs = [load(path, cases, args.rule_map_dir) for path in args.results]

    # The markdown and the console come from the same Score: if they differ,
    # the bug is in the presentation, not in the metrics.
    markdown = render(runs, cases)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")

    console = make_console(record=bool(args.svg))
    header(console, corpus=str(args.corpus), runs=runs)
    console.print()
    glossary(console)
    console.print()
    console.print(cases_table(console, runs, cases))
    console.print(metrics_table(console, runs))

    if args.svg:
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        export_svg(console, args.svg, title="sast-bench")
        console.print(f"wrote {args.svg}", highlight=False)
    console.print(f"wrote {args.out}", highlight=False)


if __name__ == "__main__":
    main()
