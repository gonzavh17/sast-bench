"""CLI: results + corpus + rule_map -> report.md"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scoring.metrics import Score, tally
from scoring.models import discover_cases, load_rule_map

RULE_MAP_DIR = Path(__file__).resolve().parent / "rule_map"


def _origin(rules: dict) -> str:
    """Where the rules came from, in one line, depending on the runner that fetched them."""
    match rules["kind"]:
        case "official":  # semgrep: rules repo + commit
            return f"{rules['repo']}@{rules['commit'][:12]} ({', '.join(rules['paths'])})"
        case "bundle":  # codeql: bundle + query suite
            return f"{rules['bundle']} ({rules['suite']})"
        case _:
            return f"custom: {rules['path']}"


def render(score: Score, results: dict) -> str:
    origin = _origin(results["rules"])

    lines = [
        f"# {results['tool']} — {len(score.pairs)} pairs",
        "",
        f"- tool: `{results['tool']} {results['tool_version']}`",
        f"- rules: {origin}",
        f"- run: {results['run_at']}",
        "",
        "## Headline",
        "",
        f"**pair score = {score.pair_score:.2f}** "
        f"({sum(p.solved for p in score.pairs)}/{len(score.pairs)} pairs)",
        "",
        "| metric | value |",
        "|---|---|",
        f"| recall | {score.recall:.2f} |",
        f"| FPR | {score.fpr:.2f} |",
        f"| precision | {score.precision:.2f} |",
        f"| F1 | {score.f1:.2f} |",
        f"| localization | {score.localization:.2f} |",
        f"| noise (unmapped findings per variant) | {score.noise:.2f} |",
        "",
        f"TP {score.tp} · FN {score.fn} · FP {score.fp} · TN {score.tn}",
        "",
        "## Per pair",
        "",
        "| case | vulnerable | safe | pair | rules that fired |",
        "|---|---|---|---|---|",
    ]

    for pair in score.pairs:
        fired = sorted({f.rule_id for f in pair.vulnerable.matched + pair.safe.matched})
        lines.append(
            f"| `{pair.case_id}` | {pair.vulnerable.cell} | {pair.safe.cell} | "
            f"{'yes' if pair.solved else 'no'} | {', '.join(f'`{r}`' for r in fired) or '—'} |"
        )

    lines += ["", "## Unmapped rule_ids", ""]
    if score.unmapped:
        lines.append("| rule_id | count |")
        lines.append("|---|---|")
        lines += [f"| `{rid}` | {n} |" for rid, n in score.unmapped.most_common()]
        lines.append("")
        lines.append("Decide for each one whether it goes to `rules` or `ignore` in the rule_map.")
    else:
        lines.append("None: everything that fired is in the rule_map.")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument(
        "--rule-map",
        type=Path,
        help="default: scoring/rule_map/<tool>.yaml, per what the results declares",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no meta.yaml found under {args.corpus}")

    results = json.loads(args.results.read_text(encoding="utf-8"))
    # Same as compare.py: the results says which rule_map it is read with. A
    # derived runner (the phase 3 filter) reuses the one of its input.
    rule_map = args.rule_map or RULE_MAP_DIR / f"{results.get('rule_map', results['tool'])}.yaml"
    if not rule_map.is_file():
        parser.error(f"missing rule_map {rule_map}")
    score = tally(cases, results, load_rule_map(rule_map))
    markdown = render(score, results)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
