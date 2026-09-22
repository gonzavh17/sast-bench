"""CLI: results + corpus + rule_map -> report.md"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scoring.metrics import Score, tally
from scoring.models import discover_cases, load_rule_map

DEFAULT_RULE_MAP = Path(__file__).resolve().parent / "rule_map" / "semgrep.yaml"


def render(score: Score, results: dict) -> str:
    rules = results["rules"]
    origin = (
        f"{rules['repo']}@{rules['commit'][:12]} ({', '.join(rules['paths'])})"
        if rules["kind"] == "official"
        else f"custom: {rules['path']}"
    )

    lines = [
        f"# {results['tool']} — {len(score.pairs)} pares",
        "",
        f"- herramienta: `{results['tool']} {results['tool_version']}`",
        f"- reglas: {origin}",
        f"- corrida: {results['run_at']}",
        "",
        "## Titular",
        "",
        f"**pair score = {score.pair_score:.2f}** "
        f"({sum(p.solved for p in score.pairs)}/{len(score.pairs)} pares)",
        "",
        "| metrica | valor |",
        "|---|---|",
        f"| recall | {score.recall:.2f} |",
        f"| FPR | {score.fpr:.2f} |",
        f"| precision | {score.precision:.2f} |",
        f"| F1 | {score.f1:.2f} |",
        f"| localizacion | {score.localization:.2f} |",
        f"| ruido (hallazgos sin mapear por variante) | {score.noise:.2f} |",
        "",
        f"TP {score.tp} · FN {score.fn} · FP {score.fp} · TN {score.tn}",
        "",
        "## Por par",
        "",
        "| caso | vulnerable | safe | par | reglas que dispararon |",
        "|---|---|---|---|---|",
    ]

    for pair in score.pairs:
        fired = sorted({f.rule_id for f in pair.vulnerable.matched + pair.safe.matched})
        lines.append(
            f"| `{pair.case_id}` | {pair.vulnerable.cell} | {pair.safe.cell} | "
            f"{'si' if pair.solved else 'no'} | {', '.join(f'`{r}`' for r in fired) or '—'} |"
        )

    lines += ["", "## rule_id sin mapear", ""]
    if score.unmapped:
        lines.append("| rule_id | veces |")
        lines.append("|---|---|")
        lines += [f"| `{rid}` | {n} |" for rid, n in score.unmapped.most_common()]
        lines.append("")
        lines.append("Decidir para cada uno si va a `rules` o a `ignore` del rule_map.")
    else:
        lines.append("Ninguno: todo lo que disparo esta en el rule_map.")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--rule-map", type=Path, default=DEFAULT_RULE_MAP)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no se encontro ningun meta.yaml bajo {args.corpus}")

    results = json.loads(args.results.read_text(encoding="utf-8"))
    score = tally(cases, results, load_rule_map(args.rule_map))
    markdown = render(score, results)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"escrito {args.out}")


if __name__ == "__main__":
    main()
