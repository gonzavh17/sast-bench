"""CLI: varios results + corpus -> tabla comparativa entre herramientas.

`report.py` mira una herramienta a la vez. Este mira varias juntas, que es lo
que hace falta para la pregunta del benchmark: no cual saca mas, sino si miden
lo mismo. Por eso ademas del titular por herramienta saca el solapamiento: los
pares que resuelven las dos, los que resuelve solo una, y los que no resuelve
ninguna.

Cada results.json dice de que herramienta es (`tool`), y el rule_map se busca
por convencion en scoring/rule_map/<tool>.yaml.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scoring.metrics import Score, tally
from scoring.models import Case, discover_cases, load_rule_map

RULE_MAP_DIR = Path(__file__).resolve().parent / "rule_map"

CELL = {True: "si", False: "no"}


def load(results_path: Path, cases: list[Case], rule_map_dir: Path) -> tuple[str, dict, Score]:
    results = json.loads(results_path.read_text(encoding="utf-8"))
    tool = results["tool"]
    rule_map_path = rule_map_dir / f"{tool}.yaml"
    if not rule_map_path.is_file():
        raise SystemExit(f"falta el rule_map de {tool}: {rule_map_path}")
    return tool, results, tally(cases, results, load_rule_map(rule_map_path))


def render(runs: list[tuple[str, dict, Score]], cases: list[Case]) -> str:
    tools = [tool for tool, _, _ in runs]
    difficulties = {case.meta.id: case.meta.difficulty.value for case in cases}

    lines = [
        f"# Comparativa — {', '.join(tools)}",
        "",
        "## Titular",
        "",
        "| herramienta | pair score | recall | FPR | precision | F1 | localizacion | ruido |",
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

    lines += ["", "## Por par", "", "| caso | dificultad | " + " | ".join(tools) + " |"]
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

    lines += ["", "## Solapamiento", ""]
    everyone = set.intersection(*solved_by.values()) if solved_by else set()
    union = set.union(*solved_by.values()) if solved_by else set()
    total = len(next(iter(by_case.values())))

    lines.append(f"- resuelven **todas**: {_ids(everyone)}")
    for tool in tools:
        only = solved_by[tool] - set.union(
            *[solved_by[other] for other in tools if other != tool]
        ) if len(tools) > 1 else solved_by[tool]
        lines.append(f"- solo `{tool}`: {_ids(only)}")
    lines.append(f"- **no resuelve ninguna**: {_ids(set(by_case[tools[0]]) - union)}")
    lines.append("")
    lines.append(
        f"Union = {len(union)}/{total} pares ({len(union) / total:.2f}). "
        "Es el techo de correr todas juntas."
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
    args = parser.parse_args()

    cases = discover_cases(args.corpus)
    if not cases:
        parser.error(f"no se encontro ningun meta.yaml bajo {args.corpus}")

    runs = [load(path, cases, args.rule_map_dir) for path in args.results]
    markdown = render(runs, cases)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"escrito {args.out}")


if __name__ == "__main__":
    main()
