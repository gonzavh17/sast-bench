"""False-positive filter: an LLM reviews each finding of a rule-based runner.

Phase 3 of PROJECT.md, minimal version. Rules for the first pass, an LLM that
reviews each finding on its own and dismisses false alarms.

Two design decisions define what is measured:

- **One request per finding.** Never batched: in a batch the model compares
  findings to each other and one verdict contaminates the next.
- **Context = the whole variant.** It is the same information CodeQL used to
  follow taint across files. With less, indirect cases would be judged blind.
  It does not scale to a real repo, but here the variant *is* the unit.

The prompt never sees meta.yaml: the label and the rationale are ground truth.

It consumes a saved results.json instead of running the tool again: same data,
and it saves 13 minutes of CodeQL per iteration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Literal

import anthropic
from dotenv import load_dotenv
from pydantic import BaseModel
from rich.console import Console

from scoring.console import log_event, make_console, progress_bar
from scoring.models import Case, Finding, Strict, discover_cases

DEFAULT_MODEL = "claude-opus-5"

SYSTEM = """\
Sos un revisor de seguridad. Un analizador estatico marco un hallazgo en codigo \
Angular y tenes que decidir si es una vulnerabilidad real o una falsa alarma.

Descartar un hallazgo real es MUCHO peor que dejar pasar una falsa alarma.

Descartalo SOLO si podes senalar la linea exacta del control que lo hace \
inexplotable, y copiala en el campo `control`. Si el dato entra desde fuera del \
codigo que ves, o no podes rastrear su origen, confirmalo.

Un control que existe no alcanza: tiene que ser suficiente. Una validacion \
parcial, una que se calcula y no se usa, o una que se aplica sobre un valor que \
ya no es el que llega al sink, no hacen inexplotable a nada.\
"""

PROMPT = """\
Hallazgo del analizador:
  regla: {rule_id}
  archivo: {path}
  linea: {line}
  severidad: {severity}

Codigo completo de la unidad analizada. La linea del hallazgo esta marcada con \
`>>>`:

{context}

Decidi si este hallazgo es una vulnerabilidad real o una falsa alarma.\
"""


class Decision(BaseModel):
    """Structured output del modelo. Una decision por hallazgo."""

    veredicto: Literal["confirmado", "descartado"]
    motivo: str
    control: str


class DecisionRecord(Strict):
    """The decision plus everything needed to audit it later."""

    case_id: str
    variant: str
    finding: Finding
    veredicto: str
    motivo: str
    control: str
    model: str
    input_tokens: int
    output_tokens: int
    decided_at: str


def build_context(variant_dir: Path, finding: Finding) -> str:
    """Every file of the variant, numbered, with the finding marked."""
    blocks: list[str] = []
    for path in sorted(variant_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(variant_dir).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        numbered = [
            f"{'>>>' if relative == finding.path and n == finding.line else '   '} "
            f"{n:3} | {text}"
            for n, text in enumerate(lines, start=1)
        ]
        blocks.append(f"--- {relative} ---\n" + "\n".join(numbered))
    return "\n\n".join(blocks)


def judge(
    client: anthropic.Anthropic,
    variant_dir: Path,
    finding: Finding,
    model: str,
) -> tuple[Decision, Any]:
    response = client.messages.parse(
        model=model,
        max_tokens=16000,
        system=SYSTEM,
        thinking={"type": "adaptive"},
        messages=[
            {
                "role": "user",
                "content": PROMPT.format(
                    rule_id=finding.rule_id,
                    path=finding.path,
                    line=finding.line,
                    severity=finding.severity,
                    context=build_context(variant_dir, finding),
                ),
            }
        ],
        output_format=Decision,
    )
    return response.parsed_output, response.usage


def _one_line(decision: Decision) -> str:
    """El motivo en una linea. Si descarta, lo que importa es el control citado."""
    if decision.veredicto == "descartado" and decision.control.strip():
        return f"[yellow]descarta[/yellow] · protegido por: {decision.control.strip()}"
    if decision.veredicto == "descartado":
        return f"[yellow]descarta[/yellow] · {decision.motivo}"
    return f"[green]confirma[/green] · {decision.motivo}"


def review(
    results: dict[str, Any],
    cases: dict[str, Case],
    client: anthropic.Anthropic,
    model: str,
    console: Console,
) -> list[DecisionRecord]:
    """One request per finding, in order, never batched."""
    pending = [
        (entry, Finding.model_validate(raw))
        for entry in results["variants"]
        for raw in entry["findings"]
    ]
    records: list[DecisionRecord] = []

    with progress_bar(console) as bar:
        task = bar.add_task("reviewing", total=len(pending))
        for entry, finding in pending:
            case = cases[entry["case_id"]]
            bar.update(task, description=f"{entry['case_id']} {entry['variant']}")
            decision, usage = judge(
                client, case.variant_dir(entry["variant"]), finding, model
            )
            records.append(
                DecisionRecord(
                    case_id=entry["case_id"],
                    variant=entry["variant"],
                    finding=finding,
                    veredicto=decision.veredicto,
                    motivo=decision.motivo,
                    control=decision.control,
                    model=model,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    decided_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                )
            )
            # Verdict and control go before the rule_id: if the line gets cut,
            # what is lost is the least important part.
            log_event(
                console,
                "hybrid",
                f"{entry['case_id']} {entry['variant']:10} {_one_line(decision)}"
                f" [dim]({finding.rule_id}:{finding.line})[/dim]",
            )
            bar.advance(task)
    return records


def apply_decisions(
    results: dict[str, Any], records: list[DecisionRecord]
) -> list[dict[str, Any]]:
    """Keep only the confirmed findings.

    Every variant is kept, including those left without findings: if they were
    dropped, `tally` would read them as absent instead of clean.
    """
    discarded = {
        (r.case_id, r.variant, r.finding.path, r.finding.line, r.finding.rule_id)
        for r in records
        if r.veredicto == "descartado"
    }
    return [
        {
            **entry,
            "findings": [
                f
                for f in entry["findings"]
                if (entry["case_id"], entry["variant"], f["path"], f["line"], f["rule_id"])
                not in discarded
            ],
        }
        for entry in results["variants"]
    ]


def filter_results(
    results: dict[str, Any],
    base_results: str,
    cases: dict[str, Case],
    client: anthropic.Anthropic,
    model: str,
    console: Console,
) -> tuple[dict[str, Any], list[DecisionRecord]]:
    """Review each finding and build the filtered results, in the usual format."""
    records = review(results, cases, client, model, console)

    confirmed = sum(r.veredicto == "confirmado" for r in records)
    log_event(
        console,
        "hybrid",
        f"{confirmed} confirmados, {len(records) - confirmed} descartados",
    )

    filtered = {
        "tool": f"{results['tool']}+llm",
        "rule_map": results.get("rule_map", results["tool"]),
        "tool_version": f"{results['tool']} {results['tool_version']} + {model}",
        "run_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "rules": results["rules"],
        "base_results": base_results,
        "variants": apply_decisions(results, records),
    }
    return filtered, records


def dump_decisions(records: list[DecisionRecord]) -> str:
    return json.dumps([r.model_dump() for r in records], indent=2, ensure_ascii=False) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True, help="results of the base tool")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True, help="audit trail")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    load_dotenv()
    cases = {case.meta.id: case for case in discover_cases(args.corpus)}
    if not cases:
        parser.error(f"no meta.yaml found under {args.corpus}")

    console = make_console()
    results = json.loads(args.results.read_text(encoding="utf-8"))
    total = sum(len(v["findings"]) for v in results["variants"])
    log_event(
        console,
        "hybrid",
        f"{total} findings from {results['tool']} to review with {args.model}",
    )

    filtered, records = filter_results(
        results, str(args.results), cases, anthropic.Anthropic(), args.model, console
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(filtered, indent=2) + "\n", encoding="utf-8")
    args.decisions.parent.mkdir(parents=True, exist_ok=True)
    args.decisions.write_text(dump_decisions(records), encoding="utf-8")
    log_event(console, "hybrid", f"wrote {args.out}")
    log_event(console, "hybrid", f"wrote {args.decisions}")


if __name__ == "__main__":
    main()
