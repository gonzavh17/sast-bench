"""Presentation layer. It computes nothing: it formats what `metrics` computed.

Everything shown here derives from the same `Score` that feeds the JSON and
report.md. If a number in the terminal does not match the JSON, the bug is in
this file, not in the metrics.

One design idea: the case table shows **one symbol per cell**, not acronyms.
TP/FN/FP/TN say which matrix cell a variant lands in; what someone wants at a
glance is different (did the tool help or not) and that is three states, not
four.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
from dataclasses import dataclass
from typing import Any

from rich import box
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from scoring.metrics import PairOutcome, Score
from scoring.models import Case


@dataclass(frozen=True)
class Symbols:
    solved: str
    missed: str
    false_alarm: str


UNICODE = Symbols(solved="✓", missed="✗", false_alarm="!")
ASCII = Symbols(solved="+", missed="x", false_alarm="!")

GLOSSARY = (
    ("solved", "caught the flaw and let the safe code through"),
    ("missed", "missed the flaw"),
    ("false_alarm", "false alarm: flagged the safe code"),
)

STYLES = {"solved": "green", "missed": "red", "false_alarm": "yellow"}


def symbols_for(console: Console) -> Symbols:
    """ASCII if the terminal cannot render the symbols, or if asked explicitly."""
    if os.environ.get("SAST_BENCH_ASCII"):
        return ASCII
    encoding = getattr(console.file, "encoding", None) or sys.getdefaultencoding()
    try:
        "".join((UNICODE.solved, UNICODE.missed)).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return ASCII
    return UNICODE


def make_console(*, record: bool = False, width: int | None = None) -> Console:
    """rich already honors NO_COLOR and turns color off outside a terminal.

    It is passed explicitly anyway, so the behavior is written in the code and
    does not depend on a library version.
    """
    return Console(
        record=record,
        width=width,
        no_color=bool(os.environ.get("NO_COLOR")),
        soft_wrap=False,
    )


def outcome_of(pair: PairOutcome) -> str:
    """A pair to one of the three glossary states.

    Order matters: if the flaw was missed, that is what gets reported even if
    the safe twin was also flagged.
    """
    if pair.vulnerable.cell == "FN":
        return "missed"
    if pair.safe.cell == "FP":
        return "false_alarm"
    return "solved"


def engine_label(tool: str, version: str) -> str:
    """`semgrep` + `1.177.0` -> `semgrep 1.177.0`.

    A derived runner already carries its name and model in the version
    (`codeql 2.27.1 + claude-opus-5`); that one is left as is.
    """
    return version if version.startswith(tool.split("+")[0]) else f"{tool} {version}"


def header(console: Console, *, corpus: str, runs: list[tuple[str, dict, Score]]) -> None:
    pairs = len(runs[0][2].pairs)
    engines = " · ".join(
        engine_label(tool, results["tool_version"]) for tool, results, _ in runs
    )
    console.print(
        f"[bold]{corpus}[/bold] · {pairs} pairs · {pairs * 2} variants · {engines}",
        highlight=False,
    )


def glossary(console: Console) -> None:
    symbols = symbols_for(console)
    for key, text in GLOSSARY:
        mark = getattr(symbols, key)
        console.print(f"  [{STYLES[key]}]{mark}[/{STYLES[key]}]  {text}", highlight=False)


def log_event(console: Console, engine: str, message: str) -> None:
    """One line per event: time, engine in brackets, and what happened.

    It is cut with an ellipsis instead of wrapping: a long reason split over
    three lines ruins the live log, and the full text is kept in the decisions
    JSON anyway, which is the auditable trail.
    """
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    console.print(
        f"[dim]{stamp}[/dim] [cyan]\\[{engine}][/cyan] {message}",
        highlight=False,
        no_wrap=True,
        overflow="ellipsis",
    )


def progress_bar(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=24),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def table_box(console: Console) -> box.Box:
    """If the terminal cannot render the symbols, it cannot render box drawing either."""
    return box.SIMPLE if symbols_for(console) is UNICODE else box.ASCII


def cases_table(
    console: Console, runs: list[tuple[str, dict, Score]], cases: list[Case]
) -> Table:
    symbols = symbols_for(console)
    tools = [tool for tool, _, _ in runs]
    by_case = {tool: {p.case_id: p for p in score.pairs} for tool, _, score in runs}

    table = Table(box=table_box(console), pad_edge=False)
    table.add_column("case", no_wrap=True)
    table.add_column("difficulty", no_wrap=True)
    for tool in tools:
        table.add_column(tool, justify="center", no_wrap=True)

    for case in sorted(cases, key=lambda c: c.meta.id):
        row = [case.meta.id, case.meta.difficulty.value]
        for tool in tools:
            key = outcome_of(by_case[tool][case.meta.id])
            row.append(f"[{STYLES[key]}]{getattr(symbols, key)}[/{STYLES[key]}]")
        table.add_row(*row)
    return table


def metrics_table(console: Console, runs: list[tuple[str, dict, Score]]) -> Table:
    """Plain names instead of acronyms. The acronyms and the rest live in the JSON and report.md."""
    table = Table(box=table_box(console), pad_edge=False)
    table.add_column("engine", no_wrap=True)
    table.add_column("pairs", justify="right", no_wrap=True)
    table.add_column("finds", justify="right", no_wrap=True)
    table.add_column("false alarms", justify="right", no_wrap=True)

    for tool, _, score in runs:
        solved = sum(p.solved for p in score.pairs)
        table.add_row(
            tool,
            f"{solved}/{len(score.pairs)}",
            f"{score.recall:.0%}",
            f"{score.fpr:.0%}",
        )
    return table


def export_svg(console: Console, path: Any, title: str) -> None:
    """To put the table in the README without taking a screenshot."""
    console.save_svg(str(path), title=title)
