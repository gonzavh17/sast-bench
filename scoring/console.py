"""Capa de presentacion. No calcula nada: formatea lo que ya calculo `metrics`.

Todo lo que sale por aca es derivado del mismo `Score` que alimenta al JSON y al
report.md. Si un numero de la terminal no coincide con el del JSON, es un bug de
este archivo, no de las metricas.

Una sola idea de diseno: en la tabla de casos va **un simbolo por celda**, no
siglas. TP/FN/FP/TN dicen que celda de la matriz ocupa la variante; lo que
alguien quiere saber de un vistazo es otra cosa —si la herramienta sirvio o no—
y eso son tres estados, no cuatro.
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
    ("solved", "detecto la falla y dejo pasar el codigo sano"),
    ("missed", "se le escapo la falla"),
    ("false_alarm", "falsa alarma: marco el codigo sano"),
)

STYLES = {"solved": "green", "missed": "red", "false_alarm": "yellow"}


def symbols_for(console: Console) -> Symbols:
    """ASCII si la terminal no puede con los simbolos, o si lo piden a mano."""
    if os.environ.get("SAST_BENCH_ASCII"):
        return ASCII
    encoding = getattr(console.file, "encoding", None) or sys.getdefaultencoding()
    try:
        "".join((UNICODE.solved, UNICODE.missed)).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return ASCII
    return UNICODE


def make_console(*, record: bool = False, width: int | None = None) -> Console:
    """rich ya respeta NO_COLOR y apaga el color fuera de una terminal.

    Se pasa explicito igual: que el comportamiento este escrito en el codigo y
    no dependa de una version de la libreria.
    """
    return Console(
        record=record,
        width=width,
        no_color=bool(os.environ.get("NO_COLOR")),
        soft_wrap=False,
    )


def outcome_of(pair: PairOutcome) -> str:
    """Un pair a uno de los tres estados del glosario.

    El orden importa: si se le escapo la falla, eso es lo que se reporta aunque
    ademas haya marcado al gemelo sano.
    """
    if pair.vulnerable.cell == "FN":
        return "missed"
    if pair.safe.cell == "FP":
        return "false_alarm"
    return "solved"


def engine_label(tool: str, version: str) -> str:
    """`semgrep` + `1.177.0` -> `semgrep 1.177.0`.

    Un runner derivado ya trae el nombre y el modelo en su version
    (`codeql 2.27.1 + claude-opus-5`); ese se deja como esta.
    """
    return version if version.startswith(tool.split("+")[0]) else f"{tool} {version}"


def header(console: Console, *, corpus: str, runs: list[tuple[str, dict, Score]]) -> None:
    pairs = len(runs[0][2].pairs)
    engines = " · ".join(
        engine_label(tool, results["tool_version"]) for tool, results, _ in runs
    )
    console.print(
        f"[bold]{corpus}[/bold] · {pairs} pares · {pairs * 2} variantes · {engines}",
        highlight=False,
    )


def glossary(console: Console) -> None:
    symbols = symbols_for(console)
    for key, text in GLOSSARY:
        mark = getattr(symbols, key)
        console.print(f"  [{STYLES[key]}]{mark}[/{STYLES[key]}]  {text}", highlight=False)


def log_event(console: Console, engine: str, message: str) -> None:
    """Una linea por evento: hora, engine entre corchetes, y que paso.

    Se corta con puntos suspensivos en vez de envolver: un motivo largo
    partido en tres lineas arruina el log en vivo, y el texto completo queda
    igual en el JSON de decisiones, que es el rastro auditable.
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


def _box_for(console: Console) -> box.Box:
    """Si la terminal no banca los simbolos, tampoco banca el box-drawing."""
    return box.SIMPLE if symbols_for(console) is UNICODE else box.ASCII


def cases_table(
    console: Console, runs: list[tuple[str, dict, Score]], cases: list[Case]
) -> Table:
    symbols = symbols_for(console)
    tools = [tool for tool, _, _ in runs]
    by_case = {tool: {p.case_id: p for p in score.pairs} for tool, _, score in runs}

    table = Table(box=_box_for(console), pad_edge=False)
    table.add_column("caso", no_wrap=True)
    table.add_column("dificultad", no_wrap=True)
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
    """Nombres en castellano. Las siglas y el resto viven en el JSON y report.md."""
    table = Table(box=_box_for(console), pad_edge=False)
    table.add_column("engine", no_wrap=True)
    table.add_column("pares", justify="right", no_wrap=True)
    table.add_column("encuentra", justify="right", no_wrap=True)
    table.add_column("ruido", justify="right", no_wrap=True)

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
    """Para meter la tabla en el README sin sacar una captura."""
    console.save_svg(str(path), title=title)
