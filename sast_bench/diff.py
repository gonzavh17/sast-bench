"""Que casos cambiaron de resultado entre dos corridas.

El delta de las metricas dice poco: 5/12 -> 5/12 puede esconder dos casos que
se arreglaron y dos que se rompieron. Lo que importa es la lista.
"""

from __future__ import annotations

from dataclasses import dataclass

from scoring.metrics import PairOutcome, Score


@dataclass(frozen=True)
class Change:
    case_id: str
    before: PairOutcome | None
    after: PairOutcome | None


@dataclass
class ScoreDiff:
    fixed: list[Change]  # de fallo a acierto
    broken: list[Change]  # de acierto a fallo
    shifted: list[Change]  # mismo par, otras celdas (p. ej. FN/TN -> TP/FP)
    only_before: list[str]
    only_after: list[str]
    unchanged: int


def cells(pair: PairOutcome) -> str:
    return f"{pair.vulnerable.cell}/{pair.safe.cell}"


def diff_scores(before: Score, after: Score) -> ScoreDiff:
    a = {p.case_id: p for p in before.pairs}
    b = {p.case_id: p for p in after.pairs}
    diff = ScoreDiff([], [], [], sorted(set(a) - set(b)), sorted(set(b) - set(a)), 0)
    for case_id in sorted(set(a) & set(b)):
        old, new = a[case_id], b[case_id]
        change = Change(case_id, old, new)
        if old.solved != new.solved:
            (diff.fixed if new.solved else diff.broken).append(change)
        elif cells(old) != cells(new):
            diff.shifted.append(change)
        else:
            diff.unchanged += 1
    return diff
