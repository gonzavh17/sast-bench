"""Which cases changed outcome between two runs.

The metric delta says little: 5/12 -> 5/12 can hide two cases that got fixed
and two that broke. What matters is the list.
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
    fixed: list[Change]  # unsolved -> solved
    broken: list[Change]  # solved -> unsolved
    shifted: list[Change]  # still unsolved, other cells (e.g. FN/TN -> TP/FP)
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
