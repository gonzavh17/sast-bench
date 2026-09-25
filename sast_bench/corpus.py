"""Corpus validation and counts.

The checks are the ones from tests/test_meta.py, pulled out into functions so
the test and `sast-bench corpus validate` run exactly the same thing. Each
check returns the list of problems it found; empty means fine.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from scoring.models import META_FILENAME, VARIANT_LABELS, Case, Difficulty, Family, load_case

# PROJECT.md, "Distribution": 4 pairs per family and difficulty.
PAIRS_PER_CELL = 4


def check_variant_dirs(case: Case) -> list[str]:
    problems = []
    for label in VARIANT_LABELS:
        variant_dir = case.variant_dir(label)
        if not variant_dir.is_dir():
            problems.append(f"missing {variant_dir}")
        elif not any(p.is_file() for p in variant_dir.iterdir()):
            problems.append(f"{variant_dir} is empty")
    return problems


def check_declared_variants(case: Case) -> list[str]:
    problems = []
    if set(case.meta.variants) != set(VARIANT_LABELS):
        problems.append(f"declared variants {sorted(case.meta.variants)}, expected {list(VARIANT_LABELS)}")
    for label, variant in case.meta.variants.items():
        if variant.label != label:
            problems.append(f"variant {label} says label: {variant.label}")
    return problems


def check_sink_declared(case: Case) -> list[str]:
    problems = []
    vulnerable = case.meta.variants.get("vulnerable")
    safe = case.meta.variants.get("safe")
    if vulnerable is not None and vulnerable.sink is None:
        problems.append("the vulnerable variant needs a sink")
    if safe is not None and safe.sink is not None:
        problems.append("the safe variant takes no sink")
    return problems


def check_sink_target(case: Case) -> list[str]:
    vulnerable = case.meta.variants.get("vulnerable")
    if vulnerable is None or vulnerable.sink is None:
        return []  # reported by check_sink_declared
    sink = vulnerable.sink
    target = case.directory / sink.file
    if not target.is_file():
        return [f"the sink points to {target}, which does not exist"]
    total = len(target.read_text(encoding="utf-8").splitlines())
    if sink.line > total:
        return [f"sink.line {sink.line} is out of {target} ({total} lines)"]
    return []


def check_sink_inside_vulnerable(case: Case) -> list[str]:
    """Corpus rule: each variant is self-contained."""
    vulnerable = case.meta.variants.get("vulnerable")
    if vulnerable is None or vulnerable.sink is None:
        return []
    if not vulnerable.sink.file.startswith("vulnerable/"):
        return [f"the sink {vulnerable.sink.file} is not inside vulnerable/"]
    return []


CHECKS = (
    check_variant_dirs,
    check_declared_variants,
    check_sink_declared,
    check_sink_target,
    check_sink_inside_vulnerable,
)


def check_case(case: Case) -> list[str]:
    return [problem for check in CHECKS for problem in check(case)]


@dataclass(frozen=True)
class Problem:
    where: str
    message: str


def validate(corpus: Path) -> tuple[list[Case], list[Problem]]:
    """Load every case and collect problems, without stopping at the first one.

    A meta.yaml that does not load (broken YAML, unknown field, family outside
    the enum) is one more problem: it gets reported and the rest carries on.
    """
    cases: list[Case] = []
    problems: list[Problem] = []
    for meta in sorted(corpus.rglob(META_FILENAME)):
        try:
            cases.append(load_case(meta.parent))
        except (ValidationError, yaml.YAMLError, OSError) as error:
            first = str(error).strip().splitlines()
            problems.append(Problem(str(meta.parent), " · ".join(first[:3])))

    if not cases and not problems:
        problems.append(Problem(str(corpus), f"no {META_FILENAME} found"))

    seen: dict[str, Case] = {}
    for case in cases:
        if case.meta.id in seen:
            problems.append(
                Problem(str(case.directory), f"id {case.meta.id} duplicated with {seen[case.meta.id].directory}")
            )
        seen[case.meta.id] = case
        problems += [Problem(str(case.directory), message) for message in check_case(case)]

    return sorted(cases, key=lambda c: c.meta.id), problems


def distribution(cases: list[Case]) -> Counter:
    """Pairs per (family, difficulty)."""
    return Counter((case.meta.family, case.meta.difficulty) for case in cases)


def short_cells(cases: list[Case]) -> list[tuple[Family, Difficulty, int]]:
    """Family x difficulty cells with fewer pairs than PROJECT.md asks for."""
    counts = distribution(cases)
    return [
        (family, difficulty, counts[(family, difficulty)])
        for family in Family
        for difficulty in Difficulty
        if counts[(family, difficulty)] < PAIRS_PER_CELL
    ]
