"""Validacion y conteo del corpus.

Los chequeos son los de tests/test_meta.py, sacados a funciones para que el
test y `sast-bench corpus validate` corran exactamente lo mismo. Cada chequeo
devuelve la lista de problemas que encontro; vacia es que esta bien.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from scoring.models import META_FILENAME, VARIANT_LABELS, Case, Difficulty, Family, load_case

# PROJECT.md, "Distribucion": 4 pares por familia y dificultad.
PAIRS_PER_CELL = 4


def check_variant_dirs(case: Case) -> list[str]:
    problems = []
    for label in VARIANT_LABELS:
        variant_dir = case.variant_dir(label)
        if not variant_dir.is_dir():
            problems.append(f"falta {variant_dir}")
        elif not any(p.is_file() for p in variant_dir.iterdir()):
            problems.append(f"{variant_dir} esta vacia")
    return problems


def check_declared_variants(case: Case) -> list[str]:
    problems = []
    if set(case.meta.variants) != set(VARIANT_LABELS):
        problems.append(f"variantes declaradas {sorted(case.meta.variants)}, se esperan {list(VARIANT_LABELS)}")
    for label, variant in case.meta.variants.items():
        if variant.label != label:
            problems.append(f"la variante {label} dice label: {variant.label}")
    return problems


def check_sink_declared(case: Case) -> list[str]:
    problems = []
    vulnerable = case.meta.variants.get("vulnerable")
    safe = case.meta.variants.get("safe")
    if vulnerable is not None and vulnerable.sink is None:
        problems.append("la vulnerable necesita sink")
    if safe is not None and safe.sink is not None:
        problems.append("la safe no lleva sink")
    return problems


def check_sink_target(case: Case) -> list[str]:
    vulnerable = case.meta.variants.get("vulnerable")
    if vulnerable is None or vulnerable.sink is None:
        return []  # lo reporta check_sink_declared
    sink = vulnerable.sink
    target = case.directory / sink.file
    if not target.is_file():
        return [f"el sink apunta a {target}, que no existe"]
    total = len(target.read_text(encoding="utf-8").splitlines())
    if sink.line > total:
        return [f"sink.line {sink.line} fuera de {target} ({total} lineas)"]
    return []


def check_sink_inside_vulnerable(case: Case) -> list[str]:
    """Restriccion del corpus: cada variante es autocontenida."""
    vulnerable = case.meta.variants.get("vulnerable")
    if vulnerable is None or vulnerable.sink is None:
        return []
    if not vulnerable.sink.file.startswith("vulnerable/"):
        return [f"el sink {vulnerable.sink.file} no esta dentro de vulnerable/"]
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
    """Carga todos los casos y junta los problemas, sin cortar en el primero.

    Un meta.yaml que no carga (YAML roto, campo desconocido, familia fuera del
    enum) es un problema mas: se reporta y se sigue con el resto.
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
        problems.append(Problem(str(corpus), f"no hay ningun {META_FILENAME}"))

    seen: dict[str, Case] = {}
    for case in cases:
        if case.meta.id in seen:
            problems.append(
                Problem(str(case.directory), f"id {case.meta.id} repetido con {seen[case.meta.id].directory}")
            )
        seen[case.meta.id] = case
        problems += [Problem(str(case.directory), message) for message in check_case(case)]

    return sorted(cases, key=lambda c: c.meta.id), problems


def distribution(cases: list[Case]) -> Counter:
    """Pares por (familia, dificultad)."""
    return Counter((case.meta.family, case.meta.difficulty) for case in cases)


def short_cells(cases: list[Case]) -> list[tuple[Family, Difficulty, int]]:
    """Celdas familia x dificultad con menos pares que los que pide PROJECT.md."""
    counts = distribution(cases)
    return [
        (family, difficulty, counts[(family, difficulty)])
        for family in Family
        for difficulty in Difficulty
        if counts[(family, difficulty)] < PAIRS_PER_CELL
    ]
