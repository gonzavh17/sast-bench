"""Valida el meta.yaml de cada caso del corpus.

Los chequeos viven en sast_bench/corpus.py: `sast-bench corpus validate` corre
los mismos.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sast_bench.corpus import (
    check_declared_variants,
    check_sink_declared,
    check_sink_inside_vulnerable,
    check_sink_target,
    check_variant_dirs,
    validate,
)
from scoring.models import Case, discover_cases

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
CASES = discover_cases(CORPUS)


def test_corpus_no_esta_vacio():
    """Un glob roto no se debe leer como suite verde."""
    assert CASES, f"no se encontro ningun meta.yaml bajo {CORPUS}"


def test_ids_unicos():
    ids = [c.meta.id for c in CASES]
    assert len(ids) == len(set(ids)), f"ids duplicados: {ids}"


def test_validate_no_encuentra_problemas():
    """Lo mismo que corre `sast-bench corpus validate`, sobre el corpus entero."""
    _, problems = validate(CORPUS)
    assert not problems, problems


@pytest.fixture(params=CASES, ids=lambda c: c.meta.id)
def case(request) -> Case:
    return request.param


def test_ambas_variantes_existen_y_tienen_archivos(case: Case):
    assert not check_variant_dirs(case)


def test_variantes_declaradas_coinciden_con_el_disco(case: Case):
    assert not check_declared_variants(case)


def test_la_vulnerable_declara_sink_y_la_safe_no(case: Case):
    assert not check_sink_declared(case)


def test_el_sink_apunta_a_un_archivo_y_linea_reales(case: Case):
    assert not check_sink_target(case)


def test_el_sink_vive_dentro_de_la_variante_vulnerable(case: Case):
    """Restriccion del corpus: cada variante es autocontenida."""
    assert not check_sink_inside_vulnerable(case)
