"""Valida el meta.yaml de cada caso del corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from scoring.models import VARIANT_LABELS, Case, discover_cases

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
CASES = discover_cases(CORPUS)


def test_corpus_no_esta_vacio():
    """Un glob roto no se debe leer como suite verde."""
    assert CASES, f"no se encontro ningun meta.yaml bajo {CORPUS}"


def test_ids_unicos():
    ids = [c.meta.id for c in CASES]
    assert len(ids) == len(set(ids)), f"ids duplicados: {ids}"


@pytest.fixture(params=CASES, ids=lambda c: c.meta.id)
def case(request) -> Case:
    return request.param


def test_ambas_variantes_existen_y_tienen_archivos(case: Case):
    for label in VARIANT_LABELS:
        variant_dir = case.variant_dir(label)
        assert variant_dir.is_dir(), f"falta {variant_dir}"
        assert any(p.is_file() for p in variant_dir.iterdir()), f"{variant_dir} esta vacia"


def test_variantes_declaradas_coinciden_con_el_disco(case: Case):
    assert set(case.meta.variants) == set(VARIANT_LABELS)
    for label, variant in case.meta.variants.items():
        assert variant.label == label


def test_la_vulnerable_declara_sink_y_la_safe_no(case: Case):
    assert case.meta.variants["vulnerable"].sink is not None, "la vulnerable necesita sink"
    assert case.meta.variants["safe"].sink is None, "la safe no lleva sink"


def test_el_sink_apunta_a_un_archivo_y_linea_reales(case: Case):
    sink = case.meta.variants["vulnerable"].sink
    assert sink is not None
    target = case.directory / sink.file
    assert target.is_file(), f"el sink apunta a {target}, que no existe"
    total = len(target.read_text(encoding="utf-8").splitlines())
    assert sink.line <= total, f"sink.line {sink.line} fuera de {target} ({total} lineas)"


def test_el_sink_vive_dentro_de_la_variante_vulnerable(case: Case):
    """Restriccion del corpus: cada variante es autocontenida."""
    sink = case.meta.variants["vulnerable"].sink
    assert sink is not None
    assert sink.file.startswith("vulnerable/"), sink.file
