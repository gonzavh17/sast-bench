"""Validate the meta.yaml of every corpus case.

The checks live in sast_bench/corpus.py: `sast-bench corpus validate` runs the
same ones.
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


def test_corpus_is_not_empty():
    """A broken glob must not read as a green suite."""
    assert CASES, f"no meta.yaml found under {CORPUS}"


def test_ids_are_unique():
    ids = [c.meta.id for c in CASES]
    assert len(ids) == len(set(ids)), f"duplicated ids: {ids}"


def test_validate_finds_no_problems():
    """What `sast-bench corpus validate` runs, over the whole corpus."""
    _, problems = validate(CORPUS)
    assert not problems, problems


@pytest.fixture(params=CASES, ids=lambda c: c.meta.id)
def case(request) -> Case:
    return request.param


def test_both_variants_exist_and_have_files(case: Case):
    assert not check_variant_dirs(case)


def test_declared_variants_match_the_disk(case: Case):
    assert not check_declared_variants(case)


def test_the_vulnerable_variant_declares_a_sink_and_the_safe_one_does_not(case: Case):
    assert not check_sink_declared(case)


def test_the_sink_points_to_a_real_file_and_line(case: Case):
    assert not check_sink_target(case)


def test_the_sink_lives_inside_the_vulnerable_variant(case: Case):
    """Corpus rule: each variant is self-contained."""
    assert not check_sink_inside_vulnerable(case)
