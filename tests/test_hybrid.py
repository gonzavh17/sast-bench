"""The pure parts of the phase 3 filter, without touching the API.

What is checked here is that filtering does not break the scoring: a variant
left without findings still exists, and dismissing one finding out of several
does not empty the whole variant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runners.hybrid import DecisionRecord, apply_decisions, build_context
from scoring.models import Finding


def finding(rule_id: str = "js/xss", path: str = "a.ts", line: int = 5) -> Finding:
    return Finding(path=path, line=line, rule_id=rule_id, severity="ERROR")


def record(
    case_id: str,
    variant: str,
    f: Finding,
    veredicto: str = "descartado",
) -> DecisionRecord:
    return DecisionRecord(
        case_id=case_id,
        variant=variant,
        finding=f,
        veredicto=veredicto,
        motivo="test",
        control="",
        model="test-model",
        input_tokens=1,
        output_tokens=1,
        decided_at="2026-09-23T00:00:00+00:00",
    )


def results(variants: list[dict]) -> dict:
    return {"tool": "codeql", "variants": variants}


def test_dismissing_the_only_finding_leaves_the_variant_empty_but_present():
    """If the variant were dropped, tally would read it as absent instead of clean."""
    f = finding()
    payload = results(
        [{"case_id": "ng-xss-009", "variant": "safe", "findings": [f.model_dump()]}]
    )
    out = apply_decisions(payload, [record("ng-xss-009", "safe", f)])
    assert len(out) == 1
    assert out[0]["case_id"] == "ng-xss-009"
    assert out[0]["findings"] == []


def test_dismissing_one_of_three_keeps_the_other_two():
    keep_a, drop, keep_b = (
        finding("js/xss", line=8),
        finding("js/bad-tag-filter", line=3),
        finding("js/incomplete-multi-character-sanitization", line=7),
    )
    payload = results(
        [
            {
                "case_id": "ng-xss-011",
                "variant": "vulnerable",
                "findings": [f.model_dump() for f in (keep_a, drop, keep_b)],
            }
        ]
    )
    out = apply_decisions(payload, [record("ng-xss-011", "vulnerable", drop)])
    assert [f["rule_id"] for f in out[0]["findings"]] == [keep_a.rule_id, keep_b.rule_id]


def test_confirmed_dismisses_nothing():
    f = finding()
    payload = results([{"case_id": "c", "variant": "vulnerable", "findings": [f.model_dump()]}])
    out = apply_decisions(payload, [record("c", "vulnerable", f, veredicto="confirmado")])
    assert len(out[0]["findings"]) == 1


def test_a_dismissal_does_not_cross_variants():
    """Same rule_id, same line, different twin: they must not be confused."""
    f = finding()
    payload = results(
        [
            {"case_id": "c", "variant": "vulnerable", "findings": [f.model_dump()]},
            {"case_id": "c", "variant": "safe", "findings": [f.model_dump()]},
        ]
    )
    out = apply_decisions(payload, [record("c", "safe", f)])
    by_variant = {e["variant"]: e["findings"] for e in out}
    assert len(by_variant["vulnerable"]) == 1
    assert by_variant["safe"] == []


@pytest.fixture
def variant_dir(tmp_path: Path) -> Path:
    (tmp_path / "svc.ts").write_text("one\ntwo\nthree\n", encoding="utf-8")
    (tmp_path / "cmp.ts").write_text("alpha\nbeta\n", encoding="utf-8")
    return tmp_path


def test_the_context_includes_every_file_of_the_variant(variant_dir: Path):
    """Without this, indirect cases would be judged without seeing where the data comes from."""
    context = build_context(variant_dir, finding(path="cmp.ts", line=2))
    assert "--- svc.ts ---" in context
    assert "--- cmp.ts ---" in context
    assert "one" in context and "beta" in context


def test_the_context_marks_the_finding_line_and_only_that_one(variant_dir: Path):
    context = build_context(variant_dir, finding(path="cmp.ts", line=2))
    marked = [line for line in context.splitlines() if line.startswith(">>>")]
    assert len(marked) == 1
    assert "beta" in marked[0]


def test_the_mark_does_not_land_on_the_same_line_of_another_file(variant_dir: Path):
    """Line 2 exists in both files; only the finding's one is marked."""
    context = build_context(variant_dir, finding(path="svc.ts", line=2))
    marked = [line for line in context.splitlines() if line.startswith(">>>")]
    assert len(marked) == 1
    assert "two" in marked[0]
