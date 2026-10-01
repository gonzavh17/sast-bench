"""Measure the funnel stage by stage, so it is clear where each case gets lost.

For every variant of the corpus, without calling any model:

- **rules**: did a candidate land on the vulnerable line (sink ± 3)?
- **slice**: does some slice show the vulnerable line at all? A candidate
  elsewhere can still bring it in, through callers or what the unit uses.
- **tokens**: what the slices would send to the LLM, against the whole
  variant that the LLM-only arm reads today.

The LLM stages (filter, analysis, skeptic) are added on top of this report
when they run.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from auditor.candidates import semgrep_candidates
from auditor.project import load_project
from auditor.slicer import CHARS_PER_TOKEN, build_slices
from runners.hybrid import build_context
from scoring.metrics import LOCALIZATION_TOLERANCE
from scoring.models import Case


@dataclass
class VariantFunnel:
    case_id: str
    family: str
    difficulty: str
    variant: str
    candidates: int
    slices: int
    orphans: int
    rules_hit: bool | None  # vulnerable only: a candidate at the sink
    slice_hit: bool | None  # vulnerable only: some slice shows the sink
    slice_tokens: int
    full_tokens: int


def _sink(case: Case) -> tuple[str, int]:
    sink = case.meta.variants["vulnerable"].sink
    assert sink is not None
    file = sink.file.removeprefix("vulnerable/")
    return file, sink.line


def measure_variant(case: Case, label: str) -> VariantFunnel:
    variant_dir = case.variant_dir(label)
    candidates = semgrep_candidates(variant_dir)
    project = load_project(variant_dir)
    slices, orphans = build_slices(project, candidates)

    rules_hit = slice_hit = None
    if label == "vulnerable":
        file, line = _sink(case)
        rules_hit = any(c.file == file and abs(c.line - line) <= LOCALIZATION_TOLERANCE for c in candidates)
        slice_hit = any(s.covers(file, line) for s in slices)

    return VariantFunnel(
        case_id=case.meta.id,
        family=case.meta.family.value,
        difficulty=case.meta.difficulty.value,
        variant=label,
        candidates=len(candidates),
        slices=len(slices),
        orphans=len(orphans),
        rules_hit=rules_hit,
        slice_hit=slice_hit,
        slice_tokens=sum(s.tokens(project) for s in slices),
        full_tokens=round(len(build_context(variant_dir)) / CHARS_PER_TOKEN),
    )


def measure(cases: list[Case]) -> list[VariantFunnel]:
    return [measure_variant(case, label) for case in cases for label in ("vulnerable", "safe")]


def to_json(rows: list[VariantFunnel]) -> list[dict]:
    return [asdict(r) for r in rows]


# ---------------------------------------------------------------- with the LLM stages


def survival(case: Case, label: str, result) -> dict:
    """Where a variant ends up after each stage of a full audit.

    Vulnerable: does the expected family survive rules, slice, triage, analysis
    and skeptic? Safe: is any family still flagged after analysis and after the
    skeptic (a false alarm)?
    """
    families = {"xss-sanitizer-bypass", "client-side-secrets", "broken-authorization"}
    expected = case.meta.family.value
    row = {
        "case_id": case.meta.id,
        "family": expected,
        "difficulty": case.meta.difficulty.value,
        "variant": label,
        "candidates": len(result.candidates),
        "slices": len(result.slices),
        "kept_slices": len(result.kept_slices()),
        "slice_tokens": sum(r.tokens for r in result.records),
    }
    if label == "vulnerable":
        file, line = _sink(case)
        row.update(
            rules=any(c.file == file and abs(c.line - line) <= LOCALIZATION_TOLERANCE for c in result.candidates),
            slice=any(s.covers(file, line) for s in result.slices),
            triage=any(s.covers(file, line) for s in result.kept_slices()),
            analysis=any(f.rule_id == expected for f in result.before_skeptic),
            skeptic=any(f.rule_id == expected for f in result.findings),
        )
    else:
        row.update(
            flagged_after_analysis=any(f.rule_id in families for f in result.before_skeptic),
            flagged_after_skeptic=any(f.rule_id in families for f in result.findings),
        )
    return row
