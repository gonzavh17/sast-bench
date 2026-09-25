"""Metrics over synthetic Findings.

The real Semgrep run over the corpus produces no FP, so that cell would go
untested. Everything here is built in memory: it covers TP/FN/FP/TN without
invoking any tool, and separates "the scoring is right" from "Semgrep found
something".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scoring.metrics import tally
from scoring.models import Case, CaseMeta, Finding, RuleMap

XSS = "xss-sanitizer-bypass"
SECRETS = "client-side-secrets"

RULE_MAP = RuleMap.model_validate(
    {
        "meta": {"tool": "test", "rules_source": "test@0000000", "mapped_at": "2026-09-21"},
        "rules": {"xss-rule": XSS, "secrets-rule": SECRETS},
        "ignore": ["style-rule"],
    }
)


def make_case(case_id: str = "ng-xss-001", sink_line: int = 19) -> Case:
    meta = CaseMeta.model_validate(
        {
            "id": case_id,
            "ecosystem": "angular",
            "family": XSS,
            "cwe": "CWE-79",
            "difficulty": "obvious",
            "source": "authored",
            "variants": {
                "vulnerable": {
                    "label": "vulnerable",
                    "rationale": "x",
                    "sink": {"file": "vulnerable/c.ts", "line": sink_line},
                },
                "safe": {"label": "safe", "rationale": "y"},
            },
        }
    )
    return Case(meta=meta, directory=Path("/nowhere") / case_id)


def make_results(case_id: str, vulnerable: list[dict], safe: list[dict]) -> dict:
    return {
        "variants": [
            {"case_id": case_id, "variant": "vulnerable", "findings": vulnerable},
            {"case_id": case_id, "variant": "safe", "findings": safe},
        ]
    }


def finding(rule_id: str, line: int = 19, path: str = "c.ts") -> dict:
    return Finding(path=path, line=line, rule_id=rule_id, severity="ERROR").model_dump()


def score_for(vulnerable: list[dict], safe: list[dict], case: Case | None = None):
    case = case or make_case()
    return tally([case], make_results(case.meta.id, vulnerable, safe), RULE_MAP)


def test_solved_pair_is_tp_plus_tn():
    score = score_for([finding("xss-rule")], [])
    assert (score.tp, score.fn, score.fp, score.tn) == (1, 0, 0, 1)
    assert score.pairs[0].solved
    assert score.pair_score == 1.0


def test_fn_when_the_vulnerable_variant_fires_nothing():
    score = score_for([], [])
    assert (score.tp, score.fn, score.fp, score.tn) == (0, 1, 0, 1)
    assert not score.pairs[0].solved
    assert score.recall == 0.0


def test_fp_when_the_safe_variant_fires():
    """The cell the real run does not exercise."""
    score = score_for([finding("xss-rule")], [finding("xss-rule")])
    assert (score.tp, score.fn, score.fp, score.tn) == (1, 0, 1, 0)
    assert not score.pairs[0].solved
    assert score.fpr == 1.0
    assert score.precision == 0.5


def test_fp_counts_any_security_family_not_only_the_expected_one():
    """PROJECT.md: FP = safe variant with >=1 finding of *any* family."""
    score = score_for([finding("xss-rule")], [finding("secrets-rule")])
    assert score.fp == 1


def test_tp_requires_the_expected_family():
    """A finding of another family in the vulnerable variant does not save the case."""
    score = score_for([finding("secrets-rule")], [])
    assert (score.tp, score.fn) == (0, 1)


def test_recall_100_and_fpr_100_give_pair_score_0():
    """The scenario PROJECT.md names as the point of the benchmark."""
    cases = [make_case("ng-xss-001"), make_case("ng-xss-002")]
    results = {"variants": []}
    for case in cases:
        results["variants"] += make_results(case.meta.id, [finding("xss-rule")], [finding("xss-rule")])["variants"]
    score = tally(cases, results, RULE_MAP)
    assert score.recall == 1.0
    assert score.fpr == 1.0
    assert score.pair_score == 0.0


def test_unmapped_rule_id_counts_as_neither_tp_nor_fp():
    score = score_for([finding("new-rule")], [finding("another-new-rule")])
    assert (score.tp, score.fn, score.fp, score.tn) == (0, 1, 0, 1)
    assert score.unmapped == {"new-rule": 1, "another-new-rule": 1}
    assert score.noise == 1.0


def test_ignored_rule_id_is_neither_noise_nor_fp():
    score = score_for([finding("xss-rule")], [finding("style-rule")])
    assert (score.tp, score.tn) == (1, 1)
    assert score.unmapped == {}
    assert score.noise == 0.0
    assert score.pairs[0].solved


@pytest.mark.parametrize("line,localized", [(19, True), (22, True), (23, False)])
def test_localization_tolerates_plus_minus_three_lines(line: int, localized: bool):
    score = score_for([finding("xss-rule", line=line)], [])
    assert score.pairs[0].vulnerable.localized is localized
    assert score.localization == (1.0 if localized else 0.0)


def test_localization_requires_the_sink_file():
    score = score_for([finding("xss-rule", path="other.ts")], [])
    assert score.pairs[0].vulnerable.localized is False


def test_empty_corpus_does_not_divide_by_zero():
    score = tally([], {"variants": []}, RULE_MAP)
    assert score.pair_score == 0.0
    assert score.f1 == 0.0
    assert score.noise == 0.0
