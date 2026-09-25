"""The pure parts of the LLM-only runner, without touching the API."""

from __future__ import annotations

from pathlib import Path

import pytest

from runners.hybrid import build_context
from runners.llm import BlindFinding, BlindReport, GuidedFinding, GuidedReport, normalize_cwe, resolve_path, to_findings
from sast_bench.estimate import FALLBACK_LLM_OUTPUT, estimate_llm


@pytest.mark.parametrize("raw", ["CWE-79", "cwe-79", "CWE79", "79", " CWE-79: Cross-site Scripting"])
def test_normalize_cwe(raw: str):
    assert normalize_cwe(raw) == "CWE-79"


def test_normalize_cwe_keeps_what_it_cannot_read():
    assert normalize_cwe("XSS") == "XSS"


def test_resolve_path_maps_prefixed_names_to_real_files():
    files = ["auth.service.ts", "login.component.ts"]
    assert resolve_path("auth.service.ts", files) == "auth.service.ts"
    assert resolve_path("./auth.service.ts", files) == "auth.service.ts"
    assert resolve_path("src/app/auth.service.ts", files) == "auth.service.ts"
    assert resolve_path("unknown.ts", files) == "unknown.ts"


def test_blind_findings_use_the_cwe_as_rule_id():
    report = BlindReport(findings=[BlindFinding(file="a.ts", line=0, cwe="cwe 922", severity="high", rationale="x")])
    [finding] = to_findings("blind", report, ["a.ts"])
    assert (finding.rule_id, finding.line, finding.severity) == ("CWE-922", 1, "HIGH")


def test_guided_findings_use_the_family_as_rule_id():
    report = GuidedReport(
        findings=[GuidedFinding(file="a.ts", line=4, family="broken-authorization", severity="medium", rationale="x")]
    )
    [finding] = to_findings("guided", report, ["a.ts"])
    assert finding.rule_id == "broken-authorization"


def test_the_llm_context_has_no_marker_column(tmp_path: Path):
    """The LLM-only arm must not get a hint of where to look."""
    (tmp_path / "a.ts").write_text("one\ntwo\n", encoding="utf-8")
    context = build_context(tmp_path)
    assert ">>>" not in context
    assert "  1 | one" in context


def test_estimate_llm_without_history_uses_code_size():
    guess = estimate_llm(["x" * 3500, "y" * 3500], "claude-opus-5", "blind", [])
    assert guess.calls == 2
    assert guess.input_per_call == 1000 + 400
    assert guess.output_per_call == FALLBACK_LLM_OUTPUT


def test_estimate_llm_averages_only_the_same_model_and_arm():
    history = [
        {"model": "claude-opus-5", "arm": "blind", "input_tokens": 1000, "output_tokens": 2000},
        {"model": "claude-opus-5", "arm": "guided", "input_tokens": 9999, "output_tokens": 9999},
    ]
    guess = estimate_llm(["x"], "claude-opus-5", "blind", history)
    assert (guess.input_per_call, guess.output_per_call, guess.sample) == (1000, 2000, 1)
