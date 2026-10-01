"""The auditor's funnel with a scripted provider: stages, stop_after, the control check."""

from __future__ import annotations

from pathlib import Path

from auditor import prompts
from auditor.funnel import survival
from auditor.pipeline import Providers, audit, valid_control
from runners.hybrid import Decision
from runners.llm import GuidedFinding, GuidedReport
from runners.providers import Reply, Usage
from scoring.models import discover_cases

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "angular"


class Scripted:
    """Answers by schema: triage keeps, analysis reports the sink, skeptic as told."""

    name = "nim"

    def __init__(self, sink: tuple[str, int], family: str, skeptic: Decision):
        self.model = "scripted"
        self.sink, self.family, self.skeptic = sink, family, skeptic
        self.calls: list[type] = []

    def structured(self, system, user, schema, effort=None):
        self.calls.append(schema)
        if schema is prompts.Triage:
            parsed = prompts.Triage(worth_review=True, reason="hotspot")
        elif schema is GuidedReport:
            file, line = self.sink
            parsed = GuidedReport(
                findings=[GuidedFinding(file=file, line=line, family=self.family, severity="high", rationale="x")]
            )
        else:
            parsed = self.skeptic
        return Reply(parsed, Usage(100, 10), "stop")


def _case(case_id: str):
    return next(c for c in discover_cases(CORPUS) if c.meta.id == case_id)


SLICE = """--- auth.service.ts ---
   7 |   remember(sessionToken: string): void {
   8 |     sessionStorage.setItem('session_token', sessionToken.slice(0, 8));
   9 |   }"""


def test_a_control_must_be_real_code_from_the_slice():
    assert valid_control("sessionStorage.setItem('session_token', sessionToken.slice(0, 8));", SLICE)
    assert valid_control("auth.service.ts:8: sessionStorage.setItem('session_token', sessionToken.slice(0, 8));", SLICE)
    assert not valid_control("if (isSafe(token)) {", SLICE)  # not in the slice
    assert not valid_control("", SLICE)


def test_a_method_signature_is_not_a_control():
    """Phase 2: ng-sec-011 vulnerable was dismissed by quoting this line."""
    assert not valid_control("remember(sessionToken: string): void {", SLICE)


def test_stop_after_slice_calls_no_model():
    case = _case("ng-sec-002")
    result = audit(case.variant_dir("vulnerable"), None, stop_after="slice")
    assert result.slices and result.records[0].kept is None
    assert survival(case, "vulnerable", result)["slice"] is True


def test_the_full_funnel_keeps_a_finding_whose_dismissal_quotes_a_signature():
    case = _case("ng-sec-011")
    bogus = Decision(verdict="dismissed", reason="x", control="remember(sessionToken: string): void {")
    provider = Scripted(("session-store.service.ts", 7), "client-side-secrets", bogus)
    result = audit(case.variant_dir("vulnerable"), Providers(provider, provider, provider))

    assert [d["control_rejected"] for d in result.decisions] == [True]
    assert [f.rule_id for f in result.findings] == ["client-side-secrets"]
    row = survival(case, "vulnerable", result)
    assert [row[s] for s in ("slice", "triage", "analysis", "skeptic")] == [True, True, True, True]
    assert result.usage["triage"].calls == len(result.slices)


def test_a_real_control_dismisses_the_finding_on_a_safe_twin():
    case = _case("ng-sec-011")
    control = "sessionStorage.setItem('session_token', sessionToken.slice(0, 8));"
    provider = Scripted(("session-store.service.ts", 8), "client-side-secrets", Decision(verdict="dismissed", reason="x", control=control))
    result = audit(case.variant_dir("safe"), Providers(provider, provider, provider))
    row = survival(case, "safe", result)
    assert row["flagged_after_analysis"] is True
    assert row["flagged_after_skeptic"] is False
