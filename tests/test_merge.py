"""scripts/merge_runs.py: a re-run replaces exactly the cases it covers."""

from __future__ import annotations

import pytest

from scripts.merge_runs import merge


def _results(tool: str, entries: list[tuple[str, str, int]]) -> dict:
    return {
        "tool": tool,
        "tool_version": "x",
        "variants": [
            {"case_id": case, "case_dir": f"corpus/angular/{family}/{case}", "variant": v, "findings": [{}] * n}
            for case, family, n in entries
            for v in ("vulnerable", "safe")
        ],
    }


def test_the_override_replaces_its_cases_and_keeps_the_rest():
    base = _results("codeql", [("a", "broken-authorization", 0), ("b", "broken-authorization", 0)])
    override = _results("codeql", [("b", "broken-authorization", 2)])
    merged = merge(base, override, "broken-authorization")
    by_case = {(e["case_id"], e["variant"]): len(e["findings"]) for e in merged["variants"]}
    assert by_case == {("a", "vulnerable"): 0, ("a", "safe"): 0, ("b", "vulnerable"): 2, ("b", "safe"): 2}


def test_the_family_filter_drops_other_families_from_the_base():
    base = _results("llm-blind", [("x", "xss-sanitizer-bypass", 1), ("a", "broken-authorization", 0)])
    override = _results("llm-blind", [("b", "broken-authorization", 1)])
    merged = merge(base, override, "broken-authorization")
    assert {e["case_id"] for e in merged["variants"]} == {"a", "b"}


def test_different_tools_do_not_merge():
    with pytest.raises(ValueError):
        merge(_results("codeql", []), _results("semgrep", []), None)
