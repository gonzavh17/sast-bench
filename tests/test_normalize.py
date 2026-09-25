"""Normalization of each tool's raw output into the common Finding.

Payloads are synthetic and minimal: they cover the shape of SARIF and of
Semgrep's JSON without invoking either tool.
"""

from __future__ import annotations

from pathlib import Path

from scoring.normalize import from_codeql, from_semgrep


def sarif(results: list[dict], rules: list[dict] | None = None) -> dict:
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "rules": rules or []}},
                "results": results,
            }
        ]
    }


def result(rule_id: str, uri: str, line: int, level: str | None = None) -> dict:
    payload = {
        "ruleId": rule_id,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if level is not None:
        payload["level"] = level
    return payload


def test_codeql_extracts_path_line_and_rule():
    findings = from_codeql(sarif([result("js/xss", "trusted-html.ts", 8, "error")]))
    assert len(findings) == 1
    assert findings[0].path == "trusted-html.ts"
    assert findings[0].line == 8
    assert findings[0].rule_id == "js/xss"
    assert findings[0].severity == "ERROR"


def test_codeql_uses_the_rule_default_when_the_result_has_no_level():
    """CodeQL only emits `level` when it differs from the driver default."""
    payload = sarif(
        [result("js/incomplete-sanitization", "a.ts", 3)],
        rules=[
            {
                "id": "js/incomplete-sanitization",
                "defaultConfiguration": {"level": "warning"},
            }
        ],
    )
    assert from_codeql(payload)[0].severity == "WARNING"


def test_codeql_does_not_shorten_the_rule_id():
    """`js/xss` has no path prefix: splitting on the dot would break it."""
    findings = from_codeql(sarif([result("js/incomplete-url-substring-sanitization", "a.ts", 1)]))
    assert findings[0].rule_id == "js/incomplete-url-substring-sanitization"


def test_codeql_drops_results_without_location():
    """A result without a location cannot be attributed to any variant."""
    assert from_codeql(sarif([{"ruleId": "js/xss", "locations": []}])) == []


def test_codeql_sorts_stably():
    findings = from_codeql(
        sarif(
            [
                result("js/xss", "b.ts", 1),
                result("js/xss", "a.ts", 9),
                result("js/xss", "a.ts", 2),
            ]
        )
    )
    assert [(f.path, f.line) for f in findings] == [("a.ts", 2), ("a.ts", 9), ("b.ts", 1)]


def test_semgrep_shortens_the_rule_id_and_relativizes_the_path():
    """Semgrep's path still works the same: both feed the same scoring."""
    variant_dir = Path("/corpus/ng-xss-001/vulnerable")
    payload = {
        "results": [
            {
                "check_id": "javascript.browser.security.insecure-innerhtml",
                "path": str(variant_dir / "note.component.ts"),
                "start": {"line": 15},
                "extra": {"severity": "ERROR"},
            }
        ]
    }
    findings = from_semgrep(payload, variant_dir)
    assert findings[0].rule_id == "insecure-innerhtml"
    assert findings[0].path == "note.component.ts"
