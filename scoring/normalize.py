"""Raw output of each tool -> common Finding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scoring.models import Finding


def from_semgrep(payload: dict[str, Any], variant_dir: Path) -> list[Finding]:
    """Normalize the `semgrep --json` output of a run over one variant.

    Paths end up relative to the variant directory, so the result does not
    depend on where the corpus is mounted.
    """
    findings: list[Finding] = []
    for result in payload.get("results", []):
        findings.append(
            Finding(
                path=_relative(result.get("path", ""), variant_dir),
                line=max(1, int(result.get("start", {}).get("line", 1))),
                rule_id=_short_rule_id(result.get("check_id", "")),
                severity=str(result.get("extra", {}).get("severity", "UNKNOWN")),
            )
        )
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def from_codeql(payload: dict[str, Any]) -> list[Finding]:
    """Normalize the SARIF from `codeql database analyze` for one variant.

    SARIF paths are already relative to --source-root, which is the variant
    directory, so there is nothing to recompute.
    """
    findings: list[Finding] = []
    for run in payload.get("runs", []):
        levels = _sarif_default_levels(run)
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            location = _sarif_location(result)
            if location is None:
                continue
            path, line = location
            findings.append(
                Finding(
                    path=path,
                    line=line,
                    rule_id=rule_id,
                    # CodeQL only emits `level` when it differs from the rule's
                    # default, so the driver's default is the one that applies.
                    severity=str(result.get("level") or levels.get(rule_id, "warning")).upper(),
                )
            )
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def _sarif_default_levels(run: dict[str, Any]) -> dict[str, str]:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    return {
        rule.get("id", ""): rule.get("defaultConfiguration", {}).get("level", "warning")
        for rule in rules
    }


def _sarif_location(result: dict[str, Any]) -> tuple[str, int] | None:
    locations = result.get("locations", [])
    if not locations:
        return None
    physical = locations[0].get("physicalLocation", {})
    uri = physical.get("artifactLocation", {}).get("uri")
    if not uri:
        return None
    return Path(uri).as_posix(), max(1, int(physical.get("region", {}).get("startLine", 1)))


def _relative(raw_path: str, variant_dir: Path) -> str:
    try:
        return Path(raw_path).resolve().relative_to(variant_dir.resolve()).as_posix()
    except ValueError:
        return Path(raw_path).as_posix()


def _short_rule_id(check_id: str) -> str:
    """Semgrep prefixes the check_id with the path of the rule file.

    `javascript.browser.security.insecure-innerhtml` -> `insecure-innerhtml`.
    The rule_map uses the short id, which is the one the rule publishes.
    """
    return check_id.rsplit(".", 1)[-1] if check_id else check_id
