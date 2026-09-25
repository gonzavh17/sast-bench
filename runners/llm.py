"""LLM-only arm: the model reviews each variant on its own, with no rule-based tool.

PROJECT.md, phase 2, "LLMs". Two arms over the same corpus:

- **blind**: "review this code and report what you find". The families are not
  named. The model reports a CWE per finding, and `scoring/rule_map/llm-blind.yaml`
  maps CWEs to families. It is the arm comparable with Semgrep and CodeQL.
- **guided**: the same, plus the three families described. The model tags each
  finding with a family id or `other`. It measures the ceiling with the scope
  narrowed down.

Design decisions that define what is measured:

- **One variant per request**, never its twin: the model is never told whether
  it is looking at the vulnerable or the safe side, and never sees meta.yaml.
- **No finding marker.** The context is every file of the variant, numbered, with
  nothing pointing at a line.
- **No fallback model.** A refusal is recorded as such, with no findings. Silently
  switching models would mix two engines in one row.

The results file has the same format as every other runner. The model's
rationales and token usage go to a separate responses trail.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Literal

import anthropic
from pydantic import BaseModel
from rich.console import Console

from runners.hybrid import build_context
from scoring.console import log_event, progress_bar
from scoring.models import VARIANT_LABELS, Case, Finding, Strict

DEFAULT_MODEL = "claude-opus-5"
ARMS = ("blind", "guided")

BLIND_SYSTEM = """\
You are a security reviewer. Analyze this Angular code and report the \
vulnerabilities you find. If there are none, return an empty list.

For each vulnerability, give the file, the line where it happens, its CWE id, \
a severity and a short rationale.\
"""

GUIDED_SYSTEM = """\
You are a security reviewer. Analyze this Angular code and report the \
vulnerabilities you find. If there are none, return an empty list.

Focus on these three families:

- xss-sanitizer-bypass: content manually marked as trusted, raw HTML written \
into the DOM, direct DOM manipulation that goes around Angular, URLs whose \
scheme or origin is not properly validated.
- client-side-secrets: sensitive data on the client: secrets in configuration \
shipped to the browser, credentials in browser storage, sensitive data in \
logs, caches or state.
- broken-authorization: authorization decided or asserted on the client based \
on data the user can modify: roles in storage, unverified token claims, \
identifiers taken from the URL, identity headers set by the client.

For each vulnerability, give the file, the line where it happens, its family \
(or `other` if it fits none of the three), a severity and a short rationale.\
"""

USER_PROMPT = """\
Code of the unit under review, every file, with line numbers:

{context}\
"""


class BlindFinding(BaseModel):
    file: str
    line: int
    cwe: str
    severity: Literal["low", "medium", "high", "critical"]
    rationale: str


class BlindReport(BaseModel):
    findings: list[BlindFinding]


class GuidedFinding(BaseModel):
    file: str
    line: int
    family: Literal["xss-sanitizer-bypass", "client-side-secrets", "broken-authorization", "other"]
    severity: Literal["low", "medium", "high", "critical"]
    rationale: str


class GuidedReport(BaseModel):
    findings: list[GuidedFinding]


ARM_SPEC: dict[str, tuple[str, type[BaseModel]]] = {
    "blind": (BLIND_SYSTEM, BlindReport),
    "guided": (GUIDED_SYSTEM, GuidedReport),
}


class ResponseRecord(Strict):
    """One variant's review, with everything needed to audit it later."""

    case_id: str
    variant: str
    arm: str
    model: str
    effort: str | None
    stop_reason: str | None
    findings: list[dict[str, Any]]
    input_tokens: int
    output_tokens: int
    reviewed_at: str


CWE = re.compile(r"CWE[\s:_-]*(\d+)", re.IGNORECASE)


def normalize_cwe(raw: str) -> str:
    """`cwe-79`, `CWE79`, `79` -> `CWE-79`. Anything else stays as reported."""
    match = CWE.search(raw) or re.fullmatch(r"\s*(\d+)\s*", raw)
    return f"CWE-{match.group(1)}" if match else raw.strip()


def resolve_path(reported: str, files: list[str]) -> str:
    """Map the file the model named to a real file of the variant.

    Models sometimes prefix a directory or `./`. If nothing matches, the path is
    kept as reported: the finding still counts for detection, it just will not
    count as localized.
    """
    cleaned = reported.strip().lstrip("./")
    if cleaned in files:
        return cleaned
    for name in files:
        if cleaned.endswith("/" + name) or cleaned.endswith(name):
            return name
    return cleaned


def to_findings(arm: str, report: BaseModel, files: list[str]) -> list[Finding]:
    findings = []
    for item in report.findings:  # type: ignore[attr-defined]
        rule_id = normalize_cwe(item.cwe) if arm == "blind" else item.family
        findings.append(
            Finding(
                path=resolve_path(item.file, files),
                line=max(1, item.line),
                rule_id=rule_id,
                severity=item.severity.upper(),
            )
        )
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def review_variant(
    client: anthropic.Anthropic, variant_dir: Path, arm: str, model: str, effort: str | None
) -> tuple[BaseModel | None, Any, str | None]:
    system, schema = ARM_SPEC[arm]
    extra: dict[str, Any] = {"output_config": {"effort": effort}} if effort else {}
    response = client.messages.parse(
        model=model,
        max_tokens=16000,
        system=system,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": USER_PROMPT.format(context=build_context(variant_dir))}],
        output_format=schema,
        **extra,
    )
    parsed = response.parsed_output if response.stop_reason != "refusal" else None
    return parsed, response.usage, response.stop_reason


def variant_files(variant_dir: Path) -> list[str]:
    return sorted(p.relative_to(variant_dir).as_posix() for p in variant_dir.rglob("*") if p.is_file())


def scan(
    cases: list[Case],
    arm: str,
    model: str,
    effort: str | None,
    client: anthropic.Anthropic,
    console: Console,
) -> tuple[dict[str, Any], list[ResponseRecord]]:
    """Review every variant with one arm. Returns the results and the responses trail."""
    variants: list[dict[str, Any]] = []
    records: list[ResponseRecord] = []
    todo = [(case, label) for case in cases for label in VARIANT_LABELS]
    tool = f"llm-{arm}"

    with progress_bar(console) as bar:
        task = bar.add_task(f"{tool} reviewing", total=len(todo))
        for case, label in todo:
            variant_dir = case.variant_dir(label)
            bar.update(task, description=f"{case.meta.id} {label}")
            parsed, usage, stop_reason = review_variant(client, variant_dir, arm, model, effort)
            findings = to_findings(arm, parsed, variant_files(variant_dir)) if parsed else []
            refused = " [red](refused)[/red]" if stop_reason == "refusal" else ""
            rules = ", ".join(sorted({f.rule_id for f in findings})) or "—"
            log_event(console, tool, f"{case.meta.id} {label:10} {len(findings)} findings · {rules}{refused}")
            variants.append(
                {
                    "case_id": case.meta.id,
                    "case_dir": str(case.directory),
                    "variant": label,
                    "findings": [f.model_dump() for f in findings],
                }
            )
            records.append(
                ResponseRecord(
                    case_id=case.meta.id,
                    variant=label,
                    arm=arm,
                    model=model,
                    effort=effort,
                    stop_reason=stop_reason,
                    findings=[item.model_dump() for item in parsed.findings] if parsed else [],  # type: ignore[attr-defined]
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    reviewed_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                )
            )
            bar.advance(task)

    results = {
        "tool": tool,
        "tool_version": f"{model}" + (f" effort={effort}" if effort else ""),
        "run_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "rules": {"kind": "prompt", "arm": arm, "model": model, "effort": effort},
        "variants": variants,
    }
    return results, records
