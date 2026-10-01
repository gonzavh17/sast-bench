"""The auditor's funnel, end to end, over one project directory.

    1. rules     Semgrep hotspot rules -> candidates                (free)
    2. slices    tree-sitter slices, grouped and merged             (free)
    3. triage    cheap model, one request per slice: worth a look?
    4. analysis  guided prompt on each kept slice -> findings
    5. skeptic   one request per finding; a dismissal must quote a real
                 control, checked in code against the slice

Every stage keeps its own token count, so the cost of each step is visible.
`stop_after` ends the run early: "slice" runs no model at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from auditor import prompts
from auditor.candidates import semgrep_candidates
from auditor.project import Project, load_project
from auditor.slicer import Candidate, Slice, build_slices
from runners.hybrid import Decision
from runners.llm import to_findings
from scoring.models import Finding

STAGES = ("triage", "analysis", "skeptic")


@dataclass
class StageUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    format_errors: int = 0

    def add(self, reply: Any) -> None:
        self.calls += 1
        self.input_tokens += reply.usage.input_tokens
        self.output_tokens += reply.usage.output_tokens
        self.format_errors += reply.stop_reason == "format_error"


@dataclass
class Providers:
    triage: Any
    analysis: Any
    skeptic: Any

    def label(self) -> str:
        def name(p: Any) -> str:
            return p.model if p.name == "anthropic" else f"{p.name}:{p.model}"

        return f"triage {name(self.triage)} · analysis {name(self.analysis)} · skeptic {name(self.skeptic)}"


@dataclass
class SliceRecord:
    files: list[str]
    candidates: list[dict[str, Any]]
    tokens: int
    kept: bool | None = None  # triage verdict; None when triage did not run
    triage_reason: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)  # analysis, before the skeptic


@dataclass
class AuditResult:
    project: Project
    candidates: list[Candidate]
    slices: list[Slice]
    records: list[SliceRecord]
    before_skeptic: list[Finding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)  # final
    decisions: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, StageUsage] = field(default_factory=lambda: {s: StageUsage() for s in STAGES})

    def kept_slices(self) -> list[Slice]:
        return [s for s, r in zip(self.slices, self.records) if r.kept]


# ---------------------------------------------------------------- the control check

DECLARATION = re.compile(
    r"^\s*(export\s+)?(default\s+)?(async\s+)?(function|class|interface|type|enum|constructor)\b"
    r"|^\s*(public\s+|private\s+|protected\s+|static\s+|readonly\s+|async\s+)*[\w$]+\s*\([^)]*\)\s*(:\s*[^={]+)?\{\s*$"
)


def _code_lines(slice_text: str) -> list[str]:
    lines = []
    for raw in slice_text.splitlines():
        if "|" in raw:
            lines.append(raw.split("|", 1)[1].strip())
    return [line for line in lines if line]


def valid_control(control: str, slice_text: str) -> bool:
    """A dismissal holds only if the quoted control is real code from the slice
    and not just a declaration (ng-sec-011 in phase 2 was dismissed by quoting a
    method signature)."""
    quoted = [line.strip() for line in control.strip().splitlines() if line.strip()]
    if not quoted:
        return False
    first = re.sub(r"^\s*[\w./-]+:\d+:\s*", "", quoted[0])  # "file.ts:6: code" -> "code"
    first = re.sub(r"\s+", " ", first)
    for line in _code_lines(slice_text):
        normalized = re.sub(r"\s+", " ", line)
        if first and (first in normalized or (len(normalized) > 12 and normalized in first)):
            return not DECLARATION.search(line)
    return False


# ---------------------------------------------------------------- the funnel


def _hints(candidates: list[Candidate]) -> str:
    return "\n".join(f"- {c.file}:{c.line} ({c.rule_id})" for c in sorted(candidates, key=lambda c: (c.file, c.line)))


def _project_files(project: Project) -> list[str]:
    return sorted(set(project.files) | set(project.templates))


def audit(
    project_dir: Path,
    providers: Providers | None,
    *,
    ecosystem: str = "angular",
    stop_after: str | None = None,
    on_progress: Any = None,
) -> AuditResult:
    """Run the funnel over a project. `providers` may be None only with stop_after="slice"."""
    candidates = semgrep_candidates(project_dir, ecosystem)
    project = load_project(project_dir)
    slices, _ = build_slices(project, candidates)
    records = [
        SliceRecord(
            files=sorted({u.file for u in s.units} | set(s.templates)),
            candidates=[c.__dict__ for c in s.candidates],
            tokens=s.tokens(project),
        )
        for s in slices
    ]
    result = AuditResult(project, candidates, slices, records)
    if stop_after == "slice":
        return result
    assert providers is not None

    # 3. triage: keep unless clearly harmless; an unreadable answer keeps it
    for piece, record in zip(slices, records):
        reply = providers.triage.structured(
            prompts.TRIAGE_SYSTEM,
            prompts.TRIAGE_PROMPT.format(hints=_hints(piece.candidates), slice=piece.render(project)),
            prompts.Triage,
        )
        result.usage["triage"].add(reply)
        record.kept = reply.parsed.worth_review if reply.parsed is not None else True
        record.triage_reason = reply.parsed.reason if reply.parsed is not None else "unreadable answer; kept"
        if on_progress:
            on_progress("triage", record)
    if stop_after == "triage":
        return result

    # 4. analysis on kept slices
    files = _project_files(project)
    origin: dict[tuple[str, int, str], Slice] = {}
    for piece, record in zip(slices, records):
        if not record.kept:
            continue
        reply = providers.analysis.structured(
            prompts.GUIDED_SYSTEM,
            prompts.ANALYSIS_PROMPT.format(hints=_hints(piece.candidates), slice=piece.render(project)),
            prompts.GuidedReport,
        )
        result.usage["analysis"].add(reply)
        if reply.parsed is None:
            continue
        record.findings = [f.model_dump() for f in reply.parsed.findings]
        for finding in to_findings("guided", reply.parsed, files):
            origin.setdefault((finding.path, finding.line, finding.rule_id), piece)
        if on_progress:
            on_progress("analysis", record)
    result.before_skeptic = [Finding(path=p, line=l, rule_id=r, severity="MEDIUM") for (p, l, r) in origin]
    if stop_after == "analysis":
        result.findings = list(result.before_skeptic)
        return result

    # 5. skeptic per finding
    for finding in result.before_skeptic:
        piece = origin[(finding.path, finding.line, finding.rule_id)]
        context = piece.render(project, mark=(finding.path, finding.line))
        reply = providers.skeptic.structured(
            prompts.SKEPTIC_SYSTEM,
            prompts.SKEPTIC_PROMPT.format(
                rule_id=finding.rule_id, path=finding.path, line=finding.line, severity="MEDIUM", context=context
            ),
            Decision,
        )
        result.usage["skeptic"].add(reply)
        decision = reply.parsed if isinstance(reply.parsed, Decision) else None
        verdict = decision.verdict if decision else "confirmed"
        control = decision.control if decision else ""
        rejected = verdict == "dismissed" and not valid_control(control, context)
        if rejected:
            verdict = "confirmed"
        result.decisions.append(
            {
                "finding": finding.model_dump(),
                "verdict": verdict,
                "reason": decision.reason if decision else "unreadable answer; kept",
                "control": control,
                "control_rejected": rejected,
                "stop_reason": reply.stop_reason,
            }
        )
        if verdict == "confirmed":
            result.findings.append(finding)
        if on_progress:
            on_progress("skeptic", result.decisions[-1])
    return result
