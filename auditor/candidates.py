"""Stage 1: rules mark candidates. Semgrep with the auditor's own hotspot rules."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from auditor.slicer import Candidate
from scoring.normalize import from_semgrep

RULES_DIR = Path(__file__).resolve().parent / "rules"

FAMILY_HINTS = {
    "hot-xss-": "xss-sanitizer-bypass",
    "hot-sec-": "client-side-secrets",
    "hot-authz-": "broken-authorization",
}


def family_hint(rule_id: str) -> str | None:
    for prefix, family in FAMILY_HINTS.items():
        if rule_id.startswith(prefix):
            return family
    return None


def semgrep_candidates(project_dir: Path, ecosystem: str = "angular") -> list[Candidate]:
    """Run the ecosystem's hotspot rules over a project. One candidate per hit."""
    completed = subprocess.run(
        [
            "semgrep",
            "--json",
            "--no-git-ignore",
            "--metrics=off",
            "--quiet",
            "--config",
            str(RULES_DIR / ecosystem),
            str(project_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if not completed.stdout.strip():
        raise RuntimeError(f"semgrep returned no JSON for {project_dir}:\n{completed.stderr}")
    findings = from_semgrep(json.loads(completed.stdout), project_dir)
    return [Candidate(f.path, f.line, f.rule_id, family_hint(f.rule_id)) for f in findings]
