"""Prompts and response schemas for the auditor's LLM stages.

- triage: cheap model, one question per slice: is there anything worth a
  closer look? It is told to keep anything it is unsure about.
- analysis: the guided arm's prompt (runners/llm.py), on a slice instead of a
  whole variant, plus the lines the rules marked, presented as hints.
- skeptic: the hybrid's filter prompt (runners/hybrid.py), on a slice with the
  finding's line marked.
"""

from __future__ import annotations

from pydantic import BaseModel

from runners.hybrid import PROMPT as SKEPTIC_PROMPT
from runners.hybrid import SYSTEM as SKEPTIC_SYSTEM
from runners.llm import GUIDED_SYSTEM, GuidedReport

TRIAGE_SYSTEM = """\
You triage the output of a static analyzer for an Angular application. You get \
a slice of the code and the lines the analyzer marked. Decide whether the slice \
deserves a careful security review for any of these: content trusted or \
written into the DOM without sanitizing, sensitive data exposed on the client \
(storage, logs, caches, configuration shipped to the browser), or an \
authorization decision taken or asserted on the client with data the user \
controls.

Keep it (worth_review = true) unless it is clearly harmless. When in doubt, \
keep it: a later step will look closely.\
"""

TRIAGE_PROMPT = """\
Lines the analyzer marked:
{hints}

Code slice, with the project's line numbers:

{slice}\
"""

ANALYSIS_PROMPT = """\
Code slice of the unit under review, with the project's line numbers. It may \
skip parts of a file; `...` marks a gap.

The rules marked these lines. They are hints about where to look, not findings:
{hints}

{slice}\
"""


class Triage(BaseModel):
    worth_review: bool
    reason: str


__all__ = [
    "ANALYSIS_PROMPT",
    "GUIDED_SYSTEM",
    "GuidedReport",
    "SKEPTIC_PROMPT",
    "SKEPTIC_SYSTEM",
    "TRIAGE_PROMPT",
    "TRIAGE_SYSTEM",
    "Triage",
]
