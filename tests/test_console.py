"""The presentation layer. It measures nothing: it checks that it shows what was computed.

What matters here is that it does not break on other people's terminals: no
color, no unicode support, and 80 columns.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from scoring.console import (
    ASCII,
    UNICODE,
    cases_table,
    engine_label,
    export_svg,
    glossary,
    header,
    log_event,
    make_console,
    metrics_table,
    outcome_of,
    symbols_for,
)
from scoring.metrics import PairOutcome, Score, VariantOutcome
from scoring.models import Case, CaseMeta

XSS = "xss-sanitizer-bypass"


def pair(case_id: str, vulnerable: str, safe: str) -> PairOutcome:
    return PairOutcome(
        case_id=case_id,
        vulnerable=VariantOutcome(case_id=case_id, label="vulnerable", cell=vulnerable),
        safe=VariantOutcome(case_id=case_id, label="safe", cell=safe),
    )


def case(case_id: str, difficulty: str = "obvious") -> Case:
    meta = CaseMeta.model_validate(
        {
            "id": case_id,
            "ecosystem": "angular",
            "family": XSS,
            "cwe": "CWE-79",
            "difficulty": difficulty,
            "source": "authored",
            "variants": {
                "vulnerable": {
                    "label": "vulnerable",
                    "rationale": "x",
                    "sink": {"file": "vulnerable/c.ts", "line": 1},
                },
                "safe": {"label": "safe", "rationale": "y"},
            },
        }
    )
    return Case(meta=meta, directory=Path("/nowhere") / case_id)


def score(pairs: list[PairOutcome]) -> Score:
    cells = [v.cell for p in pairs for v in (p.vulnerable, p.safe)]
    return Score(
        pairs=pairs,
        tp=cells.count("TP"),
        fn=cells.count("FN"),
        fp=cells.count("FP"),
        tn=cells.count("TN"),
        unmapped=__import__("collections").Counter(),
    )


@pytest.fixture
def runs():
    pairs = [
        pair("ng-xss-001", "TP", "TN"),
        pair("ng-xss-002", "FN", "TN"),
        pair("ng-xss-003", "TP", "FP"),
    ]
    return [
        ("semgrep", {"tool_version": "semgrep 1.177.0"}, score(pairs)),
        ("codeql", {"tool_version": "codeql 2.27.1"}, score(pairs)),
    ]


@pytest.fixture
def cases():
    return [case("ng-xss-001"), case("ng-xss-002", "indirect"), case("ng-xss-003", "decoy")]


# --- the three states --------------------------------------------------


def test_a_solved_pair_is_solved():
    assert outcome_of(pair("c", "TP", "TN")) == "solved"


def test_a_missed_flaw_is_missed():
    assert outcome_of(pair("c", "FN", "TN")) == "missed"


def test_flagging_the_safe_twin_is_a_false_alarm():
    assert outcome_of(pair("c", "TP", "FP")) == "false_alarm"


def test_a_missed_flaw_wins_over_a_false_alarm():
    """Both at once: the one that is worse for detection is reported."""
    assert outcome_of(pair("c", "FN", "FP")) == "missed"


# --- other people's terminals ------------------------------------------


def test_no_color_turns_color_off(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert make_console().no_color is True


def test_without_no_color_rich_decides(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert make_console().no_color is False


def test_ascii_fallback_when_the_terminal_cannot_render_symbols():
    ascii_only = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    assert symbols_for(ascii_only) == ASCII


def test_utf8_uses_the_nice_symbols():
    utf8 = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert symbols_for(utf8) == UNICODE


def test_ascii_can_be_forced_from_the_environment(monkeypatch):
    monkeypatch.setenv("SAST_BENCH_ASCII", "1")
    utf8 = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert symbols_for(utf8) == ASCII


# --- 80 columns ---------------------------------------------------------


def render_at(width: int, runs, cases) -> list[str]:
    console = make_console(width=width)
    with console.capture() as capture:
        header(console, corpus="corpus/angular", runs=runs)
        glossary(console)
        console.print(cases_table(console, runs, cases))
        console.print(metrics_table(console, runs))
    return capture.get().splitlines()


def test_nothing_goes_past_80_columns(runs, cases):
    for line in render_at(80, runs, cases):
        assert len(line) <= 80, f"{len(line)} columns: {line!r}"


def test_tables_stay_complete_at_80_columns(runs, cases):
    output = "\n".join(render_at(80, runs, cases))
    for expected in ("case", "difficulty", "semgrep", "codeql", "pairs", "finds", "false alarms"):
        assert expected in output
    for case_id in ("ng-xss-001", "ng-xss-002", "ng-xss-003"):
        assert case_id in output


def test_the_header_is_a_single_line(runs):
    console = make_console(width=200)
    with console.capture() as capture:
        header(console, corpus="corpus/angular", runs=runs)
    assert len(capture.get().strip().splitlines()) == 1


def test_the_glossary_is_three_lines():
    console = make_console(width=80)
    with console.capture() as capture:
        glossary(console)
    assert len(capture.get().strip().splitlines()) == 3


# --- numbers ------------------------------------------------------------


def test_the_metrics_table_uses_percentages_and_plain_names(runs):
    console = make_console(width=80)
    with console.capture() as capture:
        console.print(metrics_table(console, runs))
    output = capture.get()
    # Only 001 is solved: 002 was missed and 003 flagged the safe twin.
    assert "1/3" in output  # solved pairs over total
    assert "67%" in output  # finds: 2 TP out of 3 vulnerable
    assert "33%" in output  # false alarms: 1 FP out of 3 safe


def test_export_svg(tmp_path: Path, runs, cases):
    console = make_console(record=True, width=80)
    console.print(cases_table(console, runs, cases))
    target = tmp_path / "table.svg"
    export_svg(console, target, title="sast-bench")
    content = target.read_text(encoding="utf-8")
    assert content.startswith("<svg") or "<svg" in content
    assert "ng-xss-001" in content


def test_the_header_names_each_engine_with_its_version(runs):
    console = make_console(width=200)
    with console.capture() as capture:
        header(console, corpus="corpus/angular", runs=runs)
    output = capture.get()
    assert "semgrep 1.177.0" in output
    assert "codeql 2.27.1" in output
    assert "3 pairs" in output  # the fixture has 3


def test_a_derived_runner_does_not_repeat_its_name_in_the_header():
    """`codeql+llm` already carries name and model in its tool_version."""
    assert engine_label("codeql+llm", "codeql 2.27.1 + claude-opus-5") == (
        "codeql 2.27.1 + claude-opus-5"
    )
    assert engine_label("semgrep", "1.177.0") == "semgrep 1.177.0"


def test_a_long_event_stays_on_one_line():
    """The full reason lives in the decisions JSON; the log is for a quick glance."""
    console = make_console(width=80)
    with console.capture() as capture:
        log_event(console, "hybrid", "ng-xss-009 safe " + "a very long reason " * 20)
    lines = capture.get().rstrip("\n").splitlines()
    assert len(lines) == 1
    assert len(lines[0]) <= 80


def test_the_engine_goes_in_literal_brackets():
    console = make_console(width=200)
    with console.capture() as capture:
        log_event(console, "hybrid", "something happened")
    assert "[hybrid]" in capture.get()
