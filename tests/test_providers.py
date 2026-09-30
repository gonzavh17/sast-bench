"""LLM providers with the API mocked: parsing, 429 retries, spacing, debug runs, key hygiene."""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from runners import hybrid, llm
from runners.providers import NimProvider, ProviderError, extract_json, make_provider
from sast_bench.estimate import usage_costs
from sast_bench.runs import MANIFEST, list_runs
from scoring.console import make_console
from scoring.models import Finding, discover_cases

REPO = Path(__file__).resolve().parent.parent
SECRET = "nvapi-THIS-MUST-NEVER-SHOW-UP"


class FakeRateLimit(Exception):
    status_code = 429

    def __init__(self, retry_after: str | None = None):
        super().__init__("rate limited")
        self.response = SimpleNamespace(headers={"retry-after": retry_after} if retry_after else {})


def completion(content: str, prompt_tokens: int = 100, completion_tokens: int = 50):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


class FakeClient:
    """Plays back a script of answers or exceptions, and records every request."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(seconds, 3))
        self.now += seconds


def provider(script, clock=None):
    clock = clock or Clock()
    return NimProvider("test/model", client=FakeClient(script), sleep=clock.sleep, clock=clock.time), clock


EMPTY = '{"findings": []}'
ONE_BLIND = json.dumps(
    {"findings": [{"file": "a.ts", "line": 3, "cwe": "CWE-79", "severity": "high", "rationale": "x"}]}
)


# ---------------------------------------------------------------- parsing


def test_extract_json_drops_think_blocks_and_fences():
    raw = '<think>let me see {not json}</think>\n```json\n{"findings": []}\n```'
    assert json.loads(extract_json(raw)) == {"findings": []}


def test_a_valid_answer_is_parsed_and_counted():
    nim, _ = provider([completion(ONE_BLIND, 120, 40)])
    reply = nim.structured("system", "user", llm.BlindReport)
    assert reply.parsed.findings[0].cwe == "CWE-79"
    assert (reply.usage.input_tokens, reply.usage.output_tokens) == (120, 40)
    assert reply.stop_reason == "stop"


def test_an_unreadable_answer_is_a_format_error_with_no_findings():
    nim, _ = provider([completion("I think this code is fine.")])
    reply = nim.structured("system", "user", llm.BlindReport)
    assert reply.parsed is None
    assert reply.stop_reason == "format_error"


def test_the_schema_goes_into_the_system_prompt():
    nim, _ = provider([completion(EMPTY)])
    nim.structured("SYSTEM", "USER", llm.BlindReport)
    messages = nim.client.requests[0]["messages"]
    assert messages[0]["content"].startswith("SYSTEM")
    assert '"findings"' in messages[0]["content"]
    assert messages[1] == {"role": "user", "content": "USER"}


# ---------------------------------------------------------------- rate limit


def test_a_429_is_retried_with_a_growing_wait():
    nim, clock = provider([FakeRateLimit(), FakeRateLimit(), completion(EMPTY)])
    reply = nim.structured("s", "u", llm.BlindReport)
    assert reply.parsed is not None
    assert len(nim.client.requests) == 3
    assert [s for s in clock.slept if s >= 2] == [2.0, 4.0]


def test_retry_after_from_the_server_wins():
    nim, clock = provider([FakeRateLimit(retry_after="7"), completion(EMPTY)])
    nim.structured("s", "u", llm.BlindReport)
    assert 7.0 in clock.slept


def test_giving_up_after_max_retries_is_a_provider_error():
    nim, _ = provider([FakeRateLimit()] * 7)
    with pytest.raises(ProviderError, match="gave up"):
        nim.structured("s", "u", llm.BlindReport)


class FakeGatewayTimeout(Exception):
    status_code = 504


def test_server_errors_are_retried_too():
    nim, _ = provider([FakeGatewayTimeout(), completion(EMPTY)])
    assert nim.structured("s", "u", llm.BlindReport).parsed is not None
    assert len(nim.client.requests) == 2


def test_other_errors_are_not_retried():
    nim, _ = provider([ValueError("boom"), completion(EMPTY)])
    with pytest.raises(ValueError):
        nim.structured("s", "u", llm.BlindReport)
    assert len(nim.client.requests) == 1


def test_calls_are_spaced_to_stay_under_the_rate_limit():
    nim, clock = provider([completion(EMPTY), completion(EMPTY)])
    nim.structured("s", "u", llm.BlindReport)
    clock.now += 0.5  # the next call comes 0.5 s later
    nim.structured("s", "u", llm.BlindReport)
    assert clock.slept == [1.0]  # waits the rest of the 1.5 s


# ---------------------------------------------------------------- setup and key hygiene


def test_nim_without_a_key_does_not_start(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    with pytest.raises(ProviderError, match="NVIDIA_API_KEY"):
        NimProvider("test/model")


def test_nim_requires_an_explicit_model():
    with pytest.raises(ProviderError, match="--model"):
        make_provider("nim", None)


def test_the_key_never_reaches_results_records_or_logs(monkeypatch):
    import openai

    captured = {}

    def fake_openai(**kwargs):
        captured.update(kwargs)
        return FakeClient([completion(ONE_BLIND), completion(EMPTY)])

    monkeypatch.setenv("NVIDIA_API_KEY", SECRET)
    monkeypatch.setattr(openai, "OpenAI", fake_openai)
    nim = make_provider("nim", "test/model")
    nim._sleep = lambda s: None
    assert captured["api_key"] == SECRET  # it is used...
    assert captured["base_url"] == "https://integrate.api.nvidia.com/v1"

    case = next(c for c in discover_cases(REPO / "corpus") if c.meta.id == "ng-sec-011")
    buffer = io.StringIO()
    console = make_console(width=200)
    console.file = buffer
    results, records = llm.scan([case], "blind", nim, None, console)

    dumped = json.dumps(results) + json.dumps([r.model_dump() for r in records]) + buffer.getvalue()
    assert SECRET not in dumped  # ...and shown nowhere
    assert results["tool_version"] == "nim:test/model"
    assert results["rules"]["provider"] == "nim"
    assert records[0].provider == "nim"


# ---------------------------------------------------------------- hybrid with a debug provider


def test_hybrid_keeps_a_finding_when_the_answer_is_unreadable(tmp_path):
    (tmp_path / "a.ts").write_text("const x = 1;\n", encoding="utf-8")
    nim, _ = provider([completion("not json at all")])
    decision, reply = hybrid.judge(nim, tmp_path, Finding(path="a.ts", line=1, rule_id="js/xss", severity="ERROR"))
    assert decision.verdict == "confirmed"
    assert reply.stop_reason == "format_error"


# ---------------------------------------------------------------- debug runs and cost


def test_debug_runs_are_hidden_unless_asked_for(tmp_path):
    for run_id, debug in (("20260930-100000", False), ("20260930-110000", True)):
        run = tmp_path / "runs" / run_id
        run.mkdir(parents=True)
        (run / MANIFEST).write_text(
            json.dumps({"run_id": run_id, "started_at": f"2026-09-30T{run_id[-6:-4]}:00:00+00:00", "debug": debug, "engines": []}),
            encoding="utf-8",
        )
    assert [r.run_id for r in list_runs(tmp_path)] == ["20260930-100000"]
    assert [r.run_id for r in list_runs(tmp_path, include_debug=True)] == ["20260930-110000", "20260930-100000"]


def test_debug_runs_cost_zero_but_report_the_opus_equivalent():
    costs = usage_costs("nim", "test/model", 1_000_000, 100_000)
    assert costs == {"cost_usd": 0.0, "opus_equivalent_usd": 7.5}
    assert usage_costs("anthropic", "claude-opus-5", 1_000_000, 100_000)["cost_usd"] == 7.5
