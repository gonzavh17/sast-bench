"""What running the LLM filter would cost, without calling the model.

Calls = findings to review (the filter makes one per finding, never batched).
Tokens per call = the average of the real decisions already saved; if there
are none, a reference value. Output includes thinking, which is billed as
output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# USD per million tokens (input, output). Anthropic SDK pricing table, cached
# 2026-06-24. Update here if it changes.
PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-fable-5-1": (10.00, 50.00),
}

# When there are no previous decisions: the order of the first XSS run.
FALLBACK_TOKENS = (1200, 400)


@dataclass(frozen=True)
class Estimate:
    calls: int
    model: str
    input_per_call: int
    output_per_call: int
    sample: int  # previous decisions the average is based on; 0 = reference value

    @property
    def input_tokens(self) -> int:
        return self.calls * self.input_per_call

    @property
    def output_tokens(self) -> int:
        return self.calls * self.output_per_call

    @property
    def cost_usd(self) -> float | None:
        prices = PRICES_PER_MTOK.get(self.model)
        if prices is None:
            return None
        return (self.input_tokens * prices[0] + self.output_tokens * prices[1]) / 1_000_000


def count_findings(results: dict[str, Any], case_ids: set[str] | None = None) -> int:
    return sum(
        len(entry["findings"])
        for entry in results["variants"]
        if case_ids is None or entry["case_id"] in case_ids
    )


def estimate(calls: int, model: str, history: list[dict[str, Any]]) -> Estimate:
    """Average only decisions from the same model: another model thinks differently."""
    same = [r for r in history if r.get("model") == model and "input_tokens" in r]
    if same:
        return Estimate(
            calls=calls,
            model=model,
            input_per_call=round(sum(r["input_tokens"] for r in same) / len(same)),
            output_per_call=round(sum(r["output_tokens"] for r in same) / len(same)),
            sample=len(same),
        )
    return Estimate(calls, model, *FALLBACK_TOKENS, sample=0)
