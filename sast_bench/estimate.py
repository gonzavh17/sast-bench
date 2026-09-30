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

# What serious measurements run on. Debug runs (free providers) report what the
# same tokens would have cost with it.
OPUS_REFERENCE = "claude-opus-5"


def price(model: str, input_tokens: int, output_tokens: int) -> float | None:
    """USD for these tokens with `model`, or None if its price is unknown."""
    prices = PRICES_PER_MTOK.get(model)
    if prices is None:
        return None
    return (input_tokens * prices[0] + output_tokens * prices[1]) / 1_000_000


def usage_costs(provider: str, model: str, input_tokens: int, output_tokens: int) -> dict[str, float | None]:
    """What goes in the manifest: real cost, and the Opus equivalent."""
    real = 0.0 if provider != "anthropic" else price(model, input_tokens, output_tokens)
    opus = price(OPUS_REFERENCE, input_tokens, output_tokens)
    return {
        "cost_usd": None if real is None else round(real, 4),
        "opus_equivalent_usd": None if opus is None else round(opus, 4),
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
        return price(self.model, self.input_tokens, self.output_tokens)

    @property
    def opus_equivalent_usd(self) -> float | None:
        return price(OPUS_REFERENCE, self.input_tokens, self.output_tokens)


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


# For the LLM-only arm, when there are no previous responses of the same model
# and arm: code tokens are estimated from characters, output from a reference.
CHARS_PER_TOKEN = 3.5
PROMPT_OVERHEAD_TOKENS = 400  # system prompt + wrapper
FALLBACK_LLM_OUTPUT = 1500


def estimate_llm(contexts: list[str], model: str, arm: str, history: list[dict[str, Any]]) -> Estimate:
    """One call per variant. Averages previous responses of the same model and arm if any."""
    calls = len(contexts)
    same = [r for r in history if r.get("model") == model and r.get("arm") == arm and "input_tokens" in r]
    if same:
        return Estimate(
            calls=calls,
            model=model,
            input_per_call=round(sum(r["input_tokens"] for r in same) / len(same)),
            output_per_call=round(sum(r["output_tokens"] for r in same) / len(same)),
            sample=len(same),
        )
    chars = sum(len(c) for c in contexts) / max(calls, 1)
    return Estimate(
        calls=calls,
        model=model,
        input_per_call=round(chars / CHARS_PER_TOKEN) + PROMPT_OVERHEAD_TOKENS,
        output_per_call=FALLBACK_LLM_OUTPUT,
        sample=0,
    )
