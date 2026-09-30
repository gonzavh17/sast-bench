"""LLM providers behind one call: system prompt + user prompt -> validated schema.

- `anthropic`: Claude through `messages.parse`, with adaptive thinking. This is
  the provider for every serious measurement.
- `nim`: NVIDIA NIM through its OpenAI-compatible Chat Completions endpoint.
  Free, for debugging and iterating without spending. Runs made with it are
  marked as debug and hidden from history and compare by default.

The prompts, the response schemas and the scoring are the same for both. The
one difference: Chat Completions does not guarantee structured output, so the
NIM provider appends the expected JSON schema to the system prompt and
validates the answer with pydantic. An answer that does not validate is
recorded as `format_error`, with no findings.

The NIM key is read from NVIDIA_API_KEY. It is never logged, printed or stored.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

PROVIDERS = ("anthropic", "nim")
DEFAULT_MODEL = {"anthropic": "claude-opus-5"}
NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
NIM_KEY_ENV = "NVIDIA_API_KEY"


class ProviderError(Exception):
    """A provider that cannot work: missing key, missing model, retries exhausted."""


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class Reply:
    parsed: BaseModel | None
    usage: Usage
    stop_reason: str | None  # end_turn, refusal, format_error, ...


class AnthropicProvider:
    name = "anthropic"
    debug = False

    def __init__(self, model: str, client: Any = None) -> None:
        import anthropic

        self.model = model
        self.client = client or anthropic.Anthropic()

    def structured(
        self, system: str, user: str, schema: type[BaseModel], effort: str | None = None
    ) -> Reply:
        extra: dict[str, Any] = {"output_config": {"effort": effort}} if effort else {}
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=system,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": user}],
            output_format=schema,
            **extra,
        )
        parsed = response.parsed_output if response.stop_reason != "refusal" else None
        usage = Usage(response.usage.input_tokens, response.usage.output_tokens)
        return Reply(parsed, usage, response.stop_reason)


SCHEMA_INSTRUCTION = """

Answer with a single JSON object that matches this JSON schema, and nothing \
else: no prose, no markdown fences.

{schema}"""

THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL)


def extract_json(content: str) -> str | None:
    """The JSON object in a chat answer: drops <think> blocks and code fences."""
    text = THINK_BLOCK.sub("", content).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end < start:
        return None
    return text[start : end + 1]


def parse_answer(content: str, schema: type[BaseModel]) -> BaseModel | None:
    raw = extract_json(content)
    if raw is None:
        return None
    try:
        return schema.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError):
        return None


RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}
RETRYABLE_NAMES = {"APIConnectionError", "APITimeoutError"}


def is_retryable(error: Exception) -> bool:
    """Rate limits, server hiccups and dropped connections: worth another try."""
    return getattr(error, "status_code", None) in RETRYABLE_STATUS or type(error).__name__ in RETRYABLE_NAMES


def retry_after(error: Exception) -> float | None:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None) or {}
    try:
        return float(headers.get("retry-after"))
    except (TypeError, ValueError):
        return None


class NimProvider:
    """NVIDIA NIM, OpenAI-compatible. At most ~40 requests per minute.

    Calls are spaced by `min_interval` seconds. A 429, a 5xx or a dropped
    connection is retried with a growing wait (or the server's retry-after) up
    to `max_retries` times; anything else is raised as is.
    """

    name = "nim"
    debug = True

    def __init__(
        self,
        model: str,
        *,
        client: Any = None,
        min_interval: float = 1.5,
        max_retries: int = 6,
        timeout: float = 120.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.model = model
        self.min_interval = min_interval
        self.max_retries = max_retries
        self._sleep = sleep
        self._clock = clock
        self._last_call: float | None = None
        if client is None:
            key = os.environ.get(NIM_KEY_ENV)
            if not key:
                raise ProviderError(f"{NIM_KEY_ENV} is not set (put it in .env)")
            import openai

            # Retries are handled here, so the 429 policy is ours and testable.
            # A hung model must not block a run: each request gets `timeout`
            # seconds, and a timeout is retried like any transient error.
            client = openai.OpenAI(base_url=NIM_BASE_URL, api_key=key, max_retries=0, timeout=timeout)
        self.client = client

    def _throttle(self) -> None:
        if self._last_call is not None:
            wait = self.min_interval - (self._clock() - self._last_call)
            if wait > 0:
                self._sleep(wait)
        self._last_call = self._clock()

    def structured(
        self, system: str, user: str, schema: type[BaseModel], effort: str | None = None
    ) -> Reply:
        # `effort` is a Claude parameter; NIM models have no equivalent.
        messages = [
            {"role": "system", "content": system + SCHEMA_INSTRUCTION.format(schema=json.dumps(schema.model_json_schema()))},
            {"role": "user", "content": user},
        ]
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                response = self.client.chat.completions.create(
                    model=self.model, messages=messages, temperature=0, max_tokens=8192
                )
                break
            except Exception as error:  # the SDK raises typed errors; only transient ones are retried
                if not is_retryable(error):
                    raise
                if attempt == self.max_retries:
                    status = getattr(error, "status_code", None) or type(error).__name__
                    raise ProviderError(f"NIM kept failing ({status}): gave up after {attempt + 1} attempts") from None
                self._sleep(retry_after(error) or min(60.0, 2.0 * 2**attempt))

        choice = response.choices[0]
        usage = response.usage
        tokens = Usage(getattr(usage, "prompt_tokens", 0) or 0, getattr(usage, "completion_tokens", 0) or 0)
        parsed = parse_answer(choice.message.content or "", schema)
        stop_reason = choice.finish_reason if parsed is not None else "format_error"
        return Reply(parsed, tokens, stop_reason)


def make_provider(name: str, model: str | None) -> AnthropicProvider | NimProvider:
    if name not in PROVIDERS:
        raise ProviderError(f"unknown provider {name!r}; options: {', '.join(PROVIDERS)}")
    model = model or DEFAULT_MODEL.get(name)
    if not model:
        raise ProviderError(f"--model is required with --provider {name}")
    if name == "anthropic":
        return AnthropicProvider(model)
    return NimProvider(model)
