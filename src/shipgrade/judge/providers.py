"""The real provider clients behind the JudgeClient seam (spec 5.3), plus provider and
model-caller selection. Each client calls its SDK's tool-use API at temperature 0 for
judging and exposes a plain complete() at temperature 0 (no tools) that makes it a
prompt-file ModelCaller (spec 5.1, doc 03). Anthropic marks the rubric system block for
prompt caching. The SDKs are lazy-imported inside each __init__ so importing this module
never requires either SDK. Keys are read from the environment by the SDKs and never logged
or placed in a repr."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, cast

from shipgrade.adapters.base import ModelCaller
from shipgrade.judge.llm import JudgeClient
from shipgrade.models import Config, Provider

_DEFAULT_MODEL: dict[Provider, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4.1",
}

_PROVIDER_KEY_ENV: dict[Provider, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}


@dataclass(frozen=True)
class MissingProviderKey:
    """Returned by select_model_caller when a provider is explicitly configured (target or
    judge) but its API key is absent from the environment. The check happens before any SDK
    client is constructed, so the CLI gets an actionable signal instead of an SDK constructor
    exception. Deliberately NOT a tuple, so a success tuple is distinguishable by isinstance.
    Carries no key material; only the provider name."""

    provider: Provider


class AnthropicJudgeClient:
    """JudgeClient backed by the Anthropic SDK; also a prompt-file ModelCaller via complete()."""

    def __init__(self, *, model: str) -> None:
        from anthropic import AsyncAnthropic

        self._model = model
        self._client = AsyncAnthropic()

    def __repr__(self) -> str:
        return f"AnthropicJudgeClient(model={self._model!r})"

    async def complete(self, *, system: str, prompt: str) -> str:
        """Call the model as the prompt-file target: the system prompt under test as the
        system message, the probe input as the one user message, temperature 0, no tools."""
        msg = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        for block in msg.content:
            if block.type == "text":
                return block.text
        return ""

    async def get_verdict_args(
        self, *, system: list[dict], user_text: str, tool_schema: dict
    ) -> dict:
        cached = [{**system[0], "cache_control": {"type": "ephemeral"}}, *system[1:]]
        msg = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            temperature=0,
            system=cast(Any, cached),
            tools=[cast(Any, tool_schema)],
            tool_choice={"type": "tool", "name": tool_schema["name"]},
            messages=[{"role": "user", "content": user_text}],
        )
        for block in msg.content:
            if block.type == "tool_use":
                return cast(dict[str, Any], block.input)
        raise ValueError("anthropic judge returned no tool_use block")


class OpenAIJudgeClient:
    """JudgeClient backed by the OpenAI SDK; also a prompt-file ModelCaller via complete()."""

    def __init__(self, *, model: str) -> None:
        from openai import AsyncOpenAI

        self._model = model
        self._client = AsyncOpenAI()

    def __repr__(self) -> str:
        return f"OpenAIJudgeClient(model={self._model!r})"

    async def complete(self, *, system: str, prompt: str) -> str:
        """Call the model as the prompt-file target: the system prompt under test as the
        system message, the probe input as the user message, temperature 0, no tools."""
        resp = await self._client.chat.completions.create(
            model=self._model,
            temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""

    async def get_verdict_args(
        self, *, system: list[dict], user_text: str, tool_schema: dict
    ) -> dict:
        import json

        system_text = "\n\n".join(b["text"] for b in system)
        fn = {
            "type": "function",
            "function": {
                "name": tool_schema["name"],
                "description": tool_schema["description"],
                "parameters": tool_schema["input_schema"],
            },
        }
        resp = await self._client.chat.completions.create(
            model=self._model,
            temperature=0,
            tools=[cast(Any, fn)],
            tool_choice={"type": "function", "function": {"name": tool_schema["name"]}},
            messages=[
                {"role": "system", "content": system_text},
                {"role": "user", "content": user_text},
            ],
        )
        tool_calls = resp.choices[0].message.tool_calls
        if not tool_calls:
            raise ValueError("openai judge returned no tool call")
        call = tool_calls[0]
        if call.type == "function":
            return json.loads(call.function.arguments)
        raise ValueError("openai judge returned no tool call")


def select_judge(config: Config) -> tuple[JudgeClient, Provider] | None:
    """Resolve the judge by precedence: explicit config.judge_provider wins; else
    ANTHROPIC_API_KEY selects anthropic; else OPENAI_API_KEY selects openai; else None
    (the run stays deterministic-only). Both keys with no explicit choice resolves to
    anthropic. The chosen model is config.judge_model or the provider default."""
    provider: Provider | None = config.judge_provider
    if provider is None:
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        else:
            return None
    model = config.judge_model or _DEFAULT_MODEL[provider]
    client: JudgeClient
    if provider == "anthropic":
        client = AnthropicJudgeClient(model=model)
    else:
        client = OpenAIJudgeClient(model=model)
    return client, provider


def select_model_caller(
    config: Config,
) -> tuple[ModelCaller, Provider, str] | MissingProviderKey | None:
    """Resolve the provider model caller a prompt-file scan uses to call its target (doc 03).

    Provider precedence: an explicitly configured target_provider wins, else judge_provider,
    else env-key precedence (ANTHROPIC_API_KEY before OPENAI_API_KEY). Model precedence:
    target_model, else judge_model, else the provider's default.

    The key check happens BEFORE constructing any SDK client. An explicitly configured
    provider whose key is missing returns MissingProviderKey(provider) so the CLI can give an
    actionable error, never an SDK constructor exception. No explicit provider and no env key
    returns None (a prompt-file scan cannot proceed without a key). The returned model and
    provider are the RESOLVED values the CLI records in the report metadata."""
    explicit = config.target.target_provider or config.judge_provider
    if explicit is not None:
        provider = explicit
        # An explicit choice does not consult env precedence; if its key is absent we signal
        # the CLI rather than letting the SDK constructor raise (which could surface a key).
        if not os.environ.get(_PROVIDER_KEY_ENV[provider]):
            return MissingProviderKey(provider)
    elif os.environ.get("ANTHROPIC_API_KEY"):
        provider = "anthropic"
    elif os.environ.get("OPENAI_API_KEY"):
        provider = "openai"
    else:
        return None
    model = config.target.target_model or config.judge_model or _DEFAULT_MODEL[provider]
    caller: ModelCaller
    if provider == "anthropic":
        caller = AnthropicJudgeClient(model=model)
    else:
        caller = OpenAIJudgeClient(model=model)
    return caller, provider, model
