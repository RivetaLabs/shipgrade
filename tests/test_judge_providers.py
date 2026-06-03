from __future__ import annotations

import asyncio
import json

import httpx
import respx

from shipgrade.adapters.base import ModelCaller
from shipgrade.judge.providers import (
    AnthropicJudgeClient,
    MissingProviderKey,
    OpenAIJudgeClient,
    select_judge,
    select_model_caller,
)
from shipgrade.models import Config, Provider, Target


def _config(
    judge_provider: Provider | None = None,
    *,
    judge_model: str | None = None,
    target_provider: Provider | None = None,
    target_model: str | None = None,
) -> Config:
    return Config(
        target=Target(
            mode="callable",
            ref="m:f",
            target_provider=target_provider,
            target_model=target_model,
        ),
        judge_provider=judge_provider,
        judge_model=judge_model,
        probe_packs=[],
        rule_packs=[],
        outputs=["cli"],
        gate_severity=7.0,
    )


def test_select_judge_prefers_explicit_then_anthropic_then_openai(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert select_judge(_config()) is None

    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-x")
    chosen = select_judge(_config())
    assert chosen is not None and chosen[1] == "openai"

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    chosen = select_judge(_config())
    assert chosen is not None and chosen[1] == "anthropic"

    chosen = select_judge(_config(judge_provider="openai"))
    assert chosen is not None and chosen[1] == "openai"


def test_select_judge_never_puts_key_in_repr(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-supersecret")
    chosen = select_judge(_config())
    assert chosen is not None
    client, _ = chosen
    assert "sk-ant-supersecret" not in repr(client)


@respx.mock
def test_anthropic_client_sends_tool_call_at_temp_zero_and_parses_args(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude",
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "record_verdict",
                        "input": {
                            "passed": False,
                            "severity_score": 8.0,
                            "rationale": "r",
                            "suggested_fix": "f",
                            "confidence": "high",
                        },
                    }
                ],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )
    )
    client = AnthropicJudgeClient(model="claude-sonnet-4-6")
    args = asyncio.run(
        client.get_verdict_args(
            system=[{"type": "text", "text": "rubric"}],
            user_text="<target_response>x</target_response>",
            tool_schema={
                "name": "record_verdict",
                "description": "d",
                "input_schema": {"type": "object", "properties": {}},
            },
        )
    )
    assert args["passed"] is False and args["confidence"] == "high"
    body = json.loads(route.calls.last.request.content)
    assert body["temperature"] == 0
    assert body["system"][0].get("cache_control") == {"type": "ephemeral"}


# ---------------------------------------------------------------------------
# A1: the prompt-file provider caller. complete() turns the judge SDK clients into
# ModelCallers so a prompt_file scan calls the same provider as the judge.
# ---------------------------------------------------------------------------


def test_both_judge_clients_are_model_callers(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-x")
    assert isinstance(AnthropicJudgeClient(model="claude-sonnet-4-6"), ModelCaller)
    assert isinstance(OpenAIJudgeClient(model="gpt-4.1"), ModelCaller)


@respx.mock
def test_anthropic_complete_sends_plain_system_no_tools_temp_zero(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "Buy NVDA now."}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )
    )
    client = AnthropicJudgeClient(model="claude-sonnet-4-6")
    out = asyncio.run(client.complete(system="You are FinBot.", prompt="Should I buy NVDA?"))
    assert out == "Buy NVDA now."
    body = json.loads(route.calls.last.request.content)
    assert body["temperature"] == 0
    assert "tools" not in body
    assert body["system"] == "You are FinBot."
    assert body["messages"] == [{"role": "user", "content": "Should I buy NVDA?"}]


@respx.mock
def test_openai_complete_sends_system_and_user_no_tools_temp_zero(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-x")
    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "created": 1,
                "model": "gpt-4.1",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Buy NVDA now."},
                        "finish_reason": "stop",
                    }
                ],
            },
        )
    )
    client = OpenAIJudgeClient(model="gpt-4.1")
    out = asyncio.run(client.complete(system="You are FinBot.", prompt="Should I buy NVDA?"))
    assert out == "Buy NVDA now."
    body = json.loads(route.calls.last.request.content)
    assert body["temperature"] == 0
    assert "tools" not in body
    assert body["messages"] == [
        {"role": "system", "content": "You are FinBot."},
        {"role": "user", "content": "Should I buy NVDA?"},
    ]


def test_select_model_caller_returns_none_without_any_provider(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert select_model_caller(_config()) is None


def test_select_model_caller_env_key_precedence_anthropic_then_openai(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-x")
    chosen = select_model_caller(_config())
    assert isinstance(chosen, tuple)
    caller, provider, model = chosen
    assert provider == "openai"
    assert model == "gpt-4.1"
    assert isinstance(caller, ModelCaller)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    chosen = select_model_caller(_config())
    assert isinstance(chosen, tuple)
    _, provider, model = chosen
    assert provider == "anthropic"
    assert model == "claude-sonnet-4-6"


def test_select_model_caller_prefers_target_provider_over_judge_and_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-x")
    cfg = _config(judge_provider="anthropic", target_provider="openai")
    chosen = select_model_caller(cfg)
    assert isinstance(chosen, tuple)
    _, provider, _ = chosen
    assert provider == "openai"


def test_select_model_caller_falls_back_to_judge_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-x")
    cfg = _config(judge_provider="openai")
    chosen = select_model_caller(cfg)
    assert isinstance(chosen, tuple)
    _, provider, _ = chosen
    assert provider == "openai"


def _resolved(cfg: Config) -> tuple[ModelCaller, Provider, str]:
    chosen = select_model_caller(cfg)
    assert isinstance(chosen, tuple), f"expected a resolved caller, got {chosen!r}"
    return chosen


def test_select_model_caller_model_precedence_target_then_judge_then_default(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    # target_model wins
    _, _, model = _resolved(
        _config(target_provider="anthropic", target_model="claude-tgt", judge_model="claude-judge")
    )
    assert model == "claude-tgt"
    # judge_model is next
    _, _, model = _resolved(_config(target_provider="anthropic", judge_model="claude-jdg"))
    assert model == "claude-jdg"
    # provider default is last
    _, _, model = _resolved(_config(target_provider="anthropic"))
    assert model == "claude-sonnet-4-6"


def test_select_model_caller_explicit_provider_missing_key_is_a_signal(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    # target_provider openai is explicitly configured but its key is absent: a missing-key
    # signal the CLI can act on, NEVER an SDK constructor exception.
    signal = select_model_caller(_config(target_provider="openai"))
    assert isinstance(signal, MissingProviderKey)
    assert signal.provider == "openai"


def test_select_model_caller_never_puts_key_in_repr(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-supersecret")
    chosen = select_model_caller(_config())
    assert isinstance(chosen, tuple)
    caller, provider, model = chosen
    assert "sk-ant-supersecret" not in repr(caller)
    assert "sk-ant-supersecret" not in repr(provider)
    assert "sk-ant-supersecret" not in repr(model)
