import asyncio

import pytest

from shipgrade.adapters.base import AdapterError
from shipgrade.adapters.prompt_file import PromptFileAdapter
from shipgrade.models import Target


class _FakeCaller:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def complete(self, *, system: str, prompt: str) -> str:
        self.calls.append((system, prompt))
        return f"[sys={system!r}] reply to {prompt!r}"


def _target(path: str) -> Target:
    return Target(mode="prompt_file", ref=path)


def test_reads_system_prompt_and_calls_model(tmp_path):
    sp = tmp_path / "system_prompt.txt"
    sp.write_text("You are FinBot.", encoding="utf-8")
    caller = _FakeCaller()
    adapter = PromptFileAdapter(_target(str(sp)), caller)

    out = asyncio.run(adapter.respond("buy NVDA?"))

    assert caller.calls == [("You are FinBot.", "buy NVDA?")]
    assert "reply to 'buy NVDA?'" in out


def test_missing_file_is_actionable(tmp_path):
    adapter = PromptFileAdapter(_target(str(tmp_path / "nope.txt")), _FakeCaller())
    with pytest.raises(AdapterError, match="not found"):
        asyncio.run(adapter.respond("hi"))


def test_no_caller_is_actionable_about_keys(tmp_path):
    sp = tmp_path / "system_prompt.txt"
    sp.write_text("x", encoding="utf-8")
    adapter = PromptFileAdapter(_target(str(sp)), None)
    with pytest.raises(AdapterError, match="ANTHROPIC_API_KEY|provider"):
        asyncio.run(adapter.respond("hi"))
