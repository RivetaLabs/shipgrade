import asyncio
import sys
import types

import pytest

from shipgrade.adapters.base import AdapterError
from shipgrade.adapters.callable import CallableAdapter
from shipgrade.models import Target


def _install(monkeypatch, name: str, **attrs) -> str:
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    monkeypatch.setitem(sys.modules, name, mod)
    return name


def _target(ref: str) -> Target:
    return Target(mode="callable", ref=ref)


def test_callable_runs_user_function(monkeypatch):
    async def respond(prompt):
        return f"echo: {prompt}"

    _install(monkeypatch, "synthtarget", respond=respond)
    adapter = CallableAdapter(_target("synthtarget:respond"))
    assert asyncio.run(adapter.respond("hi")) == "echo: hi"


def test_ref_without_colon_is_actionable():
    with pytest.raises(AdapterError, match="module:func"):
        CallableAdapter(_target("synthtarget"))


def test_missing_attribute_is_actionable(monkeypatch):
    _install(monkeypatch, "synthtarget", other=1)
    with pytest.raises(AdapterError, match="not found"):
        CallableAdapter(_target("synthtarget:nope"))


def test_non_callable_is_actionable(monkeypatch):
    _install(monkeypatch, "synthtarget", answer=42)
    with pytest.raises(AdapterError, match="not callable"):
        CallableAdapter(_target("synthtarget:answer"))


def test_sync_function_is_rejected(monkeypatch):
    def respond(prompt):
        return prompt

    _install(monkeypatch, "synthtarget", respond=respond)
    with pytest.raises(AdapterError, match="async"):
        CallableAdapter(_target("synthtarget:respond"))
