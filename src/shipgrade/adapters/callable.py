"""Callable/module adapter (spec 5.1, 5.1.1). Imports a user module:func exposing
`async def respond(prompt: str) -> str` and runs it in-process. TRUST BOUNDARY: this
executes user-provided code with no sandbox, by design (the same trust level as running
the user's own pytest). A callable ref must never come from an untrusted or remote
source (doc 03)."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Awaitable, Callable

from shipgrade.adapters.base import AdapterError
from shipgrade.models import Target


class CallableAdapter:
    def __init__(self, target: Target) -> None:
        self._func = _load_callable(target.ref)

    async def respond(self, prompt: str) -> str:
        result = await self._func(prompt)
        if not isinstance(result, str):
            raise AdapterError(f"callable target returned {type(result).__name__}, expected str")
        return result


def _load_callable(ref: str) -> Callable[[str], Awaitable[str]]:
    if ":" not in ref:
        raise AdapterError(f"callable ref must be 'module:func', got {ref!r}")
    module_name, _, func_name = ref.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise AdapterError(f"could not import callable module {module_name!r}: {exc}") from exc
    func = getattr(module, func_name, None)
    if func is None:
        raise AdapterError(f"callable {func_name!r} not found in module {module_name!r}")
    if not callable(func):
        raise AdapterError(f"callable target {ref!r} is not callable")
    if not inspect.iscoroutinefunction(func):
        raise AdapterError(
            f"callable target {ref!r} must be `async def respond(prompt: str) -> str`"
        )
    return func
