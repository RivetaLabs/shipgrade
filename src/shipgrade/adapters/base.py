"""Adapter layer base (spec 5.1). TargetAdapter is the send-prompt-get-response seam;
ModelCaller is the provider seam the prompt-file adapter needs, implemented by the judge
provider clients (select_model_caller, judge/providers.py) and faked in tests.
summarize_target projects a Target to the secret-free TargetSummary (8.5). build_adapter
dispatches a Target to its adapter; its imports are function-local because callable,
prompt_file, and http all import this module, so a top-level import would be circular."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

from shipgrade.models import Target, TargetSummary


class AdapterError(Exception):
    """Fail-closed adapter failure with an actionable message (spec 8). One probe's
    AdapterError marks that probe errored; it never aborts the scan."""


@runtime_checkable
class ModelCaller(Protocol):
    async def complete(self, *, system: str, prompt: str) -> str: ...


@runtime_checkable
class TargetAdapter(Protocol):
    async def respond(self, prompt: str) -> str: ...


def summarize_target(target: Target) -> TargetSummary:
    if target.mode == "http":
        identity = urlparse(target.ref).hostname or target.ref
    elif target.mode == "prompt_file":
        identity = Path(target.ref).name
    else:  # callable: "module:func" carries no secret
        identity = target.ref
    return TargetSummary(
        mode=target.mode,
        identity=identity,
        target_provider=target.target_provider,
        target_model=target.target_model,
    )


def build_adapter(target: Target, *, model_caller: ModelCaller | None = None) -> TargetAdapter:
    """Dispatch a Target to its adapter (spec 5.1). model_caller is forwarded only to the
    prompt-file adapter (its provider seam). Imports are function-local to avoid the
    circular import described in the module docstring."""
    if target.mode == "callable":
        from shipgrade.adapters.callable import CallableAdapter

        return CallableAdapter(target)
    if target.mode == "prompt_file":
        from shipgrade.adapters.prompt_file import PromptFileAdapter

        return PromptFileAdapter(target, model_caller)
    from shipgrade.adapters.http import HttpAdapter

    return HttpAdapter(target)
