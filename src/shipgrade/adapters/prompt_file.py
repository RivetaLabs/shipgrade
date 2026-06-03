"""Prompt-file adapter (spec 5.1). Reads a system-prompt text file and sends it plus each
probe to a target model via the injected ModelCaller. The caller is a provider client
(shared with the judge) selected by select_model_caller; tests inject a fake one. PRIVACY:
this sends the system prompt under test to a third-party provider, so it needs a provider
key and is skipped in the key-free demo path (doc 03, spec 5.9)."""

from __future__ import annotations

from pathlib import Path

from shipgrade.adapters.base import AdapterError, ModelCaller
from shipgrade.models import Target


class PromptFileAdapter:
    def __init__(self, target: Target, model_caller: ModelCaller | None) -> None:
        self._path = Path(target.ref)
        self._caller = model_caller
        self._system: str | None = None

    def _system_prompt(self) -> str:
        if self._system is None:
            if not self._path.is_file():
                raise AdapterError(f"system-prompt file not found: {self._path}")
            self._system = self._path.read_text(encoding="utf-8")
        return self._system

    async def respond(self, prompt: str) -> str:
        if self._caller is None:
            raise AdapterError(
                "prompt-file target needs a provider key: set ANTHROPIC_API_KEY or "
                "OPENAI_API_KEY. To send nothing externally, use the HTTP or callable adapter, "
                "or run `demo` for the offline path."
            )
        return await self._caller.complete(system=self._system_prompt(), prompt=prompt)
