"""Stable SARIF dedup fingerprint (spec 5.5.1).

The fingerprint hashes ONLY the stable input tuple, never response text, scores,
timestamps, or run ids, so it survives a non-deterministic target and keeps GitHub
code-scanning dedup and committed waivers stable across runs. The separator, the
tuple order, and the 32-char truncation are frozen; the golden vector below locks
them so a recipe change fails loudly instead of silently re-keying every finding.
"""

from __future__ import annotations

import hashlib

_SEP = "|"


def fingerprint(category: str, probe_id: str, rule_id: str, adapter_target_identity: str) -> str:
    """First 32 hex chars of sha256 over category|probe_id|rule_id|target_identity."""
    raw = _SEP.join([category, probe_id, rule_id, adapter_target_identity])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# Frozen golden vector (spec 5.5.1, Section 9): a documented input tuple and its
# expected hash, committed as a constant so any recipe change breaks a test.
GOLDEN_INPUT = ("LLM02", "llm02-secret-echo-001", "", "system_prompt.txt")
GOLDEN_FINGERPRINT = "944668538602013a3814e5d5089fadca"
