"""shipgrade object model (design spec 5.5 and 5.7).

Finding (5.5) is the frozen architecture seam: any field add, remove, rename, or
retype is a gated architecture change, not a tweak (CLAUDE.md, doc 01). Every other
model attaches around it and is additive. All models are validated on load and reject
unknown fields (spec 5.8).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# --- locked enums (spec 5.4, 5.7) ---------------------------------------------

OwaspLlmId = Literal["LLM01", "LLM02", "LLM05", "LLM07", "LLM09"]
SeverityBand = Literal["critical", "high", "medium", "low"]
Confidence = Literal["high", "medium", "low"]
AdapterMode = Literal["prompt_file", "http", "callable"]
Grade = Literal["A", "B", "C", "D", "F"]
Coverage = Literal["full", "partial"]
Domain = Literal["finance", "health", "education", "custom"]
DetectorName = Literal["pii_echo", "secret_echo", "canary_leak"]
OutputFormat = Literal["cli", "html", "json", "sarif"]
Provider = Literal["anthropic", "openai"]


class StrictModel(BaseModel):
    """Base model: reject unknown fields on load (spec 5.8 fail-fast)."""

    model_config = ConfigDict(extra="forbid")


# --- the frozen contract (spec 5.5) -------------------------------------------


class Evidence(StrictModel):
    """Finding.evidence. response_excerpt is ALREADY redacted before construction (5.9)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_input: str
    response_excerpt: str
    redacted: bool
    adapter_mode: AdapterMode


class Finding(StrictModel):
    """The normalized record every detector emits and every renderer consumes (5.5).

    FROZEN: 12 fields, fixed shape. Changing this is an architecture change (doc 01).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    category: OwaspLlmId
    atlas_technique: str | None
    severity_score: float = Field(ge=0.0, le=10.0)
    severity_band: SeverityBand
    description: str
    evidence: Evidence
    fix: str
    confidence: Confidence
    fingerprint: str
    source: str = "shipgrade"


# --- probes and rules (spec 5.2, 5.7, 5.8) ------------------------------------


class Probe(StrictModel):
    id: str
    category: OwaspLlmId
    atlas_technique: str | None = None
    title: str
    inputs: list[str]
    safe_behavior: str
    detectors: list[DetectorName] = []
    severity_hint: float | None = None
    target_rule: str | None = None


class ProbePack(StrictModel):
    name: str
    version: str
    probes: list[Probe]


class Rule(StrictModel):
    id: str
    kind: Literal["must_never", "must_always"]
    statement: str
    category: OwaspLlmId
    domain: Domain = "custom"
    severity: float = Field(ge=0.0, le=10.0)
    rationale: str | None = None
    fix: str | None = None
    references: list[str] = []
    examples: dict | None = None
    detector: Literal["judge", "deterministic"] = "judge"


class RulePack(StrictModel):
    name: str
    domain: Domain
    version: str
    rules: list[Rule]


class Verdict(StrictModel):
    passed: bool
    severity_score: float = Field(ge=0.0, le=10.0)
    rationale: str
    suggested_fix: str
    confidence: Confidence


class ProbeResult(StrictModel):
    probe_id: str
    status: Literal["ok", "errored", "skipped"]
    verdict: Verdict | None = None
    evidence: Evidence | None = None
    error: str | None = None
    judged_by: Literal["llm", "deterministic", "none"]
    # Each deterministic detector that fired on this result, once per detector (deduplicated),
    # in deterministic order. Empty when nothing fired. Carries detector identity from the
    # redaction boundary up to findings_from_results so a fired secret/PII/canary echo becomes
    # a Finding on every path, key-free (spec 5.9, doc 05).
    fired_detectors: list[DetectorName] = Field(default_factory=list)


# --- score and regression records (spec 5.10, 5.7) ----------------------------


class ScoreResult(StrictModel):
    grade: Grade
    score: int = Field(ge=0, le=100)
    scale_version: str
    findings_counted: int
    counts_by_band: dict[SeverityBand, int]
    counts_by_category: dict[OwaspLlmId, int]
    probes_total: int
    probes_passed: int
    probes_failed: int
    probes_errored: int
    probes_skipped: int
    coverage: Coverage
    grade_capped_by_critical: bool


class Baseline(StrictModel):
    """Persisted at .shipgrade/baseline.json. Stores fingerprints, NOT evidence (5.7)."""

    schema_version: int
    created_at: datetime
    tool_version: str
    fingerprints: list[str]
    score: ScoreResult


class RegressionResult(StrictModel):
    new_findings: list[Finding]
    resolved_fingerprints: list[str]
    grade_delta: int
    regressed: bool


# --- adapter and run config + envelope (spec 5.1, 5.7) ------------------------


class Target(StrictModel):
    mode: AdapterMode
    ref: str
    target_provider: Provider | None = None
    target_model: str | None = None
    method: str | None = None
    headers: dict[str, str] | None = None
    body_template: str | None = None
    response_path: str | None = None
    allow_private_targets: bool = False
    authorized_target: bool = False
    connect_timeout_s: int = 5
    read_timeout_s: int = 30
    max_response_bytes: int = 5_000_000


class Config(StrictModel):
    target: Target
    judge_provider: Provider | None = None
    judge_model: str | None = None
    probe_packs: list[str]
    rule_packs: list[str]
    outputs: list[OutputFormat]
    gate_severity: float = Field(ge=0.0, le=10.0)


class TargetSummary(StrictModel):
    """Safe projection of Target. Carries NO secrets (spec 8.5). identity is the
    adapter_target_identity hashed into Finding.fingerprint (spec 5.5.1)."""

    mode: AdapterMode
    identity: str
    target_provider: Provider | None = None
    target_model: str | None = None


class RunMetadata(StrictModel):
    tool_version: str
    run_id: str
    started_at: datetime
    target: TargetSummary
    judge_provider: Literal["anthropic", "openai", "none"]
    judge_model: str | None = None
    probe_pack_versions: dict[str, str]
    rule_pack_versions: dict[str, str]
    offline: bool


class Report(StrictModel):
    metadata: RunMetadata
    findings: list[Finding]
    score: ScoreResult
    errored_probes: list[ProbeResult] = []
