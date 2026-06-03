"""Regression mode: save a baseline and compare a fresh run against it (spec 6.1, 13.8).

A baseline persists fingerprints and the score only, never evidence, because spec 5.9
forbids writing raw or redacted target text anywhere outside the live report. compare
diffs the new report's findings against the saved fingerprints: new findings (fingerprint
absent from the baseline), resolved fingerprints (present in the baseline, gone now), the
signed score delta (score now minus baseline score, spec 5.7), and a single regressed flag
for CI. The Baseline and RegressionResult
models are frozen in models.py (spec 5.7); this module only fills and reads them. The
CLI --baseline wiring and exit codes live in cli.py (T8)."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from shipgrade.models import Baseline, Finding, RegressionResult, Report, ScoreResult

__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "BaselineError",
    "save_baseline",
    "load_baseline",
    "compare",
]

BASELINE_SCHEMA_VERSION = 1


class BaselineError(Exception):
    """A baseline file is missing, malformed, or carries an incompatible schema_version."""


def save_baseline(report: Report, path: Path) -> Baseline:
    """Write ``report``'s fingerprints and score to ``path`` as a Baseline and return it.

    Persists fingerprints and the ScoreResult only, never evidence (spec 5.9). Creates the
    parent directory and overwrites any existing file. ``created_at`` and ``tool_version``
    are copied from ``report.metadata`` (doc 11), so a committed baseline records the start
    time and tool version of the run that produced it, not the moment it was serialized.
    Reading them from the report keeps save deterministic for a fixed report."""
    baseline = Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        created_at=report.metadata.started_at,
        tool_version=report.metadata.tool_version,
        fingerprints=[f.fingerprint for f in report.findings],
        score=report.score,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(baseline.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return baseline


def load_baseline(path: Path) -> Baseline:
    """Load and validate a Baseline from ``path``.

    Raises BaselineError when the file is missing, is not valid JSON for the Baseline
    schema, or carries a schema_version this build does not understand, so an old or
    tampered baseline fails loudly instead of producing a misleading diff."""
    if not path.is_file():
        raise BaselineError(f"baseline file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        baseline = Baseline.model_validate_json(raw)
    except ValidationError as exc:
        raise BaselineError(f"{path.name} is not a valid baseline:\n{exc}") from exc
    if baseline.schema_version != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            f"{path.name} schema_version {baseline.schema_version} != "
            f"{BASELINE_SCHEMA_VERSION}; re-save the baseline with this shipgrade version"
        )
    return baseline


def compare(
    report: Report,
    baseline: Baseline,
    *,
    gate: float,
    findings: list[Finding] | None = None,
    score: ScoreResult | None = None,
) -> RegressionResult:
    """Diff ``report`` against ``baseline`` into a RegressionResult.

    A finding is new when its fingerprint is absent from the baseline; a baseline
    fingerprint is resolved when it is absent from the new report. grade_delta is the signed
    score delta score.score - baseline.score.score (spec 5.7; positive improved, negative
    dropped). regressed is True when any new finding meets the severity gate (spec 5.6) or the
    score dropped, so a sub-gate new finding or a held/improved score does not by itself fail
    CI.

    ``findings`` and ``score`` default to ``report``'s whole values. Callers pass the active
    (non-waived) findings and their re-scored ScoreResult to make this a residual-risk gate
    (spec 6.1): a waived finding is then neither a gating new finding nor a source of score
    drop, exactly as it is excluded from the per-finding gate. ``report.findings`` and
    ``report.score`` stay whole for the saved baseline and the rendered report."""
    findings = report.findings if findings is None else findings
    score = report.score if score is None else score

    baseline_prints = set(baseline.fingerprints)
    new_findings = [f for f in findings if f.fingerprint not in baseline_prints]

    current_prints = {f.fingerprint for f in findings}
    resolved_fingerprints = sorted(fp for fp in baseline.fingerprints if fp not in current_prints)

    grade_delta = score.score - baseline.score.score

    new_above_gate = any(f.severity_score >= gate for f in new_findings)
    regressed = new_above_gate or grade_delta < 0

    return RegressionResult(
        new_findings=new_findings,
        resolved_fingerprints=resolved_fingerprints,
        grade_delta=grade_delta,
        regressed=regressed,
    )
