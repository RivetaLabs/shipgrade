from __future__ import annotations

import json

import pytest

from shipgrade.demo.report import make_demo_report
from shipgrade.models import (
    Baseline,
    Confidence,
    Evidence,
    Finding,
    OwaspLlmId,
    SeverityBand,
)
from shipgrade.regression import (
    BASELINE_SCHEMA_VERSION,
    BaselineError,
    compare,
    load_baseline,
    save_baseline,
)
from shipgrade.report.fingerprint import fingerprint

_TARGET = "system_prompt.txt"


def _finding(
    fid: str,
    category: OwaspLlmId,
    band: SeverityBand,
    score: float,
    confidence: Confidence,
) -> Finding:
    return Finding(
        id=fid,
        title=f"finding {fid}",
        category=category,
        atlas_technique=None,
        severity_score=score,
        severity_band=band,
        description="d",
        evidence=Evidence(
            probe_input="p",
            response_excerpt="r",
            redacted=False,
            adapter_mode="prompt_file",
        ),
        fix="f",
        confidence=confidence,
        fingerprint=fingerprint(category, f"probe-{fid}", "", _TARGET),
    )


# --- save_baseline: fingerprints + score only, no evidence (spec 5.9) ----------------


def test_save_writes_schema_version_and_fingerprints(tmp_path):
    report = make_demo_report()
    path = tmp_path / ".shipgrade" / "baseline.json"
    save_baseline(report, path)
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == BASELINE_SCHEMA_VERSION
    assert sorted(on_disk["fingerprints"]) == sorted(f.fingerprint for f in report.findings)
    assert on_disk["score"]["grade"] == "F"
    assert on_disk["score"]["score"] == 13


def test_save_stamps_created_at_and_tool_version_from_report_metadata(tmp_path):
    # doc 11 Public Interface: created_at and tool_version come from the run that produced
    # the baseline (report.metadata), not wall-clock or the installed package version, so a
    # baseline records the run that made it and save_baseline stays deterministic.
    report = make_demo_report()
    path = tmp_path / "baseline.json"
    written = save_baseline(report, path)
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert written.created_at == report.metadata.started_at
    assert written.tool_version == report.metadata.tool_version
    assert on_disk["created_at"] == report.metadata.started_at.isoformat()
    assert on_disk["tool_version"] == report.metadata.tool_version


def test_save_creates_parent_directory(tmp_path):
    report = make_demo_report()
    path = tmp_path / "nested" / "dir" / "baseline.json"
    save_baseline(report, path)
    assert path.is_file()


def test_save_persists_no_evidence_text(tmp_path):
    # spec 5.9: a persisted baseline must not carry probe inputs or response excerpts.
    report = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(report, path)
    raw = path.read_text(encoding="utf-8")
    assert "probe_input" not in raw
    assert "response_excerpt" not in raw
    assert "evidence" not in raw


# --- load_baseline: round-trip + schema mismatch fails loudly -------------------------


def test_load_round_trips_a_saved_baseline(tmp_path):
    report = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(report, path)
    loaded = load_baseline(path)
    assert isinstance(loaded, Baseline)
    assert sorted(loaded.fingerprints) == sorted(f.fingerprint for f in report.findings)
    assert loaded.score.grade == "F"


def test_load_rejects_schema_version_mismatch(tmp_path):
    report = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(report, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema_version"] = BASELINE_SCHEMA_VERSION + 1
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "does-not-exist.json")


# --- compare: new / resolved / grade_delta / regressed --------------------------------


def test_identical_report_has_no_new_or_resolved(tmp_path):
    report = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(report, path)
    baseline = load_baseline(path)
    result = compare(report, baseline, gate=7.0)
    assert result.new_findings == []
    assert result.resolved_fingerprints == []
    assert result.grade_delta == 0
    assert result.regressed is False


def test_new_finding_above_gate_regresses(tmp_path):
    base = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(base, path)
    baseline = load_baseline(path)
    # A fresh report whose findings are the demo set plus one brand-new critical.
    extra = _finding("NEW-001", "LLM01", "critical", 9.0, "high")
    newer = base.model_copy(update={"findings": [*base.findings, extra]})
    result = compare(newer, baseline, gate=7.0)
    assert [f.id for f in result.new_findings] == ["NEW-001"]
    assert result.resolved_fingerprints == []
    assert result.regressed is True


def test_new_finding_below_gate_does_not_regress(tmp_path):
    base = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(base, path)
    baseline = load_baseline(path)
    extra = _finding("NEW-LOW", "LLM05", "low", 2.0, "low")
    newer = base.model_copy(update={"findings": [*base.findings, extra]})
    result = compare(newer, baseline, gate=7.0)
    assert [f.id for f in result.new_findings] == ["NEW-LOW"]
    assert result.regressed is False


def test_resolved_fingerprint_is_reported_sorted(tmp_path):
    base = make_demo_report()
    path = tmp_path / "baseline.json"
    save_baseline(base, path)
    baseline = load_baseline(path)
    # Drop the last two demo findings; their fingerprints are now resolved.
    dropped = base.findings[:-2]
    resolved = sorted(f.fingerprint for f in base.findings[-2:])
    newer = base.model_copy(update={"findings": dropped})
    result = compare(newer, baseline, gate=7.0)
    assert result.new_findings == []
    assert result.resolved_fingerprints == resolved


def test_grade_delta_positive_when_grade_improves():
    # Baseline at Grade F (score 13), new run a clean Grade A (score 100): the signed score
    # delta is 100 - 13 == 87 (spec 5.7 "score now minus baseline score").
    base = make_demo_report()
    clean = make_demo_report().model_copy(update={"findings": []})
    clean = clean.model_copy(
        update={"score": clean.score.model_copy(update={"grade": "A", "score": 100})}
    )
    baseline = Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        created_at=base.metadata.started_at,
        tool_version=base.metadata.tool_version,
        fingerprints=[f.fingerprint for f in base.findings],
        score=base.score,
    )
    result = compare(clean, baseline, gate=7.0)
    assert result.grade_delta == 100 - base.score.score  # 100 - 13 == 87
    assert result.regressed is False


def test_grade_delta_negative_regresses():
    # Baseline clean A (score 100), new run Grade F (score 13): the signed score delta is
    # 13 - 100 == -87, regressed even with no new finding above the gate.
    worse = make_demo_report()
    clean_score = worse.score.model_copy(update={"grade": "A", "score": 100})
    baseline = Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        created_at=worse.metadata.started_at,
        tool_version=worse.metadata.tool_version,
        fingerprints=[f.fingerprint for f in worse.findings],
        score=clean_score,
    )
    result = compare(worse, baseline, gate=7.0)
    assert result.grade_delta == worse.score.score - 100  # 13 - 100 == -87
    assert result.regressed is True


# --- residual-risk gate: compare evaluates the active (non-waived) view -----------------


def test_compare_uses_passed_active_findings_and_score(tmp_path):
    # The regression gate is a residual-risk gate (spec 6.1): when the caller passes the active
    # (non-waived) findings and their re-scored ScoreResult, a waived NEW finding neither counts
    # as a gating new finding nor drops the gated score, so compare reports not-regressed. The
    # whole report.findings/score stay untouched (saved to the baseline and shown); only the
    # gate decision uses the active view. The params default to the whole report, so the calls
    # above are unaffected.
    clean = make_demo_report().model_copy(update={"findings": []})
    clean = clean.model_copy(
        update={"score": clean.score.model_copy(update={"grade": "A", "score": 100})}
    )
    path = tmp_path / "baseline.json"
    save_baseline(clean, path)  # clean baseline: no fingerprints, score 100
    baseline = load_baseline(path)

    # A whole run that surfaced one new critical, but the operator waived it: the gate sees the
    # active view (no findings, the clean score), not the whole report.
    waived_new = _finding("WAIVED-NEW", "LLM01", "critical", 9.0, "high")
    whole = clean.model_copy(update={"findings": [waived_new]})

    residual = compare(whole, baseline, gate=7.0, findings=[], score=clean.score)
    assert residual.new_findings == []
    assert residual.grade_delta == 0
    assert residual.regressed is False

    # Proof the params changed behaviour: the default (whole-report) compare DOES regress, since
    # the waived finding is then counted as a new finding above the gate.
    default = compare(whole, baseline, gate=7.0)
    assert [f.id for f in default.new_findings] == ["WAIVED-NEW"]
    assert default.regressed is True
