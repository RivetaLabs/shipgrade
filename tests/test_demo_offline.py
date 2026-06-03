from typer.testing import CliRunner

from shipgrade.cli import app
from shipgrade.demo.report import make_demo_report
from shipgrade.scoring import compute_score


def test_demo_runs_key_free_and_exits_zero(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = CliRunner().invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "finance assistant" in result.stdout
    assert "Offline, no API key" in result.stdout
    assert "F" in result.stdout  # grade reveal


def test_demo_report_is_the_frozen_hero_inventory():
    # demo-offline-guardian invariants (spec 7.2): 5 findings, score 13, grade F, full.
    r = make_demo_report()
    assert len(r.findings) == 5
    assert r.score.score == 13
    assert r.score.grade == "F"
    assert r.score.coverage == "full"


def test_demo_shows_the_adopter_ci_line():
    result = CliRunner().invoke(app, ["demo"])
    assert "shipgrade scan --config shipgrade.yaml --fail-on high" in result.stdout


def test_demo_score_is_computed_not_literal():
    # M7.T7: the demo no longer hardcodes ScoreResult; make_demo_report runs the scorer
    # (spec 5.10, worked example 7.2). The computed score must reproduce the frozen 13/100/F.
    r = make_demo_report()
    recomputed = compute_score(
        r.findings,
        probes_total=5,
        probes_passed=0,
        probes_failed=5,
        probes_errored=0,
        probes_skipped=0,
    )
    assert r.score == recomputed
    assert r.score.score == 13
    assert r.score.grade == "F"
    assert r.score.coverage == "full"
    assert r.score.grade_capped_by_critical is True
    assert r.score.counts_by_band == {"critical": 1, "high": 2, "medium": 2, "low": 0}
