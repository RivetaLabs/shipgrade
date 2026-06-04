from datetime import date, datetime

from shipgrade.demo.report import make_demo_report
from shipgrade.models import (
    Evidence,
    Finding,
    Report,
    RunMetadata,
    ScoreResult,
    TargetSummary,
)
from shipgrade.report.html import render_html
from shipgrade.suppression import Waiver


def _xss_report() -> Report:
    finding = Finding(
        id="XSS-1",
        title="payload",
        category="LLM05",
        atlas_technique=None,
        severity_score=4.0,
        severity_band="medium",
        description="hostile",
        evidence=Evidence(
            probe_input="x",
            response_excerpt="<script>alert(1)</script>",
            redacted=False,
            adapter_mode="prompt_file",
        ),
        fix="escape it",
        confidence="low",
        fingerprint="f" * 32,
    )
    score = ScoreResult(
        grade="F",
        score=20,
        scale_version="shipgrade-1",
        findings_counted=1,
        counts_by_band={"critical": 0, "high": 0, "medium": 1, "low": 0},
        counts_by_category={"LLM05": 1},
        probes_total=1,
        probes_passed=0,
        probes_failed=1,
        probes_errored=0,
        probes_skipped=0,
        coverage="full",
        grade_capped_by_critical=False,
    )
    metadata = RunMetadata(
        tool_version="0.1.1",
        run_id="r",
        started_at=datetime(2026, 6, 1, 12, 0, 0),
        target=TargetSummary(mode="prompt_file", identity="system_prompt.txt"),
        judge_provider="none",
        judge_model=None,
        probe_pack_versions={},
        rule_pack_versions={},
        offline=True,
    )
    return Report(metadata=metadata, findings=[finding], score=score)


def test_html_is_self_contained(demo_report):
    out = render_html(demo_report)
    assert out.lstrip().startswith("<!doctype html>")
    assert "<style>" in out
    assert 'rel="stylesheet"' not in out
    assert "<script src=" not in out


def test_html_renders_grade_and_cards(demo_report):
    out = render_html(demo_report)
    assert "Grade F" in out
    assert "Hardcoded provider API key" in out
    assert "Explain to my boss" in out


def test_html_autoescapes_hostile_response():
    out = render_html(_xss_report())
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_no_waivers_says_none(demo_report):
    out = render_html(demo_report)
    assert "<h2>Accepted-risk waivers</h2>" in out
    assert "None." in out


def test_html_renders_waiver_reason_and_fingerprint(demo_report):
    first = demo_report.findings[0]
    waivers = [
        Waiver(
            fingerprint=first.fingerprint,
            reason="risk accepted by founder",
            expires=date(2026, 12, 31),
        )
    ]
    out = render_html(demo_report, waivers=waivers)
    assert first.fingerprint in out
    assert "risk accepted by founder" in out
    assert "2026-12-31" in out
    # waived finding still appears as a card in the findings body
    assert first.title in out


def test_html_snapshot(demo_report, snapshot):
    assert render_html(demo_report) == snapshot


def test_html_footer_carries_the_demo_call_to_action():
    # Share loop (spec 5.10, F-01): a viewer of any shared report is one step from running it.
    html = render_html(make_demo_report())
    assert "uvx shipgrade demo" in html
    assert "https://github.com/RivetaLabs/shipgrade" in html
