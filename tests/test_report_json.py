import json
from datetime import date

from shipgrade.demo.report import make_demo_report
from shipgrade.report.json import render_json
from shipgrade.suppression import Waiver


def test_json_has_meta_and_full_report(demo_report):
    data = json.loads(render_json(demo_report))
    assert data["meta"]["scale_version"] == "shipgrade-1"
    assert "not a certification" in data["meta"]["disclaimer"]
    assert data["meta"]["run_date"] == "2026-06-01"
    assert len(data["report"]["findings"]) == 5


def test_json_carries_redaction_placeholder_not_raw_secret(demo_report):
    out = render_json(demo_report)
    assert "sk-demo" not in out
    assert "[REDACTED:secret(20)]" in out


def test_json_no_waivers_is_empty_list(demo_report):
    data = json.loads(render_json(demo_report))
    assert data["waivers"] == []


def test_json_renders_waivers(demo_report):
    first = demo_report.findings[0]
    waivers = [
        Waiver(
            fingerprint=first.fingerprint,
            reason="risk accepted by founder",
            expires=date(2026, 12, 31),
        )
    ]
    data = json.loads(render_json(demo_report, waivers=waivers))
    assert data["waivers"] == [
        {
            "fingerprint": first.fingerprint,
            "reason": "risk accepted by founder",
            "expires": "2026-12-31",
        }
    ]
    # report.findings is unchanged; the waived finding is still present
    assert len(data["report"]["findings"]) == 5


def test_json_snapshot(demo_report, snapshot):
    assert render_json(demo_report) == snapshot


def test_demo_metadata_reports_no_judge_provider_when_offline():
    # The demo runs fully offline and never calls a provider, so its metadata must not claim one.
    assert make_demo_report().metadata.judge_provider == "none"
