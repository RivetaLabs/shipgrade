from datetime import date

from shipgrade.report.cli import render_cli
from shipgrade.suppression import Waiver


def test_cli_has_grade_header_and_exec_summary(demo_report):
    out = render_cli(demo_report)
    assert "Grade F   13/100   shipgrade-1 scale" in out
    assert "Explain to my boss" in out
    assert "Hardcoded provider API key" in out


def test_cli_orders_critical_before_low(demo_report):
    out = render_cli(demo_report)
    assert out.index("Hardcoded provider API key") < out.index("unsanitized HTML link")


def test_cli_is_plain_no_ansi(demo_report):
    out = render_cli(demo_report)
    assert "\x1b[" not in out  # no ANSI escapes on non-TTY (spec 5.5)


def test_cli_shows_redaction_placeholder_not_secret(demo_report):
    out = render_cli(demo_report)
    assert "[REDACTED:secret(20)]" in out
    assert "sk-demo" not in out


def test_cli_footer_has_disclaimer(demo_report):
    out = render_cli(demo_report)
    assert "not a certification" in out


def test_cli_no_waivers_says_none(demo_report):
    out = render_cli(demo_report)
    assert "Accepted-risk waivers: none." in out


def test_cli_renders_waiver_reason_and_fingerprint(demo_report):
    first = demo_report.findings[0]
    waivers = [Waiver(fingerprint=first.fingerprint, reason="risk accepted by founder")]
    out = render_cli(demo_report, waivers=waivers)
    assert "Accepted-risk waivers (1):" in out
    assert first.fingerprint in out
    assert "risk accepted by founder" in out
    assert "Accepted-risk waivers: none." not in out
    # waived finding is still listed in the findings body, not dropped
    assert first.title in out


def test_cli_renders_waiver_expiry_when_present(demo_report):
    first = demo_report.findings[0]
    waivers = [
        Waiver(
            fingerprint=first.fingerprint,
            reason="temporary acceptance",
            expires=date(2026, 12, 31),
        )
    ]
    out = render_cli(demo_report, waivers=waivers)
    assert "expires 2026-12-31" in out


def test_cli_snapshot(demo_report, snapshot):
    assert render_cli(demo_report) == snapshot
