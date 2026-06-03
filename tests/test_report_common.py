from shipgrade.report._common import (
    coverage_banner,
    exec_summary,
    grade_explainer,
    order_findings,
)


def test_order_is_severity_then_confidence(demo_report):
    ordered = order_findings(demo_report)
    assert ordered[0].id == "DEMO-002"  # 9.5 critical first
    scores = [f.severity_score for f in ordered]
    assert scores == sorted(scores, reverse=True)


def test_order_breaks_ties_on_id(demo_report):
    # DEMO-001 (8.0 high) precedes DEMO-003 (8.0 high) by id ascending.
    ordered = [f.id for f in order_findings(demo_report)]
    assert ordered.index("DEMO-001") < ordered.index("DEMO-003")


def test_grade_explainer_matches_spec_example(demo_report):
    assert grade_explainer(demo_report.score) == (
        "Grade F (13/100, shipgrade-1 scale): started at 100, lost 87 to "
        "1 critical, 2 high, 2 medium findings; any critical caps the grade at D."
    )


def test_coverage_banner_full(demo_report):
    assert coverage_banner(demo_report.score).startswith("Full coverage")


def test_exec_summary_names_top_finding_and_grade(demo_report):
    summary = exec_summary(demo_report)
    assert "Hardcoded provider API key" in summary
    assert "Grade F (13/100, shipgrade-1 scale)" in summary


def test_report_package_exports_the_four_renderers():
    from shipgrade.report import (
        render_cli,
        render_html,
        render_json,
        render_sarif,
        sarif_json,
    )

    renderers = (render_cli, render_html, render_json, render_sarif, sarif_json)
    assert all(callable(fn) for fn in renderers)
