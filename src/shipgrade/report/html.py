"""HTML report renderer (spec 5.5). One self-contained file, inline CSS, no external
assets. Jinja2 autoescape is forced on so a hostile model response cannot inject
script into the report (spec section 9).
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from shipgrade.models import Report
from shipgrade.report._common import (
    BAND_HEX,
    DISCLAIMER,
    SEVERITY_NOTE,
    coverage_banner,
    exec_summary,
    grade_explainer,
    order_findings,
)
from shipgrade.suppression import Waiver

_env = Environment(
    loader=PackageLoader("shipgrade.report", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
)


def render_html(report: Report, waivers: list[Waiver] | None = None) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        report=report,
        score=report.score,
        meta=report.metadata,
        findings=order_findings(report),
        waivers=waivers or [],
        exec_summary=exec_summary(report),
        grade_explainer=grade_explainer(report.score),
        coverage_banner=coverage_banner(report.score),
        band_hex=BAND_HEX,
        disclaimer=DISCLAIMER,
        severity_note=SEVERITY_NOTE,
    )
