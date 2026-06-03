"""CLI report renderer (spec 5.5). Pure function returning plain, non-colored text:
the snapshot asserts it and CI/pipes read it. Output is identical on a TTY; rich's
Console is used for layout and width control only, with color, markup, and terminal
detection forced off (doc 02 tracks live colored TTY output as a known gap).
"""

from __future__ import annotations

import io

from rich.console import Console

from shipgrade.models import Report
from shipgrade.report._common import (
    DISCLAIMER,
    SEVERITY_NOTE,
    coverage_banner,
    exec_summary,
    grade_explainer,
    order_findings,
)
from shipgrade.suppression import Waiver


def render_cli(report: Report, waivers: list[Waiver] | None = None) -> str:
    out = io.StringIO()
    console = Console(
        file=out,
        force_terminal=False,
        no_color=True,
        markup=False,
        emoji=False,
        highlight=False,
        width=100,
    )
    _render(console, report, waivers or [])
    return out.getvalue()


def _render(console: Console, report: Report, waivers: list[Waiver]) -> None:
    # soft_wrap keeps each logical line intact (no mid-sentence wrapping or
    # cropping), so the plain output stays grep-able and version-stable (spec 5.5).
    def p(text: str = "") -> None:
        console.print(text, soft_wrap=True)

    s = report.score
    p(f"Grade {s.grade}   {s.score}/100   {s.scale_version} scale")
    p(grade_explainer(s))
    p(coverage_banner(s))
    p()
    p("Explain to my boss")
    p(exec_summary(report))
    p()
    cb = s.counts_by_band
    p(
        f"Findings by severity: critical {cb.get('critical', 0)}  "
        f"high {cb.get('high', 0)}  medium {cb.get('medium', 0)}  low {cb.get('low', 0)}"
    )
    p()
    for f in order_findings(report):
        p(f"[{f.severity_band.upper()} {f.severity_score}/10] {f.title}")
        p(f"  What this means: {f.description}")
        p(f"  We saw: {f.evidence.response_excerpt}")
        p(f"  Fix: {f.fix}")
        p(f"  OWASP {f.category}  ATLAS {f.atlas_technique or 'n/a'}  confidence {f.confidence}")
        p()
    if waivers:
        p(f"Accepted-risk waivers ({len(waivers)}):")
        for w in waivers:
            tail = f" (expires {w.expires.isoformat()})" if w.expires else ""
            p(f"  {w.fingerprint}: {w.reason}{tail}")
    else:
        p("Accepted-risk waivers: none.")
    if report.errored_probes:
        p(f"Errored or skipped probes: {len(report.errored_probes)}.")
    else:
        p("Errored or skipped probes: none.")
    p()
    p(DISCLAIMER)
    p(SEVERITY_NOTE)
    p(
        f"tool {report.metadata.tool_version}  "
        f"run {report.metadata.started_at.date().isoformat()}  scale {s.scale_version}"
    )
