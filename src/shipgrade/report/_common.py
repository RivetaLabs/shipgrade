"""Shared report-core helpers (spec 5.5, 5.10): the fixed canonical strings, the
severity-band chip palette (5.4), finding ordering, and the ScoreResult-derived
banner, explainer, and exec summary. All four renderers consume these so the
wording and ordering are defined once.
"""

from __future__ import annotations

from shipgrade.models import Finding, Report, ScoreResult

# Fixed canonical strings (spec 5.10, 5.4). Editing these is a copy decision.
DISCLAIMER = (
    "shipgrade is an automated heuristic audit, not a certification, security "
    "guarantee, or legal or compliance sign-off. The grade reflects the probes "
    "that ran on this date; a higher grade means fewer detected issues, not "
    "proven safety."
)
SEVERITY_NOTE = (
    "Severity is a CVSS-flavored 0-10 adaptation for LLM behavior, not "
    "CVSS-proper. EPSS and KEV are intentionally excluded."
)
NOT_A_CERTIFICATION = "A heuristic audit on this date, not a certification."

# Severity-band chip palette. Spec 5.4 bands the score; the chip color is the
# renderer's, documented in doc 02. CLI uses the rich color name, HTML the hex.
BAND_COLOR = {"critical": "red", "high": "dark_orange", "medium": "yellow", "low": "blue"}
BAND_HEX = {"critical": "#b00020", "high": "#d35400", "medium": "#b7950b", "low": "#2471a3"}

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_BANDS = ("critical", "high", "medium", "low")


def order_findings(report: Report) -> list[Finding]:
    """Severity descending, then confidence descending, ties broken by id (5.5)."""
    return sorted(
        report.findings,
        key=lambda f: (-f.severity_score, -_CONFIDENCE_RANK[f.confidence], f.id),
    )


def _band_breakdown(score: ScoreResult) -> str:
    parts = [
        f"{score.counts_by_band.get(b, 0)} {b}" for b in _BANDS if score.counts_by_band.get(b, 0)
    ]
    return ", ".join(parts) if parts else "no"


def grade_explainer(score: ScoreResult) -> str:
    """The deterministic 'number that explains itself' line (spec 5.10)."""
    line = (
        f"Grade {score.grade} ({score.score}/100, {score.scale_version} scale): "
        f"started at 100, lost {100 - score.score} to {_band_breakdown(score)} findings"
    )
    if score.grade_capped_by_critical:
        line += "; any critical caps the grade at D"
    return line + "."


def coverage_banner(score: ScoreResult) -> str:
    """Spec 5.10 coverage banner. Partial = a no-key deterministic-only run."""
    if score.coverage == "full":
        return "Full coverage: all 5 OWASP categories evaluated."
    return (
        "Partial coverage: LLM-judge categories were skipped (no API key); "
        "this is a deterministic-only run."
    )


def exec_summary(report: Report) -> str:
    """The 'Explain to my boss' summary (spec 5.5 item 2), derived from the score."""
    s = report.score
    if not report.findings:
        return (
            f"shipgrade ran {s.probes_total} probes across 5 OWASP categories "
            f"against {report.metadata.target.identity} and found no failures. "
            f"Grade {s.grade} ({s.score}/100). This is a heuristic audit, not a "
            f"certification."
        )
    top = order_findings(report)[0]
    return (
        f"shipgrade audited {report.metadata.target.identity} with {s.probes_total} "
        f"probes across 5 OWASP categories and found {s.findings_counted} failing "
        f'checks ({_band_breakdown(s)}). The most serious is "{top.title}" '
        f"({top.severity_band}, {top.severity_score}/10). "
        f"{grade_explainer(s)}"
    )
