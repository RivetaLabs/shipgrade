"""JSON report renderer (spec 5.5, 5.10). Emits a fixed meta block, the
not-a-certification disclaimer and the CVSS-flavored severity note, then the full
Report, so a machine consumer reads the same honesty the human surfaces show.
"""

from __future__ import annotations

import json

from shipgrade.models import Report
from shipgrade.report._common import DISCLAIMER, NOT_A_CERTIFICATION, SEVERITY_NOTE
from shipgrade.suppression import Waiver


def render_json(report: Report, waivers: list[Waiver] | None = None) -> str:
    payload = {
        "meta": {
            "schema": "shipgrade-report-v1",
            "tool_version": report.metadata.tool_version,
            "scale_version": report.score.scale_version,
            "run_date": report.metadata.started_at.date().isoformat(),
            "disclaimer": DISCLAIMER,
            "severity_note": SEVERITY_NOTE,
            "framing": NOT_A_CERTIFICATION,
        },
        "waivers": [w.model_dump(mode="json") for w in (waivers or [])],
        "report": report.model_dump(mode="json"),
    }
    return json.dumps(payload, indent=2) + "\n"
