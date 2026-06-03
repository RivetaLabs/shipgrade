"""shields.io endpoint badge writer (spec 5.10 "Badge").

Writes a static shields.io endpoint JSON (schemaVersion 1) to a fixed path so a committed
badge tracks the latest graded state. The message is the grade; the color comes from the
fixed band map. A partial-coverage run appends " (partial)" to the message and forces the
color to lightgrey, so an incomplete run never renders a confident green A. The file is
overwritten on every run. No badge server is hosted (Section 2 no-backend non-goal).
"""

from __future__ import annotations

import json
from pathlib import Path

from shipgrade.models import ScoreResult

_GRADE_COLOR = {
    "A": "brightgreen",
    "B": "green",
    "C": "yellow",
    "D": "orange",
    "F": "red",
}


def write_badge(score: ScoreResult, path: str = ".shipgrade/badge.json") -> dict:
    """Write the shields.io endpoint JSON for ``score`` to ``path`` and return it.

    Creates the parent directory if needed and overwrites any existing file.
    """
    message = score.grade
    color = _GRADE_COLOR[score.grade]
    if score.coverage == "partial":
        message = f"{message} (partial)"
        color = "lightgrey"
    payload = {
        "schemaVersion": 1,
        "label": "AI Safety",
        "message": message,
        "color": color,
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload
