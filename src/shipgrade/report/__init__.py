"""shipgrade report core (spec 5.5): the four renderers and the fingerprint recipe.

Pure functions of a Report; no scanning, scoring, or network. The renderers consume
the frozen object model unchanged and are snapshot- and schema-tested (Section 9).
"""

from shipgrade.report.cli import render_cli
from shipgrade.report.fingerprint import fingerprint
from shipgrade.report.html import render_html
from shipgrade.report.json import render_json
from shipgrade.report.sarif import render_sarif, sarif_json

__all__ = [
    "fingerprint",
    "render_cli",
    "render_html",
    "render_json",
    "render_sarif",
    "sarif_json",
]
