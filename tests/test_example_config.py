"""shipgrade.example.yaml must stay a real, loadable artifact (spec 5.6, 5.7, 6.1).

It is the config a new adopter copies, so it has to round-trip through the same
load_config the scan path uses, and the .shipgrade-ignore.yaml block it documents has
to round-trip through the suppression loader. If either drifts, this test fails before
a reader copies a broken example.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from shipgrade.config import load_config
from shipgrade.suppression import load_waivers

EXAMPLE = Path(__file__).resolve().parent.parent / "shipgrade.example.yaml"

_IGNORE_BEGIN = "# --- example .shipgrade-ignore.yaml (BEGIN) ---"
_IGNORE_END = "# --- example .shipgrade-ignore.yaml (END) ---"


def _extract_ignore_block(text: str) -> str:
    """Pull the commented .shipgrade-ignore.yaml example out of the config file and
    un-comment it. Each documented line is prefixed with '# ' (or is a bare '#' for a
    blank line); stripping that prefix yields the real ignore-file YAML."""
    lines = text.splitlines()
    start = lines.index(_IGNORE_BEGIN)
    end = lines.index(_IGNORE_END)
    out: list[str] = []
    for line in lines[start + 1 : end]:
        if line.startswith("# "):
            out.append(line[2:])
        elif line == "#":
            out.append("")
        else:  # pragma: no cover - guards a malformed block
            raise AssertionError(f"ignore block line is not commented: {line!r}")
    return "\n".join(out) + "\n"


def test_example_config_loads_through_load_config():
    cfg = load_config(EXAMPLE)
    assert cfg.target.mode == "http"
    assert cfg.probe_packs == ["owasp-core-v1"]
    assert cfg.rule_packs == ["finance-v1", "health-v1", "edu-v1"]
    assert cfg.outputs == ["cli", "html", "json", "sarif"]
    assert cfg.gate_severity == 7.0


def test_documented_ignore_block_loads_through_load_waivers(tmp_path):
    ignore_yaml = _extract_ignore_block(EXAMPLE.read_text(encoding="utf-8"))
    ignore_path = tmp_path / ".shipgrade-ignore.yaml"
    ignore_path.write_text(ignore_yaml, encoding="utf-8")

    waivers = load_waivers(ignore_path)

    assert [w.fingerprint for w in waivers] == [
        "944668538602013a3814e5d5089fadca",
        "0123456789abcdef0123456789abcdef",
    ]
    assert waivers[0].reason.startswith("Internal sandbox target")
    assert waivers[0].expires == date(2026, 12, 31)
    assert waivers[1].expires is None
