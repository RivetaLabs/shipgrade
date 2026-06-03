import json

import pytest

from shipgrade.badge import write_badge
from shipgrade.models import Coverage, Grade, ScoreResult


def _score(grade: Grade, coverage: Coverage) -> ScoreResult:
    return ScoreResult(
        grade=grade,
        score=13,
        scale_version="shipgrade-1",
        findings_counted=5,
        counts_by_band={"critical": 1, "high": 2, "medium": 2, "low": 0},
        counts_by_category={"LLM01": 1, "LLM02": 1, "LLM05": 1, "LLM07": 1, "LLM09": 1},
        probes_total=5,
        probes_passed=0,
        probes_failed=5,
        probes_errored=0,
        probes_skipped=0,
        coverage=coverage,
        grade_capped_by_critical=True,
    )


def test_returns_shields_endpoint_shape():
    payload = write_badge(_score("F", "full"), path="badge.json")
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "AI Safety"
    assert payload["message"] == "F"
    assert payload["color"] == "red"


@pytest.mark.parametrize(
    ("grade", "color"),
    [
        ("A", "brightgreen"),
        ("B", "green"),
        ("C", "yellow"),
        ("D", "orange"),
        ("F", "red"),
    ],
)
def test_full_coverage_color_map(grade, color):
    payload = write_badge(_score(grade, "full"), path="badge.json")
    assert payload["message"] == grade
    assert payload["color"] == color


def test_partial_appends_suffix_and_forces_lightgrey():
    payload = write_badge(_score("A", "partial"), path="badge.json")
    assert payload["message"] == "A (partial)"
    assert payload["color"] == "lightgrey"


def test_partial_overrides_band_color_for_every_grade():
    for grade in ("A", "B", "C", "D", "F"):
        payload = write_badge(_score(grade, "partial"), path="badge.json")
        assert payload["color"] == "lightgrey"
        assert payload["message"] == f"{grade} (partial)"


def test_writes_default_path_creating_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    returned = write_badge(_score("F", "full"))
    written = tmp_path / ".shipgrade" / "badge.json"
    assert written.exists()
    on_disk = json.loads(written.read_text(encoding="utf-8"))
    assert on_disk == returned
    assert on_disk == {
        "schemaVersion": 1,
        "label": "AI Safety",
        "message": "F",
        "color": "red",
    }


def test_overwrites_existing_badge(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_badge(_score("F", "full"))
    write_badge(_score("A", "full"))
    on_disk = json.loads((tmp_path / ".shipgrade" / "badge.json").read_text(encoding="utf-8"))
    assert on_disk["message"] == "A"
    assert on_disk["color"] == "brightgreen"
