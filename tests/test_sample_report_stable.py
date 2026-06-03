from pathlib import Path

from typer.testing import CliRunner

from shipgrade.cli import app
from shipgrade.demo.report import make_demo_report
from shipgrade.report.html import render_html

runner = CliRunner()

# The committed proof artifact (spec 11.4): the byte-identical default-demo HTML output.
SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-report.html"


def test_demo_html_emit_matches_committed_sample(tmp_path, monkeypatch):
    # demo --format html --out <path> writes one self-contained HTML file (spec 11.4).
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["demo", "--format", "html", "--out", str(out)])
    assert result.exit_code == 0
    produced = out.read_text(encoding="utf-8")
    # Byte-for-byte determinism against the committed deliverable (spec 11.4).
    assert produced == SAMPLE.read_text(encoding="utf-8")


def test_committed_sample_is_the_documented_demo_render():
    # The documented regeneration command is render_html(make_demo_report()); the committed
    # file must equal it exactly, so a stale examples/sample-report.html fails CI (spec 11.4).
    assert SAMPLE.read_text(encoding="utf-8") == render_html(make_demo_report())


def test_sample_is_self_contained():
    # Inline CSS, no external assets (spec 5.5 / 11.4).
    html = SAMPLE.read_text(encoding="utf-8")
    assert html.lstrip().startswith("<!doctype html>")
    assert "<style>" in html
    assert 'rel="stylesheet"' not in html
    assert "<script src=" not in html
    assert "Grade F" in html


def test_default_text_demo_writes_no_html(tmp_path, monkeypatch):
    # The default demo (no --format) is unchanged: prints the grade-F text, writes no HTML.
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "finance assistant" in result.stdout
    assert "F" in result.stdout
    assert not (tmp_path / "report.html").exists()
