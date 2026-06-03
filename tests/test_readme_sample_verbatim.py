from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from shipgrade.cli import app

# README.md lives at the repo root; this test file is at tests/, so the root is one
# directory up (the same CWD-independent pattern as test_pypi_metadata.py).
README_PATH = Path(__file__).resolve().parent.parent / "README.md"


def _readme_sample_block() -> str:
    """Return the text inside the ```text fence under the '## Sample output' heading.

    The block has no nested triple-backticks, so the first ``\\n``` `` after the opening
    fence is this block's closing fence."""
    text = README_PATH.read_text(encoding="utf-8")
    anchor = text.index("## Sample output")
    open_fence = text.index("```text\n", anchor) + len("```text\n")
    close_fence = text.index("\n```", open_fence)
    return text[open_fence:close_fence] + "\n"


def test_readme_sample_output_is_verbatim_demo_stdout(monkeypatch):
    # spec 11: the README 'Sample output' block is presented as the unedited `shipgrade demo`
    # output, and the demo is the project's 60-second adoption mechanic, so the most-read
    # public artifact must never drift from what the tool actually prints. The demo is
    # deterministic (make_demo_report freezes started_at), so this is a stable equality, not a
    # flaky compare. If this fails, the demo output changed: regenerate the README block.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    stdout = CliRunner().invoke(app, ["demo"]).stdout
    assert _readme_sample_block() == stdout
