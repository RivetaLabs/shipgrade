from __future__ import annotations

import re
from pathlib import Path

import yaml

ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"

# A pinned action ref is "<owner>/<repo>[/<path>]@<40-hex-sha>"; a 40-char lowercase hex SHA
# is the only form the posture guard (spec 11.3) accepts. A tag or branch ref must fail.
_USES_SHA = re.compile(r"^[^@\s]+@[0-9a-f]{40}( +#.*)?$")


def _load() -> dict:
    return yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))


def _steps() -> list[dict]:
    return _load()["runs"]["steps"]


def test_action_yml_exists_and_is_composite() -> None:
    action = _load()
    assert action["runs"]["using"] == "composite"
    assert "name" in action and "description" in action


def test_inputs_are_the_spec_6_2_set() -> None:
    inputs = _load()["inputs"]
    assert set(inputs) == {
        "config",
        "fail-on",
        "outputs",
        "ignore-file",
        "sarif-file",
        "upload-sarif",
        "category",
    }
    # The action is drop-in: every input is optional with a default (spec 6.2).
    for name, spec in inputs.items():
        assert spec.get("required", False) is False, f"{name} must be optional"
        assert "default" in spec, f"{name} must declare a default"


def test_outputs_are_the_spec_6_2_set() -> None:
    outputs = _load()["outputs"]
    assert set(outputs) == {"score", "grade", "sarif-path", "findings-count"}


def test_every_uses_is_pinned_to_a_40_char_sha() -> None:
    uses = [s["uses"] for s in _steps() if "uses" in s]
    assert uses, "expected at least one uses: step (the SARIF upload)"
    for ref in uses:
        assert _USES_SHA.match(ref), f"uses ref is not pinned to a 40-char SHA: {ref!r}"


def test_sarif_upload_is_the_pinned_codeql_action_with_if_always() -> None:
    upload = [
        s
        for s in _steps()
        if "uses" in s and s["uses"].startswith("github/codeql-action/upload-sarif@")
    ]
    assert len(upload) == 1, "exactly one codeql upload-sarif step"
    step = upload[0]
    # yaml.safe_load strips the trailing "# v3" inline comment, so the parsed value is the bare
    # owner/repo/path@SHA. The pin must be the exact codeql v3 commit SHA.
    assert (
        step["uses"] == "github/codeql-action/upload-sarif@03e4368ac7daa2bd82b3e85262f3bf87ee112f57"
    )
    # The "# vX" provenance comment is required by the posture guard (spec 11.3); assert it on
    # the raw text since the parser drops it.
    assert (
        "github/codeql-action/upload-sarif@03e4368ac7daa2bd82b3e85262f3bf87ee112f57 # v3"
        in ACTION_PATH.read_text(encoding="utf-8")
    )
    # Without always() a failing gate would suppress the very findings the upload exists to
    # surface (spec 6.2); the upload is also gated on the upload-sarif input being the string
    # 'true' so upload-sarif: false skips it (doc 14 lines 162-163, 228). Both clauses must be
    # present in the if: expression.
    assert "always()" in step["if"]
    assert "inputs.upload-sarif == 'true'" in step["if"]


def test_step_order_is_scan_then_upload_then_gate_exit() -> None:
    steps = _steps()
    upload_idx = next(
        i
        for i, s in enumerate(steps)
        if s.get("uses", "").startswith("github/codeql-action/upload-sarif@")
    )
    # The scan step runs uvx shipgrade scan and precedes the upload.
    scan_idx = next(i for i, s in enumerate(steps) if "uvx shipgrade scan" in s.get("run", ""))
    # The gate-exit step re-emits the scan's captured exit code and is the LAST step, after
    # the upload, so a failing gate never suppresses the SARIF upload (spec 6.2). It is located
    # by the literal `exit "$code"` line, which is unique to that step (the scan step writes
    # the exit code but does not re-raise it).
    gate_idx = next(i for i, s in enumerate(steps) if 'exit "$code"' in s.get("run", ""))
    assert scan_idx < upload_idx < gate_idx
    assert gate_idx == len(steps) - 1, "the gate-driven exit must be the final step"


def test_minimum_consumer_permissions_are_documented() -> None:
    text = ACTION_PATH.read_text(encoding="utf-8")
    assert "security-events: write" in text
    assert "contents: read" in text


def test_run_step_passes_only_real_scan_flags() -> None:
    # The action must not pass a flag the real scan command lacks. After M8.T8 the scan flags
    # are: --config, --fail-on, --ignore-file, --baseline, --allow-private-targets, --offline,
    # --no-judge, --yes. There is no --sarif or --outputs flag, so the run step must not pass
    # them.
    run_text = "\n".join(s.get("run", "") for s in _steps())
    assert "--config" in run_text
    assert "--fail-on" in run_text
    assert "--ignore-file" in run_text
    assert "--sarif" not in run_text
    assert "--outputs" not in run_text


def _upload_step() -> dict:
    return next(
        s for s in _steps() if s.get("uses", "").startswith("github/codeql-action/upload-sarif@")
    )


def _scan_step() -> dict:
    return next(s for s in _steps() if "uvx shipgrade scan" in s.get("run", ""))


def test_upload_is_gated_on_the_upload_sarif_input() -> None:
    # upload-sarif is a documented input (doc 14 lines 162-163, 228): upload-sarif: false must
    # skip the upload. Composite-action inputs are strings, so the gate compares to 'true'.
    # always() still guarantees the upload survives a failing gate (spec 6.2).
    cond = _upload_step()["if"]
    assert "always()" in cond
    assert "inputs.upload-sarif == 'true'" in cond


def test_scan_relocates_sarif_to_the_requested_path() -> None:
    # The CLI always writes the fixed path shipgrade.sarif (src/shipgrade/cli.py:267). The
    # action must move it to the requested sarif-file so a non-default value still uploads,
    # and report sarif-path as that final path, not the input string blindly.
    # After env-ifying, the SARIF_FILE env var (mapped from inputs.sarif-file) reaches the
    # shell via env:, not via ${{ }} interpolation in the run: block.
    scan = _scan_step()
    env = scan.get("env", {})
    assert "SARIF_FILE" in env, "scan step env: must map SARIF_FILE from inputs.sarif-file"
    run = scan["run"]
    assert 'mv "shipgrade.sarif" "$sarif_file"' in run
    assert 'echo "sarif-path=$sarif_file"' in run


def test_scan_warns_when_json_report_is_missing() -> None:
    # score/grade/findings-count come from shipgrade-report.json, written only when the config
    # lists json in outputs (src/shipgrade/cli.py:261-265). When it is absent the outputs are
    # empty, so the action must emit a GitHub warning telling the consumer to add json, not
    # fail silently.
    run = _scan_step()["run"]
    assert "::warning" in run
    assert "outputs list" in run


def _gate_step() -> dict:
    return next(s for s in _steps() if 'exit "$code"' in s.get("run", ""))


def test_no_context_interpolation_in_run_blocks() -> None:
    # Every run: block must be free of ${{ inputs.* }} and ${{ steps.* }} interpolation.
    # User-controlled values in shell context are a script-injection vector; they must
    # be passed via env: mappings and referenced as shell variables.
    for step in _steps():
        run = step.get("run", "")
        assert "${{ inputs." not in run, (
            f"step {step.get('id') or step.get('name')!r} interpolates inputs in run: "
            f"(injection vector); use env: mapping instead"
        )
        assert "${{ steps." not in run, (
            f"step {step.get('id') or step.get('name')!r} interpolates steps context in run: "
            f"(injection vector); use env: mapping instead"
        )


def test_run_blocks_never_emit_raw_inputs_in_workflow_commands() -> None:
    # No run: block may interpolate an env-mapped input directly inside a
    # workflow-command string (::warning ..., ::error ...). A CR/LF in the value
    # can forge additional workflow commands. The warning message must be static.
    workflow_cmd_re = re.compile(r"::(?:warning|error)[^\"'\n]*\$[A-Z_]+")
    for step in _steps():
        run = step.get("run", "")
        for line in run.splitlines():
            assert not workflow_cmd_re.search(line), (
                f"step {step.get('id') or step.get('name')!r} interpolates a variable "
                f"inside a workflow command string (CR/LF injection vector): {line!r}"
            )


def test_crlf_guard_exists_for_path_inputs() -> None:
    # The scan run: block must reject CR or LF in CONFIG, IGNORE_FILE, and SARIF_FILE
    # before those values are used in shell or written to GITHUB_OUTPUT. A CR/LF in a
    # value written to GITHUB_OUTPUT can forge workflow commands.
    run = _scan_step()["run"]
    # Each path input must have a case guard that exits on CR/LF.
    for var in ("CONFIG", "IGNORE_FILE", "SARIF_FILE"):
        assert var in run, f"env var {var} not found in scan step run:"
    # The guard pattern: case "$VAR" in *$'\n'*|*$'\r'*) exit 1;; esac
    assert "$'\\n'" in run or "$'\\r'" in run, (
        "scan step run: is missing a CR/LF guard (case ... $'\\n' ... exit 1)"
    )


def test_scan_step_has_env_block_for_inputs() -> None:
    # Inputs must reach the shell only through an env: block, not via ${{ }} interpolation.
    scan = _scan_step()
    env = scan.get("env", {})
    assert "CONFIG" in env, "scan step env: must map CONFIG from inputs.config"
    assert "FAIL_ON" in env, "scan step env: must map FAIL_ON from inputs.fail-on"
    assert "SARIF_FILE" in env, "scan step env: must map SARIF_FILE from inputs.sarif-file"
    assert "IGNORE_FILE" in env, "scan step env: must map IGNORE_FILE from inputs.ignore-file"


def test_gate_step_has_env_block_for_scan_exit_code() -> None:
    # The gate step must receive the scan exit code via env:, not via ${{ steps.* }}
    # interpolation in the run: block.
    gate = _gate_step()
    env = gate.get("env", {})
    assert "SCAN_CODE" in env, "gate step env: must map SCAN_CODE from scan outputs"
