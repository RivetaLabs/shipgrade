---
title: CLI and CI Gate
version: 1.1.2
last_updated: 2026-06-01
depends_on: [01-finding-contract, 10-ai-safety-score, 11-regression-mode, 14-ci-action-suppression]
related: [02-report-core, 09-severity-and-mapping]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS: the exit-code contract is fixed at 0 clean, 1 gate exceeded or regressed,
> 2 usage error, 3 run errored (spec 5.6). A waived finding (doc 14) is excluded from the
> gate and can never by itself produce exit 1. `--fail-on` is a per-run severity threshold
> that overrides `Config.gate_severity`; both are compared against `Finding.severity_score`
> at the same band boundaries doc 09 uses. The SARIF upload in the published Action runs
> before the gate-driven non-zero exit (doc 14), so a failing gate never suppresses findings.

## TLDR

- Current behavior: `shipgrade scan` audits a configured target, renders the chosen outputs,
  and exits with a CI-meaningful code. M8 finalizes the exit-code contract and adds three
  gate flags to `scan`: `--fail-on` (the severity gate threshold), `--ignore-file` (load
  accepted-risk waivers, doc 14), and `--baseline` (save or compare a regression baseline,
  doc 11). The gate is what makes `scan` usable in CI: it fails the build when a non-waived
  finding meets the threshold or a regression is detected.
- Core invariants: four fixed exit codes (0/1/2/3); a waived finding is excluded from the
  gate; `--fail-on` overrides `Config.gate_severity` for the run; the gate is computed only
  over active (non-waived) findings; `demo` never gates (it is a showcase, not a scan).
- Verification: `tests/test_cli.py` and `tests/test_scan.py` (T8) assert each exit code over
  fixtured findings (clean -> 0, a finding at/above the threshold -> 1, a waived-only run ->
  0, a bad flag/config -> 2, a scan that could not start -> 3); `uv run ruff check .`;
  `uv run pyright`; `uv run shipgrade demo` stays Grade F / 13 and byte-stable.
- Known gaps (deferred, spec 5.6, 6.1): SARIF `suppressions`/`baselineState` wiring (v1 keeps
  regression in its own JSON baseline, doc 11); a policy engine over the one `--fail-on`
  threshold; per-category gate thresholds; any gate that runs during `demo`.

## Data Model

This feature owns no new model. It reads frozen models already in `src/shipgrade/models.py`
(spec 5.7); do not add, rename, or retype a field.

- `Config.gate_severity: float` (validated `0.0 <= x <= 10.0`): the config-level gate
  threshold a scan uses when `--fail-on` is not passed. The starter config ships `7.0`.
- `Finding.severity_score: float` (0-10) and `Finding.severity_band: SeverityBand`
  (`critical | high | medium | low`): the gate compares each active finding's
  `severity_score` against the resolved threshold; `band_for_score` (doc 09) is the shared
  boundary function. `Finding.fingerprint: str` is the key the ignore file (doc 14) matches.
- `ScoreResult` (doc 10): `score: int`, `grade: Grade`. Regression mode (doc 11) compares the
  current `ScoreResult` against the baseline's to compute `grade_delta`; a negative delta is
  one of the two regression triggers.
- `RegressionResult` (frozen, spec 5.7, doc 11): `new_findings: list[Finding]`,
  `resolved_fingerprints: list[str]`, `grade_delta: int`, `regressed: bool`. `regressed` is
  `True` when any new finding is at/above the gate threshold or the grade dropped; a `True`
  `regressed` forces exit 1.
- `Waiver` (a LOCAL model owned by doc 14 / `suppression.py`, NOT in `models.py`):
  `fingerprint`, `reason`, optional `expires`. The gate excludes any finding whose fingerprint
  matches an unexpired waiver.

## Public Interface

`src/shipgrade/cli.py`, the `scan` command (Typer). After M8 (T8) its options are:

- `--config PATH` (required): the `shipgrade.yaml` path. Loaded via
  `config.load_config`; a load failure exits `2`.
- `--fail-on TEXT` (optional): the severity gate threshold for this run. Accepts a severity
  band name (`critical`, `high`, `medium`, `low`). When set, it overrides
  `Config.gate_severity` for the run. When absent, the gate uses `Config.gate_severity` from
  the config. The band name maps to the numeric threshold in Business Rules below.
- `--ignore-file PATH` (optional): a `.shipgrade-ignore.yaml` of accepted-risk waivers
  (doc 14). Loaded through the shared `_yaml` chokepoint into a `Waiver` list; the findings
  are partitioned by `suppression.partition` into active and waived. Waived findings still
  render (doc 02, doc 14) but are excluded from the gate.
- `--baseline PATH` (optional, default off): the regression gate is opt-in. The flag is wired
  `typer.Option(None, "--baseline")` and the gate block runs only `if baseline is not None`, so
  when `--baseline` is omitted no regression gate runs at all (no baseline is read or written).
  When `--baseline PATH` is passed, PATH is the baseline file: if it does not exist the run
  writes it (`regression.save_baseline(report, baseline)`) and does not gate on regression; if
  it exists the run compares against it (`regression.compare`) and a `regressed` result forces
  exit 1. Like the per-finding gate, the regression gate is a residual-risk gate: when a waiver
  is in force `scan` passes the active findings and their re-scored `ScoreResult` to `compare`
  (its `findings`/`score` parameters, doc 11), so a waived finding is excluded from the
  regression decision too and can never by itself force exit 1. The baseline is still saved
  whole. The `.shipgrade/baseline.json` default belongs to the
  `regression.save_baseline(report, path=".shipgrade/baseline.json")` / `load_baseline(...)`
  signatures (doc 11), NOT to this flag; do not give `--baseline` that default, or the
  regression gate would run on every scan and write `.shipgrade/baseline.json` on ordinary runs,
  contradicting doc 11's opt-in framing. The compare path's `load_baseline` call MUST be wrapped
  in a try/except that maps a load/`schema_version` error to exit `2` (Business Rules below),
  mirroring `--ignore-file`'s `PackLoadError`-to-`2` handling.
- `--allow-private-targets` (existing): permit scanning non-public hosts (HTTP adapter).
- `--offline` / `--no-judge` (existing): deterministic-only, zero network egress (spec 5.9).
- `--yes` (existing): skip the judge-egress consent line in CI.

`init` and `demo` are unchanged by this feature. `demo` never gates: it is a fixed offline
showcase (doc 06) and prints the CI line and the exit code a real `scan` would produce, but
exits 0 itself.

Functions this command composes (owned by sibling docs, referenced here, not redefined):
- `suppression.partition(findings: list[Finding], waivers: list[Waiver]) -> tuple[list[Finding], list[Finding]]`
  (doc 14): returns `(active, waived)`.
- `regression.save_baseline(report: Report, path) -> Baseline` and
  `regression.compare(report: Report, baseline: Baseline, *, gate: float) -> RegressionResult`
  (`gate` is keyword-only) (doc 11).
- `mapping.band_for_score(score: float) -> SeverityBand` (doc 09): the band boundary function
  the `--fail-on` map inverts.

## Output surface

- Exit codes (the CI contract, spec 5.6):

  | code | meaning | when |
  | --- | --- | --- |
  | 0 | clean | no active finding meets the gate threshold and no regression |
  | 1 | gate exceeded | an active (non-waived) finding's `severity_score` is at/above the threshold, OR `RegressionResult.regressed` is True |
  | 2 | usage error | a bad flag, an unknown `--fail-on` band name, a config that fails to load, an unreadable `--ignore-file`, or an unreadable / stale-`schema_version` `--baseline` (all mapped to `2` by `scan`'s try/except) |
  | 3 | run errored | the scan could not complete (could not start, an unrecoverable error after start) |

- The rendered report (CLI/HTML/JSON/SARIF, doc 02) is emitted before the process exits, so a
  gate-driven non-zero exit never hides the findings. In the published Action (doc 14) the
  SARIF upload step runs before this exit for the same reason.
- The accepted-risk / waived section (doc 02 item 5, doc 14) lists each waiver's reason;
  waived findings are visible, never silently dropped.
- No new stdout strings are specified here beyond the existing `scan` output; the exit code is
  the machine-readable surface. `demo` keeps its existing closing block (the `--fail-on high`
  CI line and "this grade (F) would exit 1" note, spec 7.3).

## Business Rules

### Exit-code contract (spec 5.6, the load-bearing rule)

- `0` clean: the gate found nothing to fail on. Either zero findings, or every finding at/above
  the threshold is waived, and no regression.
- `1` gate exceeded: at least one ACTIVE finding has `severity_score >= threshold`, OR the
  regression comparison returned `regressed == True`. Either condition alone is sufficient.
- `2` usage error: a bad flag, an unparseable `--fail-on` value (a band name not in the map
  below), a config that fails to load (`PackLoadError` on `load_config`), an unreadable
  `--ignore-file` (`PackLoadError` from `load_waivers`), or an unreadable / stale-`schema_version`
  `--baseline` (the raise from `load_baseline`, which `scan` wraps and maps to `2`). The CLI
  already exits `2` on config `PackLoadError` today; the ignore-file and baseline mappings are
  the same try/except pattern applied to those two loads.
- `3` run errored: the scan could not complete. The CLI already exits `3` on a scan-start
  `PackLoadError` today; any unrecoverable error after the report is assembled also exits `3`.
  A single probe erroring is NOT a run error: per-probe isolation (spec 8) keeps that probe a
  `ProbeResult(status="errored")` and the run continues, surfacing it in the report and in
  `coverage == "partial"` (doc 10).

Precedence when conditions overlap: a usage error (`2`) or a load failure that prevents the
run is resolved before any gate is evaluated, so it wins over `1`. Once the scan completes, the
gate decides between `0` and `1`. A `3` is only for an actual inability to produce a report.

### `--fail-on` vs `Config.gate_severity`

- The effective gate threshold is `--fail-on` when passed, else `Config.gate_severity`.
- `--fail-on` takes a severity band NAME; `Config.gate_severity` is a numeric `float`. The
  band name resolves to the numeric lower bound of that band, matching `band_for_score`
  (doc 09) so the gate and the displayed band agree:

  | `--fail-on` | numeric threshold | meaning |
  | --- | --- | --- |
  | `critical` | 9.0 | fail only on a critical finding |
  | `high` | 7.0 | fail on high or critical (the common CI setting) |
  | `medium` | 4.0 | fail on medium and worse |
  | `low` | 0.0 | fail on any finding (every finding bands at or above low) |

- A finding fails the gate when `finding.severity_score >= threshold`. `high` resolves to
  `7.0`, so a `high` (7.0-8.9) or `critical` (>= 9.0) finding fails; a `medium` (4.0-6.9) does
  not. This is consistent with `band_for_score`: `high` starts at 7.0, `critical` at 9.0.
- `low` resolves to `0.0`, the floor of the `low` band, so a `--fail-on low` gate fails on any
  finding the run produced (every `severity_score` is `>= 0.0`). This is the exact inverse of
  `band_for_score`, which bands `0.0` as `low`; T8's `_FAIL_ON_THRESHOLD["low"]` is `0.0` to
  match (spec 5.4).
- The pre-commit hook (doc 14, T10) ships `args: ["--offline", "--fail-on", "high"]`, so the
  band-name form is the documented default for the hook. The demo's closing CI line
  (`shipgrade scan --config shipgrade.yaml --fail-on high`) uses the same form.

### Waived findings are excluded from the gate (spec 6.1, doc 14)

- A waiver in the `--ignore-file` is keyed on `Finding.fingerprint` and carries a `reason` and
  optional `expires`. `suppression.partition` (doc 14) splits the findings into `active` and
  `waived`; an EXPIRED waiver does not waive (the finding stays active).
- The gate is computed ONLY over the `active` findings. A waived finding can never by itself
  produce exit `1`. This is the rule that makes the gate usable: a team accepts a known risk
  with a written reason instead of disabling the gate.
- Waived findings still render in the accepted-risk section with their reason (doc 02, doc 14);
  they are never silently dropped, so the report stays honest about what was accepted.
- The score (doc 10) is computed over the full `Finding[]` the run produced; v1 does not remove
  waived findings from the score, only from the gate. The waiver is a CI-gate decision, not a
  re-grade. (If a later milestone changes this, it is a doc 10 + doc 12 change, gated.)

### `--baseline` (regression gate, doc 11)

- When `--baseline PATH` is passed and the file does not exist: the run writes the baseline
  (`regression.save_baseline`, fingerprints + score only, no evidence, spec 5.7/5.9) and does
  NOT gate on regression. A first baseline run can still exit `1` on the severity gate.
- When the baseline exists: `regression.compare(report, load_baseline(baseline), gate=threshold)`
  returns a `RegressionResult`. `regressed == True` (a new finding at/above the threshold OR a
  grade drop) forces exit `1`, even if the severity gate alone would have passed (e.g. the new
  finding is below the threshold but the grade dropped).
- A `schema_version` mismatch between the on-disk baseline and the current `Baseline` model is
  detected by doc 11's `load_baseline`, which raises on it (doc 11 Failure Modes). `scan` MUST
  wrap that load in a try/except and map the raise to `raise typer.Exit(code=2)`, mirroring the
  `--ignore-file` path (which already maps `PackLoadError` to exit `2`). Without that wrapping
  an uncaught raise from `load_baseline` exits the Typer command with code `1` and a raw
  traceback, not the documented usage error. The required shape is:

  ```python
      from shipgrade.regression import (
          BaselineLoadError,  # or the concrete exception type doc 11 / T6 raises
          compare,
          load_baseline,
          save_baseline,
      )

      if not baseline.is_file():
          save_baseline(report, baseline)
      else:
          try:
              base = load_baseline(baseline)
          except BaselineLoadError as exc:
              typer.echo(f"baseline error: {exc}", err=True)
              raise typer.Exit(code=2) from exc
          regressed = compare(report, base, gate=threshold).regressed
  ```

  v1 treats an unreadable or stale baseline as a usage error (`2`), not a silent pass, so a stale
  baseline cannot mask a regression. The exit-2 guarantee holds only because the load is wrapped;
  if T6/T8 do not implement this wrapping, the doc and the code disagree and this is the line to
  reconcile.

### `demo` never gates

- `demo` is a fixed offline showcase (doc 06, spec 7) and exits `0`. It prints the CI line and
  the exit code a real `scan --fail-on high` would produce on the demo target (`1`, since
  DEMO-001/002/003 are at/above high), but it does not itself evaluate a gate or change its
  exit code. The Grade F / 13 demo output stays byte-identical (the M2/M4 snapshot invariant).

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| No finding meets the threshold, no regression | report renders, exit 0 | none needed; the build passes |
| An active finding at/above `--fail-on` | report renders, exit 1 | fix the finding, lower its severity, or waive it with a reason |
| Every gate-meeting finding is waived | report renders with the accepted-risk section, exit 0 | none; the risk is accepted in writing |
| Regression: a new finding above the gate or a grade drop | report renders, exit 1 | address the regression or update the baseline deliberately |
| Unknown `--fail-on` band name (e.g. `--fail-on huge`) | usage error, exit 2 | pass one of `critical`/`high`/`medium`/`low` |
| Config fails to load (`PackLoadError`) | `config error: ...` on stderr, exit 2 | fix the config YAML |
| Scan cannot start (pack load fails after config) | `scan could not start: ...` on stderr, exit 3 | fix the referenced probe/rule pack |
| A single probe errors mid-run | that probe is `status="errored"`, the run continues, `coverage` partial | none; per-probe isolation (spec 8); the report shows it |
| `--baseline` file absent | baseline written, no regression gate this run | re-run to compare against the new baseline |
| `--baseline` file has a stale `schema_version` | `load_baseline` raises (doc 11); `scan`'s try/except maps it to `baseline error: ...` on stderr, exit 2 (a stale baseline cannot silently pass). Without the wrapping the raise exits 1 with a traceback, so the wrapping is required. | regenerate the baseline |
| Expired waiver in the ignore file | the finding is treated as active and can fail the gate | renew the waiver with a current `expires`, or fix the finding |

## Edge Cases

- `--fail-on` not passed and `Config.gate_severity` is `0.0`: every finding fails, because
  `severity_score >= 0.0` holds for every finding. This is the same threshold `--fail-on low`
  resolves to (`0.0`), so a `0.0` gate and `--fail-on low` gate identically on any finding.
- Zero findings with `--fail-on` set to anything: exit 0 (nothing to fail on), regardless of
  the threshold.
- `--ignore-file` passed but empty (no waivers): every finding is active; the gate behaves as
  if no ignore file were passed.
- A waiver whose fingerprint matches no current finding: a no-op; it neither errors nor
  changes the gate. (The fingerprint recipe is frozen, spec 5.5.1, so a stale waiver simply
  stops matching once the finding is fixed.)
- `--offline` with `--fail-on`: deterministic-only findings still gate normally; the LLM-judge
  categories are skipped and the run is `coverage == "partial"` (doc 10). A partial run can
  still exit 1 on a deterministic finding (e.g. a secret echo at critical).
- `demo` with no flags: always exit 0, Grade F / 13, byte-stable; it ignores any gate concept.
