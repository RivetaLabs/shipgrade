---
title: Regression Mode
version: 1.2.0
last_updated: 2026-06-02
depends_on: [01-finding-contract, 10-ai-safety-score]
related: [02-report-core, 12-cli-and-ci-gate, 14-ci-action-suppression]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS: the baseline at `.shipgrade/baseline.json` stores `Finding.fingerprint`
> values and the `ScoreResult` only, never `Evidence` or any response text (spec 5.7), so a
> committed baseline leaks nothing. A finding is new iff its fingerprint is not in the
> baseline set; a fingerprint is resolved iff it is in the baseline but not in the current
> run. `grade_delta = current.score.score - baseline.score.score`. `regressed` is true iff
> any new finding meets the gate severity OR `grade_delta < 0`. `schema_version` is checked
> on load: a mismatch is detected and reported, never silently misread. The fingerprint
> recipe is frozen in `report/fingerprint.fingerprint`; this feature only compares
> fingerprint strings and never re-derives or re-hashes them.

## TLDR

- Current behavior: regression mode is one of the three locked stack modules (spec 6, M8).
  It saves a baseline of a graded run (`save_baseline`) and compares a later run against it
  (`compare`), so CI can fail when a prompt or config change introduces a new risk or drops
  the grade. The baseline is a small JSON file of fingerprints plus the score, never
  evidence (spec 5.7), so it is safe to commit. The comparison is pure data: set difference
  over fingerprints plus an integer score delta. It never calls a model.
- Core invariants: fingerprints-only persistence; new iff fingerprint absent from baseline;
  resolved iff baseline fingerprint absent from the current run; `grade_delta` is a signed
  score delta; `regressed` keys on a new finding meeting the gate or any grade drop;
  `schema_version` mismatch is detected, not misread.
- Verification: `tests/test_regression.py` (T6) asserts save round-trips the baseline,
  `compare` classifies new and resolved fingerprints, computes `grade_delta`, sets
  `regressed` on a gate-meeting new finding and on a grade drop, and raises on a
  `schema_version` mismatch; `uv run pyright`; `uv run ruff check .`.
- Known gaps (deferred): SARIF `baselineState`/`suppressions` wiring stays out of v1 (spec
  5.5.1); v1 keeps regression in its own JSON baseline. No per-category trend history, no
  stored grade timeline beyond the single baseline, no remote baseline store. A PR-comment
  surface off `grade_delta` is possible later (spec 5.10) but is not built here.

## Data Model

This feature owns no new model. It reads the frozen `Finding` (spec 5.5) and the frozen
`ScoreResult` and `Report`, and it reads and writes the frozen `Baseline` and
`RegressionResult`, all already in `src/shipgrade/models.py` (spec 5.7). Do not add,
rename, or retype a field; a `Baseline` or `RegressionResult` field change is an
architecture change gated per CLAUDE.md.

- `Baseline` (persisted at `.shipgrade/baseline.json`; fields in declaration order, all
  required):
  - `schema_version: int`: the baseline format version. Checked on load so an old baseline
    is detected, not silently misread (spec 5.7). Current value is `1`.
  - `created_at: datetime`: when the baseline was written.
  - `tool_version: str`: the `RunMetadata.tool_version` that produced the baseline run.
  - `fingerprints: list[str]`: the set of `Finding.fingerprint` values from the baseline
    run. Stored by fingerprint, never as full findings or evidence, so a committed baseline
    leaks no sensitive text (spec 5.7).
  - `score: ScoreResult`: the full baseline `ScoreResult` (doc 10), so `grade_delta` and
    any grade-drop check read a real prior score, not just a number.
- `RegressionResult` (the comparison output; fields in declaration order, all required):
  - `new_findings: list[Finding]`: the current-run findings whose fingerprint is not in the
    baseline set. These are the CI-failing set when one meets the gate.
  - `resolved_fingerprints: list[str]`: baseline fingerprints absent from the current run
    (a finding that was fixed or waived away).
  - `grade_delta: int`: `current.score.score - baseline.score.score` (a signed 0-100 delta;
    negative means the grade got worse).
  - `regressed: bool`: true iff any `new_findings` entry meets the gate severity OR
    `grade_delta < 0` (Business Rules below).
- `Finding.fingerprint` is the join key. It is the first 32 hex chars of a sha256 over the
  stable input tuple `category|probe_id|rule_id|adapter_target_identity` (spec 5.5.1),
  frozen in `report/fingerprint.fingerprint` with a committed golden vector. Regression
  mode compares these strings; it never recomputes them, so a baseline and a re-run agree as
  long as the recipe constant is unchanged.

## Public Interface

The two functions are built by T6 (`src/shipgrade/regression.py`) against these signatures;
this doc fixes their contract. `regression.py` imports the frozen models, the
`_yaml`/json read-write path it needs, and nothing from the judge SDK, an adapter, or a
renderer.

- `save_baseline(report: Report, path: str = ".shipgrade/baseline.json") -> Baseline`:
  builds a `Baseline` from `report` and writes it as JSON to `path`. It takes
  `schema_version = 1`, `created_at = report.metadata.started_at`,
  `tool_version = report.metadata.tool_version`,
  `fingerprints = [f.fingerprint for f in report.findings]`, and `score = report.score`. It
  creates the parent directory (`.shipgrade/`) if absent and overwrites the file each run,
  so a committed baseline tracks the latest graded state. It returns the `Baseline` it
  wrote. It never writes `Evidence` or any response text.
- `compare(report: Report, baseline: Baseline, *, gate: float, findings: list[Finding] |
  None = None, score: ScoreResult | None = None) -> RegressionResult` (all after `report`
  and `baseline` are keyword-only): compares the current `report` against `baseline` and
  returns a `RegressionResult`. `gate` is the severity threshold (the same value as
  `Config.gate_severity` / `--fail-on`, doc 12). `findings` and `score` default to
  `report.findings` and `report.score`; a caller passes the active (non-waived) findings and
  their re-scored `ScoreResult` to make this a residual-risk gate (Business Rules below), so a
  waived finding is excluded from the regression decision exactly as it is from the
  per-finding gate. The classification is set-membership over fingerprints. It is a pure
  function: same inputs, same `RegressionResult`.
- A `load_baseline(path: str = ".shipgrade/baseline.json") -> Baseline` read is implied by
  the save/compare pair; T6 owns its exact name and signature and the `schema_version`
  check it performs (Failure Modes below). This doc requires only that the load validates
  the JSON through the frozen `Baseline` model and rejects a `schema_version` it does not
  understand.

These power `scan --baseline PATH` (doc 12, T8): when the baseline file is absent, `scan`
writes it via `save_baseline` and exits clean; when it is present, `scan` compares via
`compare` and the gate uses `RegressionResult.regressed` alongside the per-finding gate
(doc 12 owns the exit-code contract, spec 5.6).

## Output surface

- None of its own beyond the JSON baseline file. `RegressionResult` is consumed by `scan`
  (doc 12) to decide the exit code and to print a one-line regression summary (new count,
  resolved count, `grade_delta`); that rendering and its exit-code mapping are owned by doc
  12, not redefined here.
- The baseline file at `.shipgrade/baseline.json` is a committed artifact a repo tracks
  across runs. `.shipgrade/` is already gitignored for the runtime badge, so committing a
  baseline is an explicit `git add` choice the adopter makes; the file is safe to commit
  because it holds fingerprints and the score only.
- `grade_delta` is available for a later PR-comment surface (spec 5.10), but no such surface
  ships in this feature.

## Business Rules

### Baseline persistence (fingerprints only, spec 5.7)

- The baseline stores `fingerprints` (the `Finding.fingerprint` set) and the full
  `ScoreResult`, and nothing else from the findings. It never stores `Evidence`,
  `response_excerpt`, `description`, `fix`, or any other free text from a finding, so a
  committed baseline cannot leak a target's redacted-but-still-sensitive content.
- `schema_version` is the integer `1` in v1. It is written on save and checked on load. A
  baseline written by a future, incompatible format carries a different `schema_version`,
  which the load path detects and reports (Failure Modes), rather than misreading old bytes
  as the current shape.

### New, resolved, and the fingerprint join (spec 5.7)

Let `current = {f.fingerprint for f in report.findings}` and `base = set(baseline.fingerprints)`.

- A current finding is **new** iff `f.fingerprint not in base`. `new_findings` is the list of
  such `Finding` objects, preserving the current run's order.
- A baseline fingerprint is **resolved** iff it is `in base` and `not in current`.
  `resolved_fingerprints` is the sorted (or current-order-stable; T6 picks one and the test
  pins it) list of those strings.
- The comparison is pure set membership over the 32-char fingerprint strings. It never
  re-hashes; a baseline and a re-run on the same target produce identical fingerprints
  because the recipe (`report/fingerprint.fingerprint`, spec 5.5.1) hashes only the stable
  input tuple, never response text, scores, or run ids. This is what lets a non-deterministic
  judge re-run not churn the new/resolved split.
- **Sanitized-identity re-keying (S2, 2026-06-02):** the `adapter_target_identity` in the
  fingerprint tuple is now the sanitized target identity (HTTP host, prompt-file basename,
  callable `module:func`), not the raw `target.ref`. Any baseline saved before this change
  was keyed on the raw ref, so every finding would read as new against it. This is a one-time
  re-key, not a schema change (`schema_version` stays `1`): a stale baseline still loads, it
  just diffs as all-new. Recovery: delete the stale baseline file and re-run
  `scan --baseline PATH` so the next run re-seeds it on the sanitized identity.

### grade_delta and regressed (the CI signal, spec 5.6, 6.1)

- `grade_delta = report.score.score - baseline.score.score`. It is a signed integer in
  `[-100, 100]`. A negative `grade_delta` means the current run scored lower than the
  baseline (the grade got worse).
- `regressed` is true iff EITHER:
  1. at least one `new_findings` entry meets the gate, i.e. its `severity_score >= gate`, OR
  2. `grade_delta < 0` (the score dropped at all).
- Otherwise `regressed` is false: a run that introduces only sub-gate new findings and does
  not lower the score has not regressed. A new finding below the gate still appears in
  `new_findings` (so it is reported) but does not by itself set `regressed`.
- `regressed` is the value `scan --baseline` feeds into the gate; the exit code it produces
  (1 when regressed, per the 5.6 contract) is owned by doc 12.

### Relationship to suppression and the per-finding gate (doc 12, doc 14)

- The regression gate is a **residual-risk gate**, like the per-finding gate: it evaluates the
  active (non-waived) findings, not the whole report. Waiver handling (doc 14,
  `.shipgrade-ignore.yaml`) is applied by `scan`, which partitions active vs waived findings
  and then passes the active findings and their re-scored `ScoreResult` to `compare` via its
  `findings`/`score` parameters. So a waived finding is neither a gating new finding nor a
  source of `grade_delta` drop: a newly-accepted (waived) risk does not fail CI through the
  regression path, exactly as it is excluded from the per-finding gate (spec 6.1). `compare`
  itself never reads the ignore file; it takes the active view `scan` hands it.
- `report.findings`, `report.score`, the badge, and the saved baseline stay **whole** (they
  include waived findings), so nothing is silently dropped from what is recorded or shown; only
  the gate decision uses the active view. With no waiver in force the active set is the full
  report, so `compare` sees the whole report unchanged and the defaults apply.
- The `gate` argument to `compare` is the same severity threshold as the per-finding gate
  (`Config.gate_severity` / `--fail-on`), so "a new finding that would fail the gate" and "a
  finding that fails the gate today" use one threshold, not two.

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| Baseline file absent on a `--baseline` run | `scan` calls `save_baseline`, writes the file, exits clean (doc 12) | None; the first run seeds the baseline |
| `schema_version` on load is not the supported value | load raises an actionable error naming the found vs expected version; the run does not silently misread | regenerate the baseline with the current tool version |
| Baseline JSON malformed or missing a required field | `Baseline.model_validate` raises a validation error (extra fields forbidden, spec 5.8) | fix or regenerate the baseline |
| Parent dir `.shipgrade/` missing on save | `save_baseline` creates it, then writes | None; idempotent, overwrites each run |
| Current run errored some probes (partial coverage) | comparison still runs over whatever findings exist; `grade_delta` uses the partial-run score; coverage is the score's concern (doc 10), not regression's | re-run with full coverage if the partial result is not actionable |

## Edge Cases

- Empty baseline (`fingerprints == []`): every current finding is new; nothing is resolved.
  `regressed` follows the gate and grade-drop rules over those new findings.
- Identical re-run (same findings, same score): `new_findings == []`,
  `resolved_fingerprints == []`, `grade_delta == 0`, `regressed == False`.
- All findings fixed (current run clean, baseline had findings): `new_findings == []`,
  every baseline fingerprint is in `resolved_fingerprints`, `grade_delta >= 0`,
  `regressed == False`.
- Grade improved but a new sub-gate finding appeared: the new finding is in `new_findings`,
  `grade_delta > 0`, and `regressed == False` (a sub-gate new finding does not regress and a
  higher score does not regress).
- Grade dropped with no new finding (e.g. an existing finding's confidence rose, raising its
  penalty): `new_findings == []` but `grade_delta < 0`, so `regressed == True` on the
  grade-drop arm alone.
- A fingerprint appears in both baseline and current (an unresolved finding that persists):
  it is neither new nor resolved; it carries no signal beyond its contribution to the score.
