---
title: CI Action and Suppression
version: 1.1.0
last_updated: 2026-06-02
depends_on: [01-finding-contract, 11-regression-mode, 12-cli-and-ci-gate]
related: [02-report-core, 04-probes, 10-ai-safety-score]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS: a waiver is keyed on `Finding.fingerprint` (the 32-hex
> `report.fingerprint.fingerprint` value, spec 5.5.1), never on a probe id or title; each
> waiver carries a non-empty `reason` and an optional ISO-8601 `expires` date; an expired
> or unmatched waiver is inert, never an error; a waived finding still renders as
> "accepted risk" with its reason and is excluded from the gate, never silently dropped
> (spec 6.1); the `.shipgrade-ignore.yaml` file loads through the shared `_yaml` chokepoint
> like every other pack; in `action.yml` the SARIF upload (`if: always()`) runs BEFORE the
> gate-driven non-zero exit, or a failing gate hides the very findings the Security tab
> should show (spec 6.2); every `uses:` in `action.yml` is pinned to a 40-char commit SHA;
> minimum consumer permissions are `security-events: write` and `contents: read`; the
> pre-commit hook runs `shipgrade scan --offline --fail-on high`, key-free and network-free;
> every `run:` block in `action.yml` is free of `${{ inputs.* }}` and `${{ steps.* }}`
> interpolation -- user-controlled values reach shell only via `env:` mapping, and path
> inputs are validated for CR/LF before use or `$GITHUB_OUTPUT` writes.

## TLDR

- Current behavior: doc 14 specifies three CI-surface artifacts (spec 6.1, M8). (1) The
  `.shipgrade-ignore.yaml` waiver file lets a risk owner accept a specific finding by its
  stable fingerprint so the CI gate stops failing on a known, reasoned exception, while the
  finding still shows in the report as accepted risk. (2) The composite `action.yml` wraps
  `uvx shipgrade scan ... --sarif <file>`, uploads SARIF to the repo Security tab, then
  exits per the gate. (3) The `.pre-commit-hooks.yaml` ships an offline, key-free local hook
  for `shipgrade scan`. None of the three adds a probe, OWASP category, model, or `Finding`
  field; each is config or a thin reuse of the existing fingerprint.
- Core invariants: waivers key on `Finding.fingerprint` only; a waived finding renders as
  accepted risk with its reason and is excluded from the gate but never dropped; an expired
  or unmatched waiver is inert; the action uploads SARIF (`if: always()`) before the
  gate-driven non-zero exit; every `action.yml` `uses:` is a 40-char SHA; the hook is
  `--offline --fail-on high`.
- Verification: `tests/test_suppression.py` (T5, the ignore-file load + `partition` +
  expiry); `tests/test_action_yml.py` (T9, the step order, the SARIF-before-exit ordering,
  the pinned-SHA and permissions invariants); `tests/test_precommit_hook.py` (T10, the hook
  structure); `tests/test_example_config.py` (T11, the documented ignore-file shape
  round-trips through the suppression loader); the parse check in Step 3; `./verify.sh`.
- Known gaps (deferred, spec 6, 11.3): full VEX output beyond the simple fingerprint-keyed
  ignore-file, SARIF `suppressions`/`baselineState` wiring (v1 keeps regression in its own
  JSON baseline, doc 11), per-rule or per-category waivers (v1 waives one fingerprint at a
  time), and a marketplace-published action listing are out of v1. SBOM/Sigstore signing
  beyond PyPI's PEP 740 attestations is deferred to the release posture (doc, spec 11.3).

## Data Model

This feature owns no `models.py` change; the frozen `Finding` contract is untouched (spec
5.5). It defines two on-disk YAML schemas and reuses one local model.

### `.shipgrade-ignore.yaml` (the waiver file, spec 6.1)

A YAML mapping with a top-level `waivers` list. Each entry is one accepted-risk waiver:

```yaml
waivers:
  - fingerprint: "944668538602013a3814e5d5089fadca"   # Finding.fingerprint (32 hex, spec 5.5.1)
    reason: "Internal sandbox target; not user-facing. Tracked in JIRA-1234."
    expires: "2026-12-31"                              # optional ISO-8601 date; omit for no expiry
  - fingerprint: "0123456789abcdef0123456789abcdef"
    reason: "Accepted by compliance 2026-06-01; disclaimer added downstream."
```

Field contract (each waiver), deserialized by T5 into a LOCAL `Waiver` Pydantic model in
`src/shipgrade/suppression.py` (NOT a `Finding`/`models.py` change, spec 6.1):

- `fingerprint: str` - the exact 32-hex-character `Finding.fingerprint` (spec 5.5.1) of the
  finding being waived. This is the value `report.fingerprint.fingerprint(category,
  probe_id, rule_id, target_identity)` produced; it is shown in the JSON/SARIF output and is
  what the reader copies into the waiver. Required, non-empty.
- `reason: str` - a non-empty plain-English justification. It renders verbatim in the
  accepted-risk section (spec 5.5 item 5), so an empty reason defeats the audit trail and is
  rejected at load.
- `expires: str | None = None` - optional ISO-8601 date (`YYYY-MM-DD`). When set and the
  date is on or before today, the waiver is expired and inert (the finding gates again).
  Omit the key for a waiver that never expires.

The file loads through the shared `_yaml` chokepoint (`src/shipgrade/_yaml.py`), so it
inherits the SafeLoader, the anchor/alias ban, and the 1 MB byte cap like every probe and
rule pack. The top-level document must be a mapping with a `waivers` key whose value is a
list; an empty or missing `waivers` list means "no waivers" (a clean run), not an error.

### `Waiver` (local model, owned by T5 `src/shipgrade/suppression.py`)

`Waiver` is a Pydantic v2 model local to the suppression module, never imported into
`models.py`. Fields mirror the file: `fingerprint: str`, `reason: str`, `expires: str | None
= None`. T5 also owns `partition(findings: list[Finding], waivers: list[Waiver]) ->
tuple[list[Finding], list[Finding]]` returning `(active, waived)`; doc 12 (T3) documents how
`scan` excludes the `waived` list from the gate. Doc 14 fixes the file shape and field
semantics; T5 implements the loader and `partition`.

### `action.yml` and `.pre-commit-hooks.yaml`

These are GitHub Action and pre-commit config files, not Pydantic models. Their full
required content is in Business Rules below; T9 and T10 build them against that.

## Public Interface

Doc 14 documents no new Python public function of its own (the loader and `partition` are
T5's, documented above and consumed per doc 12). The user-facing interface is three files
and one CLI flag they feed:

- `.shipgrade-ignore.yaml` at the repo root (or any path), passed to `scan` via
  `--ignore-file PATH` (spec 5.6; wired by T8, behavior in doc 12). The composite action
  exposes it as the `ignore-file` input.
- `action.yml` at the repo root: a composite GitHub Action consumed as
  `RivetaLabs/Shipgrade@<ref>` in a consumer workflow (spec 6.2, 11.3).
- `.pre-commit-hooks.yaml` at the repo root: the hook manifest a consumer references in
  their `.pre-commit-config.yaml` as `repo: https://github.com/RivetaLabs/Shipgrade`,
  `hooks: [{id: shipgrade}]` (spec 6.2).

## Output surface

- The waiver file changes the report's accepted-risk section: each waived finding renders
  there with its `reason` (spec 5.5 item 5, doc 02), and is removed from the gate
  computation (doc 12). It never changes the `Finding` shape or the SARIF schema.
- `action.yml` outputs (spec 6.2), set from the scan's JSON/score output for downstream
  steps: `score`, `grade`, `sarif-path`, `findings-count`.
- The exit code the action propagates is the scan's (spec 5.6): `0` clean, `1` gate
  exceeded or regressed, `2` usage, `3` run errored. The exit-code contract itself is
  documented in doc 12; the action's job is to upload SARIF before that exit fires.

## Business Rules

### Waiver matching (spec 6.1)

- A waiver matches a finding iff `waiver.fingerprint == finding.fingerprint` (exact 32-hex
  string equality). No prefix match, no probe-id match, no title match: the fingerprint is
  the only key, because it is the one value that is stable across runs (spec 5.5.1) and
  survives a non-deterministic target.
- A matched, non-expired waiver moves its finding from `active` to `waived` (T5's
  `partition`). A waived finding still renders (as accepted risk, with its `reason`) and is
  excluded from the `--fail-on` gate, so a waived finding cannot by itself produce exit `1`
  (spec 5.6, doc 12). Findings are never silently dropped (spec 6.1).
- Expiry: when `expires` is set and `date.fromisoformat(expires) <= today`, the waiver is
  expired and does NOT match; its finding stays `active` and gates normally. An absent
  `expires` never expires. "Today" is the run date (UTC date is acceptable; T5 fixes the
  exact source and tests it).
- An unmatched waiver (no finding has that fingerprint this run) is inert and is NOT an
  error: a fingerprint goes away when its finding is fixed, and the stale waiver should not
  fail the build. T5 may surface a count of unmatched/expired waivers; that is informational,
  not a gate.

### `action.yml` (composite, spec 6.2, 11.3)

The action is a thin wrapper, not new capability. Its load-bearing details:

- `runs.using: composite` with `runs.steps` a shell sequence.
- Inputs (all `required: false` with sensible defaults; T9 fixes the defaults):
  `config` (config path), `fail-on` (severity threshold passed to `--fail-on`), `outputs`
  (the `scan` output formats), `ignore-file` (path to `.shipgrade-ignore.yaml`),
  `sarif-file` (the SARIF output path), `upload-sarif` (boolean, default true), and
  `category` (the SARIF upload category for stable alert collapsing, spec 6.2).
- Outputs: `score`, `grade`, `sarif-path`, `findings-count`.
- Step order, and the ordering invariant (the single most important rule here):
  1. run `uvx shipgrade scan ... --sarif <sarif-file>` (and the other inputs as flags),
     capturing the score/grade/findings-count into the step outputs;
  2. `github/codeql-action/upload-sarif@<pinned-40-char-SHA>` with `if: always()` and a
     `with: { sarif_file: <sarif-file>, category: <category> }`, gated on the `upload-sarif`
     input being true;
  3. the gate-driven non-zero exit per the scan's exit code (spec 5.6).
  The SARIF upload MUST run before the gate-driven non-zero exit. If a failing gate exited
  the job first, GitHub would never receive the SARIF and the Security tab would be empty
  for exactly the runs that found something (spec 6.2). `if: always()` on the upload step is
  what guarantees the upload runs even when the scan step set a failing status.
- Every `uses:` in `action.yml` is pinned to a full 40-character commit SHA with a
  `# vX.Y.Z` comment (spec 11.3); a tag or branch ref is rejected by the posture guard.
  Match the pinning style already in `.github/workflows/ci.yml`
  (e.g. `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1`).
- Injection-safe pattern: every `run:` block in `action.yml` must be free of
  `${{ inputs.* }}` and `${{ steps.* }}` interpolation. User-controlled inputs reach
  shell only through an `env:` block on the step; the `run:` script references them as
  ordinary shell variables (e.g. `"$CONFIG"`). This prevents script injection and
  workflow-command injection via CR/LF in input values. Each path input (`CONFIG`,
  `IGNORE_FILE`, `SARIF_FILE`) is validated against CR/LF at the top of the `run:` block
  with a `case "$VAR" in *$'\n'*|*$'\r'*) exit 1;; esac` guard before the value is used
  in shell commands or written to `$GITHUB_OUTPUT`. Workflow-command strings
  (`::warning`, `::error`) use only static text with no interpolated variables.
  `tests/test_action_yml.py::test_no_context_interpolation_in_run_blocks` and
  `test_crlf_guard_exists_for_path_inputs` enforce these invariants.
- Minimum consumer permissions the action's usage docs state: `security-events: write`
  (to upload SARIF) and `contents: read`. The action does not request `write` on contents.
- SARIF upload identity (spec 6.2): the consumer passes a fixed `category` so re-runs
  collapse onto one alert set; the byte-stable triple is `ruleId` + the anchor-file `uri` +
  `partialFingerprints.primaryLocationLineHash` (carried by the SARIF renderer, doc 02), not
  doc 14's to implement, but doc 14 explains why `category` exists.

### `.pre-commit-hooks.yaml` (spec 6.2)

Exactly one hook, with these fields (T10 builds it, `tests/test_precommit_hook.py` asserts
the structure):

```yaml
- id: shipgrade
  name: shipgrade
  description: Audit an LLM feature for product-safety and regulated-domain compliance.
  entry: shipgrade scan
  language: python
  pass_filenames: false
  args: ["--offline", "--fail-on", "high"]
  stages: [pre-commit]
```

- `--offline` keeps the hook key-free and network-free (deterministic detectors only, spec
  5.9), so it never blocks a commit on a missing API key.
- `pass_filenames: false` because `scan` audits a target via config, not the staged files.
- No SARIF in the local hook (SARIF is the CI/action surface).
- The published `.pre-commit-config.yaml` snippet in the README quickstart carries the
  `ci: skip` line so a pre-commit.ci run does not double-run the hook (spec 6.2); that
  snippet is README copy (M9), not part of `.pre-commit-hooks.yaml`.

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| `.shipgrade-ignore.yaml` missing at the `--ignore-file` path | T5 raises the actionable `_yaml` `PackLoadError` ("file not found"); `scan` maps it to exit `2` (usage, doc 12) | fix the path or omit `--ignore-file` |
| ignore-file is not a YAML mapping, or `waivers` is not a list | `PackLoadError` from the `_yaml` chokepoint (non-mapping / schema-invalid) | correct the file shape |
| a waiver has an empty or missing `reason` | rejected at load by the `Waiver` schema (a waiver with no justification defeats the audit trail) | add a non-empty `reason` |
| `expires` is not an ISO-8601 date | rejected at load by T5's date validation | use `YYYY-MM-DD` |
| a waiver's fingerprint matches no finding this run | inert, no error (the finding was fixed; the stale waiver is harmless) | optionally remove the stale waiver |
| an expired waiver | inert; its finding gates normally as if unwaived | refresh the `expires` date or fix the finding |
| `action.yml` `uses:` pinned to a tag, not a SHA | the posture-guard CI job fails closed (spec 11.3) | re-pin to a 40-char commit SHA with a `# vX.Y.Z` comment |
| the scan step fails the gate (exit `1`) | the `if: always()` SARIF upload still runs, then the job exits non-zero | findings appear in the Security tab and the gate still fails the build |

## Edge Cases

- An empty `.shipgrade-ignore.yaml` (`waivers: []` or no `waivers` key) is a valid file
  meaning "no waivers"; the run is identical to passing no `--ignore-file`.
- Two waivers with the same fingerprint: the first non-expired match waives the finding;
  a duplicate is harmless (idempotent match). T5 fixes whether duplicates are warned.
- A waiver fingerprint with the wrong length or non-hex characters still loads (it is a
  free-form string) but simply never matches a real `Finding.fingerprint`, so it is inert.
  Doc 14 does not require shipgrade to validate the hex shape; an inert typo'd waiver is
  safe, while over-validating would reject a fingerprint recipe change (spec 5.5.1) before
  the user has re-baselined.
- `upload-sarif: false`: the action skips the upload step but still runs the scan and the
  gate exit; the SARIF file may still be written locally for an artifact upload.
- The demo path never reads a waiver file: `demo` is offline, zero-config (spec 7), so its
  Grade F / 13 output (spec 7.2) is unaffected by anything in doc 14.
