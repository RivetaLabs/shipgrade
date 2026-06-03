---
title: Report Core
version: 1.2.0
last_updated: 2026-06-03
depends_on: [01-finding-contract]
related: [09-severity-and-mapping, 06-demo-app, 11-regression, 13-data-handling]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS (do not break): all four renderers are pure functions of a `Report`;
> they add no field to any model. The fingerprint recipe and its golden vector are
> frozen (5.5.1). SARIF validates against 2.1.0 and every result carries a
> physicalLocation.artifactLocation.uri. HTML autoescape is always on. The CLI
> snapshot is the non-TTY plain rendering (no ANSI, no box-drawing). SARIF result
> messages carry the finding, never the target's output (no probe input, no response
> excerpt); evidence stays in the three local formats (5.9).

## TLDR
- Current behavior: the report core renders one `Report` four ways (CLI, JSON, HTML, SARIF). No scanning, scoring, or network; the score arrives pre-computed on the Report.
- Core invariants: pure functions of `Report`; frozen fingerprint recipe + golden vector; SARIF 2.1.0-valid with a uri per result; HTML autoescaped; CLI plain on non-TTY; byte-stable snapshots across runs.
- Verification: syrupy snapshots (CLI/JSON/HTML/SARIF), jsonschema validation against the vendored 2.1.0 schema, fingerprint golden + stability tests, the autoescape XSS test, the no-secret-in-output test.
- Known gaps: live colored TTY output and the HTTP/callable config-path SARIF uri arrive with the adapters (M3); the codeql upload-sarif ingestion test arrives with `demo` (M4); the score is hand-built in the fixture until M7.

## Data Model
Consumes the frozen `Report` (spec 5.7): `metadata: RunMetadata`, `findings: list[Finding]`, `score: ScoreResult`, `errored_probes: list[ProbeResult]`. Adds one typed model tree it owns, `SarifLog -> SarifRun -> SarifResult` (5.5.1), in `report/sarif.py`. `Finding` carries no `probe_id`; SARIF `logicalLocations[0].name` uses `Finding.id` and the uri uses `RunMetadata.target.identity`.

## Public Interface
- `render_cli(report: Report) -> str` - non-TTY plain text (the snapshot form).
- `render_json(report: Report) -> str` - a `meta` block (disclaimer, severity note, scale, run date) plus the full `Report` dump.
- `render_html(report: Report) -> str` - one self-contained HTML file, inline CSS, Jinja2 autoescape on.
- `render_sarif(report: Report) -> SarifLog` and `sarif_json(report: Report) -> str`.
- `fingerprint(category, probe_id, rule_id, adapter_target_identity) -> str` - the stable 32-hex recipe (5.5.1).
- Shared helpers in `_common.py`: `order_findings`, `exec_summary`, `grade_explainer`, `coverage_banner`, and the fixed strings.

## Output surface
The CLI and HTML share one top-to-bottom information architecture (spec 5.5): header band (grade, score, scale, grade explainer, coverage banner, run date, target identity), the "Explain to my boss" exec summary, a severity rollup, the findings as identical cards (band chip + score, plain-English title, "What this means", a redacted "We saw" evidence block, a "Fix" block, a quiet OWASP/ATLAS/confidence mapping line), ordered severity-descending then confidence-descending, then accepted-risk (none in v1 fixture), then errored/skipped (none in fixture), then a provenance + disclaimer footer. The HTML footer ends with the share-loop call to action: a repo link and `uvx shipgrade demo`, so a viewer of any shared report is one step from running it (spec 5.10). JSON mirrors the data with the disclaimer in `meta`. SARIF maps per 5.5.1, but its result messages carry only the finding (title, severity band, description, fix) and a local-evidence pointer; the redacted evidence block stays out of SARIF and lives only in the three local formats (5.9 egress contract, below).

## Business Rules
- Ordering: severity_score descending, then confidence (high>medium>low), ties broken by `Finding.id` ascending (deterministic).
- Severity-band chip palette (spec 5.4 bands the score; the chip colors are the renderer's): critical red, high dark_orange, medium yellow, low blue. Documented here because 5.4 leaves chip color to the renderer.
- fingerprint = first 32 hex of `sha256("|".join([category, probe_id, rule_id, adapter_target_identity]))` (5.5.1). The separator, order, and 32-char truncation are frozen; `GOLDEN_INPUT`/`GOLDEN_FINGERPRINT` lock them. A change is an architecture-gate change, not a tweak.
- SARIF level from band: critical/high -> error, medium -> warning, low -> note; `result.rank = severity_score * 10`; `properties["security-severity"] = str(severity_score)`; `kind = "fail"`. One rule (reportingDescriptor) per OWASP category present, id = OWASP id, name PascalCase, helpUri = the OWASP 2025 entry, defaultConfiguration.level = "warning".
- partialFingerprints = `{"primaryLocationLineHash": Finding.fingerprint, "shipgradeFindingV1": Finding.fingerprint}` (5.5.1): the first key is the only one GitHub honors for dedup; the second is shipgrade's versioned recipe tag.
- SARIF egress contract (spec 5.9, redact-before-egress): SARIF is the only format uploaded to GitHub Code Scanning, a third-party retention system, so its result messages carry the finding (title, severity band, description, fix) plus a local-evidence pointer ("Evidence is available in the local report formats; run shipgrade locally to see it."), and never the target's output. They omit both `evidence.probe_input` and `evidence.response_excerpt`, even the redacted excerpt. The three local formats (CLI, JSON, HTML) keep the full redacted evidence because the user views them on their own machine; SARIF does not, by default. The `test_sarif_messages_carry_no_response_excerpts` test guards this.
- Live-target SARIF shape: for a live (non-demo) target, `physicalLocation.artifactLocation.uri` is the sanitized hostname, and results are region-less (no `region` object). GitHub may emit warning GH1003 about missing regions on ingestion; that is acceptable for v1. Regions are omitted by design because findings are behavioral, not line-anchored to source.
- The not-a-certification disclaimer and the CVSS-flavored severity note are fixed strings, identical across CLI/JSON/HTML and (as the behavioral disclaimer) SARIF. No raw secret reaches any surface; only the redaction placeholder (e.g. `[REDACTED:secret(20)]`) is shown.

## Failure Modes
| Scenario | Behavior | Recovery |
| --- | --- | --- |
| a model response contains `<script>` | HTML autoescapes it to `&lt;script&gt;`; CLI prints it literally with no markup parsing | autoescape is non-optional; the XSS snapshot test guards it |
| zero findings (clean pass) | every renderer still emits a full artifact: grade A, what was checked, coverage, positive exec summary, the same disclaimer | never render an empty report; an A never reads as "certified safe" (5.10) |
| emitted SARIF drifts from 2.1.0 | jsonschema validation fails the suite | fix the model; do not weaken the test |
| a renderer reads a Finding field that does not exist | pyright fails | the contract is frozen; renderers consume only the 12 fields + metadata |

## Edge Cases
- Non-TTY CLI: plain text, no ANSI, no box-drawing, grep-able and snapshot-stable (5.5).
- `coverage == "partial"`: the banner says LLM-judge categories were skipped; the fixture is full coverage, so the partial banner is unit-tested separately.
- `atlas_technique is None`: the SARIF result omits its ATLAS taxa reference; the OWASP reference is always present.
