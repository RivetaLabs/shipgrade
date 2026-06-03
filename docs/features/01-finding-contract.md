---
title: Finding Contract
version: 1.0.0
last_updated: 2026-06-01
depends_on: []
related: [02-report-core, 09-severity-and-mapping]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS (do not break): the Finding field list is an architecture seam;
> any add/rename/retype is a gated architecture change, not a tweak. The source
> field is load-bearing for blastradius reuse. fingerprint / partialFingerprints
> stay byte-stable across runs.

## TLDR
- Current behavior: Finding is the frozen normalized record every detector emits and every renderer consumes.
- Core invariants: 12 frozen fields; source separates emitters; fingerprint stable across runs.
- Verification: pyright + the model unit tests (test_finding_contract.py) + the SARIF stability test (M2, spec section 9).
- Known gaps: none; a structured redactions list is deferred (spec 5.9).

## Data Model
Finding (Pydantic, spec 5.5), frozen, 12 fields: id, title, category (OwaspLlmId),
atlas_technique, severity_score (0-10), severity_band, description, evidence (Evidence),
fix, confidence, fingerprint, source. Evidence (spec 5.7): probe_input, response_excerpt
(already redacted), redacted, adapter_mode. OwaspLlmId is the locked Literal
["LLM01","LLM02","LLM05","LLM07","LLM09"]; adding a category is a visible type change.

## Public Interface
Constructed by the scoring layer from a ProbeResult; consumed by the report-core
renderers (cli/html/json/sarif) and the regression baseline. Nothing mutates a Finding
after construction (the model is frozen).

## Output surface
Every field maps to a rendered element: the finding card (spec 5.5) and the SARIF result
(spec 5.5.1). fingerprint -> partialFingerprints.primaryLocationLineHash.

## Business Rules
- fingerprint = first 32 hex chars of sha256(category + probe_id + rule_id + adapter_target_identity) (spec 5.5.1), never the response text.
- severity_score is the post-ceiling value: min(judge, rule.severity) when a rule matched (spec 5.8).
- evidence is redacted before construction (spec 5.9); no raw secret ever reaches a Finding.
- source defaults to "shipgrade"; a different value is reserved for blastradius reuse.

## Failure Modes
| Scenario | Behavior | Recovery |
| --- | --- | --- |
| detector emits an out-of-range severity | Pydantic validation error at construction | fix the detector; never clamp silently |
| rule_id absent (probe-only finding) | fingerprint hashes an empty rule_id slot | stable by design; documented |
| unknown field passed to Finding | ValidationError (extra="forbid") | do not add fields; a field change is an architecture gate |

## Edge Cases
- Zero findings: a valid empty Finding[] renders the clean-pass report (spec 5.10).
- source != "shipgrade": reserved for blastradius; renderers stay emitter-agnostic.
