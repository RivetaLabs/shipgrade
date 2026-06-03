# shipgrade design

shipgrade audits an LLM feature for product-safety and regulated-domain compliance, then prints a plain-English, severity-ranked report card, grade A to F, that the risk owner can act on, with a concrete fix for every finding.

## What it is

You point shipgrade at an AI feature, run one command, and get a plain-English, severity-ranked report a founder or compliance owner can act on, with a fix per finding. The question it answers is not only "can this be jailbroken" but "is this AI feature safe and compliant to ship in my domain." It is anchored in regulated-domain content compliance, not raw adversarial robustness. Positioning analogy: Lighthouse, but for whether your AI feature is safe to ship.

## The wedge

shipgrade is positioned on two axes, not on capability.

- `Audience.` The report is written for the person who owns the risk (founder, PM, compliance officer), not the prompt author.
- `Framing.` LLM output is treated as a product-safety and regulated-domain content-compliance problem (does this finance bot give investment advice, does this health bot diagnose, does this kids app violate COPPA or FERPA), not framework-checkbox mapping and not raw adversarial robustness. The deliverable is one graded report card the risk owner can act on, with a fix per finding.

Three differences a reader can verify by running it:

- The artifact is one graded report card, not a secondary export off an eval dashboard.
- The unit of analysis is behavioral content compliance in regulated domains, not framework-checkbox mapping and not raw capability red-teaming.
- The friction floor is an offline, zero-config, zero-key demo in one command.

promptfoo is now an OpenAI-distributed enterprise capability (acquisition announced 2026-03-09).
shipgrade is independent, vendor-neutral, and runs offline.

## Architecture: six layers

The seam between the layers is the `Finding` model, which is what makes a future supply-chain auditor a drop-in module rather than a second project.

```
config + rules -> [1 Target Adapter] -> [2 Probe Packs] -> run probes
                                                              |
                                              responses <-----+
                                                  |
                                                  v
                                        [3 Judge + 4 Severity/Mapping]
                                                  |
                                            Finding[] (normalized)
                                                  |
                                                  v
                                        [5 Report Core] -> CLI | HTML | JSON | SARIF
                                                  ^
                            [6 CLI Orchestrator] -+  (scan | init | demo)
```

1. `Target Adapter`: three modes in v1. A prompt-file adapter points at a system-prompt text file. An HTTP adapter takes a URL plus a request template with a `{{prompt}}` placeholder and a response path. A callable/module adapter points at a Python module exposing `async def respond(prompt: str) -> str`. Adapters fail closed: a transport error on one probe marks that probe errored and the run continues. The HTTP adapter blocks non-public targets (SSRF guard) unless `--allow-private-targets` is set.
2. `Probe Packs`: version-controlled YAML test cases. Each probe has an id, an OWASP LLM category, an optional MITRE ATLAS technique, the input(s) to send, and the safe-behavior criteria the judge evaluates against. v1 ships a focused pack of 20 to 30 probes across five categories, weighted toward the regulated-domain wedge, not a 120-probe library.
3. `Judge`: evaluates each response against the probe's safe-behavior criteria and returns a structured verdict (pass/fail, severity 0 to 10, rationale, suggested fix, confidence). Two paths exist. An LLM judge is provider-pluggable, uses structured tool-use output at low temperature, and needs an API key. Deterministic detectors (regex and heuristics for secret and PII echo, and canary-token detection for system-prompt leakage) run always and power the key-free demo.
4. `Severity and Mapping`: severity is a transparent, CVSS-flavored 0 to 10 score, banded critical/high/medium/low. The probe carries the OWASP LLM Top 10 (2025) id and the MITRE ATLAS technique id, and the scoring layer bands the score and attaches the mappings. This is an adaptation for LLM findings, not CVSS-proper. EPSS and KEV are deliberately excluded; they are CVE-keyed and do not apply to behavioral findings.
5. `Report Core`: takes a normalized `Finding[]` plus run metadata and renders four ways - a rich CLI report, one self-contained HTML file (inline CSS, no external assets), JSON, and SARIF 2.1.0. All four are pure functions of the `Report` envelope. This is the reusable heart; the same core renders any emitter's findings unchanged.
6. `CLI Orchestrator`: the `scan`, `init`, and `demo` commands. `scan` loads config, rule packs, and probe packs, runs the probes through the adapter, judges, scores, and reports, with a `--fail-on` severity gate and the exit-code contract (0 clean, 1 gate exceeded, 2 usage error, 3 run errored). `demo` runs against the bundled vulnerable finance assistant fully offline, zero config, no API key.

## The Finding contract (the seam)

A `Finding` is the frozen normalized record every detector emits and every renderer consumes. It has 12 fields:

- `id`: the finding id.
- `title`: a plain-English title, never a bare probe id.
- `category`: one of LLM01, LLM02, LLM05, LLM07, LLM09.
- `atlas_technique`: the MITRE ATLAS technique id, or null.
- `severity_score`: 0 to 10.
- `severity_band`: critical, high, medium, or low.
- `description`: plain English, risk-owner readable.
- `evidence`: the probe input plus a redacted response excerpt.
- `fix`: a concrete remediation.
- `confidence`: high, medium, or low.
- `fingerprint`: a stable hash for SARIF dedup across runs.
- `source`: the scanner name.

Two invariants are locked:

- The field list is frozen. Any add, rename, or retype is an architecture change, not a tweak.
- The `source` field lets a future supply-chain / dependency auditor on the roadmap emit into the same report core unchanged. That is why the report core is built first and reused, not rebuilt.

## Privacy and the offline demo

The data-handling ordering is normative: detect (deterministic, local) -> redact (local) -> {LLM judge egress | report egress}. There is no code path where a raw target response or a raw probe-elicited secret reaches an external API. Redaction happens once, locally, before either the judge call or any renderer.

The demo runs against the bundled vulnerable finance assistant fully offline, zero config, no API key, replaying recorded judge fixtures, so it produces a full-coverage graded report (Grade F, 13 out of 100 on the demo target) with zero network egress.

shipgrade itself emits no telemetry. The only egress that ever carries probe inputs or target responses is the judge call on a keyed `scan`, and only after local redaction. The HTTP adapter additionally calls the user's own target URL (guarded against non-public addresses by default). The prompt-file and callable adapters make no network calls, and `demo` makes none at all.

## What v1 ships

- Five OWASP categories: LLM01 prompt injection, LLM02 sensitive-information disclosure, LLM05 improper output handling, LLM07 system-prompt leakage, LLM09 regulated-domain content.
- Three regulated-domain rule packs (finance, health, education), roughly 30 hand-authored rules grounded in cited US regulatory provisions.
- Deterministic PII/secret echo and canary-token detectors, no key required.
- The report in four formats (CLI, self-contained HTML, JSON, SARIF 2.1.0) with OWASP and ATLAS mapping and a fix per finding.
- An AI Safety Score (0 to 100, grade A to F) with a shareable badge.
- Per-finding suppression via a fingerprint-keyed ignore file.
- Regression mode for CI.
- A published composite GitHub Action plus a pre-commit hook.

## Roadmap (advertised, not built in v1)

These are deliberate scope, not missing features.

- NIST AI RMF and EU AI Act framework mapping. This is deliberately not v1's lane; v1 differentiates on the domain packs and their concrete fixes, not the count of frameworks mapped.
- More OWASP categories (LLM06, LLM08, LLM10).
- Multi-model comparison.
- A fast-follow supply-chain / dependency auditor that reuses this report core and the `Finding` contract unchanged.

## Severity and grading disclaimer

shipgrade is an automated heuristic audit, not a certification, security guarantee, or legal or compliance sign-off. The grade reflects the probes that ran on this date; a higher grade means fewer detected issues, not proven safety.

Severity is a CVSS-flavored 0 to 10 adaptation for LLM behavior, not CVSS-proper. EPSS and KEV are intentionally excluded.

## License and security

shipgrade is MIT licensed; see `LICENSE`.

Report a vulnerability via GitHub Security Advisories; see `SECURITY.md`.

shipgrade is a portfolio project; maintainer response may be slow.
