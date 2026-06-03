# shipgrade feature docs (index)

Doc-first: read the feature doc before touching its code (see
`.claude/rules/documentation-handbook.md`). One doc per feature, numbered.

`AGENTS.md` in this directory is a symlink to this file; edit only `CLAUDE.md`.

| Doc | Feature | Milestone | Status |
| --- | --- | --- | --- |
| 01-finding-contract | The frozen Finding object model (spec 5.5, 5.7) | M1 | current |
| 02-report-core | The four renderers from a fixed Report (spec 5.5, 5.5.1) | M2 | current |
| 03-adapters | The three target adapters, their safety guards, and the scan pipeline (spec 5.1, 5.1.1, 5.6) | M3 | current |
| 04-probes | The YAML load chokepoint, the probe loader, and the owasp-core-v1 pack (spec 5.2, 8) | M3 | current |
| 05-deterministic-detectors | The three key-free detectors and the DetectorSpan contract (spec 5.3, 5.9) | M4 | current |
| 06-demo-app | The bundled finance assistant and the offline demo command (spec 7) | M4 | current |
| 07-llm-judge | The provider-pluggable LLM judge, its prompt contract, and provider selection (spec 5.3) | M5 | current |
| 13-data-handling | The redact-before-egress pipeline and placeholder contract (spec 5.9) | M5 | current |
| 08-domain-rule-packs | The custom rule DSL and the finance/health/education packs (spec 5.8) | M6 | current |
| 09-severity-and-mapping | Severity banding and the OWASP/ATLAS mapping the scoring layer attaches (spec 5.4) | M7 | current |
| 10-ai-safety-score | The penalty-from-100 AI Safety Score, grade scale, and shareable badge (spec 5.10) | M7 | current |
| 11-regression-mode | Baseline save/compare and the new-finding-by-fingerprint regression gate (spec 6.1, 5.7) | M8 | current |
| 12-cli-and-ci-gate | The scan exit-code contract and the --fail-on/--ignore-file/--baseline flags (spec 5.6, 6.1) | M8 | current |
| 14-ci-action-suppression | The .shipgrade-ignore.yaml waiver schema, composite action.yml, and pre-commit hook (spec 6.1, 6.2) | M8 | current |
| 15-launch-artifacts | The demo HTML emit path and the committed sample-report.html proof (spec 11.4) | M9 | current |

Docs 07-14 are created doc-first as each milestone builds its feature (spec 10.1).
