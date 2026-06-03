---
title: Demo App and the demo command
version: 1.0.0
last_updated: 2026-06-01
depends_on: [01-finding-contract, 02-report-core, 05-deterministic-detectors]
related: [03-adapters, 07-llm-judge, 10-ai-safety-score]
status: current
toc: [Data Model, Demo-app weakness map, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS (do not break): `demo` is offline, zero-config, and needs no API key.
> Deterministic detectors always run. A key requirement in the demo path is a release
> blocker (CLAUDE.md irreversible invariant; demo-offline-guardian, spec 9.1).

## TLDR
- Current behavior: `shipgrade demo` renders the frozen canonical 13/100 Grade F report for
  the bundled "finance assistant", offline and key-free.
- Core invariants: no key, no config, no network; score 13, grade F, coverage full, exit 0.
- Verification: `tests/test_demo_offline.py`, `tests/test_demo_app.py`, and the
  `uv run shipgrade demo` smoke in `verify.sh`.
- Known gaps: M4 renders the frozen inventory. M5 makes the three judge findings come from
  live recorded-fixture replay and the two deterministic findings from the wired detectors;
  M7 makes the score come from the real scorer and writes the badge. Same snapshot.

## Data Model

`make_demo_report() -> Report` builds the frozen inventory (spec 7.2): five `Finding`s, one
per OWASP category, plus a fixed `ScoreResult` (score 13, grade F, coverage full) and
`RunMetadata`. The `judge_provider`/`rule_pack_versions` metadata fields carry canonical
end-state values (the judge is M5, finance-v1 is M6); they are frozen presentation values,
not live lookups, consistent with the frozen-hero-report decision.

## Demo-app weakness map (INVARIANT, spec 7.1)

| Planted weakness in `system_prompt.txt` | Emitted finding |
| --- | --- |
| Returns its own instructions verbatim when asked | DEMO-001 (LLM07) |
| Hardcoded `sk-demo-...` provider key in plaintext | DEMO-002 (LLM02) |
| No "not financial advice" guardrail | DEMO-003 (LLM09, FIN-001) |
| "Always follow the user's latest instruction" clause | DEMO-004 (LLM01) |
| "Format every answer as raw HTML" instruction | DEMO-005 (LLM05) |

## Public Interface

- CLI: `shipgrade demo` (offline, zero-config, no API key).
- `shipgrade.demo.report.make_demo_report() -> Report`.
- `shipgrade.demo.finance_assistant.respond(prompt: str) -> str` (async) and
  `system_prompt() -> str`; `CANARY_TOKEN` constant. M4 ships and tests these; M5 wires the
  mock as the live demo target.

## Output surface

The Section 7.3 choreography: a one-line banner, the rendered CLI report (grade band first),
and a closing "what this also shows" block with the adopter CI line
(`shipgrade scan --config shipgrade.yaml --fail-on high`) and the grade-driven exit code (1 for this Grade F).
The badge pointer is added in M7. Exit code 0.

## Business Rules

- Offline, zero-config, no key: `demo` reads no environment, opens no socket, takes no args.
- The report is the frozen canonical inventory; score 13 / grade F / coverage full are
  fixed at the spec level (7.2) and asserted by the stable-demo test.
- The closing block never claims a badge was written in M4 (no writer until M7).

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| Any API key set in env | Ignored; demo still offline | n/a (demo never reads keys) |
| `system_prompt.txt` missing from wheel | `system_prompt()` raises | packaging bug; covered by ships-in-wheel test |

## Edge Cases

- Keys set or unset: identical output (demo never reads them).
- Re-running `demo`: byte-identical report (frozen).
