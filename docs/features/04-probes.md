---
title: Probe Packs and the YAML Load Chokepoint
version: 1.3.4
last_updated: 2026-06-03
depends_on: [01-finding-contract.md]
related: [03-adapters.md, 08-domain-rule-packs.md, 09-severity-and-mapping.md]
status: current
toc: [data-model, public-interface, output-surface, business-rules, failure-modes, edge-cases]
---

## TLDR

- **Current behavior:** Probe packs are version-controlled YAML test cases loaded into the
  `ProbePack`/`Probe` models. v1 ships one bundled pack, `owasp-core-v1` (version `1.0.0`),
  with 26 probes across the five locked OWASP categories, weighted to the LLM09 wedge:
  LLM09 7, LLM07 5, LLM02 7, LLM01 4, LLM05 3 (spec 5.2 bands). The first probe in each
  category is the worked demo probe (`...-001`) that elicits DEMO-001 through DEMO-005;
  the bundled demo report does not load the pack, so its five findings are independent.
  Each domain probe binds its single best-fit rule via `Probe.target_rule`; a failed bound
  probe cites that exact rule, an unbound probe (the generic LLM01/05/07 probes) produces a
  probe-only finding that cites no rule (doc 09).
- **Core invariants:** Every pack and config loads through one chokepoint (`_yaml.py`):
  a `SafeLoader` that also bans anchors/aliases, a 1 MB byte cap, then Pydantic validation
  with `extra="forbid"`. Probe categories are locked to the v1 five by the `OwaspLlmId`
  type. `atlas_technique` ids are verified against the live MITRE ATLAS matrix. A
  `target_rule` binding is validated against the loaded rule packs before any probe runs: a
  missing rule id, a category mismatch, or a duplicate rule id across packs fails the run
  fast (`BindingError`, doc 09), before any API spend, and is re-checked at findings assembly
  as a net, never a silent mis-citation.
- **Verification:** `tests/test_yaml_loader.py`, `tests/test_probe_loader.py`,
  `tests/test_probe_pack_owasp_core.py`, `tests/test_scan.py` (binding validation, including
  the pre-scan fail-fast).
- **Known gaps:** Rule packs (M6) reuse the same chokepoint but are not built here. The
  per-category allocation (spec 5.2) is fully authored at 26 probes (LLM09 7, LLM07 5,
  LLM02 7, LLM01 4, LLM05 3). EDU-006 and EDU-007 (the LLM09 edu rules) have no authored
  probe after the two child-PII probes were re-categorized to LLM02; the rule-seed mechanism
  (doc 08, spec 5.8) now exercises them as `seed:EDU-006#0` / `seed:EDU-007#0` probes bound
  to their origin rule. Multi-turn and obfuscation injection stays deferred to PyRIT and
  generic hallucination stays out of LLM09 scope (spec 5.2 sub-taxonomy).

## Data Model

- `ProbePack { name, version, probes: list[Probe] }` and `Probe { id, category,
  atlas_technique, title, inputs, safe_behavior, detectors, severity_hint, target_rule }`,
  both in `models.py` (spec 5.7). `category` is `OwaspLlmId` (the five-category lock at the
  type level). `detectors` are drawn from `pii_echo | secret_echo | canary_leak`.
- `target_rule: str | None = None` is the per-probe rule binding (S3). When set, it is the
  id of the single best-fit rule a failed verdict cites; the bound rule supplies the
  description citation, the severity ceiling, and the `rule_id` slot in the fingerprint. When
  `None`, a failed verdict produces a probe-only finding citing no rule (doc 09). The binding
  is the seam that fixes cross-domain mis-citation: a failed `llm09-health-*` probe cites a
  health rule, never the first finance rule in the LLM09 category.

## Public Interface

- `load_yaml_model(path: Path, model: type[M]) -> M`: the chokepoint. Raises `PackLoadError`
  on a missing file, an oversized file, malformed YAML, a non-mapping document, or a
  schema violation.
- `load_probe_pack(name_or_path: str) -> ProbePack`: resolves a bundled pack name (e.g.
  `"owasp-core-v1"`) or a filesystem path to a validated `ProbePack`.
- `load_probe_packs(names: list[str]) -> list[ProbePack]`.

## Output surface

None (internal). Loaded packs feed `scan` (doc 03).

## Business Rules

- **Hostile-pack defense (spec 8 abuse case 6):** `yaml.load` with a `SafeLoader` subclass
  (never `yaml.full_load`) blocks arbitrary object construction; the subclass also raises
  on YAML anchors/aliases, which closes the billion-laughs expansion bomb (packs never
  legitimately use anchors). A 1 MB byte cap rejects huge files before parse. Pydantic
  `extra="forbid"` rejects unknown keys. The load fails fast, before any probe runs.
- **Category lock (spec, "do not chase breadth"):** a pack whose probe `category` is
  outside `LLM01/LLM02/LLM05/LLM07/LLM09` fails `OwaspLlmId` validation at load. Adding a
  category is a visible type change, never a silent data add.
- **ATLAS mapping (spec 5.2):** `atlas_technique` is `AML.T0051` for LLM01
  prompt-injection probes and LLM07 injection-forced leakage, `AML.T0056` for the four
  pure LLM07 system-prompt extraction probes, and `None` for LLM02/LLM05/LLM09 in v1,
  verified against the live MITRE ATLAS matrix at authoring.
- **Per-probe rule binding (S3, spec 5.2).** Each domain probe binds its single most-specific
  rule via `target_rule`. The binding table for `owasp-core-v1`:

  | probe | target_rule | category |
  | --- | --- | --- |
  | llm09-finance-advice-001 | FIN-001 (recommend a named security) | LLM09 |
  | llm09-finance-leverage-002 | FIN-001 (recommend a named security) | LLM09 |
  | llm09-finance-guaranteed-return-003 | FIN-003 (guarantee a return) | LLM09 |
  | llm09-finance-tax-evasion-004 | FIN-011 (tax evasion, 26 U.S.C. 7201) | LLM09 |
  | llm09-health-diagnosis-005 | HLT-011 (definitive diagnosis, 21 U.S.C. 360j(o)) | LLM09 |
  | llm09-health-dosage-006 | HLT-001 (drug dose/route direction, 21 CFR 201.5) | LLM09 |
  | llm09-health-cure-claim-007 | HLT-004 (supplement disease claim) | LLM09 |
  | llm02-edu-minor-pii-008 | EDU-001 (child PII) | LLM02 |
  | llm02-edu-student-records-009 | EDU-005 (other student's records) | LLM02 |

  `llm09-finance-leverage-002` binds FIN-001 rather than FIN-005 (risk acknowledgment): the
  probe's disqualifying behavior is laying out a concrete leveraged buy/sell plan on a named
  security, which is a recommendation of a named security (FIN-001), not merely a one-sided
  benefit-without-risk description (FIN-005). FIN-001 is the more specific match. The health
  probes bind distinct rules: the diagnosis probe binds HLT-011 (definitive diagnosis, grounded
  in the FDA decision-support boundary 21 U.S.C. 360j(o)) and the dosage probe binds HLT-001
  (drug dose, frequency, and route direction, grounded in 21 CFR 201.5). HLT-001 was narrowed
  to dosing and the diagnosis obligation split out into HLT-011 in the re-citation task.
- **Two child-PII probes are LLM02, not LLM09 (S3).** `llm02-edu-minor-pii-008` and
  `llm02-edu-student-records-009` (formerly `llm09-edu-*`) test Sensitive Information
  Disclosure obligations under COPPA/FERPA, so they carry `category: LLM02` and bind the
  LLM02 edu rules. This is the honest recount: LLM09 has 7 authored probes, LLM02 has 7.
  EDU-006 and EDU-007 (the LLM09 edu rules) then have no authored probe; the rule-seed
  mechanism (doc 08, spec 5.8) exercises them instead, so no new probe was authored to fill
  the gap.
- **Bundled packs ship in the wheel:** packs live under `shipgrade/probes/packs/` and are
  resolved via `importlib.resources`; hatchling includes the non-Python files by default.

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| Pack name not found (no bundled pack, no file) | `PackLoadError` naming the lookup | Fix the name in config, or pass a path |
| YAML uses an anchor/alias | `PackLoadError` (anchors not allowed) | Remove anchors; packs do not need them |
| File over 1 MB | `PackLoadError` (cap) | Split the pack; v1 packs are kilobytes |
| Unknown key in the YAML | `PackLoadError` (Pydantic `extra=forbid`) | Remove the key; check the `Probe` schema |
| `category` outside the v1 five | `PackLoadError` (`OwaspLlmId`) | Use a locked category |

## Edge Cases

- Empty `probes: []` -> a valid (if useless) pack; `scan` runs zero probes.
- A `.yml` path and a `.yaml` path are both accepted as filesystem packs.
- A bundled name that collides with a local file: a real `.yaml`/`.yml` file path wins
  (it is checked first), so a user can override a bundled pack by path.
