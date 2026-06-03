---
title: Severity and Mapping
version: 1.2.0
last_updated: 2026-06-02
depends_on: [01-finding-contract, 04-probes, 05-deterministic-detectors, 08-domain-rule-packs]
related: [02-report-core, 07-llm-judge, 10-ai-safety-score]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS: severity is a transparent CVSS-flavored 0-10 adaptation, not CVSS-proper,
> and the output says so; bands are `critical >= 9.0`, `high 7.0-8.9`, `medium 4.0-6.9`,
> `low 0.1-3.9` (a 0.0 score bands low); `severity_score = min(judge_proposed, rule.severity)`
> when a rule matched (the judge never exceeds the author ceiling); the OWASP id is carried
> from the probe/rule `category` and the ATLAS technique from `probe.atlas_technique`; a
> `Finding` is constructed by the scoring layer from a failed `ProbeResult`, never mutated
> after; the fingerprint reuses `report.fingerprint.fingerprint`, never a re-implemented
> hash; EPSS and KEV are deliberately excluded.

## TLDR

- Current behavior: the scoring layer turns each failed, judged `ProbeResult` into one
  frozen `Finding` (spec 5.5). It bands the 0-10 severity into one of four bands (spec 5.4),
  carries the OWASP LLM Top 10 (2025) id from the probe/rule `category` and the MITRE ATLAS
  technique from `probe.atlas_technique`, applies the `min(judge, rule.severity)` ceiling,
  and stamps the stable fingerprint from the existing recipe. The 0-100 AI Safety Score and
  the A-F grade computed over the resulting `Finding[]` are doc 10.
- Core invariants: bands `critical >= 9.0`, `high 7.0-8.9`, `medium 4.0-6.9`, `low 0.1-3.9`
  (a 0.0 score bands low); `severity_score = min(judge_proposed, rule.severity)`; the OWASP
  id is the `category` (one of the v1 five), ATLAS is `probe.atlas_technique` (may be
  `None`); the fingerprint is `report.fingerprint.fingerprint(category, probe_id, rule_id,
  target_identity)`; severity is a CVSS-flavored adaptation and the report states so; EPSS
  and KEV are not used.
- Verification: `tests/test_mapping.py` (the shipped `mapping.band_for_score` /
  `mapping.map_to_finding`); `tests/test_scoring.py` (M7.T5, the band boundaries and
  `scoring.build_finding`); `tests/test_report_sarif.py` (the band-to-`result.level` map,
  spec 5.5.1); `tests/test_report_fingerprint.py` (the frozen golden vector); `uv run pyright`.
- Attribution is per-probe (S3): a failed verdict on a probe bound to a rule via
  `Probe.target_rule` (doc 04) cites that exact rule (rule-grounded path); a failed verdict
  on an unbound probe cites no rule (probe-only path). The bound rule must share the probe's
  category, validated at scan assembly.
- A third, independent source feeds the same `Finding[]` (S4): a fired deterministic detector
  (doc 05) becomes a `Finding` whose category and severity come from the detector, key-free,
  on every path. A probe that both fails its rule and echoes a secret emits BOTH findings.
- Known gaps: per-category sub-scores, domain-weighted penalties, user-tunable weight
  profiles, and a tunable band map are deferred (spec 5.10); v1 locks one band table and one
  ceiling rule. Rule-exact judging (the judge naming which rule it judged against, via a
  future `Verdict.rule_id`) is roadmap; v1 attributes by the probe's single `target_rule`
  binding. EPSS/KEV are intentionally never added: they are CVE-keyed and read as theater on
  behavioral findings (spec 5.4).

## Data Model

Severity and mapping own no new model; they document how the scoring layer fills the frozen
`Finding` (spec 5.5) and the frozen severity/coverage fields of `ScoreResult` (spec 5.10,
doc 10) from a `ProbeResult` plus its `Probe` and matched `Rule` (all in
`src/shipgrade/models.py`). Do not add, rename, or retype a field.

- `SeverityBand = Literal["critical", "high", "medium", "low"]` (spec 5.4, 5.7): the banded
  output of a 0-10 score. It is `Finding.severity_band` and the key type of
  `ScoreResult.counts_by_band`.
- `Finding` fields this layer fills (spec 5.5), and where each comes from:
  - `category: OwaspLlmId`: from `rule.category` (a matched rule) or `probe.category` (no
    matched rule); always one of the v1 five `LLM01`, `LLM02`, `LLM05`, `LLM07`, `LLM09`.
  - `atlas_technique: str | None`: from `probe.atlas_technique`; `None` when the probe
    declares none.
  - `severity_score: float` (validated `0.0-10.0`): the post-ceiling value
    `min(verdict.severity_score, rule.severity)` when a rule matched; the
    judge-proposed `verdict.severity_score` otherwise.
  - `severity_band: SeverityBand`: `band_for_score(severity_score)` (see Business Rules).
  - `confidence: Confidence`: from `verdict.confidence` (`high | medium | low`); it travels
    with the score so a low-confidence finding reads as "worth checking," not "proven," and
    it scales the doc-10 score penalty.
  - `fingerprint: str`: `report.fingerprint.fingerprint(category, probe_id, rule_id,
    target_identity)` (32 hex chars).
  - `source: str`: `"shipgrade"` (the default; a different value is reserved for the
    deferred `blastradius` reuse, doc 01).
- `ScoreResult` severity/coverage fields this layer informs (spec 5.10, fully specified in
  doc 10): `counts_by_band: dict[SeverityBand, int]`, `counts_by_category:
  dict[OwaspLlmId, int]`, and `grade_capped_by_critical: bool` (any unresolved `critical`
  caps the grade at D). The score, grade, and coverage arithmetic live in doc 10; this doc
  owns only the banding and the per-finding mapping those counts are built from.

## Public Interface

The banding helper and the `Finding`-assembly mapper are pure functions over the frozen
models; they import only `shipgrade.models` and `shipgrade.report.fingerprint`, never a
provider SDK, a loader, or a renderer.

- `band_for_score(score: float) -> SeverityBand` (shipped in `src/shipgrade/mapping.py`;
  re-exported by `src/shipgrade/scoring.py` in M7.T5 so the scoring layer bands through one
  function): bands a 0-10 score per the spec-5.4 table. The thresholds and the boundary
  behavior are fixed and tested (see Business Rules). T5's `scoring.band_for_score` MUST
  return the identical band for every input; if T5 re-exports rather than re-implements,
  there is one source of truth.
- `map_to_finding(result: ProbeResult, *, probe: Probe, rule: Rule, target_identity: str)
  -> Finding` (shipped in `src/shipgrade/mapping.py`, spec 5.8): the rule-bound path. It
  requires `result.verdict` and `result.evidence` (a failed judged result carries both) and
  raises `ValueError` naming `result.probe_id` otherwise, so misuse fails loudly instead of
  building a half `Finding`. It applies the `min(verdict.severity_score, rule.severity)`
  ceiling, bands via `band_for_score`, sets `fix = verdict.suggested_fix or rule.fix or ""`,
  builds the description from `verdict.rationale` (appending `rule.rationale` as grounding
  when set), and stamps `fingerprint(rule.category, probe.id, rule.id, target_identity)`.
- `map_probe_to_finding(result: ProbeResult, *, probe: Probe, target_identity: str) ->
  Finding` (shipped in `src/shipgrade/mapping.py`, S3): the probe-only path for an unbound
  probe (no `target_rule`). It cites no rule: `category = probe.category`, `severity_score =
  probe.severity_hint` when set else `verdict.severity_score` (still validated `0.0-10.0` by
  the `Finding` model), `description` and `fix` derived from `probe.safe_behavior` and the
  OWASP category, `atlas_technique = probe.atlas_technique`, and `fingerprint(probe.category,
  probe.id, "", target_identity)` (the empty `rule_id` slot is by design and is the committed
  golden-vector case, doc 01). It requires `verdict` and `evidence` and raises `ValueError`
  otherwise, same as the rule-bound path.
- `build_finding(result, *, probe, matched_rule, target_identity)` (M7.T5,
  `src/shipgrade/scoring.py`): the rule-bound scoring-layer entry. When `matched_rule` is a
  `Rule` it delegates to `map_to_finding` (one mapping path); when `matched_rule` is `None`
  it returns `None`. `findings_from_results` (doc 12, `scan.py`) is what routes per probe: a
  bound probe goes through `build_finding` with its resolved rule, an unbound probe goes
  through `map_probe_to_finding`.
- `compute_score(...) -> ScoreResult` and `assemble_report(...) -> Report` (M7.T5,
  `src/shipgrade/scoring.py`): the 0-100 / A-F / coverage arithmetic and the `Report`
  envelope. Their formula, grade scale, and coverage rule are doc 10; this doc only supplies
  the per-finding banding and `counts_by_band` / `counts_by_category` inputs they roll up.

## Output surface

None directly (internal scoring/mapping). The banding and mapping surface only through
fields a renderer already shows:
- The finding card (doc 02, spec 5.5) renders the severity band chip with the 5.4 color map,
  the 0-10 `severity_score`, and a de-emphasized mapping line carrying the OWASP id, the
  ATLAS technique (omitted when `None`), and `confidence`.
- The SARIF result (doc 02, spec 5.5.1) maps `severity_band` to `result.level`
  (`critical`/`high` -> `error`, `medium` -> `warning`, `low` -> `note`), puts the raw 0-10
  score in `result.properties["security-severity"]`, and sets `result.rank = severity_score
  * 10`. The OWASP id is the `result.ruleId`; the ATLAS technique becomes a `result.taxa`
  entry, omitted when `atlas_technique` is `None`.
- The severity rollup (`counts_by_band`) and the `counts_by_category` strip in the report
  header (doc 02, spec 5.5) are built from the banded `Finding[]`.
- The not-a-certification footer pairs the doc-10 disclaimer with the 5.4 line that severity
  is a CVSS-flavored adaptation, not CVSS-proper, and that EPSS and KEV are excluded.

## Business Rules

### Severity bands (spec 5.4)

- Severity is a transparent, CVSS-flavored 0-10 score, banded by `band_for_score`:

  | severity_score | severity_band |
  | --- | --- |
  | `>= 9.0` | critical |
  | `7.0 - 8.9` | high |
  | `4.0 - 6.9` | medium |
  | `0.1 - 3.9` | low |

- Boundary behavior is fixed and tested: `9.0` is `critical`, `8.9` is `high`, `7.0` is
  `high`, `6.9` is `medium`, `4.0` is `medium`, `3.9` is `low`, and `0.0` bands `low`
  (the spec's low band reads "0.1-3.9", and a `0.0` score bands `low` in code; there is no
  band below low). The comparisons are inclusive-lower (`>=`), so a score sitting exactly on
  a threshold takes the higher band.
- The bands are the only severity taxonomy in v1. There is no per-category band table and no
  user-tunable threshold; the band map is locked alongside `scale_version` "shipgrade-1"
  (spec 5.10, doc 10). Severity is stated in the report as an adaptation for LLM findings,
  not CVSS-proper, because classical CVSS poorly differentiates LLM issues (spec 5.4).

### The severity ceiling (spec 5.4, 5.8)

- The judge proposes a severity (`verdict.severity_score`); the rule author sets a per-rule
  `rule.severity` ceiling. When a rule matched, the finding's score is
  `severity_score = min(verdict.severity_score, rule.severity)`: the judge can lower a score
  below the author's ceiling but never raise it above. This is exactly what the shipped
  `mapping.map_to_finding` computes; `scoring.build_finding` (T5) applies it on the matched
  path by delegating to that mapper.
- `probe.severity_hint` is the probe-author prior used when the probe binds no rule; it never
  raises a score above a matched `rule.severity` (spec 5.2). On the probe-only path
  (an unbound probe), the finding's score is `probe.severity_hint` when set, falling back to
  the judge-proposed `verdict.severity_score` when the probe declares no hint; the `Finding`
  model still validates the result into `0.0-10.0`.

### OWASP and ATLAS carry (spec 5.4)

- The OWASP LLM Top 10 (2025) id is the finding's `category`, carried from `rule.category`
  on the rule-bound path and `probe.category` on the probe-only path. With the binding
  category-match invariant (doc 04), the bound rule shares the probe's category, so the two
  paths agree. It is always one of the locked v1 five (`OwaspLlmId`); the scoring layer never
  assigns a category outside that Literal, and adding one is a visible type change, not a
  silent data add (doc 01, spec 5.7).
- The MITRE ATLAS technique is `probe.atlas_technique` (e.g. `"AML.T0051"`), attached to the
  finding unchanged, or `None` when the probe declares none. The judge does not propose an
  ATLAS technique; it rides from the probe definition. A `None` ATLAS technique is omitted
  from the finding card mapping line and from `result.taxa` in SARIF (doc 02, spec 5.5.1).
- EPSS and KEV are deliberately not attached. They are CVE-keyed and do not apply to
  behavioral findings; claiming them would read as theater (spec 5.4).

### Finding constructed by the scoring layer from a ProbeResult (spec 5.5, doc 01)

- A `Finding` is built once, from a failed judged `ProbeResult`, and is never mutated
  afterward (the model is frozen). The inputs are the `ProbeResult` (its `verdict` and
  already-redacted `evidence`), the `Probe` (for `category`, `atlas_technique`, `id`,
  `safe_behavior`, `severity_hint`), and the bound `Rule` for a bound probe.
- Only a `ProbeResult` with `status == "ok"` and a failed verdict (`verdict.passed is
  False`) becomes a `Finding`. A passing verdict produces no finding; an `errored` or
  `skipped` `ProbeResult` produces no finding and instead feeds the coverage counts in doc
  10 (`probes_errored`, `probes_skipped`). The mapper requires both `verdict` and `evidence`
  and raises `ValueError` if either is missing, so an errored or skipped result is never fed
  to it.
- `fix = verdict.suggested_fix or rule.fix or ""` on the rule-bound path (the rule's `fix` is
  the fallback when the judge proposes none). On the probe-only path the `fix` is the probe's
  `safe_behavior` restated as remediation, so a probe-only finding always shows a concrete
  action even though no rule supplied one.
- `source = "shipgrade"`. A different `source` is reserved for the deferred `blastradius`
  emitter and is out of scope for v1 (doc 01, spec 5.5).

### Fingerprint (spec 5.5.1)

- The finding's `fingerprint` is `report.fingerprint.fingerprint(category, probe_id,
  rule_id, target_identity)`: the first 32 hex chars of `sha256` over
  `category|probe_id|rule_id|target_identity` (the `|` separator, the tuple order, and the
  32-char truncation are frozen). On the matched path `rule_id = rule.id`; on the probe-only
  path `rule_id = ""`. The recipe is locked by the golden vector
  `GOLDEN_INPUT = ("LLM02", "llm02-secret-echo-001", "", "system_prompt.txt")` ->
  `"944668538602013a3814e5d5089fadca"` (`tests/test_report_fingerprint.py`). Never
  re-implement the hash; import it. It excludes the response text, scores, timestamps, and
  run ids so it stays stable across runs on a non-deterministic target and keeps SARIF dedup
  and committed waivers stable (spec 5.5.1, doc 01).

### The detector path: fingerprint key and overlap policy (S4, doc 05)

- A fired deterministic detector becomes a `Finding` through
  `mapping.map_detector_to_finding`, the key-free third source (doc 05). Its category,
  severity, title, description, and fix come from the DETECTOR's fixed map, not the probe;
  `confidence` is always `high` (an exact deterministic match) and `atlas_technique` is
  `None` (matching the demo's equivalent hand-built findings). The detector severities are
  locked: `secret_echo` 9.5 critical, `pii_echo` 8.0 high, `canary_leak` 9.5 critical (doc
  05). The category override means a `secret_echo` hit on an LLM09 probe still files as LLM02.
- The detector fingerprint reuses the same recipe with NO new key: `fingerprint(detector
  category, f"{probe_id}:{detector}", "", target_identity)`. The rule-id slot stays empty (a
  detector cites no rule), and the detector name is folded into the probe-id slot so two
  detectors firing on one probe (e.g. `secret_echo` and `pii_echo` in one response) get
  distinct, stable fingerprints. The empty rule-id slot keeps it parallel to the probe-only
  path and never collides with a rule-bound finding's fingerprint, which carries a non-empty
  `rule.id`.
- Overlap policy: a probe that BOTH fails its bound rule AND fires a detector emits TWO
  findings. They are different failures (a content-rule violation vs a verbatim secret/PII
  echo) with different category/probe-id fingerprint keys, so neither masks or dedups the
  other. The detector path runs independent of the verdict pre-filter, so a deterministic-only
  result (`verdict is None`) still emits its detector finding even though it produces no
  verdict finding (`tests/test_scan.py`).

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| Mapper called on a `ProbeResult` with `verdict is None` | `ValueError` naming `result.probe_id` (no half `Finding` built) | Only feed failed `ok` results to the mapper; route errored/skipped to coverage counts |
| Mapper called on a `ProbeResult` with `evidence is None` | `ValueError` naming `result.probe_id` | Same; a failed judged result carries redacted evidence |
| `map_detector_to_finding` called on a result with `evidence is None` | `ValueError` naming `result.probe_id` (no half `Finding` built) | A result that fired a detector always carries redacted evidence; never feed an evidence-less result to the detector mapper |
| `min(judge, rule.severity)` lands out of `0.0-10.0` | cannot happen for in-range inputs; the `Finding` model rejects an out-of-range `severity_score` at construction | Fix the judge/rule source; never clamp silently (doc 01) |
| A score sits exactly on a band threshold (e.g. `7.0`) | takes the higher band (`>=` is inclusive-lower); deterministic and tested | Expected; the band table is locked |
| `probe.atlas_technique is None` | `Finding.atlas_technique` is `None`; ATLAS is omitted from the card mapping line and SARIF `result.taxa` | Expected; ATLAS is optional per probe |
| A category outside the v1 five reaches the mapper | impossible: `category` is `OwaspLlmId`, rejected at model load on the probe/rule | Use a locked category; adding one is an architecture gate (doc 01) |

## Edge Cases

- Probe-only finding (an unbound probe, no `target_rule`): `category = probe.category`,
  `severity_score = probe.severity_hint` (falling back to `verdict.severity_score` when the
  probe declares no hint), the description and fix derived from `probe.safe_behavior`, and
  `rule_id = ""` in the fingerprint. The empty `rule_id` slot is by design and is the
  committed golden-vector case (doc 01, spec 5.5.1).
- Zero findings: a valid empty `Finding[]` produces empty `counts_by_band` /
  `counts_by_category` rollups and the clean-pass grade A report (doc 10, spec 5.10); the
  banding layer is simply never invoked.
- `verdict.suggested_fix` empty and `rule.fix` `None`: on the matched path `fix` falls back
  to `""`; the upstream rule packs ship a non-empty `rule.fix` or `rule.statement`-derived
  remediation so the finding card always shows an action (doc 08).
- `rule.rationale` `None`: the description is `verdict.rationale` alone, with no grounding
  clause appended (doc 08).
- A 0.0 severity score bands `low`, not a fifth band; there is no band below low, and a
  finding always carries a band (spec 5.4).
