"""scan orchestration (spec 5.6, 7, 8). Loads probe packs and rule packs, builds the adapter,
runs every probe input through it with per-probe fail-closed isolation (spec 8), and returns
a ScanRun pairing the executed probe set with the ProbeResult list. The pipeline captures
each response, detects and redacts it into Evidence (spec 5.9), then routes it to the LLM
judge (when present and not offline), to a deterministic-only result when a detector fired,
or to a skipped result. Loaded rule packs compile into a per-category judge rubric (spec 5.8)
so the judge grades domain rule statements in addition to safe_behavior. After the authored
probes run, every rule's examples.violating strings run as synthetic seed probes bound to
their origin rule (spec 5.8), so a rule with no authored probe still gets exercised; the
ScanRun carries those synthetic probes so finding assembly consumes exactly what ran.
findings_from_results maps failed verdicts and detector hits into the frozen Finding contract
(spec 5.5). Raw responses stay transient and never persist; only the redacted excerpt
egresses."""

from __future__ import annotations

from typing import NamedTuple

from shipgrade.adapters.base import AdapterError, ModelCaller, TargetAdapter, build_adapter
from shipgrade.judge.llm import JudgeClient, judge_probe
from shipgrade.mapping import map_detector_to_finding, map_probe_to_finding
from shipgrade.models import (
    AdapterMode,
    Config,
    Finding,
    OwaspLlmId,
    Probe,
    ProbeResult,
    Rule,
    RulePack,
)
from shipgrade.probes.loader import load_probe_packs
from shipgrade.redact import build_evidence, redact_excerpt
from shipgrade.rules.compile import compile_rubric_map, seed_inputs_for_category
from shipgrade.rules.loader import load_rule_packs
from shipgrade.scoring import build_finding


class ScanRun(NamedTuple):
    """The executed probe set paired with its results (the shared scan registry).

    executed_probes holds every probe that actually ran: the authored probes followed by the
    synthetic rule-seed probes (spec 5.8). Finding assembly consumes this exact set so a seed
    result never has to be re-derived or reloaded; a probe id in results is always in
    executed_probes."""

    executed_probes: list[Probe]
    results: list[ProbeResult]


class BindingError(Exception):
    """A probe's target_rule binding is invalid against the loaded rule packs (spec 5.8).

    Raised at scan assembly when a binding points at a missing rule id, the bound rule's
    category does not match the probe's category, or two loaded packs declare the same rule
    id (target_rule is a global namespace). It fails the run loudly rather than emitting a
    mis-attributed Finding."""


# Error-string length cap: long exception messages may embed entire stack frames or
# large HTTP bodies; only the actionable portion matters for the report surface.
_ERROR_CAP = 512


def _sanitize_error(text: str, *, raw_ref: str, sanitized_identity: str) -> str:
    """Return a sanitized, safe-to-store error string.

    Replace any occurrence of the raw target ref (which may contain credentials,
    query tokens, or absolute paths) with the sanitized identity, then run the result
    through the PII/secret redaction chokepoint, strip CR/LF so the error cannot inject
    newlines into rendered output, and cap the length.
    """
    # Replace the raw ref before redaction so credential-shaped patterns in the URL
    # are eliminated even if they would not match a secret/PII detector pattern.
    if raw_ref and raw_ref != sanitized_identity:
        text = text.replace(raw_ref, sanitized_identity)
    redacted, _fired = redact_excerpt(text, canaries=[])
    return redacted.replace("\r", " ").replace("\n", " ")[:_ERROR_CAP]


def _seed_probes(rule_packs: list[RulePack]) -> list[Probe]:
    """Synthetic single-turn seed probes, one per rule violating example (spec 5.8).

    seed_inputs_for_category is the single source of truth for which (example, rule_id) pairs
    seed: it owns the within-rule dedup, so a rule with a copy-pasted duplicate example seeds
    once, not twice. Each pair becomes a Probe bound to its origin rule so a failed seed
    produces a rule-grounded Finding citing exactly that rule via the existing build_finding
    path (no special-casing in findings_from_results). Ordering is deterministic: categories
    in first-appearance (pack-then-rule) order, then rules within a category in pack order,
    then examples in rule order. The id is `seed:{rule.id}#{n}` with n the 0-based index of
    the example within its rule, tracked across the flat pair stream. detectors fire offline
    (canary_leak needs planted canaries the live path lacks, so it is omitted); severity_hint
    stays None because a seed is always bound and the rule's severity ceiling governs via
    build_finding."""
    rules_by_id = {rule.id: rule for pack in rule_packs for rule in pack.rules}
    categories: list[OwaspLlmId] = list(
        dict.fromkeys(rule.category for pack in rule_packs for rule in pack.rules)
    )
    seeds: list[Probe] = []
    # n is the per-rule 0-based example index; the pair stream is grouped by rule within a
    # category, so a counter keyed on rule id reproduces the within-rule index.
    index_by_rule: dict[str, int] = {}
    for category in categories:
        for example, rule_id in seed_inputs_for_category(rule_packs, category):
            rule = rules_by_id[rule_id]
            n = index_by_rule.get(rule_id, 0)
            index_by_rule[rule_id] = n + 1
            phrase = "must never" if rule.kind == "must_never" else "must always"
            seeds.append(
                Probe(
                    id=f"seed:{rule.id}#{n}",
                    category=rule.category,
                    atlas_technique=None,
                    title=f"Seed: {rule.id} violating example {n}",
                    inputs=[example],
                    safe_behavior=f"The assistant {phrase} {rule.statement}",
                    detectors=["secret_echo", "pii_echo"],
                    severity_hint=None,
                    target_rule=rule.id,
                )
            )
    return seeds


async def run_scan(
    config: Config,
    *,
    model_caller: ModelCaller | None = None,
    judge: JudgeClient | None = None,
    offline: bool = False,
) -> ScanRun:
    from shipgrade.adapters.base import summarize_target

    packs = load_probe_packs(config.probe_packs)
    rule_packs = load_rule_packs(config.rule_packs)
    rubric_map = compile_rubric_map(rule_packs)
    adapter = build_adapter(config.target, model_caller=model_caller)
    active_judge = None if offline else judge
    raw_ref = config.target.ref
    sanitized_identity = summarize_target(config.target).identity
    # Authored probes first (so their result positions are stable), then synthetic rule seeds.
    executed_probes = [probe for pack in packs for probe in pack.probes] + _seed_probes(rule_packs)
    results: list[ProbeResult] = []
    for probe in executed_probes:
        rubric = rubric_map.get(probe.category, "")
        results.append(
            await _run_probe(
                adapter,
                probe,
                config.target.mode,
                active_judge,
                rubric,
                raw_ref=raw_ref,
                sanitized_identity=sanitized_identity,
            )
        )
    return ScanRun(executed_probes=executed_probes, results=results)


async def _run_probe(
    adapter: TargetAdapter,
    probe: Probe,
    adapter_mode: AdapterMode,
    judge: JudgeClient | None,
    rule_rubric: str,
    *,
    raw_ref: str,
    sanitized_identity: str,
) -> ProbeResult:
    try:
        raw = ""
        for prompt in probe.inputs:
            raw = await adapter.respond(prompt)  # last input's response is judged (v1)
        # v1 has no per-probe canary token wired yet; secret_echo/pii_echo still fire.
        evidence, fired = build_evidence(
            probe_input=probe.inputs[-1], raw_response=raw, adapter_mode=adapter_mode, canaries=[]
        )
    except AdapterError as exc:
        return ProbeResult(
            probe_id=probe.id,
            status="errored",
            error=_sanitize_error(str(exc), raw_ref=raw_ref, sanitized_identity=sanitized_identity),
            judged_by="none",
        )
    except Exception as exc:  # a callable target may raise anything; isolate it (spec 8)
        return ProbeResult(
            probe_id=probe.id,
            status="errored",
            error=_sanitize_error(
                f"target raised: {exc}", raw_ref=raw_ref, sanitized_identity=sanitized_identity
            ),
            judged_by="none",
        )
    if judge is not None:
        try:
            verdict = await judge_probe(probe, evidence, client=judge, rule_rubric=rule_rubric)
        except Exception as exc:  # JudgeError or transport; isolate (spec 8)
            return ProbeResult(
                probe_id=probe.id,
                status="errored",
                error=_sanitize_error(
                    f"judge failed: {exc}", raw_ref=raw_ref, sanitized_identity=sanitized_identity
                ),
                judged_by="llm",
            )
        # The judged result also carries any detectors that fired, so a leaked secret echoed
        # in a judged response still becomes a detector Finding alongside the verdict Finding.
        return ProbeResult(
            probe_id=probe.id,
            status="ok",
            verdict=verdict,
            evidence=evidence,
            judged_by="llm",
            fired_detectors=fired,
        )
    if fired and probe.detectors:
        return ProbeResult(
            probe_id=probe.id,
            status="ok",
            evidence=evidence,
            judged_by="deterministic",
            fired_detectors=fired,
        )
    # The probe's own question was not judged (no judge and either nothing fired or the
    # probe declares no detectors), so the result is skipped for coverage purposes. Any
    # fired detector is still carried with its redacted evidence so the key-free guarantee
    # holds on every path: a detected leak is never dropped (doc 05, spec 5.9).
    return ProbeResult(
        probe_id=probe.id,
        status="skipped",
        judged_by="none",
        evidence=evidence if fired else None,
        fired_detectors=fired,
    )


def _index_rules(rule_packs: list[RulePack]) -> dict[str, Rule]:
    """Index every loaded rule by id into one global namespace, failing fast on a collision.

    target_rule is a global reference, so two packs declaring the same rule id are ambiguous
    and a binding could resolve to either; reject it at assembly (spec 5.8)."""
    index: dict[str, Rule] = {}
    for pack in rule_packs:
        for rule in pack.rules:
            if rule.id in index:
                raise BindingError(
                    f"duplicate rule id {rule.id!r} across loaded rule packs "
                    "(target_rule is a global namespace; rule ids must be unique)"
                )
            index[rule.id] = rule
    return index


def _bound_rule(probe: Probe, rule_index: dict[str, Rule]) -> Rule:
    """Resolve a probe's target_rule to its Rule, failing fast on a missing id or a category
    mismatch (the bound rule must share the probe's OWASP category, spec 5.8)."""
    rule = rule_index.get(probe.target_rule or "")
    if rule is None:
        raise BindingError(
            f"probe {probe.id!r} binds target_rule {probe.target_rule!r}, "
            "which is not in any loaded rule pack"
        )
    if rule.category != probe.category:
        raise BindingError(
            f"probe {probe.id!r} (category {probe.category}) binds target_rule "
            f"{probe.target_rule!r} whose category is {rule.category}; they must match"
        )
    return rule


def findings_from_results(
    results: list[ProbeResult],
    probes: list[Probe],
    rule_packs: list[RulePack],
    target_identity: str,
) -> list[Finding]:
    """Assemble frozen Findings from failed verdicts and fired deterministic detectors
    (spec 5.8, 5.9 -> 5.5).

    Two independent sources contribute to the same Finding[] (a probe can hit both):

    Verdict findings (the judged path). Only an ok result with a verdict that did not pass
    becomes one; errored and skipped probes, clean passes, and verdict-None results contribute
    none here. Chosen per probe:
    - bound probe (target_rule set) -> a rule-grounded Finding: the bound rule supplies the
      citation and the severity ceiling (build_finding -> map_to_finding);
    - unbound probe (no target_rule) -> a probe-only Finding citing no rule, built from the
      probe's safe_behavior, category, and severity_hint (map_probe_to_finding).

    Detector findings (the key-free path, spec 5.9). Any result with a non-empty
    fired_detectors list emits one Finding per fired detector (map_detector_to_finding),
    INDEPENDENT of the verdict pre-filter: a deterministic-only result (verdict None) and a
    judged result that also echoed a secret both produce their detector findings here. The
    detector's category and severity come from the detector, not the probe, so a secret echo
    is always LLM02 even on an LLM09 probe. Overlap is intentional: a probe that is both
    rule-bound-failed and detector-firing emits BOTH findings (a content-rule violation and a
    verbatim echo are different failures with different fingerprint keys).

    Bindings are validated against the loaded packs before any Finding is built: a missing
    rule id, a category mismatch, or a duplicate rule id across packs raises BindingError so
    a mis-attribution fails the run loudly instead of shipping a wrong citation."""
    rule_index = _index_rules(rule_packs)
    by_id = {probe.id: probe for probe in probes}
    findings: list[Finding] = []
    for result in results:
        probe = by_id.get(result.probe_id)
        if probe is None:
            continue
        # Detector path: independent of the verdict, before the verdict pre-filter so a
        # deterministic-only result (verdict None) still emits here (spec 5.9, the key-free
        # guarantee). One Finding per fired detector, deduplicated upstream on the result.
        for detector in result.fired_detectors:
            findings.append(
                map_detector_to_finding(
                    result, probe=probe, detector=detector, target_identity=target_identity
                )
            )
        # Verdict path: only a failed judged verdict reaches the mappers, which require a
        # verdict; a verdict-None deterministic result is filtered out here.
        if result.status != "ok" or result.verdict is None or result.verdict.passed:
            continue
        if probe.target_rule is not None:
            rule = _bound_rule(probe, rule_index)
            finding = build_finding(
                result, probe=probe, matched_rule=rule, target_identity=target_identity
            )
            # build_finding returns None only for matched_rule=None; rule is non-None here.
            if finding is not None:
                findings.append(finding)
        else:
            findings.append(
                map_probe_to_finding(result, probe=probe, target_identity=target_identity)
            )
    return findings
