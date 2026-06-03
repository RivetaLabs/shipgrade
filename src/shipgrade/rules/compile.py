"""Compile loaded rule packs into the per-category judge inputs (spec 5.8).

A pure, judge-SDK-free transform: select rules by OWASP category, render each rule's
`kind` + `statement` + `examples` into one deterministic rubric-fragment string (the text
Section 4 prompt-caches and the judge splices into its cached system block), and surface
`examples.violating` strings as origin-preserving (example, rule_id) seed inputs. Imports
only the object model; it never calls a provider and never touches the frozen Finding
contract.
"""

from __future__ import annotations

from shipgrade.models import OwaspLlmId, Rule, RulePack

_KIND_PHRASE = {"must_never": "must never", "must_always": "must always"}


def _rules_for_category(packs: list[RulePack], category: OwaspLlmId) -> list[Rule]:
    """Rules whose category matches, in pack-then-rule input order (deterministic)."""
    selected: list[Rule] = []
    for pack in packs:
        for rule in pack.rules:
            if rule.category == category:
                selected.append(rule)
    return selected


def _examples(rule: Rule, key: str) -> list[str]:
    """The violating/compliant example strings for a rule, [] when absent or malformed."""
    if not rule.examples:
        return []
    values = rule.examples.get(key, [])
    if not isinstance(values, list):
        return []
    return [str(v) for v in values]


def _render_rule(rule: Rule) -> str:
    """One rule as: an id-tagged kind+statement line, then fixed-order labeled examples."""
    lines = [f"{rule.id}: the assistant {_KIND_PHRASE[rule.kind]} {rule.statement}"]
    for example in _examples(rule, "violating"):
        lines.append(f"  Violating example: {example}")
    for example in _examples(rule, "compliant"):
        lines.append(f"  Compliant example: {example}")
    return "\n".join(lines)


def compile_rule_rubric(packs: list[RulePack], category: OwaspLlmId) -> str:
    """The rubric fragment for one OWASP category: each matching rule's kind, statement,
    and labeled few-shot examples, in input order. Empty string when no rule matches."""
    rendered = [_render_rule(rule) for rule in _rules_for_category(packs, category)]
    return "\n".join(rendered)


def compile_rubric_map(packs: list[RulePack]) -> dict[OwaspLlmId, str]:
    """Category -> rubric fragment, keyed only for categories that have at least one rule.
    The scan layer threads this into the judge per probe category."""
    result: dict[OwaspLlmId, str] = {}
    for pack in packs:
        for rule in pack.rules:
            if rule.category not in result:
                result[rule.category] = compile_rule_rubric(packs, rule.category)
    return result


def seed_inputs_for_category(packs: list[RulePack], category: OwaspLlmId) -> list[tuple[str, str]]:
    """examples.violating strings for the category as origin-preserving single-turn seed
    inputs: each (violating_example, origin_rule_id) pair, in pack-then-rule-then-example
    input order, so a rule with no matching probe still gets exercised (spec 5.8 'Seed
    probes'). Origin is preserved so a failed seed cites exactly its rule; a literal
    duplicate example within one rule is dropped, but the same string under two different
    rules keeps both pairs (each rule owns its seed). No generation engine in v1."""
    seeds: list[tuple[str, str]] = []
    for rule in _rules_for_category(packs, category):
        seen_within_rule: set[str] = set()
        for example in _examples(rule, "violating"):
            if example in seen_within_rule:
                continue
            seen_within_rule.add(example)
            seeds.append((example, rule.id))
    return seeds
