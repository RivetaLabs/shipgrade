from collections import Counter

from shipgrade.probes.loader import load_probe_pack

# The five pinned demo probes (spec 5.2 "worked probes"). They stay verbatim and first;
# the rest of the pack is authored around them. demo elicits DEMO-001..DEMO-005 from these.
DEMO_IDS = {
    "llm07-sysprompt-extract-001",
    "llm02-secret-echo-001",
    "llm09-finance-advice-001",
    "llm01-injection-override-001",
    "llm05-output-handling-001",
}

# Per-category count bands from spec 5.2 (the lopsided-toward-the-wedge allocation). The two
# child-PII probes are LLM02 (Sensitive Information Disclosure), not LLM09, so the wedge band
# floor is 7 and the LLM02 ceiling is 7 (the honest recount after re-categorization).
CATEGORY_BANDS = {
    "LLM09": (7, 10),
    "LLM07": (5, 6),
    "LLM02": (5, 7),
    "LLM01": (4, 5),
    "LLM05": (3, 4),
}

# The spec 5.2 ATLAS allow-set: v1 maps prompt-injection probes to AML.T0051
# and pure system-prompt extraction probes to AML.T0056. Every other category
# carries None. A probe whose atlas_technique falls outside this set is a
# spec-5.2 mapping regression.
ALLOWED_ATLAS = {"AML.T0051", "AML.T0056"}


def test_owasp_core_pack_loads_with_five_categories():
    pack = load_probe_pack("owasp-core-v1")
    assert pack.name == "owasp-core-v1"
    assert pack.version == "1.0.0"
    cats = {p.category for p in pack.probes}
    assert cats == {"LLM01", "LLM02", "LLM05", "LLM07", "LLM09"}


def test_pack_size_uniqueness_and_per_category_bands():
    probes = load_probe_pack("owasp-core-v1").probes
    ids = [p.id for p in probes]

    # The five demo probes are still present (a subset), not the whole pack.
    assert DEMO_IDS.issubset(set(ids))

    # All ids unique across the whole pack.
    assert len(ids) == len(set(ids))

    # Total probe count inside the spec 5.2 "~20-30 probes" range.
    assert 20 <= len(ids) <= 30

    # Per-category counts inside the spec 5.2 allocation bands.
    counts = Counter(p.category for p in probes)
    for category, (low, high) in CATEGORY_BANDS.items():
        assert low <= counts[category] <= high, (
            f"{category} has {counts[category]} probes; spec 5.2 band is {low}-{high}"
        )


def test_atlas_only_on_injection_categories():
    probes = load_probe_pack("owasp-core-v1").probes

    # Robust invariant: any probe carrying an ATLAS technique is an injection/leakage
    # category (LLM01 or LLM07) and the id is one the spec 5.2 table authorizes. The
    # membership check (not a shape regex) is what catches a mapping regression: an id
    # like AML.T0054 or AML.T0099 has the right shape but is not in the spec allow-set.
    for p in probes:
        if p.atlas_technique is not None:
            assert p.category in {"LLM01", "LLM07"}, (
                f"{p.id} ({p.category}) must not carry an ATLAS technique"
            )
            assert p.atlas_technique in ALLOWED_ATLAS, (
                f"{p.id} maps {p.atlas_technique!r}, outside the spec 5.2 allow-set {ALLOWED_ATLAS}"
            )

    # The pinned demo probes keep their exact spec-5.2 ATLAS mapping.
    by_id = {p.id: p for p in probes}
    assert by_id["llm01-injection-override-001"].atlas_technique == "AML.T0051"
    assert by_id["llm07-sysprompt-extract-001"].atlas_technique == "AML.T0056"
    assert by_id["llm02-secret-echo-001"].atlas_technique is None
    assert by_id["llm05-output-handling-001"].atlas_technique is None
    assert by_id["llm09-finance-advice-001"].atlas_technique is None


def test_llm07_extraction_and_injected_leak_use_distinct_atlas_techniques():
    by_id = {p.id: p for p in load_probe_pack("owasp-core-v1").probes}

    pure_extraction_ids = {
        "llm07-sysprompt-extract-001",
        "llm07-sysprompt-roleplay-002",
        "llm07-sysprompt-translate-003",
        "llm07-sysprompt-encode-004",
    }
    for probe_id in pure_extraction_ids:
        assert by_id[probe_id].atlas_technique == "AML.T0056"

    assert by_id["llm07-sysprompt-injected-leak-005"].atlas_technique == "AML.T0051"


# The S3 per-probe binding table: every domain probe binds its single best-fit rule, and the
# bound rule shares the probe's category. The two child-PII probes are re-categorized LLM02.
EXPECTED_BINDINGS = {
    "llm09-finance-advice-001": "FIN-001",
    "llm09-finance-leverage-002": "FIN-001",
    "llm09-finance-guaranteed-return-003": "FIN-003",
    "llm09-finance-tax-evasion-004": "FIN-011",
    "llm09-health-diagnosis-005": "HLT-011",
    "llm09-health-dosage-006": "HLT-001",
    "llm09-health-cure-claim-007": "HLT-004",
    "llm02-edu-minor-pii-008": "EDU-001",
    "llm02-edu-student-records-009": "EDU-005",
}


def test_domain_probes_bind_their_exact_rule():
    by_id = {p.id: p for p in load_probe_pack("owasp-core-v1").probes}
    for probe_id, rule_id in EXPECTED_BINDINGS.items():
        assert probe_id in by_id, f"{probe_id} missing from the pack"
        assert by_id[probe_id].target_rule == rule_id, (
            f"{probe_id} must bind {rule_id}, got {by_id[probe_id].target_rule!r}"
        )


def test_re_categorized_edu_probes_are_llm02():
    by_id = {p.id: p for p in load_probe_pack("owasp-core-v1").probes}
    assert by_id["llm02-edu-minor-pii-008"].category == "LLM02"
    assert by_id["llm02-edu-student-records-009"].category == "LLM02"
    # The old LLM09 ids are gone (renamed to the llm02- prefix).
    assert "llm09-edu-minor-pii-008" not in by_id
    assert "llm09-edu-student-records-009" not in by_id


def test_bound_rules_resolve_against_the_bundled_packs_with_matching_category():
    from shipgrade.rules.loader import load_rule_packs

    by_id = {p.id: p for p in load_probe_pack("owasp-core-v1").probes}
    rules = {
        r.id: r
        for pack in load_rule_packs(["finance-v1", "health-v1", "edu-v1"])
        for r in pack.rules
    }
    for probe_id, rule_id in EXPECTED_BINDINGS.items():
        assert rule_id in rules, f"{rule_id} not in the bundled rule packs"
        assert rules[rule_id].category == by_id[probe_id].category, (
            f"{probe_id} ({by_id[probe_id].category}) binds {rule_id} "
            f"(category {rules[rule_id].category}); categories must match"
        )
