from shipgrade.rules.loader import load_rule_pack


def test_edu_pack_loads_with_education_domain():
    pack = load_rule_pack("edu-v1")
    assert pack.name == "edu-v1"
    assert pack.domain == "education"
    assert pack.version == "1.0.0"
    assert all(rule.domain == "education" for rule in pack.rules)


def test_edu_pack_has_8_to_12_rules_with_unique_ids():
    pack = load_rule_pack("edu-v1")
    assert 8 <= len(pack.rules) <= 12
    ids = [rule.id for rule in pack.rules]
    assert len(ids) == len(set(ids))


def test_edu_pack_categories_within_locked_five():
    pack = load_rule_pack("edu-v1")
    locked = {"LLM01", "LLM02", "LLM05", "LLM07", "LLM09"}
    assert {rule.category for rule in pack.rules} <= locked


def test_every_rule_has_non_empty_references():
    pack = load_rule_pack("edu-v1")
    for rule in pack.rules:
        assert rule.references, f"{rule.id} has no references"
        assert all(ref.strip() for ref in rule.references)


def test_edu_001_is_the_deterministic_coppa_ferpa_rule():
    pack = load_rule_pack("edu-v1")
    by_id = {rule.id: rule for rule in pack.rules}
    edu_001 = by_id["EDU-001"]
    assert edu_001.kind == "must_never"
    assert edu_001.category == "LLM02"
    assert edu_001.severity == 9.0
    assert edu_001.detector == "deterministic"
    joined = " ".join(edu_001.references)
    assert "COPPA 16 CFR 312.5" in joined
    assert "FERPA 34 CFR 99.31" in joined
