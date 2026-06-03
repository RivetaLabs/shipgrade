from shipgrade.rules.loader import load_rule_pack

V1_CATEGORIES = {"LLM01", "LLM02", "LLM05", "LLM07", "LLM09"}


def test_health_pack_loads_as_health_domain():
    pack = load_rule_pack("health-v1")
    assert pack.name == "health-v1"
    assert pack.domain == "health"
    assert pack.version == "1.0.0"


def test_health_pack_rule_count_is_8_to_12():
    pack = load_rule_pack("health-v1")
    assert 8 <= len(pack.rules) <= 12


def test_health_pack_ships_11_rules():
    """The re-citation task split HLT-001's diagnosis obligation into HLT-011, taking the
    pack from 10 to 11 rules."""
    pack = load_rule_pack("health-v1")
    assert len(pack.rules) == 11


def test_hlt_001_matches_the_spec_5_8_anchor():
    pack = load_rule_pack("health-v1")
    by_id = {r.id: r for r in pack.rules}
    hlt = by_id["HLT-001"]
    assert hlt.kind == "must_never"
    assert hlt.category == "LLM09"
    assert hlt.severity == 8.5
    assert hlt.domain == "health"
    assert any("21 CFR 201.5" in ref for ref in hlt.references)


def test_no_health_rule_cites_the_device_labeling_section():
    """801.5 is medical-device labeling; it must not ground any drug, diagnosis, or
    clinical-claim rule. Every prior 801.5 cite was re-grounded in this task."""
    pack = load_rule_pack("health-v1")
    for rule in pack.rules:
        for ref in rule.references:
            assert "801.5" not in ref, f"{rule.id} still cites device-labeling 801.5"


def test_hlt_011_is_the_definitive_diagnosis_rule_cited_to_360j():
    """The diagnosis obligation split out of HLT-001 lands in HLT-011, LLM09, grounded in
    the FDA clinical-decision-support software boundary (21 U.S.C. 360j(o))."""
    pack = load_rule_pack("health-v1")
    by_id = {r.id: r for r in pack.rules}
    assert "HLT-011" in by_id, "HLT-011 (definitive diagnosis) is missing"
    hlt = by_id["HLT-011"]
    assert hlt.kind == "must_never"
    assert hlt.category == "LLM09"
    assert hlt.domain == "health"
    assert hlt.severity >= 8.5
    assert any("21 U.S.C. 360j(o)" in ref for ref in hlt.references)


def test_every_health_rule_is_well_formed():
    pack = load_rule_pack("health-v1")
    for rule in pack.rules:
        assert rule.domain == "health"
        assert rule.category in V1_CATEGORIES
        assert rule.references, f"{rule.id} has no references"
        assert all(ref.strip() for ref in rule.references), f"{rule.id} has an empty reference"
        assert rule.statement.strip(), f"{rule.id} has an empty statement"


def test_health_rule_ids_are_unique():
    pack = load_rule_pack("health-v1")
    ids = [r.id for r in pack.rules]
    assert len(ids) == len(set(ids))
