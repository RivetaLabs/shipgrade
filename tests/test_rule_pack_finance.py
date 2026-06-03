from shipgrade.rules.loader import load_rule_pack

V1_CATEGORIES = {"LLM01", "LLM02", "LLM05", "LLM07", "LLM09"}


def test_finance_pack_loads_with_fixed_identity():
    pack = load_rule_pack("finance-v1")
    assert pack.name == "finance-v1"
    assert pack.version == "1.0.0"
    assert pack.domain == "finance"


def test_finance_pack_rule_count_in_range():
    pack = load_rule_pack("finance-v1")
    assert 8 <= len(pack.rules) <= 12


def test_finance_pack_rule_ids_unique():
    rules = load_rule_pack("finance-v1").rules
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_fin001_is_the_canonical_must_never_rule():
    by_id = {r.id: r for r in load_rule_pack("finance-v1").rules}
    fin001 = by_id["FIN-001"]
    assert fin001.kind == "must_never"
    assert fin001.category == "LLM09"
    assert fin001.severity == 8.0
    assert fin001.domain == "finance"
    assert fin001.references  # non-empty


def test_fin002_is_a_must_always_disclaimer_rule():
    by_id = {r.id: r for r in load_rule_pack("finance-v1").rules}
    fin002 = by_id["FIN-002"]
    assert fin002.kind == "must_always"
    assert fin002.domain == "finance"
    assert fin002.references  # non-empty


def test_fin_004_cites_performance_prediction_rule():
    by_id = {r.id: r for r in load_rule_pack("finance-v1").rules}
    fin004 = by_id["FIN-004"]
    assert fin004.kind == "must_never"
    assert "Never predict or project investment performance" in fin004.statement
    assert "imply that past performance will recur" in fin004.statement
    assert any("FINRA Rule 2210(d)(1)(F)" in ref for ref in fin004.references)
    assert any(
        "never predict or project investment performance" in ref for ref in fin004.references
    )


def test_fin011_is_the_tax_evasion_rule_with_the_verified_citation():
    by_id = {r.id: r for r in load_rule_pack("finance-v1").rules}
    fin011 = by_id["FIN-011"]
    assert fin011.kind == "must_never"
    assert fin011.category == "LLM09"
    assert fin011.domain == "finance"
    # The citation was verified live against uscode.house.gov: 26 U.S.C. 7201 is
    # "Attempt to evade or defeat tax".
    assert any("26 U.S.C. 7201" in ref for ref in fin011.references)
    assert any("evade or defeat tax" in ref for ref in fin011.references)


def test_every_rule_is_finance_in_v1_categories_with_references():
    for r in load_rule_pack("finance-v1").rules:
        assert r.domain == "finance"
        assert r.category in V1_CATEGORIES
        assert r.references, f"{r.id} has empty references"
        assert all(ref.strip() for ref in r.references), f"{r.id} has a blank reference"
