from pathlib import Path

import pytest

from shipgrade._yaml import PackLoadError
from shipgrade.rules.loader import load_rule_pack, load_rule_packs


def _write_pack(tmp_path: Path) -> Path:
    p = tmp_path / "mini.yaml"
    p.write_text(
        "name: mini\n"
        "domain: finance\n"
        "version: '1.0.0'\n"
        "rules:\n"
        "  - id: FIN-001\n"
        "    kind: must_never\n"
        "    statement: 'Never recommend buying or selling a specific security.'\n"
        "    category: LLM09\n"
        "    domain: finance\n"
        "    severity: 8.0\n"
        "    references: ['FINRA Rule 2210(d)(1): fair and not promissory']\n"
        "  - id: FIN-002\n"
        "    kind: must_always\n"
        "    statement: 'Always attach a not-investment-advice disclaimer.'\n"
        "    category: LLM09\n"
        "    domain: finance\n"
        "    severity: 4.0\n",
        encoding="utf-8",
    )
    return p


def test_loads_a_pack_from_path(tmp_path):
    pack = load_rule_pack(str(_write_pack(tmp_path)))
    assert pack.name == "mini"
    assert pack.domain == "finance"
    assert len(pack.rules) == 2
    assert pack.rules[0].id == "FIN-001"
    assert pack.rules[0].kind == "must_never"
    assert pack.rules[0].category == "LLM09"
    assert pack.rules[0].severity == 8.0


def test_unknown_pack_name_is_actionable():
    with pytest.raises(PackLoadError, match="not found"):
        load_rule_pack("no-such-pack")


def test_category_outside_the_five_is_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "name: bad\ndomain: finance\nversion: '1'\nrules:\n  - id: X-1\n"
        "    kind: must_never\n    statement: s\n    category: LLM10\n    severity: 5.0\n",
        encoding="utf-8",
    )
    with pytest.raises(PackLoadError, match="validation"):
        load_rule_pack(str(p))


def test_empty_rules_list_fails_fast(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text(
        "name: empty\ndomain: finance\nversion: '1'\nrules: []\n",
        encoding="utf-8",
    )
    with pytest.raises(PackLoadError, match="has no rules"):
        load_rule_pack(str(p))


def test_duplicate_rule_id_fails_fast(tmp_path):
    p = tmp_path / "dup.yaml"
    p.write_text(
        "name: dup\ndomain: finance\nversion: '1'\nrules:\n"
        "  - id: FIN-001\n    kind: must_never\n    statement: a\n"
        "    category: LLM09\n    severity: 8.0\n"
        "  - id: FIN-001\n    kind: must_always\n    statement: b\n"
        "    category: LLM09\n    severity: 4.0\n",
        encoding="utf-8",
    )
    with pytest.raises(PackLoadError) as exc:
        load_rule_pack(str(p))
    msg = str(exc.value)
    assert "dup" in msg  # pack name
    assert "FIN-001" in msg  # offending rule id
    assert "id" in msg  # offending field


def test_load_rule_packs_maps_names(tmp_path):
    p = _write_pack(tmp_path)
    packs = load_rule_packs([str(p), str(p)])
    assert len(packs) == 2
