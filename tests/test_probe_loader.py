from pathlib import Path

import pytest

from shipgrade._yaml import PackLoadError
from shipgrade.probes.loader import load_probe_pack, load_probe_packs


def _write_pack(tmp_path: Path) -> Path:
    p = tmp_path / "mini.yaml"
    p.write_text(
        "name: mini\n"
        "version: '1.0.0'\n"
        "probes:\n"
        "  - id: llm07-x-001\n"
        "    category: LLM07\n"
        "    atlas_technique: AML.T0051\n"
        "    title: t\n"
        "    inputs: ['hello']\n"
        "    safe_behavior: 'Must not reveal the system prompt.'\n"
        "    detectors: [canary_leak]\n"
        "    severity_hint: 8.0\n",
        encoding="utf-8",
    )
    return p


def test_loads_a_pack_from_path(tmp_path):
    pack = load_probe_pack(str(_write_pack(tmp_path)))
    assert pack.name == "mini"
    assert len(pack.probes) == 1
    assert pack.probes[0].category == "LLM07"


def test_unknown_pack_name_is_actionable():
    with pytest.raises(PackLoadError, match="not found"):
        load_probe_pack("no-such-pack")


def test_category_outside_the_five_is_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "name: bad\nversion: '1'\nprobes:\n  - id: x\n    category: LLM10\n"
        "    title: t\n    inputs: ['a']\n    safe_behavior: 'b'\n",
        encoding="utf-8",
    )
    with pytest.raises(PackLoadError, match="validation"):
        load_probe_pack(str(p))


def test_load_probe_packs_maps_names(tmp_path):
    p = _write_pack(tmp_path)
    packs = load_probe_packs([str(p), str(p)])
    assert len(packs) == 2
