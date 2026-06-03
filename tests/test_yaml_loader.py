from pathlib import Path

import pytest
from pydantic import BaseModel

from shipgrade._yaml import PackLoadError, load_yaml_model


class _Toy(BaseModel):
    model_config = {"extra": "forbid"}
    name: str
    count: int


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "toy.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_a_valid_mapping(tmp_path):
    p = _write(tmp_path, "name: probe\ncount: 3\n")
    model = load_yaml_model(p, _Toy)
    assert model.name == "probe"
    assert model.count == 3


def test_missing_file_is_actionable(tmp_path):
    with pytest.raises(PackLoadError, match="not found"):
        load_yaml_model(tmp_path / "nope.yaml", _Toy)


def test_unknown_key_is_rejected(tmp_path):
    p = _write(tmp_path, "name: probe\ncount: 3\nextra: boom\n")
    with pytest.raises(PackLoadError, match="validation"):
        load_yaml_model(p, _Toy)


def test_non_mapping_is_rejected(tmp_path):
    p = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(PackLoadError, match="mapping"):
        load_yaml_model(p, _Toy)


def test_yaml_aliases_are_rejected(tmp_path):
    # A billion-laughs-shaped document: anchors/aliases are banned outright.
    p = _write(tmp_path, "name: &a probe\ncount: 3\nalias: *a\n")
    with pytest.raises(PackLoadError):
        load_yaml_model(p, _Toy)


def test_oversized_file_is_rejected(tmp_path):
    p = _write(tmp_path, "name: x\ncount: 1\n# " + ("z" * 1_000_001))
    with pytest.raises(PackLoadError, match="cap"):
        load_yaml_model(p, _Toy)
