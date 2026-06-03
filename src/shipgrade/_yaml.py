"""Single YAML-loading chokepoint (spec 5.8, 8 abuse case 6). Every probe pack, rule
pack, and config loads through here, so the hostile-pack defense lives and is tested in
one place: a SafeLoader that also bans anchors/aliases (kills the billion-laughs
expansion bomb), a byte cap before parse, then Pydantic validation with extra=forbid.
"""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError
from yaml.events import AliasEvent

_MAX_YAML_BYTES = 1_000_000  # 1 MB; a probe/rule/config file is kilobytes

M = TypeVar("M", bound=BaseModel)


class PackLoadError(Exception):
    """Actionable load failure: missing file, oversized, malformed YAML, alias bomb,
    non-mapping document, or schema-invalid."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that also refuses YAML anchors/aliases. SafeLoader already blocks
    arbitrary object construction (never yaml.full_load); banning aliases closes the
    billion-laughs expansion bomb. shipgrade packs never use anchors, so this rejects
    only hostile input."""

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(AliasEvent):
            raise yaml.YAMLError("YAML anchors/aliases are not allowed in shipgrade packs")
        return super().compose_node(parent, index)


def load_yaml_model(path: Path, model: type[M]) -> M:
    if not path.is_file():
        raise PackLoadError(f"file not found: {path}")
    raw = path.read_bytes()
    if len(raw) > _MAX_YAML_BYTES:
        raise PackLoadError(
            f"{path.name} is {len(raw)} bytes; cap is {_MAX_YAML_BYTES} (hostile-pack guard)"
        )
    try:
        data = yaml.load(raw, Loader=_StrictLoader)
    except yaml.YAMLError as exc:
        raise PackLoadError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PackLoadError(f"{path.name} must be a YAML mapping, got {type(data).__name__}")
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise PackLoadError(f"{path.name} failed {model.__name__} validation:\n{exc}") from exc
