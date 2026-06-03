"""Rule-pack loader (spec 5.8). Resolves a bundled pack name (under packs/) or a filesystem
path to a validated RulePack through the shared YAML chokepoint, then enforces the cross-rule
fail-fast invariants Pydantic cannot express: no empty rules list and no duplicate rule id.
One aggregated error names the pack, the offending rule id, and the field, and exits before
any probe runs."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from shipgrade._yaml import PackLoadError, load_yaml_model
from shipgrade.models import RulePack


def _resolve(name_or_path: str) -> Path:
    candidate = Path(name_or_path)
    if candidate.suffix in {".yaml", ".yml"} and candidate.is_file():
        return candidate
    bundled = files("shipgrade.rules").joinpath("packs", f"{name_or_path}.yaml")
    if bundled.is_file():
        # v1 ships as an unpacked wheel (pipx/uvx venv), so the resource is a real file.
        return Path(str(bundled))
    raise PackLoadError(
        f"rule pack not found: {name_or_path!r} (looked for a bundled pack and a .yaml/.yml file)"
    )


def _check_cross_rule(pack: RulePack) -> None:
    """Spec-5.8 invariants Pydantic cannot see: empty rules, duplicate rule id. Aggregate
    every problem into one PackLoadError naming pack + rule id + field, so a malformed pack
    is never silently dropped and the author sees all problems at once."""
    errors: list[str] = []
    if not pack.rules:
        errors.append(f"rule pack {pack.name!r} has no rules (field 'rules' is empty)")
    seen: set[str] = set()
    for rule in pack.rules:
        if rule.id in seen:
            errors.append(f"rule pack {pack.name!r}: duplicate rule id {rule.id!r} (field 'id')")
        seen.add(rule.id)
    if errors:
        raise PackLoadError("\n".join(errors))


def load_rule_pack(name_or_path: str) -> RulePack:
    pack = load_yaml_model(_resolve(name_or_path), RulePack)
    _check_cross_rule(pack)
    return pack


def load_rule_packs(names: list[str]) -> list[RulePack]:
    return [load_rule_pack(n) for n in names]
