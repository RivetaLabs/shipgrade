"""Probe-pack loader (spec 5.2, 5.7). Resolves a bundled pack name (under packs/) or a
filesystem path to a validated ProbePack through the shared YAML chokepoint."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from shipgrade._yaml import PackLoadError, load_yaml_model
from shipgrade.models import ProbePack


def _resolve(name_or_path: str) -> Path:
    candidate = Path(name_or_path)
    if candidate.suffix in {".yaml", ".yml"} and candidate.is_file():
        return candidate
    bundled = files("shipgrade.probes").joinpath("packs", f"{name_or_path}.yaml")
    if bundled.is_file():
        # v1 ships as an unpacked wheel (pipx/uvx venv), so the resource is a real file.
        return Path(str(bundled))
    raise PackLoadError(
        f"probe pack not found: {name_or_path!r} (looked for a bundled pack and a .yaml/.yml file)"
    )


def load_probe_pack(name_or_path: str) -> ProbePack:
    return load_yaml_model(_resolve(name_or_path), ProbePack)


def load_probe_packs(names: list[str]) -> list[ProbePack]:
    return [load_probe_pack(n) for n in names]
