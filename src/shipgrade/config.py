"""Config loader (spec 5.6, 5.7). Reads a shipgrade.yaml into a validated Config through
the shared YAML chokepoint used by scan and init."""

from __future__ import annotations

from pathlib import Path

from shipgrade._yaml import load_yaml_model
from shipgrade.models import Config


def load_config(path: Path) -> Config:
    return load_yaml_model(path, Config)
