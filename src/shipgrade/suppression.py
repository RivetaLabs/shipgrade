"""Per-finding suppression (spec 6.1). A .shipgrade-ignore.yaml file lists waivers
keyed on Finding.fingerprint, each with a reason and an optional expires date. The
file loads through the shared _yaml chokepoint into LOCAL Waiver models (no models.py
change; Finding stays frozen). partition() splits findings into (active, waived) so
the CI gate can ignore waived findings while the report still renders them as
accepted risk. An expired waiver no longer suppresses: its finding stays active.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from shipgrade._yaml import load_yaml_model
from shipgrade.models import Finding


class Waiver(BaseModel):
    """One accepted-risk waiver, keyed on Finding.fingerprint (spec 6.1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: str
    reason: str
    expires: date | None = None


class IgnoreFile(BaseModel):
    """On-disk shape of .shipgrade-ignore.yaml: a mapping with a waivers list, so it
    loads through the chokepoint (which requires a top-level mapping model)."""

    model_config = ConfigDict(extra="forbid")

    waivers: list[Waiver] = []


def load_waivers(path: Path) -> list[Waiver]:
    """Load .shipgrade-ignore.yaml through the shared chokepoint. Raises PackLoadError
    on a missing file, oversized/hostile YAML, a non-mapping document, or schema-invalid
    content (the same fail-fast contract every pack uses)."""
    return load_yaml_model(path, IgnoreFile).waivers


def partition(
    findings: list[Finding],
    waivers: list[Waiver],
    *,
    today: date | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (active, waived), preserving input order in each list. A
    finding is waived when a non-expired waiver matches its fingerprint. A waiver with
    no expires never lapses; expires is the last valid day (inclusive)."""
    today = today or date.today()
    active_fingerprints = {
        w.fingerprint for w in waivers if w.expires is None or w.expires >= today
    }
    active: list[Finding] = []
    waived: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in active_fingerprints:
            waived.append(finding)
        else:
            active.append(finding)
    return active, waived
