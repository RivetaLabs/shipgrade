"""SARIF 2.1.0 renderer (spec 5.5.1). A typed Pydantic model tree plus the mapping
from a Report. Validated against the vendored official 2.1.0 schema in tests. A
finding is behavioral, so it carries a logicalLocation for behavioral identity and
a physicalLocation.artifactLocation.uri (the run's artifact) that GitHub ingestion
requires; regions are omitted on purpose. partialFingerprints carry Finding.fingerprint
under primaryLocationLineHash (the only key GitHub honors) and a versioned tag.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from shipgrade.models import Finding, Report

# OWASP 2025 rule metadata (helpUri slugs verified against genai.owasp.org, 2026-06-02).
_OWASP = {
    "LLM01": ("PromptInjection", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
    "LLM02": (
        "SensitiveInformationDisclosure",
        "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    ),
    "LLM05": (
        "ImproperOutputHandling",
        "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    ),
    "LLM07": (
        "SystemPromptLeakage",
        "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
    ),
    "LLM09": ("Misinformation", "https://genai.owasp.org/llmrisk/llm092025-misinformation/"),
}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

_OWASP_TAXONOMY = "OWASP-LLM-Top-10-2025"
_ATLAS_TAXONOMY = "MITRE-ATLAS"
_TOOL_VERSION = "0.1.0"
_INFO_URI = "https://github.com/RivetaLabs/Shipgrade"
_SARIF_DISCLAIMER = (
    "Findings are behavioral observations of an LLM feature's responses, not static "
    "defects in source lines. Severity is a CVSS-flavored 0-10 adaptation for LLM "
    "behavior, not CVSS-proper. EPSS and KEV are intentionally excluded."
)


class _S(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class SarifArtifactLocation(_S):
    uri: str


class SarifPhysicalLocation(_S):
    artifactLocation: SarifArtifactLocation


class SarifLogicalLocation(_S):
    name: str
    fullyQualifiedName: str
    kind: str = "member"


class SarifLocation(_S):
    physicalLocation: SarifPhysicalLocation
    logicalLocations: list[SarifLogicalLocation]


class SarifMessage(_S):
    text: str


class SarifDescriptorReference(_S):
    id: str
    toolComponent: dict[str, str]


class SarifResult(_S):
    ruleId: str
    level: str
    kind: str = "fail"
    rank: float
    message: SarifMessage
    locations: list[SarifLocation]
    partialFingerprints: dict[str, str]
    properties: dict[str, str]
    taxa: list[SarifDescriptorReference]


class SarifReportingDescriptor(_S):
    id: str
    name: str | None = None
    helpUri: str | None = None
    defaultConfiguration: dict[str, str] | None = None


class SarifToolComponent(_S):
    name: str
    version: str | None = None
    informationUri: str | None = None
    organization: str | None = None
    rules: list[SarifReportingDescriptor] | None = None
    taxa: list[SarifReportingDescriptor] | None = None
    properties: dict[str, str] | None = None


class SarifTool(_S):
    driver: SarifToolComponent


class SarifAutomationDetails(_S):
    id: str


class SarifRun(_S):
    tool: SarifTool
    results: list[SarifResult]
    taxonomies: list[SarifToolComponent]
    automationDetails: SarifAutomationDetails


class SarifLog(_S):
    schema_uri: str = Field(
        default="https://json.schemastore.org/sarif-2.1.0.json", alias="$schema"
    )
    version: str = "2.1.0"
    runs: list[SarifRun]


def _result(finding: Finding, target_identity: str) -> SarifResult:
    taxa = [SarifDescriptorReference(id=finding.category, toolComponent={"name": _OWASP_TAXONOMY})]
    if finding.atlas_technique is not None:
        taxa.append(
            SarifDescriptorReference(
                id=finding.atlas_technique, toolComponent={"name": _ATLAS_TAXONOMY}
            )
        )
    return SarifResult(
        ruleId=finding.category,
        level=_LEVEL[finding.severity_band],
        rank=finding.severity_score * 10,
        message=SarifMessage(
            text=(
                f"{finding.title} (severity {finding.severity_band}).\n"
                f"{finding.description}\n"
                f"Fix: {finding.fix}\n"
                "Evidence is available in the local report formats; "
                "run shipgrade locally to see it."
            )
        ),
        locations=[
            SarifLocation(
                physicalLocation=SarifPhysicalLocation(
                    artifactLocation=SarifArtifactLocation(uri=target_identity)
                ),
                logicalLocations=[
                    SarifLogicalLocation(
                        name=finding.id,
                        fullyQualifiedName=f"{target_identity}/{finding.category}/{finding.id}",
                    )
                ],
            )
        ],
        partialFingerprints={
            "primaryLocationLineHash": finding.fingerprint,
            "shipgradeFindingV1": finding.fingerprint,
        },
        properties={"security-severity": str(finding.severity_score)},
        taxa=taxa,
    )


def render_sarif(report: Report) -> SarifLog:
    from shipgrade.report._common import order_findings

    findings = order_findings(report)
    target_identity = report.metadata.target.identity

    categories = sorted({f.category for f in findings})
    rules = [
        SarifReportingDescriptor(
            id=cat,
            name=_OWASP[cat][0],
            helpUri=_OWASP[cat][1],
            defaultConfiguration={"level": "warning"},
        )
        for cat in categories
    ]
    owasp_taxa = [SarifReportingDescriptor(id=cat) for cat in categories]
    atlas_ids = sorted({f.atlas_technique for f in findings if f.atlas_technique})
    atlas_taxa = [SarifReportingDescriptor(id=a) for a in atlas_ids]

    driver = SarifToolComponent(
        name="shipgrade",
        version=_TOOL_VERSION,
        informationUri=_INFO_URI,
        rules=rules,
        properties={"disclaimer": _SARIF_DISCLAIMER},
    )
    taxonomies = [
        SarifToolComponent(
            name=_OWASP_TAXONOMY,
            organization="OWASP",
            informationUri="https://genai.owasp.org/llm-top-10/",
            taxa=owasp_taxa,
        ),
        SarifToolComponent(
            name=_ATLAS_TAXONOMY,
            organization="MITRE",
            informationUri="https://atlas.mitre.org/",
            taxa=atlas_taxa,
        ),
    ]
    run = SarifRun(
        tool=SarifTool(driver=driver),
        results=[_result(f, target_identity) for f in findings],
        taxonomies=taxonomies,
        automationDetails=SarifAutomationDetails(id=f"shipgrade/{report.metadata.run_id}"),
    )
    return SarifLog(runs=[run])


def sarif_json(report: Report) -> str:
    return render_sarif(report).model_dump_json(indent=2, by_alias=True, exclude_none=True) + "\n"
