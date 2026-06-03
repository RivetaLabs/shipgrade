import json
from pathlib import Path

import jsonschema

from shipgrade.report.sarif import render_sarif, sarif_json

_SCHEMA = json.loads((Path(__file__).parent / "sarif-schema-2.1.0.json").read_text())


def test_sarif_validates_against_2_1_0_schema(demo_report):
    doc = json.loads(sarif_json(demo_report))
    jsonschema.validate(instance=doc, schema=_SCHEMA)  # raises on any violation


def test_sarif_version_schema_and_result_count(demo_report):
    doc = json.loads(sarif_json(demo_report))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"][0]["results"]) == 5


def test_render_sarif_returns_typed_model(demo_report):
    log = render_sarif(demo_report)
    assert log.version == "2.1.0"
    assert len(log.runs[0].results) == 5


def test_sarif_rules_use_verified_owasp_help_uris(demo_report):
    doc = json.loads(sarif_json(demo_report))
    rules = {r["id"]: r["helpUri"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules == {
        "LLM01": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "LLM02": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
        "LLM05": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
        "LLM07": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
        "LLM09": "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
    }


def _by_rule(doc: dict) -> dict:
    return {r["ruleId"]: r for r in doc["runs"][0]["results"]}


def test_every_result_has_physical_location_uri(demo_report):
    doc = json.loads(sarif_json(demo_report))
    for r in doc["runs"][0]["results"]:
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri  # non-empty: the GitHub ingestion requirement (5.5.1)


def _primary_fingerprints(doc: dict) -> list:
    return sorted(
        r["partialFingerprints"]["primaryLocationLineHash"] for r in doc["runs"][0]["results"]
    )


def test_partial_fingerprints_use_finding_fingerprint(demo_report):
    doc = json.loads(sarif_json(demo_report))
    fp = _by_rule(doc)["LLM02"]["partialFingerprints"]
    assert fp["primaryLocationLineHash"] == "944668538602013a3814e5d5089fadca"
    assert fp["shipgradeFindingV1"] == "944668538602013a3814e5d5089fadca"


def test_partial_fingerprints_stable_across_runs(demo_report):
    a = json.loads(sarif_json(demo_report))
    b = json.loads(sarif_json(demo_report))
    assert _primary_fingerprints(a) == _primary_fingerprints(b)


def test_level_and_security_severity_mapping(demo_report):
    by_rule = _by_rule(json.loads(sarif_json(demo_report)))
    assert by_rule["LLM02"]["level"] == "error"  # critical
    assert by_rule["LLM02"]["properties"]["security-severity"] == "9.5"
    assert by_rule["LLM07"]["level"] == "error"  # high
    assert by_rule["LLM05"]["level"] == "warning"  # medium 4.0


def test_taxonomies_and_atlas_reference(demo_report):
    doc = json.loads(sarif_json(demo_report))
    names = {t["name"] for t in doc["runs"][0]["taxonomies"]}
    assert {"OWASP-LLM-Top-10-2025", "MITRE-ATLAS"} <= names
    by_rule = _by_rule(doc)
    llm07_taxa = {t["id"] for t in by_rule["LLM07"]["taxa"]}
    assert "AML.T0056" in llm07_taxa  # DEMO-001 carries an ATLAS technique
    llm01_taxa = {t["id"] for t in by_rule["LLM01"]["taxa"]}
    assert "AML.T0051" in llm01_taxa  # DEMO-004 carries prompt-injection ATLAS
    llm02_taxa = {t["id"] for t in by_rule["LLM02"]["taxa"]}
    assert "AML.T0056" not in llm02_taxa  # DEMO-002 has none


def test_sarif_messages_carry_no_response_excerpts(demo_report):
    # SARIF is the egress format (uploaded to GitHub Code Scanning, a third-party
    # retention system). It carries the finding, not the target's output (spec 5.9).
    doc = json.loads(sarif_json(demo_report))
    findings_by_id = {f.id: f for f in demo_report.findings}
    excerpts = {f.evidence.response_excerpt for f in demo_report.findings}
    inputs = {f.evidence.probe_input for f in demo_report.findings}
    for r in doc["runs"][0]["results"]:
        text = r["message"]["text"]
        for excerpt in excerpts:
            assert excerpt not in text  # no target response content egresses
        for probe_input in inputs:
            assert probe_input not in text  # no probe input egresses
        finding = findings_by_id[r["locations"][0]["logicalLocations"][0]["name"]]
        assert finding.title in text  # the message still names the finding
        assert finding.severity_band in text  # and its severity band
        assert "run shipgrade locally" in text  # and points at the local evidence


def test_sarif_snapshot(demo_report, snapshot):
    assert sarif_json(demo_report) == snapshot
