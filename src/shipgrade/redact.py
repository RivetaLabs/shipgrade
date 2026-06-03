"""The single redaction boundary (spec 5.9, doc 13). Detect (deterministic, local) ->
redact (local) -> egress. Detected secret/PII spans in target responses become
deterministic placeholders before the excerpt reaches the judge or any renderer; raw
responses stay transient in memory and never persist. Canary detection fires only when
the caller supplies canaries; the v1 live path supplies none (canary injection is roadmap).
This is the one redaction function (threat model abuse case 3)."""

from __future__ import annotations

from shipgrade.judge.deterministic import (
    DetectorSpan,
    canary_leak,
    pii_echo,
    secret_echo,
)
from shipgrade.models import AdapterMode, DetectorName, Evidence

# Excerpt-length cap before storing in Evidence (spec 5.1.1, abuse case 8). Applied AFTER
# redaction so a placeholder is never split mid-token.
_EXCERPT_CAP = 2_048


def _placeholder(span: DetectorSpan) -> str:
    if span.detector == "secret_echo":
        return f"[REDACTED:secret({span.end - span.start})]"
    if span.detector == "pii_echo":
        return f"[REDACTED:pii:{span.hint}]"
    return "[REDACTED:canary]"


def redact_excerpt(text: str, *, canaries: list[str]) -> tuple[str, list[DetectorName]]:
    """Return (redacted_text, fired). `fired` is each detector that matched, once per detector
    (deduplicated), in detector order (secret_echo, pii_echo, canary_leak); empty when nothing
    fired. Spans from all three detectors are merged by covering range so overlapping hits
    (e.g. a phone-shaped email local part) leave no raw value behind. The fired list carries
    detector identity past the redaction boundary so the scan can map a hit to a Finding (doc
    05); the raw matched value never leaves this function; only the placeholder does."""
    spans = secret_echo(text) + pii_echo(text) + canary_leak(text, canaries)
    if not spans:
        return text, []
    # Detector order is fixed by the concatenation above; dedupe preserving first occurrence so
    # one response with two PII spans yields a single pii_echo entry, never a duplicate.
    fired: list[DetectorName] = []
    for span in spans:
        if span.detector not in fired:
            fired.append(span.detector)
    spans = sorted(spans, key=lambda s: (s.start, -s.end))
    out: list[str] = []
    cursor = 0
    for span in spans:
        if span.start < cursor:  # overlaps an already-redacted range
            if span.end > cursor:  # ...but extends past it: cover the raw tail, never emit it
                out.append(_placeholder(span))
                cursor = span.end
            continue
        out.append(text[cursor : span.start])
        out.append(_placeholder(span))
        cursor = span.end
    out.append(text[cursor:])
    return "".join(out), fired


def build_evidence(
    *,
    probe_input: str,
    raw_response: str,
    adapter_mode: AdapterMode,
    canaries: list[str],
) -> tuple[Evidence, list[DetectorName]]:
    """The one chokepoint that turns a raw target response into a redacted Evidence. Detected
    secret/PII spans are replaced with placeholders before the excerpt is stored; the raw
    response stays transient in this call and never persists. Canary detection fires only when
    the caller supplies canaries (the v1 live path supplies none). Returns the Evidence and the
    list of detectors that fired (empty when none did), so the caller can record detector
    identity on the ProbeResult and map each hit to a Finding (doc 05). Evidence.redacted is
    bool(fired)."""
    excerpt, fired = redact_excerpt(raw_response, canaries=canaries)
    evidence = Evidence(
        probe_input=probe_input,
        response_excerpt=excerpt[:_EXCERPT_CAP],
        redacted=bool(fired),
        adapter_mode=adapter_mode,
    )
    return evidence, fired
