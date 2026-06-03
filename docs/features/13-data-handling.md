---
title: Data-handling pipeline (privacy)
version: 1.4.2
last_updated: 2026-06-02
depends_on: [01-finding-contract, 05-deterministic-detectors]
related: [07-llm-judge, 02-report-core]
status: current
toc: [Data Model, Public Interface, Output surface, Business Rules, Failure Modes, Edge Cases]
---

> INVARIANTS: detect (local) -> redact (local) -> {judge egress | report egress};
> redaction happens once, before any egress; no raw target response or secret reaches an
> external API; the judge never sees more than the report. SARIF (the GitHub Code Scanning
> egress) carries the finding, not the target's output: no probe input, no response excerpt,
> even the redacted one; evidence stays in the three local formats.

## TLDR
- Current behavior: `redact_excerpt` turns a raw target response into a placeholder-only
  excerpt, and `build_evidence` is the single chokepoint that runs the detectors, redacts,
  caps the excerpt, and returns a frozen `Evidence`.
- Core invariants: redaction is local, key-free, and happens once before any egress; the
  placeholder, never the value, survives; `Evidence.redacted` is True iff a span fired.
- Verification: `tests/test_redact.py`; `uv run pyright`.
- Known gaps: a structured `Redaction` model and a configurable redaction policy are
  deferred (spec 5.9); v1 carries the type and hint inline in the placeholder.

## Data Model

This feature owns no new Pydantic model. It consumes two existing ones:
- `DetectorSpan` (doc 05) - the half-open `[start, end)` hit each detector emits, with the
  `detector` tag and a PII `hint`. Redaction reads these; it never constructs them.
- `Evidence` (doc 01, frozen, spec 5.5) - `build_evidence` is the only place that builds
  one from a raw response. Its `response_excerpt` is already redacted at construction time
  and its `redacted` bool flags that a span fired.

A structured `redactions: list[Redaction]` model is deferred (spec 5.9); v1 carries the
span type and hint inline in the placeholder string.

## Public Interface

- `redact_excerpt(text: str, *, canaries: list[str]) -> tuple[str, list[DetectorName]]` -
  returns the redacted text and the deduplicated list of detectors that fired (empty when
  none did).
- `build_evidence(*, probe_input: str, raw_response: str, adapter_mode: AdapterMode,
  canaries: list[str]) -> tuple[Evidence, list[DetectorName]]` - the one chokepoint that
  turns a raw target response into a redacted, frozen `Evidence`, returned with the fired
  detectors so the scan can record detector identity on the `ProbeResult` (doc 05).

Both are pure: no I/O, no key, no global state.

## Output surface

None directly; this is an internal boundary. The redacted excerpt feeds the judge user
turn (M5, doc 07) and the report evidence block (M2, doc 02). The user only ever sees the
placeholder, never the raw value.

## Business Rules

- Placeholder shapes, deterministic per span:
  - secret -> `[REDACTED:secret(N)]` where `N = end - start` (the length hint).
  - pii -> `[REDACTED:pii:<hint>]` where `<hint>` is the `DetectorSpan.hint`
    (`email` | `ssn` | `phone`).
  - canary -> `[REDACTED:canary]`.
- The placeholder, not the value, feeds the fingerprint, so redaction cannot make
  `partialFingerprints` flap (spec 5.9). The type and a length or subtype hint survive so
  the finding stays actionable; the value never does.
- `Evidence.redacted` is True iff at least one span fired across the three detectors.
- The excerpt is capped at 2048 characters (spec 5.1.1, abuse case 8) before it is stored
  in `Evidence`. The cap is applied after redaction so a placeholder is never split
  mid-token.
- Overlapping spans (for example a phone-shaped email local part where `pii_echo` email and
  phone both fire on overlapping ranges) are merged by covering range; the widest covering
  placeholder wins and no raw value survives.
- This is the one redaction function (threat model abuse case 3). No other module redacts;
  detected secret/PII spans in target responses become placeholders before the excerpt
  reaches the judge or any renderer. Raw responses stay transient in memory and never
  persist. Canary detection fires only when the caller supplies canaries; the v1 live path
  supplies none (canary injection is roadmap).
- **Error-string sanitization:** `scan._run_probe` sanitizes exception text before storing
  it in `ProbeResult.error`. The sanitizer replaces the raw target ref (which may contain
  URL credentials, query-string tokens, or absolute paths) with the sanitized identity,
  runs the result through `redact_excerpt(text, canaries=[])`, strips CR/LF, and caps to
  512 characters. The same `redact_excerpt` chokepoint covers PII/secret patterns that may
  appear in error text independently of the target ref (for example, a transport error that
  echoes a response body containing a secret). The ref replacement is exact-string: a
  credential fragment echoed without the full ref does not match and is not replaced, so the
  secret/PII detectors in `redact_excerpt` are the backstop for that case. This boundary is
  deliberate; v1 does not parse error text for partial-ref fragments.
- **Where error text surfaces:** `ProbeResult.error` (after sanitization) reaches the JSON
  report in full (the JSON renderer serializes the whole `Report`, including
  `errored_probes`). The CLI and HTML reports show only the count of errored probes, never
  the error text. SARIF never carries it at all: `sarif_json` renders findings only, never
  errored probes. So the sanitization matters most for the JSON surface.

- **Prompt-file system prompt egress (the audited text):** a prompt-file scan sends the full
  system prompt under test, secrets included, UNREDACTED to the TARGET provider, because the
  system prompt is the artifact being audited (redacting it would defeat the audit). This is
  the one deliberate exception to "no raw value egresses", and it is gated twice: a provider
  key must be present (`select_model_caller`, doc 03), and without `--yes` the CLI prints a
  second consent line, separate from the judge consent line, naming the resolved provider and
  stating the prompt goes unredacted. `--offline` sends nothing, so `--offline` + prompt-file
  is a usage error. This egress is the system prompt only; the redaction chokepoint still
  governs the target's RESPONSE (and the response feeds the judge as a redacted excerpt).

### §5.9 egress table

"To report" is the three local formats (CLI, JSON, HTML), which the user views on their own
machine. "To SARIF" is the GitHub Code Scanning egress: SARIF is the one format uploaded to a
third-party retention system, so it carries the finding (title, severity band, description,
fix), not the target's output (spec 5.9, doc 02 SARIF egress contract). The redacted excerpt
and the probe input both stay out of SARIF; a SARIF result points the reader back to the local
formats for evidence.

| Class | Local-only | To judge | To target provider (prompt-file) | To report (CLI/JSON/HTML) | To SARIF (GitHub Code Scanning) |
| --- | --- | --- | --- | --- | --- |
| target raw response | yes (transient, in memory) | no | n/a | no | never |
| detected secret/PII span | yes | no, placeholder only | n/a | no, placeholder only | no |
| redacted excerpt | n/a | yes | n/a | yes | no, local-evidence pointer only |
| probe input (our prompt) | n/a | yes | yes (the user message) | yes | no |
| finding (title, band, description, fix) | n/a | n/a | n/a | yes | yes |
| prompt-file system prompt under test | n/a | no | yes, UNREDACTED, gated by key + consent | identity only (basename) | identity only (basename) |
| API keys (ANTHROPIC/OPENAI) | yes, never logged, never in evidence | no | no | no | no |
| canary tokens | local match only | placeholder if echoed | n/a | placeholder if echoed | no |
| target identity | sanitized from `target.ref` once | n/a | n/a | sanitized only, in all four formats | sanitized hostname (artifactLocation.uri) |
| ProbeResult.error text | sanitized before it is stored | no | n/a | JSON only (full text); CLI/HTML show counts | never SARIF |

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| Clean text, no span fires | Text returned unchanged, `redacted=False` | Caller treats as no sensitive content |
| Overlapping spans | Widest covering placeholder, no raw value survives | n/a |
| Oversized response | Excerpt capped at 2048 chars after redaction | Caller stores the capped excerpt |

## Edge Cases

- Empty text -> `("", False)`.
- No canaries (`canaries=[]`) -> secret and PII spans still redact; only canary matching is
  skipped.
- A placeholder is never split mid-token by the cap, because the cap is applied after
  redaction has already replaced each span with its complete placeholder.
