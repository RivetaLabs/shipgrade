---
title: Target Adapters and the Scan Pipeline
version: 1.2.1
last_updated: 2026-06-02
depends_on: [01-finding-contract.md]
related: [04-probes.md, 02-report-core.md]
status: current
toc: [data-model, public-interface, output-surface, business-rules, failure-modes, edge-cases]
---

## TLDR

- **Current behavior:** Three adapters send a probe to a target and return its text:
  prompt-file (via an injected model caller), HTTP (a user URL), and callable (a user
  Python module). `scan` loads probe packs, builds the adapter from config, runs every
  probe input through it with per-probe fail-closed isolation, and prints a run summary.
- **Core invariants:** Adapters fail closed (one probe's error never aborts the scan).
  The HTTP adapter blocks non-public resolved IPs (SSRF) unless `--allow-private-targets`.
  No raw target response is persisted or printed (redaction pipeline, doc 13). The
  prompt-file adapter calls a provider model via `select_model_caller`; tests inject a fake
  caller. A prompt-file scan fails closed at the CLI: no provider key, or `--offline`, is a
  usage error (exit 2), never a per-probe error on every probe.
- **Verification:** `tests/test_adapter_*.py`, `tests/test_ssrf.py`, `tests/test_scan.py`,
  `tests/test_judge_providers.py`, `tests/test_cli.py`.
- **Known gaps:** The SSRF guard is resolve-and-validate; the residual DNS-rebinding window
  is documented below and full connection-level IP pinning is roadmap.

## Data Model

The adapter layer owns no Pydantic model. It consumes `Target` and `Config` and projects
`Target -> TargetSummary` (the secret-free view used in `RunMetadata`). It produces
`list[ProbeResult]`. All three are defined in `models.py` (spec 5.7); M3 adds none.

- `summarize_target(target) -> TargetSummary`: `identity` is the host for HTTP (never the
  full URL, query, or auth), the filename for prompt-file, and `module:func` for callable.
  This `identity` is the `adapter_target_identity` hashed into `Finding.fingerprint` (5.5.1).
  **Redact-the-identity rule:** `cli.py` must call `summarize_target` once and pass
  `target_summary.identity` to `findings_from_results` and `RunMetadata`. It must never
  pass `cfg.target.ref` (the raw value) to either; the raw ref may contain URL credentials,
  query-string tokens, or absolute paths that would flow into all four report formats and
  into finding fingerprints. `run_scan` applies the same rule when building error strings:
  any error text that embeds the raw ref has the raw ref replaced with `sanitized_identity`
  before the string is stored in `ProbeResult.error`.

## Public Interface

- `build_adapter(target: Target, *, model_caller: ModelCaller | None = None) -> TargetAdapter`:
  dispatches on `target.mode`.
- `TargetAdapter` (Protocol): `async def respond(self, prompt: str) -> str`.
- `ModelCaller` (Protocol): `async def complete(self, *, system: str, prompt: str) -> str`.
  The provider-backed implementations are the judge clients (doc 07); tests inject a fake.
- `select_model_caller(config) -> tuple[ModelCaller, Provider, str] | MissingProviderKey | None`
  (in `judge/providers.py`, doc 07) resolves the caller for a prompt-file scan and returns the
  RESOLVED `(caller, provider, model)`, a `MissingProviderKey(provider)` signal, or `None`.
- `run_scan(config, *, model_caller=None, judge=None, offline=False) -> list[ProbeResult]`.
- `load_config(path: Path) -> Config`.
- CLI: `shipgrade scan --config PATH [--allow-private-targets] [--offline] [--yes]`.

## Output surface

- `scan` prints to stdout: `ran N probes`, `M reached the target (unjudged)`, `K errored`,
  one line per errored probe with its actionable message, and a note that judging and
  scoring arrive in M5/M7. Exit codes: `0` success, `2` config/usage error, `3` the run
  could not start (e.g., a probe pack failed to load). The full gate contract is M8.
- The HTTP adapter prints one stderr notice on a live scan ("only scan targets you own or
  are authorized to test") unless `authorized_target: true`.

## Business Rules

- **Per-probe fail-closed isolation (spec 8):** any single probe raising `AdapterError`
  (transport error, SSRF block, size cap, timeout, missing file) marks that probe
  `errored` and the loop continues. One failure never aborts the scan.
- **Status mapping in M3:** `AdapterError -> errored`; adapter returned but no judge yet
  -> `skipped`; `ok` (meaning "scored") is never produced before M7.
- **SSRF block (spec 5.1.1, abuse case 4):** resolve the target host and refuse to connect
  when the resolved IP is non-public (loopback, link-local incl. 169.254.169.254 metadata,
  RFC1918, IPv6 ULA, 0.0.0.0). `--allow-private-targets` (config `allow_private_targets`)
  opts in for internal scans. **Limitation:** this is resolve-and-validate; a hostname can
  re-resolve to a private address between the check and httpx's own connect (DNS rebinding
  TOCTOU). Connection-level IP pinning is deferred to the roadmap (spec 5.1.1).
- **No redirects (spec 5.1.1):** httpx `follow_redirects=False`; a 3xx is recorded as the
  response, never chased, because a redirect can re-target an internal host.
- **Response-size cap (abuse case 8):** stream the body; abort past `max_response_bytes`
  (default 5 MB) with an `AdapterError`, never an OOM.
- **Timeouts:** separate `connect_timeout_s` (5) and `read_timeout_s` (30); httpx raising
  on timeout routes into per-probe fail-closed.
- **Callable trust boundary (spec 5.1.1, abuse case 7):** this adapter imports and runs
  user Python in-process with no sandbox, by design (same trust as running their own
  pytest). A callable ref must never come from an untrusted or remote source.
- **Prompt-file provider call (spec 5.1, 5.9):** `select_model_caller(config)` resolves which
  provider client serves as the target. Provider precedence: `target.target_provider`, else
  `judge_provider`, else env-key precedence (`ANTHROPIC_API_KEY` before `OPENAI_API_KEY`).
  Model precedence: `target.target_model`, else `judge_model`, else the provider default. The
  key is checked BEFORE any SDK client is constructed: an explicitly configured provider whose
  key is absent returns `MissingProviderKey(provider)` so the CLI gives an actionable error,
  never an SDK constructor exception that could surface a key. The CLI records the resolved
  provider/model in the report's `TargetSummary`.
- **Prompt-file fail-closed at the CLI (the first-use guard):** a prompt-file scan that cannot
  call a provider is a usage error (exit 2) at the CLI, never a per-probe error on every probe.
  `--offline` + prompt-file is a usage error because `--offline` promises "send nothing" and
  prompt-file must call a provider; the two are incoherent. No resolvable key (`None` or
  `MissingProviderKey`) is a usage error naming `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and the
  config provider field. The system prompt is the text under test, so it is sent UNREDACTED to
  the target provider; without `--yes` the CLI prints a second consent line stating this,
  separate from the judge consent line (doc 13).
- **Prompt-file privacy (spec 5.1, 5.9):** this sends the system prompt under test to a
  third-party provider, so it needs a provider key and is skipped in the key-free demo path.
- **No raw-response egress (spec 5.9):** the raw response is transient; M3 persists and
  prints none of it. Redaction (M4) and judge egress (M5) come later.

## Failure Modes

| Scenario | Behavior | Recovery |
| --- | --- | --- |
| Prompt-file scan, no provider key | CLI usage error (exit 2) naming the two key env vars | Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` |
| Prompt-file scan + `--offline` | CLI usage error (exit 2) | Drop `--offline`, or use an http/callable target with `--offline` |
| Explicit provider configured, its key absent | CLI usage error (exit 2), never an SDK exception | Set that provider's key, or change the config provider |
| Prompt-file adapter built with no model caller | `AdapterError` naming the key env vars | The CLI resolves a caller first; this is the adapter backstop |
| HTTP host resolves to a private IP | `AdapterError` naming the IP | Pass `--allow-private-targets` if intentional |
| HTTP response exceeds `max_response_bytes` | `AdapterError`, probe errored | Lower the target's verbosity or raise the cap in config |
| HTTP connect/read timeout | `AdapterError`, probe errored | Raise `connect_timeout_s`/`read_timeout_s` |
| Callable ref not `module:func` or not importable | `AdapterError`, probe errored | Fix the ref; ensure the module is importable |
| Callable returns a non-str or is not `async` | `AdapterError`, probe errored | Make it `async def respond(prompt: str) -> str` |
| Config YAML missing/oversized/malformed/invalid | exit 2 with an actionable message | Fix the config; see doc 04 for the load chokepoint |
| A probe pack named in config fails to load | exit 3 (run could not start) | Fix the pack name or YAML |

## Edge Cases

- Empty `probe_packs` -> `run_scan` returns `[]`; the summary reports zero probes.
- A probe with multiple `inputs` -> each input is sent; any one input erroring marks the
  whole probe errored (fail-closed). Input-to-verdict aggregation is a judge concern (M5).
- `response_path` set but the body is not JSON, or the path does not resolve to a string
  -> `AdapterError`.
- `--offline`/`--no-judge` selects no judge (deterministic-only); with a prompt-file target
  it is a usage error (exit 2), since a prompt-file scan must call a provider.
