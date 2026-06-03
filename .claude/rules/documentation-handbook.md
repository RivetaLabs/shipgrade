---
description: Doc-first rule for shipgrade features. Read the feature doc before writing, modifying, or debugging its code.
paths:
  - "docs/**"
  - "src/shipgrade/**"
---

# Documentation Handbook (doc-first)

Rules make an agent disciplined; feature docs make it informed. Before writing,
modifying, or debugging code for a feature, read its doc in `docs/features/` first.
Do not start by grepping source.

- If no doc exists for the feature, create it first with `status: gap`, or stop and ask.
- Business rules (severity thresholds, fail-closed behavior, provider selection,
  determinism guarantees) cannot be reliably inferred from source. That is what makes
  code behaviorally wrong while structurally correct.
- Quality bar: a fresh agent reads only the doc and implements the feature correctly
  without opening source.

## Layout

- `docs/features/NN-name.md`: one doc per feature, numbered in sequence. A new feature
  takes the next free number.
- `docs/features/CLAUDE.md` plus a byte-identical `AGENTS.md` (a symlink): the index.
- `docs/features/archived/`: docs for removed or replaced features (`status: archived`).

## Frontmatter (every doc)

```yaml
title: Feature Name
version: 1.0.0          # semver, bump on doc change
last_updated: YYYY-MM-DD
depends_on: []          # docs to read first
related: []             # docs that may break if this feature changes
status: current | stub | gap | draft | archived
toc: [ ... ]
```

Open the body with a TLDR block: Current behavior, Core invariants, Verification, Known gaps.

## Section order

- **Data Model** - the Pydantic models the feature owns or touches: fields, types,
  validation, invariants.
- **Public Interface** - the CLI commands and flags it powers, and the functions or
  classes other modules call, with signatures.
- **Output surface** - what the user sees: rich tables, HTML sections, JSON/SARIF fields,
  exit codes. "None" for internal-only modules.
- **Business Rules** - severity bands and thresholds, OWASP/ATLAS mapping, adapter
  fail-closed behavior, provider selection, evidence redaction, determinism guarantees,
  CI gate logic. This section carries the weight.
- **Failure Modes** - a `Scenario | Behavior | Recovery` table of actual current behavior.
- **Edge Cases** - empty inputs, missing API key, malformed YAML, schema-failing judge
  output, transport errors.

## Lifecycle (folds into the TDD loop)

DOCUMENT the feature or update its doc, then write the failing test, then the code that
matches the doc, then check the code against the doc's Business Rules, then update the doc
if implementation forced a change, then ship doc, code, and tests in the same commit.
Code and docs drift the moment they ship apart.
