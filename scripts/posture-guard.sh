#!/usr/bin/env bash
# Release-posture linter (spec 11.3, abuse-case 9 in 8.5). Fails closed on drift:
#   - every `uses:` is pinned to a full 40-char commit SHA (no tags, no branches)
#   - no workflow declares a top-level `write` permission or `write-all`
#   - the publish job in release.yml carries only `id-token: write` plus the `pypi` environment
# Lints .github/workflows/*.yml and, when present, action.yml. Run in CI and locally.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() { echo "posture-guard: FAIL: $1" >&2; exit 1; }

FILES=()
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$f" ] && FILES+=("$f")
done
[ -f action.yml ] && FILES+=("action.yml")
[ -f action.yaml ] && FILES+=("action.yaml")
[ "${#FILES[@]}" -eq 0 ] && fail "no workflow or action files found"

# 1. Every `uses:` must be pinned to a 40-hex-char commit SHA.
for f in "${FILES[@]}"; do
  while IFS= read -r line; do
    ref="${line#*uses:}"
    ref="$(echo "$ref" | sed -e 's/#.*//' -e 's/[[:space:]]//g')"
    [ -z "$ref" ] && continue
    case "$ref" in
      ./*) continue ;;  # local composite action reference, not a remote pin
    esac
    sha="${ref##*@}"
    if ! echo "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
      fail "$f: unpinned action '$ref' (expected a 40-char commit SHA)"
    fi
  done < <(grep -nE '^[[:space:]]*-?[[:space:]]*uses:' "$f")
done

# 2. No top-level `write` permission or `write-all` in any workflow.
#    (action.yml has no top-level permissions block; it is consumer-scoped.)
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$f" ] || continue
  python3 - "$f" <<'PY' || exit 1
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
# Find a top-level (column 0) `permissions:` key and scan its block.
in_block = False
block = []
for ln in lines:
    if ln.startswith("permissions:"):
        in_block = True
        rest = ln.split("permissions:", 1)[1].strip()
        if rest:
            block.append(rest)  # inline form, e.g. permissions: write-all
        continue
    if in_block:
        if ln and not ln[0].isspace():
            break  # dedented back to column 0; block ended
        block.append(ln.strip())
text = " ".join(block).lower()
if "write-all" in text or ": write" in text:
    sys.stderr.write(f"posture-guard: FAIL: {path}: top-level permissions grant write ({text!r})\n")
    sys.exit(1)
sys.exit(0)
PY
done

# 3. release.yml publish job: only `id-token: write` and the `pypi` environment.
REL=".github/workflows/release.yml"
[ -f "$REL" ] || fail "missing $REL"
python3 - "$REL" <<'PY' || exit 1
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()

# Locate the `publish:` job (a key indented under jobs:, i.e. exactly two leading spaces).
job_indent = None
start = None
for i, ln in enumerate(lines):
    if ln.startswith("  publish:") and ln.strip() == "publish:":
        job_indent = len(ln) - len(ln.lstrip())
        start = i + 1
        break
if start is None:
    sys.stderr.write(f"posture-guard: FAIL: {path}: no 'publish:' job found\n")
    sys.exit(1)

# Collect the publish job's lines until the next job at the same indent.
job = []
for ln in lines[start:]:
    if ln.strip() == "":
        continue
    indent = len(ln) - len(ln.lstrip())
    if indent <= job_indent and ln.strip().endswith(":"):
        break
    job.append(ln)
joined = "\n".join(job)

if "environment: pypi" not in joined:
    sys.stderr.write(f"posture-guard: FAIL: {path}: publish job missing 'environment: pypi'\n")
    sys.exit(1)
if "id-token: write" not in joined:
    sys.stderr.write(f"posture-guard: FAIL: {path}: publish job missing 'id-token: write'\n")
    sys.exit(1)
# Any other `: write` in the publish job's permissions is over-privilege.
for ln in job:
    s = ln.strip()
    if s.endswith(": write") and s != "id-token: write":
        sys.stderr.write(f"posture-guard: FAIL: {path}: publish job over-privileged ('{s}')\n")
        sys.exit(1)
sys.exit(0)
PY

echo "posture-guard: PASS"
exit 0
