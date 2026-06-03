#!/usr/bin/env bash
# The single confirm-green check. Run at start of session and before any "done" claim.
set -euo pipefail

uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -q
uv run shipgrade demo
