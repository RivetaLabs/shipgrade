from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FEATURE_DOCS = REPO_ROOT / "docs" / "features"
# The root-level public markdown files carry the same no-em-dash house style; the
# feature-doc glob above does not reach them.
ROOT_PUBLIC_DOCS = ("README.md", "CONTRIBUTING.md", "SECURITY.md")


def test_feature_docs_do_not_use_em_dash() -> None:
    offenders: list[str] = []

    for path in sorted(FEATURE_DOCS.rglob("*.md")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "\u2014" in line:
                offenders.append(f"{path.relative_to(FEATURE_DOCS.parent)}:{lineno}")

    assert offenders == [], "U+2014 em dash is not allowed in docs/features/:\n" + "\n".join(
        offenders
    )


def test_root_public_docs_do_not_use_em_dash() -> None:
    offenders: list[str] = []

    for name in ROOT_PUBLIC_DOCS:
        path = REPO_ROOT / name
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "\u2014" in line:
                offenders.append(f"{name}:{lineno}")

    assert offenders == [], "U+2014 em dash is not allowed in root public docs:\n" + "\n".join(
        offenders
    )
