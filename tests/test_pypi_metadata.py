from __future__ import annotations

import tomllib
from pathlib import Path

# pyproject.toml lives at the repo root; this test file is at tests/, so the root is
# one directory up. Resolve it CWD-independently (same pattern as test_precommit_hook.py).
PYPROJECT_PATH = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _load_project() -> dict:
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    return data["project"]


def test_readme_points_at_the_committed_readme():
    # PyPI long_description mirrors the README (spec 11.5). hatchling renders README.md
    # as the long description at build time, so the file must exist (created by M9.T8).
    project = _load_project()
    assert project["readme"] == "README.md"
    assert (PYPROJECT_PATH.parent / "README.md").is_file()


def test_keywords_are_the_locked_discovery_set():
    # Locked keyword set (spec 11.5), order preserved so the list is reviewable.
    project = _load_project()
    assert project["keywords"] == [
        "llm-security",
        "ai-security",
        "prompt-injection",
        "system-prompt-leakage",
        "owasp",
        "owasp-llm",
        "compliance",
        "ai-compliance",
        "llm-evaluation",
        "sarif",
        "ai-safety",
        "regulated-ai",
    ]


def test_trove_classifiers_are_the_locked_set():
    # Trove classifiers (spec 11.5). PyPI validates these against its registered list;
    # an unknown string is rejected at upload, so the set is pinned here verbatim.
    project = _load_project()
    assert project["classifiers"] == [
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ]


def test_project_urls_cover_docs_source_issues_security_and_no_changelog():
    # Project URLs (spec 11.5). No Changelog URL until CHANGELOG.md is un-deferred, or the
    # link would 404. The repo slug is lowercase `shipgrade` (spec 11.1; the public repo was
    # renamed lowercase on 2026-06-03 to match the package, CLI, and PyPI name).
    project = _load_project()
    urls = project["urls"]
    assert urls == {
        "Documentation": "https://github.com/RivetaLabs/shipgrade#readme",
        "Source": "https://github.com/RivetaLabs/shipgrade",
        "Issues": "https://github.com/RivetaLabs/shipgrade/issues",
        "Security": "https://github.com/RivetaLabs/shipgrade/blob/main/SECURITY.md",
    }
    assert "Changelog" not in urls


def test_license_classifier_matches_the_declared_license():
    # The MIT license is declared once as `license = "MIT"` and once as the Trove
    # classifier; they must agree (LICENSE itself is M9.T2, copyright Jacob Dennis).
    project = _load_project()
    assert project["license"] == "MIT"
    assert "License :: OSI Approved :: MIT License" in project["classifiers"]
