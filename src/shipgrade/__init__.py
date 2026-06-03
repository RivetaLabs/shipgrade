"""shipgrade: grade your LLM feature before you ship.

A Python CLI that audits an LLM feature for product-safety and regulated-domain
compliance, then prints a severity-ranked A-to-F report card. See the design spec
under docs/superpowers/specs/.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("shipgrade")
except PackageNotFoundError:  # pragma: no cover - only before an editable install
    __version__ = "0.0.0"

__all__ = ["__version__"]
