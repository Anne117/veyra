"""Concrete threat-taxonomy catalogs.

Each catalog is a static, deterministic, immutable :class:`ThreatTaxonomy`.
Catalogs perform no network access at runtime.
"""

from veyra.threats.catalogs.owasp_agentic_2026 import (
    OWASP_AGENTIC_2026,
    get_owasp_agentic_2026,
)

__all__ = [
    "OWASP_AGENTIC_2026",
    "get_owasp_agentic_2026",
]
