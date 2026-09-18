"""OWASP Agentic AI 2026 taxonomy catalog."""

from veyra.threats.models import ThreatSource
from veyra.threats.taxonomy import ThreatTaxonomy, ThreatTaxonomyEntry

# Official source: OWASP Top 10 for Agentic Applications 2026 (Version 2026,
# December 2025). This catalog is static and deterministic; it performs no
# network access at runtime.
_SOURCE = ThreatSource(
    name="OWASP Top 10 for Agentic Applications",
    version="2026",
    reference=(
        "https://genai.owasp.org/resource/"
        "owasp-top-10-for-agentic-applications-for-2026/"
    ),
)

_OWASP_AGENTIC_2026_ENTRIES = (
    ThreatTaxonomyEntry(
        entry_id="ASI01",
        name="Agent Goal Hijack",
        description="An attacker manipulates an agent's stated task or objective so the "
        "agent pursues the attacker's goal instead of the user's intent.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI02",
        name="Tool Misuse and Exploitation",
        description="An attacker induces an agent to invoke a tool in an unintended, "
        "unsafe, or abusive way, exploiting the capabilities exposed to the agent.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI03",
        name="Identity and Privilege Abuse",
        description="An attacker abuses an agent's identity, roles, or the privileges it "
        "holds to perform actions the user did not authorize.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI04",
        name="Agentic Supply Chain Vulnerabilities",
        description="A vulnerability originating from a compromised or untrusted component "
        "in the agent's supply chain, such as skills, models, data, or plugins.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI05",
        name="Unexpected Code Execution (RCE)",
        description="An attacker causes an agent to execute code or shell commands the "
        "user did not intend, resulting in unintended remote code execution.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI06",
        name="Memory & Context Poisoning",
        description="An attacker injects malicious content into an agent's memory or "
        "context so that later inference and actions are poisoned.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI07",
        name="Insecure Inter-Agent Communication",
        description="An attacker intercepts, forges, or manipulates the messages exchanged "
        "between two agents because the communication channel is not protected.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI08",
        name="Cascading Failures",
        description="A failure or compromise of one agent propagates to other connected "
        "agents, causing widespread, connected-system failure.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI09",
        name="Human-Agent Trust Exploitation",
        description="An attacker exploits a human's trust in or oversight of an agent to "
        "manipulate decisions or conceal malicious behavior.",
        source=_SOURCE,
    ),
    ThreatTaxonomyEntry(
        entry_id="ASI10",
        name="Rogue Agents",
        description="A rogue or compromised agent acts independently and against the "
        "intent of its owner or the wider system.",
        source=_SOURCE,
    ),
)

OWASP_AGENTIC_2026 = ThreatTaxonomy(
    taxonomy_id="owasp-agentic-2026",
    name="OWASP Top 10 for Agentic Applications",
    version="2026",
    reference=_SOURCE.reference,
    entries=_OWASP_AGENTIC_2026_ENTRIES,
)


def get_owasp_agentic_2026() -> ThreatTaxonomy:
    """Return the immutable OWASP Agentic AI 2026 catalog."""
    return OWASP_AGENTIC_2026
