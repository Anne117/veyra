"""Concrete benchmark adapters.

Each adapter converts an already-supplied external benchmark-style case into a
:class:`veyra.threats.benchmarks.BenchmarkCase`. Adapters are pure data
transformations: no network access, no dataset downloads, no benchmark or
scanner execution, no LLM calls.
"""

from veyra.threats.adapters.agentdojo import AgentDojoAdapter
from veyra.threats.adapters.agentthreatbench import AgentThreatBenchAdapter

__all__ = ["AgentDojoAdapter", "AgentThreatBenchAdapter"]
