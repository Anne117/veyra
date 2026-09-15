"""Veyra - security scanner for AI agent skills and MCP-related resources."""

from veyra.policy import (
    CORRELATED_SECRET_EXECUTION_POLICY,
    DATA_EXFILTRATION_POLICY,
    SECRET_EXFILTRATION_POLICY,
    Policy,
    PolicyEngine,
    PolicyResult,
)

__all__ = [
    "Policy",
    "PolicyResult",
    "PolicyEngine",
    "SECRET_EXFILTRATION_POLICY",
    "DATA_EXFILTRATION_POLICY",
    "CORRELATED_SECRET_EXECUTION_POLICY",
]

__version__ = "0.1.0"
