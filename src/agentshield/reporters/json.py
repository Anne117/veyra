"""JSON report renderer."""

from __future__ import annotations

import json

from agentshield.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
