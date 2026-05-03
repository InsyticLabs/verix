from __future__ import annotations

import hashlib


def generate_fingerprint(tool: str, rule_id: str, file_path: str, start_line: int | None) -> str:
    """Generate a stable fingerprint for a finding."""
    payload = f"{tool}:{rule_id}:{file_path}:{start_line or 0}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
