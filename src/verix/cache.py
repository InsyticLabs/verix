from __future__ import annotations

import json
from pathlib import Path

from verix.findings.models import Finding


def save_scan_cache(findings: list[Finding], cache_dir: str = ".verix") -> str:
    """Save scan findings to the local cache and return the file path."""
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)

    data = {
        "findings": [f.model_dump(mode="json") for f in findings],
    }

    file_path = cache_path / "last_scan.json"
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return str(file_path)


def load_scan_cache(cache_dir: str = ".verix") -> list[Finding]:
    """Load scan findings from the local cache."""
    file_path = Path(cache_dir) / "last_scan.json"

    if not file_path.exists():
        raise FileNotFoundError("No scan cache found. Run `verix scan` first.")

    data = json.loads(file_path.read_text(encoding="utf-8"))
    return [Finding.model_validate(f) for f in data.get("findings", [])]
