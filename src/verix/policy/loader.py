from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml

from verix.findings.models import Finding

from .models import VerixConfig


def load_policy(config_path: str = "verix.yaml") -> VerixConfig:
    """Load Verix policy from a YAML file, returning defaults if missing."""
    path = Path(config_path)

    if not path.exists():
        return VerixConfig()

    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    if data is None:
        return VerixConfig()

    if not isinstance(data, dict):
        got = type(data).__name__
        raise ValueError(f"Invalid YAML in {config_path}: expected mapping, got {got}")

    return VerixConfig.model_validate(data)


def save_policy(config: VerixConfig, config_path: str = "verix.yaml") -> None:
    """Serialize a VerixConfig to a YAML file."""
    path = Path(config_path)
    data = config.model_dump(mode="json")

    yaml_text = yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    path.write_text(yaml_text, encoding="utf-8")


def is_suppressed(finding: Finding, config: VerixConfig) -> bool:
    """Check whether a finding matches an active, non-expired suppression."""
    today = date.today()

    for suppression in config.suppressions:
        if not suppression.active:
            continue

        if suppression.expires is not None and suppression.expires < today:
            continue

        if (
            suppression.fingerprint == finding.fingerprint
            and suppression.rule_id == finding.scanner.rule_id
            and suppression.file == finding.location.path
        ):
            return True

    return False
