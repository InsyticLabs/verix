from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field

from verix.findings.models import Severity


class SeverityOverride(BaseModel):
    """Override the severity of a specific rule."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    reason: str


class PathExclusion(BaseModel):
    """Exclude a rule from matching specific paths."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    paths: list[str]
    reason: str


class Rules(BaseModel):
    """Custom rule configuration for Verix."""

    model_config = ConfigDict(frozen=True)

    severity_overrides: list[SeverityOverride] = Field(default_factory=list)
    path_exclusions: list[PathExclusion] = Field(default_factory=list)


class Suppression(BaseModel):
    """A suppressed finding that should be ignored in future scans."""

    model_config = ConfigDict(frozen=True)

    id: str
    fingerprint: str
    rule_id: str
    file: str
    reason: str
    added_by: str = "unknown"
    expires: date | None = None
    active: bool = True


class ScanConfig(BaseModel):
    """Scan behavior configuration."""

    model_config = ConfigDict(frozen=True)

    severity_threshold: str = "medium"
    include: list[str] = Field(default_factory=lambda: ["**"])
    exclude: list[str] = Field(default_factory=list)


class ToolConfig(BaseModel):
    """Configuration for an individual scanner tool."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    config: str = "auto"
    ignore_file: str | None = None


class ToolsConfig(BaseModel):
    """Configuration for all scanner tools."""

    model_config = ConfigDict(frozen=True)

    semgrep: ToolConfig = Field(default_factory=ToolConfig)
    gitleaks: ToolConfig = Field(default_factory=ToolConfig)


class ProjectConfig(BaseModel):
    """Project metadata for Verix."""

    model_config = ConfigDict(frozen=True)

    name: str = "unknown"
    language: str = "unknown"
    framework: str | None = None
    min_python: str | None = None


class VerixConfig(BaseModel):
    """Top-level Verix policy configuration."""

    model_config = ConfigDict(frozen=True)

    version: int = 1
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    rules: Rules = Field(default_factory=Rules)
    suppressions: list[Suppression] = Field(default_factory=list)
