from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from verix.findings.models import Finding


class ScanRequest(BaseModel):
    """Parameters for a single scan invocation."""

    model_config = ConfigDict(frozen=True)

    root_dir: Path
    severity: str | None = None
    scanners: list[str] | None = None
    files: list[str] = Field(default_factory=list)
    diff_only: bool = False


class ScannerAdapter(ABC):
    """Base class for all Verix scanner adapters."""

    name: ClassVar[str] = ""

    registry: ClassVar[dict[str, type[ScannerAdapter]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Auto-register concrete scanner adapters by name."""
        super().__init_subclass__(**kwargs)
        if cls.name:
            ScannerAdapter.registry[cls.name] = cls

    @abstractmethod
    def scan(self, request: ScanRequest) -> list[Finding]:
        """Run the scanner against the request and return normalized findings."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the scanner binary/tool is installed and callable."""

    @classmethod
    def get_adapter(cls, name: str) -> type[ScannerAdapter]:
        """Return a registered scanner adapter class by its name."""
        try:
            return cls.registry[name]
        except KeyError as exc:
            raise ValueError(f"Unknown scanner adapter: {name}") from exc

    def run_subprocess(
        self,
        command: list[str],
        *,
        timeout: int = 120,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command with captured stdout/stderr and a strict timeout."""
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
