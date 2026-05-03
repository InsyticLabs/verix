from __future__ import annotations

from pathlib import Path


def generate_github_workflow(
    block_on_severity: str = "high",
    sarif_upload: bool = True,
    python_version: str = "3.12",
) -> str:
    """Generate a GitHub Actions workflow YAML for Verix security scanning."""
    sarif_step = (
        """      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: verix.sarif
        if: always()
"""
        if sarif_upload
        else ""
    )

    return f"""name: Verix Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    name: Verix Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install uv
        uses: astral-sh/setup-uv@v4
        with:
          version: "latest"

      - name: Set up Python
        run: uv python install {python_version}

      - name: Install Verix
        run: uv tool install verix

      - name: Install Semgrep
        run: uv tool install semgrep

      - name: Run Verix scan
        run: verix scan --sarif --output verix.sarif --severity {block_on_severity}

{sarif_step}      - name: Check for findings
        run: |
          verix scan --json --severity {block_on_severity} | python3 -c "
          import json, sys
          data = json.load(sys.stdin)
          total = data.get('total', 0)
          if total > 0:
              print(f'Found {{total}} security findings at {block_on_severity} severity or above')
              sys.exit(1)
          print('No security findings found')
          "
"""


def write_github_workflow(
    output_dir: Path,
    block_on_severity: str = "high",
    sarif_upload: bool = True,
    python_version: str = "3.12",
) -> str:
    """Write the GitHub Actions workflow file to the output directory."""
    workflow_dir = output_dir / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)

    content = generate_github_workflow(
        block_on_severity=block_on_severity,
        sarif_upload=sarif_upload,
        python_version=python_version,
    )

    file_path = workflow_dir / "verix.yml"
    file_path.write_text(content)

    return str(file_path)
