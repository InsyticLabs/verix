from __future__ import annotations

import json
from pathlib import Path

from verix.policy.loader import save_policy
from verix.policy.models import (
    ProjectConfig,
    Rules,
    ScanConfig,
    ToolConfig,
    ToolsConfig,
    VerixConfig,
)


def detect_project(root_dir: Path) -> tuple[str, str | None]:
    """Detect the project language and framework from root directory markers."""
    pyproject = root_dir / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8").lower()
        if "fastapi" in content:
            return ("python", "fastapi")
        elif "django" in content:
            return ("python", "django")
        elif "flask" in content:
            return ("python", "flask")
        elif "typer" in content:
            return ("python", "typer")
        return ("python", None)

    package_json = root_dir / "package.json"
    if package_json.exists():
        data = json.loads(package_json.read_text(encoding="utf-8"))
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        if "next" in all_deps:
            return ("nodejs", "nextjs")
        elif "express" in all_deps:
            return ("nodejs", "express")
        elif "fastify" in all_deps:
            return ("nodejs", "fastify")
        return ("nodejs", None)

    if (root_dir / "go.mod").exists():
        return ("go", None)

    if (root_dir / "pom.xml").exists():
        return ("java", None)

    if (root_dir / "build.sbt").exists():
        return ("scala", None)

    return ("unknown", None)


def generate_semgrepignore(language: str) -> str:
    """Return the content of a .semgrepignore file for the given language."""
    if language == "python":
        return (
            "# Python build artifacts\n"
            ".venv/\n"
            "__pycache__/\n"
            "dist/\n"
            "build/\n"
            "*.egg-info/\n"
            ".pytest_cache/\n"
            "# Test directories\n"
            "tests/\n"
            "test/\n"
            "# Examples\n"
            "examples/\n"
        )
    elif language == "nodejs":
        return (
            "# Node.js build artifacts\n"
            "node_modules/\n"
            "dist/\n"
            ".next/\n"
            "build/\n"
            "coverage/\n"
            "# Test files\n"
            "**/*.test.ts\n"
            "**/*.test.js\n"
            "**/*.spec.ts\n"
            "**/*.spec.js\n"
        )
    elif language == "go":
        return "# Go build artifacts\nvendor/\nbin/\n# Test files\n**/*_test.go\n"
    else:
        return "# Build artifacts\ndist/\nbuild/\nvendor/\nnode_modules/\n.venv/\n"


def generate_gitleaksignore(language: str) -> str:
    """Return the content of a .gitleaksignore file."""
    return (
        "# Test fixtures with intentional fake secrets\n"
        "tests/\n"
        "test/\n"
        "examples/\n"
        "**/*.test.*\n"
        "**/*.spec.*\n"
        "# Lock files\n"
        "*.lock\n"
        "package-lock.json\n"
    )


def generate_initial_policy(
    root_dir: Path,
    language: str,
    framework: str | None,
) -> VerixConfig:
    """Build an initial VerixConfig for the detected project."""
    if language == "nodejs":
        include = ["src/**", "app/**"]
        exclude = [
            "node_modules/**",
            "dist/**",
            ".next/**",
            "build/**",
            "coverage/**",
        ]
    elif language == "python":
        include = ["src/**"]
        exclude = [
            ".venv/**",
            "__pycache__/**",
            "dist/**",
            "build/**",
            "*.egg-info/**",
            ".pytest_cache/**",
            "tests/**",
            "test/**",
            "examples/**",
        ]
    elif language == "go":
        include = ["**/*.go"]
        exclude = [
            "vendor/**",
            "bin/**",
            "**/*_test.go",
        ]
    elif language in ("java", "scala"):
        include = ["src/**"]
        exclude = [
            "target/**",
            "build/**",
            "dist/**",
            "vendor/**",
            "node_modules/**",
            ".venv/**",
        ]
    else:
        include = ["**"]
        exclude = [
            "dist/**",
            "build/**",
            "vendor/**",
            "node_modules/**",
            ".venv/**",
        ]

    return VerixConfig(
        version=1,
        project=ProjectConfig(
            name=root_dir.name,
            language=language,
            framework=framework,
        ),
        scan=ScanConfig(
            severity_threshold="medium",
            include=include,
            exclude=exclude,
        ),
        tools=ToolsConfig(
            semgrep=ToolConfig(
                enabled=True,
                config="auto",
                ignore_file=".semgrepignore",
            ),
            gitleaks=ToolConfig(
                enabled=True,
                ignore_file=".gitleaksignore",
            ),
        ),
        rules=Rules(),
        suppressions=[],
    )


def run_policy_init(
    root_dir: Path,
    force: bool = False,
) -> tuple[VerixConfig, list[str]]:
    """Generate policy files in the project root, respecting force flag."""
    language, framework = detect_project(root_dir)
    config = generate_initial_policy(root_dir, language, framework)

    files_to_create = {
        "verix.yaml": root_dir / "verix.yaml",
        ".semgrepignore": root_dir / ".semgrepignore",
        ".gitleaksignore": root_dir / ".gitleaksignore",
    }

    created: list[str] = []

    for name, path in files_to_create.items():
        if path.exists() and not force:
            continue
        if name == "verix.yaml":
            save_policy(config, str(path))
        elif name == ".semgrepignore":
            path.write_text(generate_semgrepignore(language), encoding="utf-8")
        elif name == ".gitleaksignore":
            path.write_text(generate_gitleaksignore(language), encoding="utf-8")
        created.append(str(path))

    return config, created
