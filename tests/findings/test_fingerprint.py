from __future__ import annotations

from verix.findings.fingerprint import generate_fingerprint


def test_fingerprint_is_stable():
    """generate_fingerprint returns the same value for identical inputs."""
    first = generate_fingerprint("semgrep", "rule-1", "src/app.py", 10)
    second = generate_fingerprint("semgrep", "rule-1", "src/app.py", 10)
    assert first == second


def test_fingerprint_differs_on_different_input():
    """generate_fingerprint returns different values for different inputs."""
    a = generate_fingerprint("semgrep", "rule-a", "src/app.py", 10)
    b = generate_fingerprint("semgrep", "rule-b", "src/app.py", 10)
    assert a != b


def test_fingerprint_handles_none_start_line():
    """generate_fingerprint handles None start_line without raising."""
    result = generate_fingerprint("gitleaks", "secret-1", "config.env", None)
    assert isinstance(result, str)


def test_fingerprint_is_16_chars():
    """generate_fingerprint returns exactly 16 hex characters."""
    result = generate_fingerprint("semgrep", "rule-1", "src/app.py", 10)
    assert len(result) == 16
