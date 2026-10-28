"""Report formats: terminal text, JSON and SARIF 2.1.0. Every format masks secrets in the
code it shows, and none of them adds anything the scan didn't find."""

from __future__ import annotations

from silentbug_lite.models import Finding, ScanResult, Severity

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")


def failing(result: ScanResult, fail_on: str) -> list[Finding]:
    """Findings at or above the `--fail-on` level (none for 'none')."""
    if fail_on == "none":
        return []
    limit = Severity(fail_on).rank
    return [f for f in result.findings if f.severity.rank <= limit]


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
