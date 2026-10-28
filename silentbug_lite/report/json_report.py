"""JSON report. `schema_version` changes only when a field is removed or changes meaning."""

from __future__ import annotations

import json
from typing import Any

from silentbug_lite import TOOL_NAME, __version__
from silentbug_lite.models import Finding, ScanResult
from silentbug_lite.report import failing, severity_counts
from silentbug_lite.rules import CHECKS, RULES, check_for
from silentbug_lite.secrets import redact

SCHEMA_VERSION = 1


def _finding(finding: Finding) -> dict[str, Any]:
    check = check_for(finding.rule_id)
    return {
        "rule_id": finding.rule_id,
        "check": check.key,
        "title": check.title,
        "severity": finding.severity.value,
        "file": finding.file,
        "line": finding.line,
        "message": finding.message,
        "fix": check.fix,
        "snippet": redact(finding.snippet),
        "snippet_start": finding.snippet_start,
        "symbol": finding.symbol,
        "language": finding.language,
        "fingerprint": finding.fingerprint,
    }


def to_payload(result: ScanResult, target: str, fail_on: str) -> dict[str, Any]:
    by_check = {check.key: 0 for check in CHECKS}
    for finding in result.findings:
        by_check[RULES[finding.rule_id].check] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "target": target,
        "summary": {
            "files_scanned": result.files_scanned,
            "findings": len(result.findings),
            "by_severity": severity_counts(result.findings),
            "by_check": by_check,
            "ignored": len(result.ignored),
            "skipped": len(result.skipped),
            "fail_on": fail_on,
            "failing": len(failing(result, fail_on)),
            "languages": sorted(result.languages),
            "frameworks": sorted(result.frameworks),
        },
        "findings": [_finding(f) for f in result.findings],
        "ignored": [
            {
                "rule_id": f.rule_id,
                "file": f.file,
                "line": f.line,
                "reason": f.ignore_reason or "",
                "fingerprint": f.fingerprint,
            }
            for f in result.ignored
        ],
        "skipped": [{"file": s.file, "reason": s.reason} for s in result.skipped],
    }


def to_json(result: ScanResult, target: str, fail_on: str) -> str:
    return json.dumps(to_payload(result, target, fail_on), indent=2) + "\n"
