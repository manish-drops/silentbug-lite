"""SARIF 2.1.0, in the shape GitHub code scanning accepts.

File URIs are relative paths, which GitHub resolves against the repository root, so run
the scan from the root of the checkout. Security rules carry a `security-severity` score,
which is how GitHub ranks security alerts.
"""

from __future__ import annotations

import json
from typing import Any

from silentbug_lite import FULL_VERSION_URL, TOOL_NAME, __version__
from silentbug_lite.models import Finding, ScanResult, Severity
from silentbug_lite.rules import RULES, Rule, check_for

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
FINGERPRINT_KEY = "silentbugLite/v1"


def _rule(rule: Rule) -> dict[str, Any]:
    check = check_for(rule.id)
    properties: dict[str, Any] = {
        "tags": list(rule.tags),
        "precision": "medium",
        "problem.severity": "warning" if rule.severity is Severity.MEDIUM else "error",
    }
    if rule.security_severity:
        properties["security-severity"] = rule.security_severity
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": check.title},
        "fullDescription": {"text": rule.summary},
        "help": {
            "text": f"{rule.summary}\n\nFix: {check.fix}",
            "markdown": f"{rule.summary}\n\n**Fix:** {check.fix}",
        },
        "helpUri": FULL_VERSION_URL,
        "defaultConfiguration": {"level": LEVEL[rule.severity.value]},
        "properties": properties,
    }


def _result(finding: Finding, index: dict[str, int]) -> dict[str, Any]:
    check = check_for(finding.rule_id)
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": index[finding.rule_id],
        "level": LEVEL[finding.severity.value],
        "message": {"text": f"{finding.message} Fix: {check.fix}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {"startLine": max(1, finding.line)},
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": {"severity": finding.severity.value, "check": check.key},
    }


def to_payload(result: ScanResult) -> dict[str, Any]:
    rules = list(RULES.values())
    index = {rule.id: position for position, rule in enumerate(rules)}
    notes = [
        {"level": "note", "message": {"text": f"Skipped {s.file}: {s.reason}"}}
        for s in result.skipped
    ]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": FULL_VERSION_URL,
                        "rules": [_rule(rule) for rule in rules],
                    }
                },
                "invocations": [
                    {"executionSuccessful": True, "toolExecutionNotifications": notes}
                ],
                "results": [_result(f, index) for f in result.findings],
            }
        ],
    }


def to_sarif(result: ScanResult) -> str:
    return json.dumps(to_payload(result), indent=2) + "\n"
