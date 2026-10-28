"""The five checks, and the rule IDs each one reports under.

Rule IDs are the same as in the full silentbug, so an ignore comment written for one
(`# silentbug: ignore[db.sql-injection] reason: ...`) works in the other.
"""

from __future__ import annotations

from dataclasses import dataclass

from silentbug_lite.models import Severity


@dataclass(frozen=True)
class Check:
    key: str
    title: str
    fix: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class Rule:
    id: str
    check: str  # Check.key
    name: str  # PascalCase, for SARIF
    severity: Severity
    summary: str
    tags: tuple[str, ...]
    security_severity: str = ""  # GitHub code scanning's 0.0-10.0 score, security rules only


CHECKS: tuple[Check, ...] = (
    Check(
        "success-on-exception",
        "Error still returns success",
        "Re-raise the error or return a failure (an error status or flag), so whoever called "
        "this knows it failed.",
        ("errors.success-on-exception",),
    ),
    Check(
        "sql-injection",
        "SQL injection",
        "Use a parameterised query: pass the values separately instead of formatting them "
        "into the SQL text.",
        ("db.sql-injection",),
    ),
    Check(
        "hardcoded-secret",
        "Secret written in the code",
        "Move it to an environment variable or a secrets manager, and rotate the key, since "
        "it is already exposed.",
        ("config.hardcoded-secret",),
    ),
    Check(
        "llm-call-in-loop",
        "LLM call inside a loop",
        "Batch the items into one call where you can, or cap how many calls run; set a token "
        "limit and a timeout.",
        ("ai.llm-call-in-loop",),
    ),
    Check(
        "no-login-check",
        "Route with no login check",
        "Add an authentication and permission check (a dependency, middleware or guard) before "
        "the handler runs.",
        ("auth.unprotected-route", "auth.destructive-no-auth"),
    ),
)

RULES: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        Rule(
            "errors.success-on-exception",
            "success-on-exception",
            "SuccessOnException",
            Severity.CRITICAL,
            "An error handler reports success instead of failing, so the caller never "
            "learns the operation failed.",
            ("correctness", "reliability"),
        ),
        Rule(
            "db.sql-injection",
            "sql-injection",
            "SqlInjection",
            Severity.CRITICAL,
            "SQL text is built from values and handed to the database driver, so input can "
            "change the query.",
            ("security", "external/cwe/cwe-089"),
            "9.0",
        ),
        Rule(
            "config.hardcoded-secret",
            "hardcoded-secret",
            "HardcodedSecret",
            Severity.CRITICAL,
            "An API key, token or password is written into the source code.",
            ("security", "external/cwe/cwe-798"),
            "9.0",
        ),
        Rule(
            "ai.llm-call-in-loop",
            "llm-call-in-loop",
            "LlmCallInLoop",
            Severity.HIGH,
            "A paid LLM call runs once per item in a loop, so cost and latency grow with "
            "the data.",
            ("cost", "performance"),
        ),
        Rule(
            "auth.unprotected-route",
            "no-login-check",
            "UnprotectedRoute",
            Severity.HIGH,
            "A route has none of the auth checks the other routes in its file use.",
            ("security", "external/cwe/cwe-306"),
            "7.5",
        ),
        Rule(
            "auth.destructive-no-auth",
            "no-login-check",
            "DestructiveNoAuth",
            Severity.HIGH,
            "A route that changes or deletes data has no auth check at all.",
            ("security", "external/cwe/cwe-306"),
            "7.5",
        ),
    )
}

CHECKS_BY_KEY: dict[str, Check] = {check.key: check for check in CHECKS}


def check_for(rule_id: str) -> Check:
    return CHECKS_BY_KEY[RULES[rule_id].check]
