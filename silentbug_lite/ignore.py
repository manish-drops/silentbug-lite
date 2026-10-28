"""Inline ignores: `# silentbug: ignore[<rule>] reason: ...` (or `// ...` in JS/TS), on the
flagged line or the line above it.

`<rule>` can be a rule ID (`db.sql-injection`), its category (`db`) or a check name
(`no-login-check`); separate several with commas. The same comment works in the full
silentbug, and `silentbug-lite: ignore[...]` is accepted too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from silentbug_lite.models import Finding
from silentbug_lite.rules import RULES

_IGNORE = re.compile(
    r"silentbug(?:-lite)?:\s*ignore\[([^\]]*)\](?:\s*reason:\s*(.*))?", re.IGNORECASE
)


@dataclass(frozen=True)
class Ignore:
    line: int
    names: frozenset[str]
    reason: str


def parse_ignores(comments: list[tuple[int, str]]) -> list[Ignore]:
    found = []
    for line, text in comments:
        match = _IGNORE.search(text)
        if match:
            names = frozenset(p.strip().lower() for p in match.group(1).split(",") if p.strip())
            found.append(Ignore(line, names, (match.group(2) or "").strip()))
    return found


def _names_for(rule_id: str) -> set[str]:
    return {rule_id, rule_id.split(".")[0], RULES[rule_id].check}


def matching_ignore(finding: Finding, ignores: list[Ignore]) -> Ignore | None:
    names = _names_for(finding.rule_id)
    return next(
        (
            ignore
            for ignore in ignores
            if ignore.line in (finding.line, finding.line - 1) and ignore.names & names
        ),
        None,
    )
