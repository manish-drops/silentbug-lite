from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """0 is the most severe."""
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}[self.value]


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


@dataclass(frozen=True)
class ParsedModule:
    """One parsed source file. `tree` is an `ast.Module` for Python and a tree-sitter
    `Tree` for JavaScript/TypeScript; each check only looks at the language it handles."""

    file: str  # path relative to the scan root, with forward slashes
    source: str
    tree: Any
    lines: list[str] = field(default_factory=list)
    language: str = Language.PYTHON.value
    frameworks: frozenset[str] = frozenset()  # web frameworks this file uses

    def snippet(self, line: int, before: int = 0, after: int = 0) -> str:
        start = max(0, line - 1 - before)
        end = min(len(self.lines), line + after)
        return "\n".join(self.lines[start:end])


@dataclass(frozen=True)
class Finding:
    """A place in the code that matches one of the checks."""

    rule_id: str
    severity: Severity
    file: str
    line: int
    message: str
    snippet: str = ""
    snippet_start: int = 0  # line number of the snippet's first line
    symbol: str = "<module>"  # the function or class it sits in
    node_key: str = ""  # normalised source of the flagged code, for the fingerprint
    language: str = Language.PYTHON.value
    fingerprint: str = ""
    ignore_reason: str | None = None  # set when an inline ignore comment covers it


@dataclass(frozen=True)
class SkippedFile:
    file: str
    reason: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    ignored: list[Finding] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    files_scanned: int = 0
    languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
