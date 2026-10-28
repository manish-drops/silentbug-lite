"""Terminal output. Plain ASCII, so it reads the same in any terminal and CI log."""

from __future__ import annotations

import textwrap

from silentbug_lite import FULL_VERSION_URL, TOOL_NAME, __version__
from silentbug_lite.models import Finding, ScanResult
from silentbug_lite.report import failing, severity_counts
from silentbug_lite.rules import CHECKS, check_for
from silentbug_lite.secrets import redact

WIDTH = 100
MAX_SKIPPED_SHOWN = 5
_COLOURS = {"critical": "\033[1;31m", "high": "\033[1;33m", "medium": "\033[33m", "low": "\033[2m"}
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

LANGUAGE_NAMES = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript"}
FRAMEWORK_NAMES = {"fastapi": "FastAPI", "flask": "Flask", "django": "Django",
                   "express": "Express", "nextjs": "Next.js", "nestjs": "NestJS", "react": "React"}


def full_version_line() -> str:
    return (
        f"{TOOL_NAME} ran {len(CHECKS)} checks. The full silentbug adds more checks and an AI "
        f"judge: {FULL_VERSION_URL}"
    )


class _Style:
    def __init__(self, colour: bool):
        self.colour = colour

    def paint(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.colour else text


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _stack(result: ScanResult) -> str:
    languages = [LANGUAGE_NAMES.get(x, x) for x in sorted(result.languages)]
    frameworks = [FRAMEWORK_NAMES.get(x, x) for x in sorted(result.frameworks)]
    parts = [", ".join(languages), ", ".join(frameworks)]
    shown = " / ".join(p for p in parts if p)
    return f" ({shown})" if shown else ""


def _wrapped(label: str, text: str, indent: int = 4) -> list[str]:
    pad = " " * indent
    return textwrap.wrap(
        f"{label}{text}", width=WIDTH, initial_indent=pad, subsequent_indent=pad,
        break_on_hyphens=False,
    ) or [pad]


def _snippet(finding: Finding, style: _Style) -> list[str]:
    if not finding.snippet:
        return []
    lines = redact(finding.snippet).splitlines()
    last = finding.snippet_start + len(lines) - 1
    width = len(str(last))
    out = []
    for offset, code in enumerate(lines):
        number = finding.snippet_start + offset
        marker = ">" if number == finding.line else " "
        row = f"  {marker} {str(number).rjust(width)} | {code}".rstrip()
        out.append(row if number == finding.line else style.paint(row, _DIM))
    return out


def _finding(finding: Finding, style: _Style) -> list[str]:
    check = check_for(finding.rule_id)
    severity = style.paint(finding.severity.value.upper().ljust(8), _COLOURS[finding.severity])
    where = style.paint(f"{finding.file}:{finding.line}", _BOLD)
    lines = [f"{severity}  {where}  {check.title}  {style.paint(f'[{finding.rule_id}]', _DIM)}"]
    lines += _snippet(finding, style)
    lines += _wrapped("", finding.message)
    lines += _wrapped("Fix: ", check.fix)
    return lines


def render(
    result: ScanResult,
    target: str,
    fail_on: str,
    colour: bool = False,
    notes: list[str] | None = None,
) -> str:
    style = _Style(colour)
    lines = [
        f"{TOOL_NAME} {__version__} - {_plural(result.files_scanned, 'file')} checked in "
        f"{target}{_stack(result)}",
        "",
    ]
    for finding in result.findings:
        lines += _finding(finding, style)
        lines.append("")
    if result.skipped:
        lines.append(f"Skipped {_plural(len(result.skipped), 'file')}:")
        for skipped in result.skipped[:MAX_SKIPPED_SHOWN]:
            lines.append(f"  {skipped.file}: {skipped.reason}")
        if len(result.skipped) > MAX_SKIPPED_SHOWN:
            lines.append(f"  ...and {len(result.skipped) - MAX_SKIPPED_SHOWN} more")
        lines.append("")
    lines.append(_summary(result))
    over = failing(result, fail_on)
    if over:
        lines.append(
            style.paint(f"Failing: {len(over)} at or above '{fail_on}' (--fail-on {fail_on})",
                        _BOLD)
        )
    lines += notes or []
    lines += ["", full_version_line()]
    return "\n".join(lines) + "\n"


def _summary(result: ScanResult) -> str:
    if not result.findings:
        head = f"No possible bugs found by the {len(CHECKS)} checks"
    else:
        counts = severity_counts(result.findings)
        by_severity = ", ".join(f"{n} {name}" for name, n in counts.items() if n)
        bugs = "possible bug" if len(result.findings) == 1 else "possible bugs"
        head = f"{len(result.findings)} {bugs} ({by_severity})"
    if result.ignored:
        head += f", {len(result.ignored)} ignored by comment"
    return head + "."
