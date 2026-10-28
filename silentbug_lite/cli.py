"""`silentbug-lite [path]`.

Exit codes: 0 nothing at or above --fail-on, 1 findings at or above --fail-on, 2 usage
error (bad flag, missing path, unwritable output), 3 internal error, 130 interrupted.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from silentbug_lite import TOOL_NAME, __version__
from silentbug_lite.models import ScanResult
from silentbug_lite.report import FAIL_ON_CHOICES, failing
from silentbug_lite.rules import CHECKS, RULES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
EXIT_INTERRUPTED = 130


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse exits with 2 too; keep the wording ours
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=TOOL_NAME,
        description="Five checks for bugs that tests and linters miss, in Python and "
        "JavaScript/TypeScript. Reads the code only; nothing is run or sent anywhere.",
    )
    parser.add_argument("path", nargs="?", default=".", help="folder or file to check (default: .)")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to FILE; the text summary still prints to the terminal",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="high",
        help="exit with 1 when a finding is at or above this severity (default: high; "
        "'none' always exits 0)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="skip paths matching GLOB, relative to the folder (repeatable), e.g. 'tests/*'",
    )
    parser.add_argument("--no-color", action="store_true", help="plain text, no colours")
    parser.add_argument("--list-checks", action="store_true", help="list the checks and exit")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def _list_checks() -> str:
    lines = []
    for number, check in enumerate(CHECKS, start=1):
        lines.append(f"{number}. {check.title}")
        for rule_id in check.rules:
            rule = RULES[rule_id]
            lines.append(f"   {rule_id} ({rule.severity.value}): {rule.summary}")
    return "\n".join(lines) + "\n"


def _path_prefix(target: Path) -> str:
    """Report paths relative to where the command runs, when the target is inside it, so
    `silentbug-lite src` reports `src/app.py` and GitHub can map SARIF results to files."""
    root = target if target.is_dir() else target.parent
    try:
        rel = root.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        return ""
    return "" if rel.as_posix() == "." else rel.as_posix()


def _use_colour(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except (ValueError, OSError, AttributeError):
        return False


def _render(
    result: ScanResult, fmt: str, target: str, fail_on: str, colour: bool, notes: list[str]
) -> str:
    if fmt == "json":
        from silentbug_lite.report.json_report import to_json

        return to_json(result, target, fail_on)
    if fmt == "sarif":
        from silentbug_lite.report.sarif import to_sarif

        return to_sarif(result)
    from silentbug_lite.report.terminal import render

    return render(result, target, fail_on, colour=colour, notes=notes)


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        sys.stdout.write(_list_checks())
        return EXIT_OK
    target = Path(args.path)
    if not target.exists():
        sys.stderr.write(f"{TOOL_NAME}: {args.path}: no such file or folder\n")
        return EXIT_USAGE
    from silentbug_lite.scan import scan

    result = scan(target, args.exclude, path_prefix=_path_prefix(target))
    colour = _use_colour(args.no_color)
    if args.output:
        report = _render(result, args.format, args.path, args.fail_on, False, [])
        try:
            Path(args.output).write_text(report, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"{TOOL_NAME}: can't write {args.output}: {exc.strerror or exc}\n")
            return EXIT_USAGE
        notes = [f"Report written to {args.output}"]
        sys.stdout.write(_render(result, "text", args.path, args.fail_on, colour, notes))
    else:
        sys.stdout.write(_render(result, args.format, args.path, args.fail_on, colour, []))
    return EXIT_FINDINGS if failing(result, args.fail_on) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass  # not a text stream we can reconfigure (a test capture, for example)
    try:
        return run(argv)
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return EXIT_INTERRUPTED
    except Exception as exc:  # noqa: BLE001 - one clear line instead of a traceback
        sys.stderr.write(f"{TOOL_NAME}: internal error: {type(exc).__name__}: {exc}\n")
        return EXIT_INTERNAL
