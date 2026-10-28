"""Find the source files, parse them and run every check. Nothing raises out of a scan: a
file that can't be read or parsed, or a check that fails on a file, becomes a SkippedFile."""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from silentbug_lite.checks import Detector, detectors
from silentbug_lite.frameworks import project
from silentbug_lite.frameworks.detect import (
    frameworks_from_js_imports,
    frameworks_from_python_imports,
    nextjs_route_file,
    package_json_frameworks,
)
from silentbug_lite.ignore import matching_ignore, parse_ignores
from silentbug_lite.lang import SUFFIX_LANGUAGE
from silentbug_lite.lang.python import imported_roots, parse_python, python_comments
from silentbug_lite.models import Finding, Language, ParsedModule, ScanResult, SkippedFile
from silentbug_lite.rules import RULES

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", ".nox", "build", "dist",
    ".next", ".nuxt", ".output", ".svelte-kit", ".turbo", ".vercel", ".parcel-cache",
    "coverage", "htmlcov", "site-packages", ".silentbug", ".idea", ".vscode",
}
MAX_SOURCE_BYTES = 1_000_000
MINIFIED_SHARE = 0.6  # of the file's characters, in lines over MAX_LINE_LENGTH
MAX_LINE_LENGTH = 1_000  # longer lines mean a minified or generated file


def _excluded(rel: str, globs: list[str]) -> bool:
    if any(part in EXCLUDED_DIRS for part in rel.split("/")[:-1]):
        return True
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*") for g in globs)


def iter_files(root: Path, exclude: list[str] | None = None) -> Iterator[str]:
    """Every file under `root` a scan may look at, as relative POSIX paths. Symlinks are
    never followed, so a scan can't wander out of the folder it was given."""
    globs = exclude or []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            rel = entry.relative_to(root).as_posix()
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in EXCLUDED_DIRS and not _excluded(rel + "/x", globs):
                    stack.append(entry)
            elif entry.is_file() and not _excluded(rel, globs):
                yield rel


def source_language(rel: str) -> Language | None:
    if rel.endswith((".d.ts", ".min.js", ".min.mjs")):
        return None
    return SUFFIX_LANGUAGE.get(Path(rel).suffix)


def _too_big_or_minified(source: str, size: int, minify_check: bool) -> str | None:
    if size > MAX_SOURCE_BYTES:
        return f"larger than {MAX_SOURCE_BYTES // 1000} KB (likely generated)"
    if minify_check and source:
        # Minified code puts most of the file on a few huge lines. Hand-written components
        # often have one or two long lines too, so look at the share of the file.
        long_chars = sum(len(line) for line in source.splitlines() if len(line) > MAX_LINE_LENGTH)
        if long_chars / len(source) > MINIFIED_SHARE:
            return "looks minified or generated (very long lines)"
    return None


def fingerprint(finding: Finding) -> str:
    """sha256 of rule, path, enclosing function and the flagged code. No line numbers:
    moving code up or down keeps the fingerprint, editing the flagged code changes it."""
    material = "\x1f".join((finding.rule_id, finding.file, finding.symbol, finding.node_key))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def scan(
    target: Path,
    exclude: list[str] | None = None,
    *,
    path_prefix: str = "",
    checks: list[Detector] | None = None,
) -> ScanResult:
    """Scan a folder, or a single file. Reported paths are relative to the folder (or the
    file's folder), with `path_prefix` in front."""
    target = Path(target).resolve()
    if target.is_file():
        root, files = target.parent, [target.name]
    else:
        root, files = target, list(iter_files(target, exclude))
    result = ScanResult()
    try:
        context = project.build(root, files)
    except Exception as exc:  # noqa: BLE001 - reported, and the scan goes on without it
        context = project.ProjectContext()
        result.skipped.append(SkippedFile(".", f"project files unreadable: {exc}"))
    with project.using(context):
        _scan_files(root, files, checks or detectors(), result)
    prefix = path_prefix.strip("/")
    _finish(result, prefix)
    return result


def _parse(
    source: str, rel: str, language: Language, js_frameworks: set[str]
) -> tuple[ParsedModule, list[tuple[int, str]]]:
    if language is Language.PYTHON:
        module = parse_python(source, rel)
        frameworks = frameworks_from_python_imports(imported_roots(module.tree))
        comments = python_comments(source)
    else:
        from silentbug_lite.lang.javascript import js_comments, js_imports, parse_js

        module = parse_js(source, rel, language)
        frameworks = frameworks_from_js_imports(js_imports(module))
        if nextjs_route_file(rel) and "nextjs" in js_frameworks:
            frameworks.add("nextjs")
        if "use server" in source:
            frameworks.add("nextjs")  # Server Actions: the Next.js adapter finds them
        comments = js_comments(module)
    return replace(module, frameworks=frozenset(frameworks)), comments


def _scan_files(root: Path, files: list[str], checks: list[Detector], result: ScanResult) -> None:
    js_frameworks = package_json_frameworks(root)
    for rel in sorted(files):
        language = source_language(rel)
        if language is None:
            continue
        path = root / rel
        try:
            size = path.stat().st_size
            source = "" if size > MAX_SOURCE_BYTES else path.read_text("utf-8", errors="replace")
        except OSError as exc:
            result.skipped.append(SkippedFile(rel, f"can't be read: {exc.strerror or exc}"))
            continue
        too_big = _too_big_or_minified(source, size, language is not Language.PYTHON)
        if too_big:
            result.skipped.append(SkippedFile(rel, too_big))
            continue
        try:
            module, comments = _parse(source, rel, language, js_frameworks)
        except SyntaxError as exc:
            result.skipped.append(SkippedFile(rel, f"syntax error: {exc.msg}"))
            continue
        except (OSError, ValueError) as exc:
            result.skipped.append(SkippedFile(rel, f"can't be parsed: {exc}"))
            continue
        result.files_scanned += 1
        result.languages.add(language.value)
        result.frameworks |= set(module.frameworks)
        _run_checks(module, comments, checks, result)


def _run_checks(
    module: ParsedModule, comments: list[tuple[int, str]], checks: list[Detector],
    result: ScanResult,
) -> None:
    ignores = parse_ignores(comments)
    # One finding per check and line: a route that breaks the file's auth pattern and also
    # deletes data is one missing login check, not two.
    seen: set[tuple[str, int]] = set()
    seen_ignored: set[tuple[str, int]] = set()
    for check in checks:
        if module.language not in check.languages:
            continue
        try:
            found = list(check.run(module))
        except Exception as exc:  # noqa: BLE001 - reported as a skipped file, never hidden
            result.skipped.append(
                SkippedFile(module.file, f"check {check.id} failed: {type(exc).__name__}: {exc}")
            )
            continue
        for finding in found:
            key = (RULES[finding.rule_id].check, finding.line)
            ignore = matching_ignore(finding, ignores)
            if ignore is not None:
                if key not in seen_ignored:
                    seen_ignored.add(key)
                    result.ignored.append(replace(finding, ignore_reason=ignore.reason))
            elif key not in seen:
                seen.add(key)
                result.findings.append(finding)


def _finish(result: ScanResult, prefix: str) -> None:
    def place(finding: Finding) -> Finding:
        file = f"{prefix}/{finding.file}" if prefix else finding.file
        return replace(finding, file=file)

    counts: dict[str, int] = {}

    def stamp(finding: Finding) -> Finding:
        base = fingerprint(finding)
        counts[base] = counts.get(base, 0) + 1
        return replace(finding, fingerprint=base if counts[base] == 1 else f"{base}#{counts[base]}")

    order = lambda f: (f.severity.rank, f.file, f.line, f.rule_id)  # noqa: E731
    result.findings = sorted((stamp(place(f)) for f in result.findings), key=order)
    result.ignored = sorted((stamp(place(f)) for f in result.ignored), key=order)
    result.skipped = [
        SkippedFile(f"{prefix}/{s.file}" if prefix and s.file != "." else s.file, s.reason)
        for s in result.skipped
    ]
