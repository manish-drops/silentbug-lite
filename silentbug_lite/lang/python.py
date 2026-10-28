"""Python through the standard library `ast`, plus the tree helpers the checks share."""

from __future__ import annotations

import ast
import io
import tokenize
from collections.abc import Iterator

from silentbug_lite.models import Finding, Language, ParsedModule
from silentbug_lite.rules import RULES

FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
BARRIERS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def parse_python(source: str, rel: str) -> ParsedModule:
    """Parse with `ast`. Raises SyntaxError for the caller to report."""
    return ParsedModule(
        file=rel,
        source=source,
        tree=ast.parse(source, filename=rel),
        lines=source.splitlines(),
        language=Language.PYTHON.value,
    )


def python_comments(source: str) -> list[tuple[int, str]]:
    """(line, text) of every real comment. `tokenize` never mistakes a `#` inside a
    string for a comment, which a regex over the source would."""
    comments: list[tuple[int, str]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comments.append((token.start[0], token.string.lstrip("#").strip()))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass  # a file that tokenizes badly also fails to parse, and is reported there
    return comments


def imported_roots(tree: ast.Module) -> set[str]:
    """Top-level package names imported anywhere in the module."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def walk_shallow(node: ast.AST) -> Iterator[ast.AST]:
    """Descendants, without entering nested function or class bodies. A `return` in a
    closure defined inside an except handler belongs to the closure, not the handler."""
    for child in ast.iter_child_nodes(node):
        yield child
        if not isinstance(child, BARRIERS):
            yield from walk_shallow(child)


def enclosing_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for candidate in ast.walk(tree):
        if not isinstance(candidate, FUNCTIONS):
            continue
        end = getattr(candidate, "end_lineno", candidate.lineno)
        if candidate.lineno <= line <= end and (best is None or candidate.lineno > best.lineno):
            best = candidate
    return best


def qualified_symbol(tree: ast.AST, line: int) -> str:
    """Dotted name of the innermost class or function containing `line`."""
    best: list[str] = []

    def visit(node: ast.AST, trail: list[str]) -> None:
        nonlocal best
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (*FUNCTIONS, ast.ClassDef)):
                end = getattr(child, "end_lineno", child.lineno)
                if child.lineno <= line <= end:
                    here = [*trail, child.name]
                    if len(here) > len(best):
                        best = here
                    visit(child, here)
            else:
                visit(child, trail)

    visit(tree, [])
    return ".".join(best) or "<module>"


def node_key(node: ast.AST) -> str:
    """A dump without line numbers: the same code keeps the same key wherever it moves."""
    return ast.dump(node, include_attributes=False)


def dotted(node: ast.AST | None) -> str:
    """`deps.get_current_admin` -> 'deps.get_current_admin'; a call resolves to its callee."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def py_finding(
    rule_id: str,
    module: ParsedModule,
    node: ast.AST,
    message: str,
    *,
    line: int | None = None,
    before: int = 2,
    after: int = 1,
) -> Finding:
    at = line if line is not None else node.lineno  # type: ignore[attr-defined]
    return Finding(
        rule_id=rule_id,
        severity=RULES[rule_id].severity,
        file=module.file,
        line=at,
        message=message,
        snippet=module.snippet(at, before=before, after=after),
        snippet_start=max(1, at - before),
        symbol=qualified_symbol(module.tree, at),
        node_key=node_key(node),
        language=module.language,
    )
