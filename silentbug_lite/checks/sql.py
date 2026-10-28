"""Check: SQL text glued together from values and handed to the driver (db.sql-injection)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from typing import Any

from silentbug_lite.lang import ALL_LANGUAGES
from silentbug_lite.lang import javascript as js
from silentbug_lite.lang.python import py_finding, walk_shallow
from silentbug_lite.models import Finding, Language, ParsedModule

RULE = "db.sql-injection"


class SqlInjection:
    id = RULE
    languages = ALL_LANGUAGES

    def run(self, module: ParsedModule) -> Iterator[Finding]:
        if module.language == Language.PYTHON.value:
            yield from _python(module)
        else:
            yield from _javascript(module)


# --- Python ---------------------------------------------------------------------

_SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|where|from|into|values|order\s+by)\b")
_EXECUTE_ATTRS = {
    "execute",
    "executemany",
    "executescript",
    "raw",
    "extra",
    "query",
    "exec_driver_sql",
}


def _literal_text(node: ast.AST) -> str:
    """The constant parts of a string-building expression."""
    return " ".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def _is_dynamic_sql(node: ast.AST | None) -> bool:
    """An f-string, `%`, `+` or `.format()` that mixes SQL text with values."""
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        dynamic = any(isinstance(v, ast.FormattedValue) for v in node.values)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        dynamic = not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        dynamic = bool(node.args or node.keywords)
    else:
        return False
    return dynamic and bool(_SQL_WORDS.search(_literal_text(node)))


def _local_assignments(scope: ast.AST) -> dict[str, ast.expr]:
    found: dict[str, ast.expr] = {}
    for node in walk_shallow(scope):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                found[target.id] = node.value
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            found[node.target.id] = (
                node.value if _is_dynamic_sql(node.value) else found.get(node.target.id, node.value)
            )
    return found


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _python(module: ParsedModule) -> Iterator[Finding]:
    scopes: list[ast.AST] = [module.tree] + [
        n for n in ast.walk(module.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    seen: set[int] = set()
    for scope in scopes:
        local = _local_assignments(scope)
        for node in walk_shallow(scope):
            if not isinstance(node, ast.Call) or id(node) in seen or not node.args:
                continue
            name = _call_name(node)
            if name not in _EXECUTE_ATTRS and name != "text":
                continue
            arg = node.args[0]
            # session.execute(text(f"...")): look inside SQLAlchemy's text()
            if isinstance(arg, ast.Call) and _call_name(arg) == "text" and arg.args:
                arg = arg.args[0]
            if isinstance(arg, ast.Name) and arg.id in local:
                arg = local[arg.id]
            if not _is_dynamic_sql(arg):
                continue
            seen.add(id(node))
            yield py_finding(
                RULE,
                module,
                node,
                f"The SQL passed to {name}() is built from values with string formatting, so "
                "input can change the query.",
            )


# --- JavaScript / TypeScript --------------------------------------------------------

SQL_CALLS = {"query", "execute", "$queryRawUnsafe", "$executeRawUnsafe", "raw", "unsafe"}


def _local_values(fn: Any) -> dict[str, Any]:
    found: dict[str, Any] = {}
    if fn is None:
        return found
    for node in js.walk_shallow(fn):
        if node.type == "variable_declarator":
            value = js.field(node, "value")
            if value is not None:
                found[js.text(js.field(node, "name"))] = value
    return found


def _javascript(module: ParsedModule) -> Iterator[Finding]:
    for node in js.walk(module.tree.root_node):
        if node.type != "call_expression":
            continue
        args_field = js.field(node, "arguments")
        if args_field is None or args_field.type == "template_string":
            continue  # a tagged template (sql`...`, $queryRaw`...`) is parameterised
        name = js.callee(node)
        if "." not in name or name.split(".")[-1] not in SQL_CALLS:
            continue
        args = js.arguments(node)
        if not args:
            continue
        arg = args[0]
        if arg.type == "identifier":
            arg = _local_values(js.enclosing_function(node)).get(js.text(arg), arg)
        if not js.is_dynamic_sql(arg):
            continue
        yield js.js_finding(
            RULE,
            module,
            node,
            f"The SQL passed to {name.split('.')[-1]}() is built from values with a template "
            "literal or +, so input can change the query.",
        )
