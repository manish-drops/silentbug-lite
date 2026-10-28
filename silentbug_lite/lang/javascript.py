"""JavaScript and TypeScript through tree-sitter, plus the tree helpers the checks share.
It only parses: nothing is run, installed or resolved, and Node.js is not needed."""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Any

from silentbug_lite.models import Finding, Language, ParsedModule
from silentbug_lite.rules import RULES

MAX_ERROR_SHARE = 0.10  # skip a file when parse errors cover more than this share of it

FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
    "function",
}
CLASSES = {"class_declaration", "class", "abstract_class_declaration"}
LOOP_CALLBACKS = {
    "map",
    "forEach",
    "flatMap",
    "filter",
    "reduce",
    "some",
    "every",
    "find",
    "findIndex",
    "reduceRight",
}
_SQL = re.compile(r"(?i)\b(select|insert|update|delete|where|from|into|values|order\s+by)\b")


# --- parsing ------------------------------------------------------------------


@lru_cache(maxsize=4)
def _grammar(name: str) -> Any:
    import tree_sitter as ts

    if name == "javascript":
        import tree_sitter_javascript as grammar

        return ts.Language(grammar.language())
    import tree_sitter_typescript as grammar

    return ts.Language(grammar.language_tsx() if name == "tsx" else grammar.language_typescript())


def grammar_name(rel: str) -> str:
    suffix = PurePosixPath(rel).suffix
    if suffix == ".tsx":
        return "tsx"
    if suffix in (".ts", ".mts", ".cts"):
        return "typescript"
    return "javascript"


def _error_bytes(node: Any) -> int:
    if node.type == "ERROR" or node.is_missing:
        return max(1, node.end_byte - node.start_byte)
    if not node.has_error:
        return 0
    return sum(_error_bytes(child) for child in node.children)


def parse_js(source: str, rel: str, language: Language) -> ParsedModule:
    """Parse with the right grammar. Raises SyntaxError when the file is mostly errors."""
    import tree_sitter as ts

    data = source.encode("utf-8")
    tree = ts.Parser(_grammar(grammar_name(rel))).parse(data)
    root = tree.root_node
    if root.has_error and data:
        share = _error_bytes(root) / len(data)
        if share > MAX_ERROR_SHARE:
            error = SyntaxError(f"parse errors cover {share:.0%} of the file")
            error.msg = f"parse errors cover {share:.0%} of the file"
            raise error
    return ParsedModule(
        file=rel, source=source, tree=tree, lines=source.splitlines(), language=language.value
    )


def _walk_all(node: Any) -> Iterator[Any]:
    """Every descendant including anonymous nodes (comments are named, but be thorough)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def js_comments(module: ParsedModule) -> list[tuple[int, str]]:
    """(line, text) of every comment node; strings are never mistaken for comments."""
    comments = []
    for node in _walk_all(module.tree.root_node):
        if node.type == "comment":
            body = text(node)
            if body.startswith("//"):
                body = body[2:]
            elif body.startswith("/*"):
                body = body[2:-2] if body.endswith("*/") else body[2:]
            comments.append((node.start_point[0] + 1, body.strip(" *\t")))
    return comments


def js_imports(module: ParsedModule) -> set[str]:
    """Module specifiers from `import`, `export ... from`, `require()` and `import()`."""
    found: set[str] = set()
    for node in _walk_all(module.tree.root_node):
        if node.type in ("import_statement", "export_statement"):
            value = string_value(node.child_by_field_name("source"))
            if value:
                found.add(value)
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type in ("identifier", "import"):
                if text(function) in ("require", "import"):
                    args = arguments(node)
                    value = string_value(args[0]) if args else None
                    if value:
                        found.add(value)
    return found


def directives(node: Any) -> set[str]:
    """Leading directive strings of a program or function body: `"use server"`."""
    found: set[str] = set()
    for child in node.named_children:
        if child.type == "comment":
            continue
        if child.type != "expression_statement" or not child.named_children:
            break
        first = child.named_children[0]
        value = string_value(first)
        if first.type != "string" or value is None:
            break
        found.add(value)
    return found


# --- tree helpers ---------------------------------------------------------------


def text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def line(node: Any) -> int:
    return node.start_point[0] + 1


def end_line(node: Any) -> int:
    return node.end_point[0] + 1


def walk(node: Any) -> Iterator[Any]:
    """Every named descendant, pre-order (including `node`)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def walk_shallow(node: Any) -> Iterator[Any]:
    """Named descendants, without entering nested functions or classes."""
    for child in node.named_children:
        yield child
        if child.type not in FUNCTIONS and child.type not in CLASSES:
            yield from walk_shallow(child)


def field(node: Any, name: str) -> Any:
    return node.child_by_field_name(name) if node is not None else None


def same(a: Any, b: Any) -> bool:
    """tree-sitter hands out a new Python object per access, so compare node ids."""
    return a is not None and b is not None and a.id == b.id


def callee(call: Any) -> str:
    """Dotted name of a call's function: `prisma.user.findMany`, `res.status.json`."""
    return dotted(field(call, "function"))


def dotted(node: Any) -> str:
    if node is None:
        return ""
    if node.type in (
        "identifier",
        "property_identifier",
        "this",
        "shorthand_property_identifier",
        "type_identifier",
        "private_property_identifier",
        "meta_property",
    ):
        return text(node)
    if node.type == "member_expression":
        base = dotted(field(node, "object"))
        prop = text(field(node, "property"))
        return f"{base}.{prop}" if base else prop
    if node.type == "call_expression":
        return dotted(field(node, "function"))
    if node.type in ("await_expression", "parenthesized_expression", "non_null_expression"):
        return dotted(node.named_children[0] if node.named_children else None)
    if node.type == "new_expression":
        return dotted(field(node, "constructor"))
    if node.type == "subscript_expression":
        return dotted(field(node, "object"))
    return ""


def arguments(call: Any) -> list[Any]:
    args = field(call, "arguments")
    return [a for a in args.named_children if a.type != "comment"] if args is not None else []


def object_props(node: Any) -> dict[str, Any]:
    """`{ key: value, short }` -> {"key": value_node, "short": node}."""
    props: dict[str, Any] = {}
    if node is None or node.type != "object":
        return props
    for child in node.named_children:
        if child.type == "pair":
            key = field(child, "key")
            name = string_value(key) if key is not None and key.type == "string" else text(key)
            if name is not None:
                props[name] = field(child, "value")
        elif child.type == "shorthand_property_identifier":
            props[text(child)] = child
        elif child.type == "spread_element":
            props["..."] = child
    return props


def string_value(node: Any) -> str | None:
    """The value of a string literal, or of a template literal with no `${}`."""
    if node is None:
        return None
    if node.type == "string":
        return "".join(
            text(c) for c in node.named_children if c.type in ("string_fragment", "escape_sequence")
        )
    if node.type == "template_string" and not any(
        c.type == "template_substitution" for c in node.named_children
    ):
        return text(node).strip("`")
    return None


def is_dynamic_string(node: Any) -> bool:
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.named_children)
    if node.type == "binary_expression" and text(field(node, "operator")) == "+":
        return any(child.type != "string" for child in (field(node, "left"), field(node, "right")))
    return False


def literal_text(node: Any) -> str:
    return (
        " ".join(text(n) for n in walk(node) if n.type == "string_fragment")
        + " "
        + " ".join(text(n) for n in walk(node) if n.type == "template_string")
    )


def is_dynamic_sql(node: Any) -> bool:
    return is_dynamic_string(node) and bool(_SQL.search(literal_text(node)))


def parent_chain(node: Any) -> Iterator[Any]:
    current = node.parent
    while current is not None:
        yield current
        current = current.parent


def enclosing_function(node: Any) -> Any:
    for parent in parent_chain(node):
        if parent.type in FUNCTIONS:
            return parent
    return None


def function_name(fn: Any) -> str:
    if fn is None:
        return "<module>"
    name = field(fn, "name")
    if name is not None:
        return text(name)
    parent = fn.parent
    if parent is not None:
        if parent.type == "variable_declarator":
            return text(field(parent, "name"))
        if parent.type == "pair":
            return text(field(parent, "key"))
        if parent.type == "assignment_expression":
            return dotted(field(parent, "left")) or "<anonymous>"
        if parent.type == "arguments":
            call = parent.parent
            first = arguments(call)[0] if call is not None and arguments(call) else None
            route = string_value(first) if first is not None else None
            target = callee(call) if call is not None else ""
            if route is not None:
                return f"{target.split('.')[-1]} {route}"
            return f"<callback of {target}>" if target else "<anonymous>"
    return "<anonymous>"


def qualified_symbol(node: Any) -> str:
    names = []
    for parent in parent_chain(node):
        if parent.type in FUNCTIONS:
            names.append(function_name(parent))
        elif parent.type in CLASSES:
            names.append(text(field(parent, "name")) or "<class>")
    return ".".join(reversed(names)) or "<module>"


def node_key(node: Any) -> str:
    """Node type plus its source with comments removed and whitespace collapsed."""
    tokens: list[str] = []

    def collect(current: Any) -> None:
        if current.type == "comment":
            return
        if current.child_count == 0:
            tokens.append(text(current))
            return
        for child in current.children:
            collect(child)

    collect(node)
    return f"{node.type}:" + " ".join(t for t in tokens if t.strip())


def _constant_bound_for(loop: Any) -> bool:
    """`for (let i = 0; i < 3; i++)` is a retry loop, not a loop over data."""
    condition = field(loop, "condition")
    if condition is None:
        return False
    expr = (
        condition.named_children[0]
        if condition.type == "expression_statement" and condition.named_children
        else condition
    )
    if expr.type != "binary_expression":
        return False
    right = field(expr, "right")
    return right is not None and right.type == "number"


def in_data_loop(node: Any) -> bool:
    """Inside a loop over data in the same function: for, for...of, for...in, or an array
    callback like `.map()`. `while` loops (agents, retries) don't count."""
    child = node
    for parent in parent_chain(node):
        if parent.type == "for_in_statement":
            if same(child, field(parent, "body")):
                return True
        elif parent.type == "for_statement":
            if same(child, field(parent, "body")) and not _constant_bound_for(parent):
                return True
        elif parent.type in FUNCTIONS:
            holder = parent.parent
            if holder is not None and holder.type == "arguments":
                call = holder.parent
                if call is not None and callee(call).split(".")[-1] in LOOP_CALLBACKS:
                    return True
            return False
        child = parent
    return False


def js_finding(
    rule_id: str,
    module: ParsedModule,
    node: Any,
    message: str,
    *,
    line: int | None = None,
    before: int = 2,
    after: int = 1,
) -> Finding:
    at = line if line is not None else node.start_point[0] + 1
    return Finding(
        rule_id=rule_id,
        severity=RULES[rule_id].severity,
        file=module.file,
        line=at,
        message=message,
        snippet=module.snippet(at, before=before, after=after),
        snippet_start=max(1, at - before),
        symbol=qualified_symbol(node),
        node_key=node_key(node),
        language=module.language,
    )
