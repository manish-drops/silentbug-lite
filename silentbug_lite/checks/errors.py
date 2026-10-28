"""Check: an error handler that still reports success (errors.success-on-exception).

A payment webhook catches an exception, logs it and returns {"status": "success"}. The
provider sees a 200, never retries, and the payment is lost.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from typing import Any

from silentbug_lite.lang import ALL_LANGUAGES
from silentbug_lite.lang import javascript as js
from silentbug_lite.lang.python import py_finding, walk_shallow
from silentbug_lite.models import Finding, Language, ParsedModule

RULE = "errors.success-on-exception"

SUCCESS_WORDS = {"success", "ok", "succeeded", "done", "completed"}
STATUS_KEYS = {"status", "success", "ok", "result", "state"}

# A function whose name asserts a block: returning True from its error handler is the
# safe choice (it fails closed), so that return isn't a success report.
_DENY_WORDS = (
    "blacklist", "banned", "blocked", "revoked", "expired", "locked",
    "suspended", "rate_limited", "ratelimited", "forbidden", "denied",
)


def _is_deny_check(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in _DENY_WORDS)


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


class SuccessOnException:
    id = RULE
    languages = ALL_LANGUAGES

    def run(self, module: ParsedModule) -> Iterator[Finding]:
        if module.language == Language.PYTHON.value:
            yield from _python(module)
        else:
            yield from _javascript(module)


# --- Python ---------------------------------------------------------------------


def _handlers(tree: ast.AST) -> Iterator[ast.ExceptHandler]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            yield node


def _shallow_returns(handler: ast.ExceptHandler) -> list[ast.Return]:
    return [n for n in walk_shallow(handler) if isinstance(n, ast.Return)]


def _reraises(handler: ast.ExceptHandler) -> bool:
    return any(isinstance(n, ast.Raise) for n in walk_shallow(handler))


def _is_success_shaped(value: ast.expr | None) -> bool:
    if value is None:
        return False
    if isinstance(value, ast.Constant) and value.value is True:
        return True
    if isinstance(value, ast.Dict):
        for key, val in zip(value.keys, value.values, strict=True):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if key.value.lower() not in STATUS_KEYS or not isinstance(val, ast.Constant):
                continue
            if val.value is True:
                return True
            if isinstance(val.value, str) and val.value.lower() in SUCCESS_WORDS:
                return True
    return False


def _fail_closed_returns(tree: ast.AST) -> set[int]:
    """`return True` from a deny check (`is_token_blacklisted`) in an except handler."""
    closed: set[int] = set()
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_deny_check(func.name):
            continue
        for handler in _handlers(func):
            for ret in _shallow_returns(handler):
                if isinstance(ret.value, ast.Constant) and ret.value.value is True:
                    closed.add(id(ret))
    return closed


def _python(module: ParsedModule) -> Iterator[Finding]:
    closed = _fail_closed_returns(module.tree)
    for handler in _handlers(module.tree):
        if _reraises(handler):
            continue
        for ret in _shallow_returns(handler):
            if not _is_success_shaped(ret.value) or id(ret) in closed:
                continue
            yield py_finding(
                RULE,
                module,
                ret,
                "This except block returns a success value and never re-raises, so the caller "
                "can't tell the operation failed.",
                before=3,
                after=1,
            )


# --- JavaScript / TypeScript --------------------------------------------------------

_RESPONDERS = {"json", "send", "end"}
_PASS_ON = {"next", "reject", "done", "callback", "cb"}
_NOTIFIERS = {"toast", "message", "notification", "notify", "notifications", "snackbar"}
_SUCCESS_FLAGS = {"success", "succeeded", "saved", "done", "completed", "submitted", "sent",
                  "paid", "ok", "isSuccess", "issuccess", "issaved", "isdone", "issubmitted"}
_STATUS_SETTERS = {"setstatus", "setstate", "setresult", "setphase", "setstep"}


def _success_value(node: Any) -> bool:
    if node is None:
        return False
    if node.type == "true":
        return True
    if node.type == "object":
        for key, value in js.object_props(node).items():
            if key.lower() not in STATUS_KEYS or value is None:
                continue
            if value.type == "true":
                return True
            literal = js.string_value(value)
            if literal is not None and literal.lower() in SUCCESS_WORDS:
                return True
    return False


def _success_response(call: Any) -> bool:
    """`res.json({success: true})`, `res.status(200).json(...)`, `NextResponse.json({ok: true})`."""
    last = js.callee(call).split(".")[-1]
    args = js.arguments(call)
    if last == "sendStatus":
        return bool(args) and js.text(args[0]).startswith("2")
    if last not in _RESPONDERS:
        return False
    if re.search(r"status\(\s*[45]\d\d", js.text(call)):
        return False
    return bool(args) and _success_value(args[0])


def _ui_success(call: Any) -> str | None:
    """`toast.success(...)`, `setSuccess(true)`, `setStatus("success")`: the UI says it worked."""
    name = js.callee(call)
    parts = name.split(".")
    if len(parts) == 2 and parts[0] in _NOTIFIERS and parts[1] == "success":
        return f"{name}()"
    if len(parts) != 1 or not re.match(r"^set[A-Z]", name):
        return None
    args = js.arguments(call)
    if not args:
        return None
    if name[3:].lower() in _SUCCESS_FLAGS and args[0].type == "true":
        return f"{name}(true)"
    literal = js.string_value(args[0])
    if name.lower() in _STATUS_SETTERS and literal is not None and literal.lower() in (
        SUCCESS_WORDS | {"saved", "sent", "paid", "submitted"}
    ):
        return f"{name}({literal!r})"
    return None


def _passes_error_on(body: Any) -> bool:
    for node in js.walk_shallow(body):
        if node.type == "throw_statement":
            return True
        if node.type == "call_expression" and js.callee(node).split(".")[-1] in _PASS_ON:
            return True
    return False


def _javascript(module: ParsedModule) -> Iterator[Finding]:
    for clause in js.walk(module.tree.root_node):
        if clause.type != "catch_clause":
            continue
        body = js.field(clause, "body")
        if body is None or _passes_error_on(body):
            continue
        fn = js.enclosing_function(clause)
        fails_closed = fn is not None and _is_deny_check(
            _snake(js.function_name(fn).split(".")[-1])
        )
        seen: set[int] = set()
        for node in js.walk_shallow(body):
            hit = None
            if node.type == "return_statement":
                value = node.named_children[0] if node.named_children else None
                if fails_closed and value is not None and value.type == "true":
                    continue
                if _success_value(value) or (
                    value is not None
                    and value.type == "call_expression"
                    and _success_response(value)
                ):
                    hit = node
            elif node.type == "call_expression" and _success_response(node):
                hit = node
            ui = _ui_success(node) if node.type == "call_expression" else None
            if ui is not None:
                hit = node
            if hit is None or hit.start_point[0] in seen:
                continue
            seen.add(hit.start_point[0])
            message = (
                f"This catch block shows success ({ui}) and never surfaces the error, so the "
                "user is told it worked when it failed."
                if ui is not None
                else "This catch block reports success and never rethrows, so the caller can't "
                "tell the operation failed."
            )
            yield js.js_finding(RULE, module, hit, message, before=3, after=1)
