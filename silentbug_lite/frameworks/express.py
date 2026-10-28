"""Express routes: `app.<method>(path, ...middleware, handler)`, plus app- and
router-level `use(...)` auth middleware that protects the routes after it."""

from __future__ import annotations

from typing import Any

from silentbug_lite.frameworks.base import Route, looks_like_auth
from silentbug_lite.lang import JS_FAMILY
from silentbug_lite.lang.javascript import (
    FUNCTIONS,
    arguments,
    callee,
    dotted,
    field,
    function_name,
    line,
    string_value,
    text,
    walk,
)
from silentbug_lite.models import ParsedModule

METHODS = {"get", "post", "put", "patch", "delete", "all"}
_RECEIVER_HINTS = ("app", "router", "api", "routes", "server", "admin")


def _receivers(root: Any) -> set[str]:
    """Names bound to `express()` / `express.Router()` / `Router()`."""
    names = set()
    for node in walk(root):
        if node.type == "variable_declarator":
            value = field(node, "value")
            if value is not None and value.type == "call_expression":
                target = callee(value)
                if target in ("express", "express.Router", "Router", "express.default"):
                    names.add(text(field(node, "name")))
    return names


def _middleware_names(args: list[Any]) -> list[str]:
    names = []
    for arg in args:
        if arg.type in FUNCTIONS:
            continue
        if arg.type == "array":
            names += _middleware_names(list(arg.named_children))
            continue
        names.append(dotted(arg) or text(arg))
    return names


class ExpressAdapter:
    name = "express"
    languages = JS_FAMILY

    def routes(self, module: ParsedModule) -> list[Route]:
        root = module.tree.root_node
        known = _receivers(root)
        uses: dict[str, list[tuple[int, str]]] = {}  # receiver -> [(line, auth middleware)]
        candidates = []
        for node in walk(root):
            if node.type != "call_expression":
                continue
            function = field(node, "function")
            if function is None or function.type != "member_expression":
                continue
            receiver = dotted(field(function, "object"))
            method = text(field(function, "property"))
            if known and receiver not in known:
                continue
            if not known and not receiver.split(".")[-1].lower().startswith(_RECEIVER_HINTS):
                continue
            args = arguments(node)
            if method == "use":
                for name in _middleware_names(args):
                    if looks_like_auth(name):
                        uses.setdefault(receiver, []).append((line(node), name))
                continue
            if method not in METHODS or not args:
                continue
            path = string_value(args[0])
            if path is None:
                continue
            candidates.append((node, receiver, method, path, args))

        routes = []
        for node, receiver, method, path, args in candidates:
            middleware = _middleware_names(args[1:-1] if len(args) > 1 else [])
            handler = args[-1]
            auth = {m.split(".")[-1] for m in middleware if looks_like_auth(m)}
            for at, name in uses.get(receiver, []):
                if at < line(node):
                    auth.add(f"{receiver}.use({name})")
            name = function_name(handler) if handler.type in FUNCTIONS else text(handler)
            if not name or name.startswith("<"):
                name = f"{method.upper()} {path}"
            routes.append(
                Route(
                    framework=self.name,
                    method="ANY" if method == "all" else method.upper(),
                    path=path,
                    name=name,
                    line=line(node),
                    node=node,
                    auth=frozenset(auth),
                )
            )
        return routes
