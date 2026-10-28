"""NestJS controllers: HTTP method decorators, `@UseGuards` on the class or the
method, global guards (APP_GUARD / useGlobalGuards), auth middleware applied in a
module's `configure()` (`consumer.apply(...).forRoutes(...)`), and public-route
decorators."""

from __future__ import annotations

from typing import Any

from silentbug_lite.frameworks import project
from silentbug_lite.frameworks.base import Route, looks_like_rate_limit
from silentbug_lite.lang import JS_FAMILY
from silentbug_lite.lang.javascript import (
    arguments,
    callee,
    dotted,
    field,
    line,
    string_value,
    text,
    walk,
)
from silentbug_lite.models import ParsedModule

METHOD_DECORATORS = {
    "Get": "GET",
    "Post": "POST",
    "Put": "PUT",
    "Patch": "PATCH",
    "Delete": "DELETE",
    "All": "ANY",
    "Head": "HEAD",
    "Options": "OPTIONS",
}
PUBLIC_DECORATORS = {"Public", "AllowAnonymous", "SkipAuth", "IsPublic", "NoAuth"}


def _decorator_name(node: Any) -> tuple[str, Any]:
    """(name, call node or None) for `@Name(...)` / `@Name`."""
    inner = node.named_children[0] if node.named_children else None
    if inner is None:
        return "", None
    if inner.type == "call_expression":
        return callee(inner).split(".")[-1], inner
    return dotted(inner).split(".")[-1], None


def _guards(call: Any) -> set[str]:
    names = set()
    for arg in arguments(call) if call is not None else []:
        names.add((dotted(arg) or text(arg)).split("(")[0].split(".")[-1])
    return names


def _class_decorators(cls: Any) -> list[Any]:
    found = [c for c in cls.named_children if c.type == "decorator"]
    parent = cls.parent
    if parent is not None and parent.type == "export_statement":
        found += [c for c in parent.named_children if c.type == "decorator"]
    return found


class NestAdapter:
    name = "nestjs"
    languages = JS_FAMILY

    def routes(self, module: ParsedModule) -> list[Route]:
        context = project.current()
        routes = []
        for cls in walk(module.tree.root_node):
            if cls.type not in ("class_declaration", "abstract_class_declaration"):
                continue
            class_decorators = [_decorator_name(d) for d in _class_decorators(cls)]
            names = {name for name, _ in class_decorators}
            if "Controller" not in names:
                continue
            base = ""
            class_auth: set[str] = set()
            class_public = bool(names & PUBLIC_DECORATORS)
            for name, call in class_decorators:
                if name == "Controller" and call is not None and arguments(call):
                    base = string_value(arguments(call)[0]) or ""
                if name == "UseGuards":
                    class_auth |= {g for g in _guards(call) if not looks_like_rate_limit(g)}
            body = field(cls, "body")
            if body is None:
                continue
            pending: list[tuple[str, Any]] = []
            for member in body.named_children:
                if member.type == "decorator":
                    pending.append(_decorator_name(member))
                    continue
                if member.type != "method_definition":
                    pending = []
                    continue
                decorators, pending = pending, []
                method = next(
                    (METHOD_DECORATORS[n] for n, _ in decorators if n in METHOD_DECORATORS), None
                )
                if method is None:
                    continue
                sub = next(
                    (
                        string_value(arguments(c)[0]) or ""
                        for n, c in decorators
                        if n in METHOD_DECORATORS and c is not None and arguments(c)
                    ),
                    "",
                )
                auth = set(class_auth)
                public = class_public
                for name, call in decorators:
                    if name == "UseGuards":
                        auth |= {g for g in _guards(call) if not looks_like_rate_limit(g)}
                    elif name in PUBLIC_DECORATORS:
                        public = True
                if context.nest_global_auth:
                    auth.add("APP_GUARD")
                path = "/" + "/".join(p.strip("/") for p in (base, sub) if p and p.strip("/"))
                if context.nest_middleware_covers(path, method, text(field(cls, "name"))):
                    auth.add("middleware")
                method_name = text(field(member, "name"))
                routes.append(
                    Route(
                        framework=self.name,
                        method=method,
                        path=path,
                        name=f"{text(field(cls, 'name'))}.{method_name}",
                        line=line(member),
                        node=member,
                        auth=frozenset(auth),
                        public=public,
                    )
                )
        return routes
