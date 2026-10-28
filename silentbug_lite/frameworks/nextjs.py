"""Next.js API handlers: `pages/api/**` default exports, App Router `route.ts`
method exports, and Server Actions (`"use server"` functions, which anyone can
call with a POST). Auth comes from a session check in the handler, or from
`middleware.ts` matchers covering the route (see frameworks/project.py)."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from silentbug_lite.frameworks import project
from silentbug_lite.frameworks.base import Route, looks_like_auth
from silentbug_lite.frameworks.detect import nextjs_route_file
from silentbug_lite.lang import JS_FAMILY
from silentbug_lite.lang.javascript import FUNCTIONS, callee, directives, field, line, text, walk
from silentbug_lite.models import ParsedModule

HTTP_EXPORTS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
SESSION_CALLS = {"getServerSession", "getSession", "auth", "currentUser", "getToken", "getAuth",
                 "verifySession", "requireUser", "requireAuth", "validateRequest", "getUser",
                 "withAuth", "withApiAuthRequired", "getKindeServerSession"}


def route_path(rel: str) -> str:
    """`app/api/admin/users/[id]/route.ts` → `/api/admin/users/:id`."""
    parts = list(PurePosixPath(rel).parts)
    if "pages" in parts:
        parts = parts[parts.index("pages") + 1 :]
        parts[-1] = PurePosixPath(parts[-1]).stem
        if parts[-1] == "index":
            parts = parts[:-1]
    elif "app" in parts:
        parts = parts[parts.index("app") + 1 : -1]
    segments = []
    for part in parts:
        if part.startswith("(") and part.endswith(")"):
            continue  # route groups don't appear in the URL
        segments.append(re.sub(r"^\[\.{0,3}([^\]]+)\]$", r":\1", part))
    return "/" + "/".join(segments)


def _auth_in(fn: Any) -> set[str]:
    found = set()
    for node in walk(fn):
        if node.type == "call_expression":
            name = callee(node).split(".")[-1]
            if name in SESSION_CALLS or looks_like_auth(name):
                found.add(name)
    return found


def _covered(path: str) -> bool:
    context = project.current()
    return context.next_middleware_all or any(p.match(path) for p in context.next_middleware)


class NextAdapter:
    name = "nextjs"
    languages = JS_FAMILY

    def routes(self, module: ParsedModule) -> list[Route]:
        actions = _server_actions(module, self.name)
        if not nextjs_route_file(module.file):
            return actions
        root = module.tree.root_node
        path = route_path(module.file)
        pages = "pages" in PurePosixPath(module.file).parts
        handlers: list[tuple[str, Any, Any]] = []  # (method, handler function, anchor node)
        for node in root.named_children:
            if node.type != "export_statement":
                continue
            declaration = field(node, "declaration")
            is_default = any(child.type == "default" for child in node.children)
            if pages and is_default:
                value = declaration or next((c for c in node.named_children), None)
                if value is not None and value.type == "call_expression":
                    # export default withAuth(handler)
                    wrapper = callee(value)
                    fn = value
                    handlers.append(("ANY", fn, node if wrapper not in SESSION_CALLS else None))
                elif value is not None:
                    handlers.append(("ANY", value, node))
                continue
            if declaration is None:
                continue
            if declaration.type == "function_declaration":
                name = text(field(declaration, "name"))
                if name in HTTP_EXPORTS:
                    handlers.append((name, declaration, node))
            elif declaration.type == "lexical_declaration":
                for declarator in declaration.named_children:
                    name = text(field(declarator, "name"))
                    value = field(declarator, "value")
                    if name in HTTP_EXPORTS and value is not None:
                        handlers.append((name, value, node))
        routes = []
        for method, fn, anchor in handlers:
            if anchor is None:
                auth = {"wrapper"}
                anchor = fn
            else:
                auth = _auth_in(fn)
            if _covered(path):
                auth.add("middleware.ts")
            routes.append(
                Route(
                    framework=self.name,
                    method=method,
                    path=path,
                    name=f"{method} {path}",
                    line=line(anchor),
                    node=anchor,
                    auth=frozenset(auth),
                )
            )
        return routes + actions


def _function_value(node: Any) -> Any:
    """The function behind `function f() {}` or `const f = async () => {}`."""
    if node.type == "function_declaration":
        return node
    if node.type == "lexical_declaration":
        for declarator in node.named_children:
            value = field(declarator, "value")
            if value is not None and value.type in FUNCTIONS:
                return value
    return None


def _declared_name(node: Any, fn: Any) -> str:
    if node.type == "function_declaration":
        return text(field(node, "name"))
    if node.type == "lexical_declaration" and node.named_children:
        return text(field(node.named_children[0], "name"))
    return text(field(fn, "name")) or "action"


def _server_actions(module: ParsedModule, framework: str) -> list[Route]:
    """Server Actions: exported functions of a `"use server"` file, and functions whose
    body starts with `"use server"`. Each one is a public POST endpoint."""
    root = module.tree.root_node
    found: list[tuple[str, Any, Any]] = []  # (name, function, anchor)
    if "use server" in directives(root):
        for node in root.named_children:
            if node.type != "export_statement":
                continue
            declaration = field(node, "declaration")
            fn = _function_value(declaration) if declaration is not None else None
            if fn is not None:
                found.append((_declared_name(declaration, fn), fn, node))
    seen = {f.id for _, f, _ in found}
    for node in walk(root):
        if node.type not in FUNCTIONS or node.id in seen:
            continue
        body = field(node, "body")
        if body is None or body.type != "statement_block" or "use server" not in directives(body):
            continue
        parent = node.parent
        declarator = parent is not None and parent.type == "variable_declarator"
        anchor = parent.parent if declarator else node
        if anchor is not None and anchor.type == "lexical_declaration":
            name = text(field(parent, "name"))
        else:
            name = text(field(node, "name")) or "action"
        found.append((name, node, anchor if anchor is not None else node))
    covered = project.current().next_middleware_all
    routes = []
    for name, fn, anchor in found:
        auth = _auth_in(fn)
        if covered:
            auth.add("middleware.ts")
        routes.append(
            Route(
                framework=framework,
                method="POST",
                path="",
                name=f"server action {name}",
                line=line(anchor),
                node=anchor,
                auth=frozenset(auth),
            )
        )
    return routes

