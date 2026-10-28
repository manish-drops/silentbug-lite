"""Check: a route with no login check. Two rules report under it:

- auth.unprotected-route: a route without the auth check the rest of its file uses. It
  compares each route with its neighbours, so a deliberately public router reports nothing.
- auth.destructive-no-auth: a route that changes or deletes data and has no auth check at
  all, even in a file with no auth anywhere.

Routes come from the framework adapters: FastAPI, Flask, Django, Express, Next.js, NestJS.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from typing import Any

from silentbug_lite.frameworks import Route, routes_for
from silentbug_lite.frameworks.base import DESTRUCTIVE_METHODS, DESTRUCTIVE_WORDS
from silentbug_lite.lang import ALL_LANGUAGES
from silentbug_lite.lang.javascript import js_finding
from silentbug_lite.lang.python import py_finding
from silentbug_lite.models import Finding, Language, ParsedModule

UNPROTECTED = "auth.unprotected-route"
DESTRUCTIVE = "auth.destructive-no-auth"

MIN_ROUTES = 3  # fewer routes than this say nothing about the file's usual auth
PREVALENCE = 0.6  # share of routes that must use an auth check for it to be "usual"
_STRONGER = ("admin", "superuser", "staff", "role", "permission", "scope", "owner")
# Flows that are public by design, even when their names sound destructive.
_PUBLIC_FLOWS = ("password", "forgot", "login", "logout", "signin", "signup", "register",
                 "verify", "confirm", "webhook", "unsubscribe")


def _finding(rule_id: str, module: ParsedModule, node: Any, message: str, line: int) -> Finding:
    build = py_finding if module.language == Language.PYTHON.value else js_finding
    return build(rule_id, module, node, message, line=line, before=1, after=3)


def _public_flow(name: str, path: str) -> bool:
    text = f"{name} {path}".lower()
    return any(flow in text for flow in _PUBLIC_FLOWS)


def destructive_word(name: str, path: str) -> str | None:
    if _public_flow(name, path):
        return None
    text = f"{name} {path}".lower()
    return next((word for word in DESTRUCTIVE_WORDS if word in text), None)


class UnprotectedRoute:
    id = UNPROTECTED
    languages = ALL_LANGUAGES

    def run(self, module: ParsedModule) -> Iterator[Finding]:
        routes = routes_for(module)
        if len(routes) < MIN_ROUTES:
            return
        counts: Counter[str] = Counter()
        for route in routes:
            counts.update(route.auth)
        threshold = len(routes) * PREVALENCE
        prevailing = {name for name, count in counts.items() if count >= threshold}
        if not prevailing:
            return
        for route in routes:
            if route.public or route.auth & prevailing or _public_flow(route.name, route.path):
                continue
            if route.framework != "fastapi" and route.auth:
                # Outside FastAPI's single dependency style, decorators and permission
                # classes mix freely: any auth marker counts as protected.
                continue
            if any(word in name.lower() for name in route.auth for word in _STRONGER):
                continue  # an admin or permission check is stricter than the usual one
            yield _finding(
                self.id,
                module,
                route.node,
                f"{route.method} route {route.name!r} has none of the auth checks the other "
                f"routes in this file use ({', '.join(sorted(prevailing))}).",
                route.line,
            )


class DestructiveNoAuth:
    id = DESTRUCTIVE
    languages = ALL_LANGUAGES

    def run(self, module: ParsedModule) -> Iterator[Finding]:
        for route in routes_for(module):
            if not _unguarded_change(route):
                continue
            word = destructive_word(route.name, route.path) or "DELETE"
            what = f"{route.method} {route.path or route.name}".strip()
            yield _finding(
                self.id,
                module,
                route.node,
                f"{what} changes or deletes data ({word}) and has no auth check, so anyone who "
                "can reach it can call it.",
                route.line,
            )


def _unguarded_change(route: Route) -> bool:
    if route.public or route.auth or route.method not in DESTRUCTIVE_METHODS:
        return False
    return route.method == "DELETE" or destructive_word(route.name, route.path) is not None
