from __future__ import annotations

import ast

from silentbug_lite.frameworks.base import Route, looks_like_auth
from silentbug_lite.lang import PYTHON_ONLY
from silentbug_lite.lang.python import FUNCTIONS, dotted
from silentbug_lite.models import ParsedModule

_SHORTCUTS = {"get", "post", "put", "patch", "delete"}
_PUBLIC_MARKERS = ("public", "allow_anonymous", "no_auth", "exempt_auth")


def _methods(dec: ast.Call) -> str:
    attr = dec.func.attr.lower() if isinstance(dec.func, ast.Attribute) else ""
    if attr in _SHORTCUTS:
        return attr.upper()
    for keyword in dec.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
            values = [
                e.value.upper()
                for e in keyword.value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
            if values:
                # The most dangerous declared method decides how the route is judged.
                for method in ("DELETE", "PUT", "PATCH", "POST"):
                    if method in values:
                        return method
                return values[0]
    return "GET"


def _guarded_blueprints(tree: ast.AST) -> set[str]:
    """`@bp.before_request` hooks that check auth protect every route on `bp`."""
    guarded: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, FUNCTIONS):
            continue
        for dec in node.decorator_list:
            name = dotted(dec)
            if not name.endswith("before_request"):
                continue
            body = ast.unparse(node).lower()
            if any(
                hint in body for hint in ("current_user", "abort(401", "abort(403", "auth", "login")
            ):
                guarded.add(name.rsplit(".", 1)[0] if "." in name else "")
    return guarded


class FlaskAdapter:
    name = "flask"
    languages = PYTHON_ONLY

    def routes(self, module: ParsedModule) -> list[Route]:
        guarded = _guarded_blueprints(module.tree)
        routes: list[Route] = []
        for node in ast.walk(module.tree):
            if not isinstance(node, FUNCTIONS):
                continue
            route_dec: ast.Call | None = None
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and (dec.func.attr == "route" or dec.func.attr in _SHORTCUTS)
                ):
                    route_dec = dec
                    break
            if route_dec is None:
                continue
            others = [dotted(d) for d in node.decorator_list if d is not route_dec]
            owner = dotted(route_dec.func).rsplit(".", 1)[0]
            auth = {name.split(".")[-1] for name in others if looks_like_auth(name)}
            if owner in guarded:
                auth.add(f"{owner}.before_request")
            path = ""
            if route_dec.args and isinstance(route_dec.args[0], ast.Constant):
                path = str(route_dec.args[0].value)
            routes.append(
                Route(
                    framework=self.name,
                    method=_methods(route_dec),
                    path=path,
                    name=node.name,
                    line=node.lineno,
                    node=node,
                    auth=frozenset(auth),
                    public=any(m in n.lower() for n in others for m in _PUBLIC_MARKERS),
                )
            )
        return routes
