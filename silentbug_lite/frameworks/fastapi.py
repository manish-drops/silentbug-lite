from __future__ import annotations

import ast
import re

from silentbug_lite.frameworks import project
from silentbug_lite.frameworks.base import Route, looks_like_auth
from silentbug_lite.lang import PYTHON_ONLY
from silentbug_lite.lang.python import FUNCTIONS, dotted
from silentbug_lite.models import ParsedModule

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_DEPENDENCY_CALLS = {"Depends", "Security"}


def route_method(dec: ast.expr) -> str | None:
    """The HTTP method for `@router.get(...)`-shaped decorators."""
    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
        return None
    if dec.func.attr.lower() not in HTTP_METHODS:
        return None
    return dec.func.attr.lower()


def dependency_names(node: ast.AST | None) -> set[str]:
    """Every `Depends(x)` / `Security(x)` target reachable from this expression."""
    names: set[str] = set()
    if node is None:
        return names
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if dotted(child.func).split(".")[-1] not in _DEPENDENCY_CALLS:
            continue
        if child.args:
            resolved = dotted(child.args[0])
            if resolved:
                names.add(resolved.split(".")[-1])
    return names


def _router_dependencies(tree: ast.AST) -> dict[str, set[str]]:
    """`router = APIRouter(dependencies=[Depends(auth)])`: every route on it is protected."""
    routers: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if dotted(node.value.func).split(".")[-1] not in {"APIRouter", "FastAPI"}:
            continue
        deps: set[str] = set()
        for keyword in node.value.keywords:
            if keyword.arg == "dependencies":
                deps |= dependency_names(keyword.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                routers[target.id] = deps
    return routers


def _local_aliases(tree: ast.AST) -> dict[str, str]:
    """`CurrentUser = Annotated[User, Depends(get_current_user)]` in this module."""
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if isinstance(target, ast.Name) and isinstance(value, ast.Subscript):
            if dotted(value.value).split(".")[-1] == "Annotated":
                deps = dependency_names(value)
                if deps:
                    found[target.id] = sorted(deps)[0]
    return found


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _annotation_dependencies(func: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Dependencies declared through parameter annotations: inline `Annotated[..., Depends(x)]`,
    a known alias, or an alias whose own name says what it is (`CurrentUser`)."""
    names: set[str] = set()
    args = func.args  # type: ignore[attr-defined]
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        annotation = arg.annotation
        if annotation is None:
            continue
        names |= dependency_names(annotation)
        alias = dotted(annotation).split(".")[-1]
        if alias in aliases:
            names.add(aliases[alias].split(".")[-1])
        elif alias and alias[0].isupper() and looks_like_auth(_snake(alias)):
            names.add(_snake(alias))
    return names


def _path(dec: ast.Call) -> str:
    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
        return dec.args[0].value
    return ""


class FastAPIAdapter:
    name = "fastapi"
    languages = PYTHON_ONLY

    def routes(self, module: ParsedModule) -> list[Route]:
        routers = _router_dependencies(module.tree)
        aliases = dict(project.current().fastapi_aliases) | _local_aliases(module.tree)
        routes: list[Route] = []
        for node in ast.walk(module.tree):
            if not isinstance(node, FUNCTIONS):
                continue
            for dec in node.decorator_list:
                method = route_method(dec)
                if method is None:
                    continue
                assert isinstance(dec, ast.Call)
                names: set[str] = set()
                for default in list(node.args.defaults) + list(node.args.kw_defaults):
                    names |= dependency_names(default)
                names |= _annotation_dependencies(node, aliases)
                for keyword in dec.keywords:
                    if keyword.arg == "dependencies":
                        names |= dependency_names(keyword.value)
                owner = dotted(dec.func).split(".")[0]
                names |= routers.get(owner, set())
                routes.append(
                    Route(
                        framework=self.name,
                        method=method.upper(),
                        path=_path(dec),
                        name=node.name,
                        line=node.lineno,
                        node=node,
                        auth=frozenset(n for n in names if looks_like_auth(n)),
                    )
                )
                break
        return routes
