from __future__ import annotations

import ast

from silentbug_lite.frameworks.base import Route, looks_like_auth
from silentbug_lite.lang import PYTHON_ONLY
from silentbug_lite.lang.python import FUNCTIONS, dotted
from silentbug_lite.models import ParsedModule

_VIEW_BASES = (
    "View",
    "APIView",
    "ViewSet",
    "ModelViewSet",
    "GenericViewSet",
    "ReadOnlyModelViewSet",
    "GenericAPIView",
    "CreateAPIView",
    "UpdateAPIView",
    "DestroyAPIView",
    "ListCreateAPIView",
    "RetrieveUpdateDestroyAPIView",
    "RetrieveDestroyAPIView",
    "RetrieveUpdateAPIView",
    "FormView",
    "CreateView",
    "UpdateView",
    "DeleteView",
    "TemplateView",
    "DetailView",
    "ListView",
    "RedirectView",
)
_AUTH_MIXINS = ("LoginRequiredMixin", "PermissionRequiredMixin", "UserPassesTestMixin")
_HANDLER_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "create",
    "update",
    "partial_update",
    "destroy",
    "list",
    "retrieve",
}
_METHOD_OF = {
    "create": "POST",
    "update": "PUT",
    "partial_update": "PATCH",
    "destroy": "DELETE",
    "list": "GET",
    "retrieve": "GET",
}


def _names_in(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    return [dotted(n) for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute))]


def _class_attr(cls: ast.ClassDef, attr: str) -> ast.expr | None:
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == attr:
                    return stmt.value
    return None


def _decorator_methods(decorators: list[ast.expr]) -> str:
    for dec in decorators:
        name = dotted(dec).split(".")[-1]
        if name.startswith("require_") and name[8:].upper() in {"GET", "POST", "SAFE"}:
            return "GET" if name[8:].upper() in {"GET", "SAFE"} else "POST"
        if name in {"require_http_methods", "api_view"} and isinstance(dec, ast.Call) and dec.args:
            arg = dec.args[0]
            if isinstance(arg, (ast.List, ast.Tuple)):
                values = [e.value.upper() for e in arg.elts if isinstance(e, ast.Constant)]
                for method in ("DELETE", "PUT", "PATCH", "POST"):
                    if method in values:
                        return method
                if values:
                    return values[0]
    return "ANY"


def _permission_markers(value: ast.expr | None) -> tuple[set[str], bool]:
    names = {n.split(".")[-1] for n in _names_in(value)}
    public = "AllowAny" in names
    auth = {n for n in names if n != "AllowAny" and (n.startswith("Is") or looks_like_auth(n))}
    return auth, public


def _takes_request(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = func.args.posonlyargs + func.args.args
    return bool(args) and args[0].arg == "request"


class DjangoAdapter:
    name = "django"
    languages = PYTHON_ONLY

    def routes(self, module: ParsedModule) -> list[Route]:
        routes: list[Route] = []
        methods_in_classes: set[int] = set()
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ClassDef):
                bases = [dotted(b).split(".")[-1] for b in node.bases]
                if not any(b in _VIEW_BASES or b.endswith(("View", "ViewSet")) for b in bases):
                    continue
                auth = {b for b in bases if b in _AUTH_MIXINS}
                perm_auth, public = _permission_markers(_class_attr(node, "permission_classes"))
                auth |= perm_auth
                auth |= {
                    dotted(d).split(".")[-1]
                    for d in node.decorator_list
                    if looks_like_auth(dotted(d))
                }
                for stmt in node.body:
                    if isinstance(stmt, FUNCTIONS) and stmt.name in _HANDLER_METHODS:
                        methods_in_classes.add(id(stmt))
                        method_auth = set(auth) | {
                            dotted(d).split(".")[-1]
                            for d in stmt.decorator_list
                            if looks_like_auth(dotted(d))
                        }
                        routes.append(
                            Route(
                                framework=self.name,
                                method=_METHOD_OF.get(stmt.name, stmt.name.upper()),
                                path="",
                                name=f"{node.name}.{stmt.name}",
                                line=stmt.lineno,
                                node=stmt,
                                auth=frozenset(method_auth),
                                public=public,
                            )
                        )
        for node in ast.walk(module.tree):
            if not isinstance(node, FUNCTIONS) or id(node) in methods_in_classes:
                continue
            decorators = [dotted(d) for d in node.decorator_list]
            is_view = _takes_request(node) and (
                any(
                    d.split(".")[-1] in {"api_view", "require_http_methods"}
                    or d.split(".")[-1].startswith("require_")
                    or looks_like_auth(d)
                    for d in decorators
                )
                or module.file.endswith("views.py")
            )
            if not is_view:
                continue
            auth = {d.split(".")[-1] for d in decorators if looks_like_auth(d)}
            public = False
            for dec in node.decorator_list:
                if dotted(dec).split(".")[-1] == "permission_classes" and isinstance(dec, ast.Call):
                    perm_auth, public = _permission_markers(dec.args[0] if dec.args else None)
                    auth |= perm_auth
            routes.append(
                Route(
                    framework=self.name,
                    method=_decorator_methods(node.decorator_list),
                    path="",
                    name=node.name,
                    line=node.lineno,
                    node=node,
                    auth=frozenset(auth),
                    public=public,
                )
            )
        return routes
