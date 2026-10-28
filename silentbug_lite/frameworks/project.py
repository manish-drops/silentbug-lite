"""Project-wide facts that live outside the file being checked: Next.js middleware matchers,
NestJS global guards and middleware, and FastAPI `Annotated` auth aliases. Built once per
scan and read by the adapters through a context variable."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from silentbug_lite.frameworks.base import looks_like_auth, looks_like_rate_limit

_MIDDLEWARE_FILES = ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js")
_AUTH_WORDS = ("auth", "session", "token", "login", "signin", "unauthorized", "401", "clerk", "jwt")


@dataclass(frozen=True)
class ProjectContext:
    next_middleware: tuple[re.Pattern[str], ...] = ()  # paths the auth middleware covers
    next_middleware_all: bool = False  # auth middleware with no matcher: every path
    nest_global_auth: bool = False
    # `consumer.apply(AuthMiddleware).forRoutes(...)`: (path regex, method) pairs, controllers
    nest_middleware: tuple[tuple[re.Pattern[str], str], ...] = ()
    nest_middleware_controllers: frozenset[str] = frozenset()
    # FastAPI `CurrentUser = Annotated[User, Depends(get_current_user)]`: alias -> dependency
    fastapi_aliases: tuple[tuple[str, str], ...] = ()

    def nest_middleware_covers(self, path: str, method: str, controller: str) -> bool:
        if controller in self.nest_middleware_controllers:
            return True
        bare = path.strip("/")
        return any(
            regex.match(bare) and (allowed == "ALL" or allowed == method)
            for regex, allowed in self.nest_middleware
        )


_EMPTY = ProjectContext()
_PROJECT: ContextVar[ProjectContext | None] = ContextVar("silentbug_lite_project", default=None)


def current() -> ProjectContext:
    return _PROJECT.get() or _EMPTY


@contextmanager
def using(context: ProjectContext) -> Iterator[None]:
    token = _PROJECT.set(context)
    try:
        yield
    finally:
        _PROJECT.reset(token)


def _group_end(pattern: str, start: int) -> int:
    """Index of the `)` closing the group that opens at `start` (nesting and escapes aware)."""
    depth = 0
    i = start
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "(":
            depth += 1
        elif pattern[i] == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def matcher_regex(pattern: str) -> re.Pattern[str] | None:
    """Next.js matcher (path-to-regexp style) to regex: `/admin/:path*` -> `/admin(/.*)?`.
    None when the matcher can't be understood: the route then counts as not covered."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern[i] == ":":
            match = re.match(r":[A-Za-z_][A-Za-z0-9_]*([*+?])?", pattern[i:])
            if match:
                modifier = match.group(1)
                out = out.rstrip("/")
                if modifier in ("*", "?"):
                    out += "(?:/.*)?" if modifier == "*" else "(?:/[^/]+)?"
                elif modifier == "+":
                    out += "/.+"
                else:
                    out += "/[^/]+"
                i += len(match.group(0))
                continue
        if pattern[i] == "(":
            end = _group_end(pattern, i)
            if end != -1:
                out += pattern[i : end + 1]  # a custom regex group, used as written
                i = end + 1
                continue
        out += re.escape(pattern[i])
        i += 1
    try:
        return re.compile("^" + out + "$")
    except re.error:
        return None


def _matchers(source: str) -> list[str] | None:
    match = re.search(r"matcher\s*:\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")", source)
    if not match:
        return None
    found = re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))
    return [m.replace("\\\\", "\\") for m in found]  # JS string escapes: "\\." is \.


def _nest_path_regex(path: str) -> re.Pattern[str]:
    """`articles/:slug/comments` -> `^articles/[^/]+/comments$`; `*` and `(.*)` match all."""
    out = ""
    for part in re.split(r"(:[A-Za-z_][A-Za-z0-9_]*|\(\.\*\)|\*)", path.strip("/")):
        if part.startswith(":"):
            out += "[^/]+"
        elif part in ("*", "(.*)"):
            out += ".*"
        else:
            out += re.escape(part)
    return re.compile("^" + out + "$")


def _nest_middleware(source: str) -> tuple[list[tuple[re.Pattern[str], str]], set[str]]:
    """Routes an auth middleware is applied to in a NestJS module's `configure()`."""
    routes: list[tuple[re.Pattern[str], str]] = []
    controllers: set[str] = set()
    for match in re.finditer(r"\.apply\(([^)]*)\)[^;]*?\.forRoutes\(", source):
        if not any(looks_like_auth(n) for n in re.findall(r"[A-Za-z_]\w*", match.group(1))):
            continue
        start = match.end() - 1
        end = _group_end(source, start)
        args = source[start + 1 : end] if end != -1 else ""
        for obj in re.findall(r"\{[^}]*\}", args):
            path = re.search(r"path\s*:\s*['\"]([^'\"]*)['\"]", obj)
            method = re.search(r"method\s*:\s*RequestMethod\.(\w+)", obj)
            if path:
                allowed = method.group(1) if method else "ALL"
                routes.append((_nest_path_regex(path.group(1)), allowed))
        rest = re.sub(r"\{[^}]*\}", "", args)
        routes += [(_nest_path_regex(p), "ALL") for p in re.findall(r"['\"]([^'\"]+)['\"]", rest)]
        controllers |= set(re.findall(r"\b([A-Z]\w*Controller)\b", rest))
    return routes, controllers


_ANNOTATED_ALIAS = re.compile(
    r"^([A-Za-z_]\w*)\s*(?::\s*\w+\s*)?=\s*Annotated\[.*?(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)",
    re.M,
)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def build(root: Path, files: list[str]) -> ProjectContext:
    next_patterns: list[re.Pattern[str]] = []
    next_all = False
    for rel in _MIDDLEWARE_FILES:
        source = _read(root / rel) if (root / rel).is_file() else None
        if source is None or not any(word in source.lower() for word in _AUTH_WORDS):
            continue
        matchers = _matchers(source)
        if matchers is None:
            next_all = True
        else:
            next_patterns += [r for r in map(matcher_regex, matchers) if r is not None]
    nest_auth = False
    nest_routes: list[tuple[re.Pattern[str], str]] = []
    nest_controllers: set[str] = set()
    aliases: set[tuple[str, str]] = set()
    for rel in files:
        if rel.endswith(".py"):
            source = _read(root / rel)
            if source and "Annotated[" in source and "Depends(" in source:
                aliases |= set(_ANNOTATED_ALIAS.findall(source))
            continue
        if not rel.endswith((".ts", ".js")) or "node_modules" in rel:
            continue
        source = _read(root / rel)
        if source is None:
            continue
        if ".forRoutes(" in source:
            found_routes, found_controllers = _nest_middleware(source)
            nest_routes += found_routes
            nest_controllers |= found_controllers
        if "APP_GUARD" not in source and "useGlobalGuards" not in source:
            continue
        for guard in re.findall(r"(?:useClass\s*:\s*|new\s+)([A-Za-z_][A-Za-z0-9_]*)", source):
            if looks_like_rate_limit(guard):
                continue  # a global throttle guard protects nothing from strangers
            if looks_like_auth(guard) or guard.endswith("Guard"):
                nest_auth = True
    return ProjectContext(
        next_middleware=tuple(next_patterns),
        next_middleware_all=next_all,
        nest_global_auth=nest_auth,
        nest_middleware=tuple(nest_routes),
        nest_middleware_controllers=frozenset(nest_controllers),
        fastapi_aliases=tuple(sorted(aliases)),
    )
