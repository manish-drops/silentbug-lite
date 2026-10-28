"""Framework adapters: every framework's routes described one way (Route).

Adapters run for the frameworks a file imports. When none is detected, every adapter for
the file's language runs on code shape alone, and duplicate routes are dropped.
"""

from __future__ import annotations

from silentbug_lite.frameworks.base import FrameworkAdapter, Route
from silentbug_lite.models import ParsedModule

__all__ = ["FrameworkAdapter", "Route", "adapters", "routes_for"]


def adapters() -> list[FrameworkAdapter]:
    from silentbug_lite.frameworks.django import DjangoAdapter
    from silentbug_lite.frameworks.express import ExpressAdapter
    from silentbug_lite.frameworks.fastapi import FastAPIAdapter
    from silentbug_lite.frameworks.flask import FlaskAdapter
    from silentbug_lite.frameworks.nestjs import NestAdapter
    from silentbug_lite.frameworks.nextjs import NextAdapter

    return [FastAPIAdapter(), FlaskAdapter(), DjangoAdapter(), ExpressAdapter(), NextAdapter(),
            NestAdapter()]


def routes_for(module: ParsedModule) -> list[Route]:
    candidates = [a for a in adapters() if module.language in a.languages]
    if module.frameworks:
        candidates = [a for a in candidates if a.name in module.frameworks]
    routes: list[Route] = []
    seen: set[int] = set()
    for adapter in candidates:
        for route in adapter.routes(module):
            if route.line in seen:
                continue
            seen.add(route.line)
            routes.append(route)
    return sorted(routes, key=lambda r: r.line)
