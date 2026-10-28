from __future__ import annotations

import json
from pathlib import Path

PYTHON_IMPORTS = {
    "fastapi": "fastapi",
    "starlette": "fastapi",
    "flask": "flask",
    "django": "django",
    "rest_framework": "django",
}
JS_PACKAGES = {
    "express": "express",
    "next": "nextjs",
    "@nestjs/core": "nestjs",
    "@nestjs/common": "nestjs",
    "react": "react",
    "react-dom": "react",
}


def frameworks_from_python_imports(roots: set[str]) -> set[str]:
    return {PYTHON_IMPORTS[root] for root in roots if root in PYTHON_IMPORTS}


def frameworks_from_js_imports(specifiers: set[str]) -> set[str]:
    found = set()
    for spec in specifiers:
        if spec in JS_PACKAGES:
            found.add(JS_PACKAGES[spec])
        elif spec.startswith("next/"):
            found.add("nextjs")
        elif spec.startswith("@nestjs/"):
            found.add("nestjs")
    return found


def package_json_frameworks(root: Path) -> set[str]:
    """Frameworks declared in the root package.json (dependencies of any kind)."""
    path = root / "package.json"
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return set()
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            names |= set(section)
    return frameworks_from_js_imports(names)


def nextjs_route_file(rel: str) -> bool:
    """Next.js API handlers live in pages/api/** or App Router route.(ts|js) files."""
    parts = rel.split("/")
    if "pages" in parts:
        index = parts.index("pages")
        if len(parts) > index + 1 and parts[index + 1] == "api":
            return True
    return parts[-1].split(".")[0] == "route" and "app" in parts
