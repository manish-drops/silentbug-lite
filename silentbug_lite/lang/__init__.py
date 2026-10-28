"""Language layer: source files become ParsedModules (Python through `ast`, JavaScript and
TypeScript through tree-sitter). Nothing here imports or runs the code it reads."""

from __future__ import annotations

from silentbug_lite.models import Language

SUFFIX_LANGUAGE: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".cts": Language.TYPESCRIPT,
}

JS_FAMILY = frozenset({Language.JAVASCRIPT.value, Language.TYPESCRIPT.value})
PYTHON_ONLY = frozenset({Language.PYTHON.value})
ALL_LANGUAGES = PYTHON_ONLY | JS_FAMILY
