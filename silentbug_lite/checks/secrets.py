"""Check: an API key, token or password written into the source (config.hardcoded-secret).

Known key shapes (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, ...) always count. Anything
else needs a secret-sounding name plus a random-looking value, and stays quiet in test files,
where fake keys are normal.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any

from silentbug_lite.lang import ALL_LANGUAGES
from silentbug_lite.lang import javascript as js
from silentbug_lite.lang.python import dotted, py_finding
from silentbug_lite.models import Finding, Language, ParsedModule
from silentbug_lite.secrets import (
    find_secrets,
    is_placeholder,
    looks_high_entropy,
    looks_like_a_name,
    mask,
    redact,
)

RULE = "config.hardcoded-secret"

SECRET_NAME = re.compile(
    r"(?i)(api[_-]?key|secret|token|passw(or)?d|pwd|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|auth[_-]?key|signing[_-]?key|webhook[_-]?secret|credentials?)"
)
_GENERIC_KINDS = {"assigned_secret", "env_secret"}  # shapes that need a name to count


def is_test_path(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    name = parts[-1] if parts else ""
    return (
        any(
            p in {"tests", "test", "__tests__", "spec", "testing", "mocks", "__mocks__", "e2e"}
            for p in parts[:-1]
        )
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js", ".test.tsx"))
    )


def secret_kind(value: str, name: str, in_test: bool) -> str | None:
    """The kind of secret this literal is, or None."""
    for match in find_secrets(value):
        if match.kind not in _GENERIC_KINDS:
            return match.kind
    if in_test or not name or not SECRET_NAME.search(name):
        return None
    if is_placeholder(value) or len(value) < 8 or looks_like_a_name(value):
        return None  # a placeholder, or a name or URL like "https://auth.example.com/token"
    if looks_high_entropy(value) or (any(c.isdigit() for c in value) and len(value) >= 12):
        return "hardcoded_secret"
    return None


class HardcodedSecret:
    id = RULE
    languages = ALL_LANGUAGES

    def run(self, module: ParsedModule) -> Iterator[Finding]:
        if module.language == Language.PYTHON.value:
            yield from _python(module)
        else:
            yield from _javascript(module)


_LABELS = {
    "anthropic_key": "Anthropic API key",
    "openai_key": "OpenAI API key",
    "aws_access_key": "AWS access key",
    "github_token": "GitHub token",
    "github_pat": "GitHub token",
    "slack_token": "Slack token",
    "stripe_key": "Stripe secret key",
    "google_api_key": "Google API key",
    "huggingface_token": "Hugging Face token",
    "sendgrid_key": "SendGrid API key",
    "jwt": "JSON Web Token",
    "private_key": "private key",
    "url_credentials": "password inside a URL",
    "hardcoded_secret": "secret",
}


def _message(kind: str, name: str) -> str:
    label = _LABELS.get(kind, kind.replace("_", " "))
    article = "An" if label[0].lower() in "aeiou" else "A"
    where = f" ({name})" if name else ""
    return (
        f"{article} {label} is written into the code{where}. Anyone who can read the code "
        "has it."
    )


def _masked(finding: Finding, value: str) -> Finding:
    """Never keep the key in the snippet, even when its shape isn't one the redaction
    patterns know (those keep a recognisable prefix: `sk-ant-****abcd`)."""
    snippet = redact(finding.snippet)
    if value and value in snippet:
        snippet = snippet.replace(value, mask(value))
    return replace(finding, snippet=snippet)


# --- Python ---------------------------------------------------------------------


def _named_strings(tree: ast.AST) -> Iterator[tuple[str, ast.Constant]]:
    """(name, literal) for every string bound to a name, keyword, dict key or default."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                for target in targets:
                    yield dotted(target), value
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    yield keyword.arg or "", keyword.value
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    yield key.value, value
        elif isinstance(node, ast.arguments):
            positional = node.posonlyargs + node.args
            for arg, default in zip(
                positional[len(positional) - len(node.defaults) :], node.defaults, strict=True
            ):
                if isinstance(default, ast.Constant) and isinstance(default.value, str):
                    yield arg.arg, default


def _python(module: ParsedModule) -> Iterator[Finding]:
    in_test = is_test_path(module.file)
    seen: set[int] = set()
    for name, literal in _named_strings(module.tree):
        if id(literal) in seen:
            continue
        kind = secret_kind(literal.value, name, in_test)
        if kind is None:
            continue
        seen.add(id(literal))
        finding = py_finding(RULE, module, literal, _message(kind, name), before=1, after=1)
        yield _masked(finding, literal.value)
    # Known key shapes in strings that aren't bound to a name (f-strings, lists, ...).
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in seen:
            continue
        matches = [m for m in find_secrets(node.value) if m.kind not in _GENERIC_KINDS]
        if matches:
            seen.add(id(node))
            finding = py_finding(RULE, module, node, _message(matches[0].kind, ""), before=1)
            yield _masked(finding, node.value)


# --- JavaScript / TypeScript --------------------------------------------------------


def _js_named_strings(root: Any) -> Iterator[tuple[str, Any]]:
    for node in js.walk(root):
        if node.type == "variable_declarator":
            value = js.field(node, "value")
            if value is not None and js.string_value(value) is not None:
                yield js.text(js.field(node, "name")), value
        elif node.type == "pair":
            value = js.field(node, "value")
            if value is not None and js.string_value(value) is not None:
                key = js.field(node, "key")
                name = js.string_value(key) if key is not None and key.type == "string" else None
                yield (name if name is not None else js.text(key)), value
        elif node.type == "assignment_expression":
            value = js.field(node, "right")
            if value is not None and js.string_value(value) is not None:
                yield js.dotted(js.field(node, "left")), value


def _javascript(module: ParsedModule) -> Iterator[Finding]:
    in_test = is_test_path(module.file)
    for name, literal in _js_named_strings(module.tree.root_node):
        value = js.string_value(literal) or ""
        kind = secret_kind(value, name, in_test)
        if kind is None:
            continue
        finding = js.js_finding(RULE, module, literal, _message(kind, name), before=1, after=1)
        yield _masked(finding, value)
