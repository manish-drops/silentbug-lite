"""Check: a paid LLM call made once per item in a loop (ai.llm-call-in-loop).

Which calls are LLM calls comes from `data/llm_signatures.json` (OpenAI, Anthropic, Gemini,
Ollama, LiteLLM, LangChain and the Vercel AI SDK), so adding an SDK is a data change.
Retry loops (`for attempt in range(3)`, `while`) don't count: only loops over data do.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

from silentbug_lite.lang import ALL_LANGUAGES
from silentbug_lite.lang import javascript as js
from silentbug_lite.lang.python import FUNCTIONS, dotted, py_finding
from silentbug_lite.models import Finding, Language, ParsedModule

RULE = "ai.llm-call-in-loop"


@dataclass(frozen=True)
class Signature:
    name: str
    language: str
    imports: tuple[str, ...]
    calls: tuple[str, ...]
    module_calls: bool = False  # `ollama.chat(...)`, `generateText(...)`: no client object
    clients: tuple[str, ...] = ()  # classes whose instances make the calls
    receiver_constructors: tuple[str, ...] = ()  # LangChain chat models


@lru_cache(maxsize=1)
def signatures() -> tuple[Signature, ...]:
    raw = json.loads(
        resources.files("silentbug_lite")
        .joinpath("data/llm_signatures.json")
        .read_text(encoding="utf-8")
    )
    return tuple(
        Signature(
            name=sdk["name"],
            language=sdk["language"],
            imports=tuple(sdk["imports"]),
            calls=tuple(sdk["calls"]),
            module_calls=bool(sdk.get("module_calls", False)),
            clients=tuple(sdk.get("clients", ())),
            receiver_constructors=tuple(sdk.get("receiver_constructors", ())),
        )
        for sdk in raw["sdks"]
    )


def signatures_for(language: str) -> list[Signature]:
    family = "javascript" if language in ("javascript", "typescript") else language
    return [s for s in signatures() if s.language == family]


@dataclass
class _Imports:
    sdks: set[str] = field(default_factory=set)  # names of imported SDK signatures
    module_alias: dict[str, Signature] = field(default_factory=dict)  # alias -> sdk
    functions: dict[str, tuple[Signature, str]] = field(default_factory=dict)  # name -> call
    constructors: dict[str, Signature] = field(default_factory=dict)  # class name -> sdk


def _match_shape(
    name: str,
    imports: _Imports,
    clients: dict[str, Signature],
    sigs: list[Signature],
) -> tuple[Signature, str] | None:
    """Which SDK call `name` is (`client.chat.completions.create`), if any."""
    if name in imports.functions:
        return imports.functions[name]
    for sig in sigs:
        if sig.name not in imports.sdks:
            continue
        for shape in sig.calls:
            if name != shape and not name.endswith("." + shape):
                continue
            receiver = name[: -len(shape)].rstrip(".")
            client = clients.get(receiver)
            if client is not None and client.name == sig.name:
                return sig, shape
            alias = imports.module_alias.get(receiver)
            if alias is not None and alias.name == sig.name:
                if sig.module_calls or "." in shape:
                    return sig, shape
            if "." in shape and not sig.receiver_constructors and receiver:
                return sig, shape  # a distinctive multi-part shape on an unknown receiver
    return None


def _message(sdk: str, call: str) -> str:
    return (
        f"{sdk} {call}() runs once per loop iteration, so cost and latency grow with the "
        "data."
    )


class LLMCallInLoop:
    id = RULE
    languages = ALL_LANGUAGES

    def run(self, module: ParsedModule) -> Iterator[Finding]:
        if module.language == Language.PYTHON.value:
            yield from _python(module)
        else:
            yield from _javascript(module)


# --- Python ---------------------------------------------------------------------


def _python_imports(tree: ast.AST, sigs: list[Signature]) -> _Imports:
    found = _Imports()

    def sdk_for(module: str) -> list[Signature]:
        return [
            s for s in sigs if any(module == i or module.startswith(i + ".") for i in s.imports)
        ]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for sig in sdk_for(alias.name):
                    found.sdks.add(sig.name)
                    found.module_alias[alias.asname or alias.name.split(".")[0]] = sig
                    if alias.asname is None and "." in alias.name:
                        found.module_alias[alias.name] = sig
        elif isinstance(node, ast.ImportFrom) and node.module:
            for sig in sdk_for(node.module):
                found.sdks.add(sig.name)
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name in sig.calls and sig.module_calls:
                        found.functions[local] = (sig, alias.name)
                    if alias.name in sig.clients or alias.name in sig.receiver_constructors:
                        found.constructors[local] = sig
                    elif alias.name in ("genai", "generativeai"):
                        found.module_alias[local] = sig  # from google import genai
    return found


def _python_clients(tree: ast.AST, imports: _Imports) -> dict[str, Signature]:
    """Variables (and self attributes) holding an SDK client or a chat model."""
    clients: dict[str, Signature] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if not isinstance(value, ast.Call):
            continue
        name = dotted(value.func)
        sig = imports.constructors.get(name)
        head, last = name.split(".")[0], name.split(".")[-1]
        if sig is None and head in imports.module_alias:
            candidate = imports.module_alias[head]
            if last in candidate.clients or last in candidate.receiver_constructors:
                sig = candidate
        if sig is None:
            continue
        for target in targets:
            if dotted(target):
                clients[dotted(target)] = sig
    return clients


def _constant_range(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and dotted(node.func) == "range"
        and all(isinstance(a, ast.Constant) for a in node.args)
    )


def _calls_in_loops(tree: ast.AST) -> set[int]:
    """ids of the Call nodes that run once per item of a loop over data."""
    looped: set[int] = set()

    def visit(node: ast.AST, in_loop: bool) -> None:
        if isinstance(node, ast.Call) and in_loop:
            looped.add(id(node))
        if isinstance(node, (*FUNCTIONS, ast.Lambda)):
            for child in ast.iter_child_nodes(node):
                visit(child, False)  # a function defined in a loop runs when it's called
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.target, in_loop)
            visit(node.iter, in_loop)
            data = not _constant_range(node.iter)  # `for attempt in range(5)` is a retry
            for stmt in [*node.body, *node.orelse]:
                visit(stmt, in_loop or data)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for index, gen in enumerate(node.generators):
                visit(gen.iter, in_loop if index == 0 else True)
                visit(gen.target, True)
                for cond in gen.ifs:
                    visit(cond, True)
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            for part in parts:
                visit(part, True)
            return
        # `while` loops are agents and retries, not "a call per item": no change here.
        for child in ast.iter_child_nodes(node):
            visit(child, in_loop)

    visit(tree, False)
    return looped


def _python(module: ParsedModule) -> Iterator[Finding]:
    sigs = signatures_for(Language.PYTHON.value)
    imports = _python_imports(module.tree, sigs)
    if not imports.sdks:
        return
    clients = _python_clients(module.tree, imports)
    looped = _calls_in_loops(module.tree)
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call) or id(node) not in looped:
            continue
        name = dotted(node.func)
        matched = _match_shape(name, imports, clients, sigs) if name else None
        if matched is None:
            continue
        sig, shape = matched
        yield py_finding(RULE, module, node, _message(sig.name, shape), before=2, after=2)


# --- JavaScript / TypeScript --------------------------------------------------------


def _sdk_for(spec: str, sigs: list[Signature]) -> list[Signature]:
    return [s for s in sigs if any(spec == i or spec.startswith(i + "/") for i in s.imports)]


def _record(local: str, imported: str, sig: Signature, found: _Imports) -> None:
    found.sdks.add(sig.name)
    if imported in sig.calls and sig.module_calls:
        found.functions[local] = (sig, imported)
    if imported in sig.clients or imported in sig.receiver_constructors:
        found.constructors[local] = sig


def _js_imports(root: Any, sigs: list[Signature]) -> _Imports:
    found = _Imports()
    for node in js.walk(root):
        if node.type == "import_statement":
            spec = js.string_value(node.child_by_field_name("source"))
            for sig in _sdk_for(spec, sigs) if spec else []:
                found.sdks.add(sig.name)
                for clause in node.named_children:
                    if clause.type == "import_clause":
                        _import_clause(clause, sig, found)
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is None or value.type != "call_expression" or js.callee(value) != "require":
                continue
            args = js.arguments(value)
            spec = js.string_value(args[0]) if args else None
            for sig in _sdk_for(spec, sigs) if spec else []:
                found.sdks.add(sig.name)
                name_node = node.child_by_field_name("name")
                if name_node is not None and name_node.type == "identifier":
                    local = js.text(name_node)
                    found.module_alias[local] = sig
                    if sig.clients:
                        found.constructors[local] = sig  # const OpenAI = require("openai")
                elif name_node is not None and name_node.type == "object_pattern":
                    for prop in name_node.named_children:
                        imported = js.text(prop).split(":")[0].strip()
                        local = js.text(prop).split(":")[-1].strip()
                        _record(local, imported, sig, found)
    return found


def _import_clause(clause: Any, sig: Signature, found: _Imports) -> None:
    for part in clause.named_children:
        if part.type == "identifier":  # default import: `import OpenAI from "openai"`
            local = js.text(part)
            found.module_alias[local] = sig
            if sig.clients or local in sig.receiver_constructors:
                found.constructors[local] = sig
        elif part.type == "namespace_import":
            ident = next((c for c in part.named_children if c.type == "identifier"), None)
            if ident is not None:
                found.module_alias[js.text(ident)] = sig
        elif part.type == "named_imports":
            for spec_node in part.named_children:
                if spec_node.type != "import_specifier":
                    continue
                imported = js.text(spec_node.child_by_field_name("name"))
                alias = spec_node.child_by_field_name("alias")
                _record(js.text(alias) if alias is not None else imported, imported, sig, found)


def _js_clients(root: Any, imports: _Imports) -> dict[str, Signature]:
    clients: dict[str, Signature] = {}
    for node in js.walk(root):
        if node.type == "assignment_expression":
            target, value = node.child_by_field_name("left"), node.child_by_field_name("right")
        elif node.type in ("variable_declarator", "public_field_definition"):
            target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        else:
            continue
        if value is None or value.type != "new_expression":
            continue
        constructor = js.dotted(value.child_by_field_name("constructor"))
        sig = imports.constructors.get(constructor) or imports.constructors.get(
            constructor.split(".")[-1]
        )
        if sig is None:
            continue
        name = js.dotted(target) or js.text(target)
        if node.type == "public_field_definition":
            name = f"this.{js.text(target)}"
        clients[name] = sig
    return clients


def _javascript(module: ParsedModule) -> Iterator[Finding]:
    sigs = signatures_for(module.language)
    root = module.tree.root_node
    imports = _js_imports(root, sigs)
    if not imports.sdks:
        return
    clients = _js_clients(root, imports)
    for node in js.walk(root):
        if node.type != "call_expression":
            continue
        name = js.callee(node)
        matched = _match_shape(name, imports, clients, sigs) if name else None
        if matched is None or not js.in_data_loop(node):
            continue
        sig, shape = matched
        yield js.js_finding(RULE, module, node, _message(sig.name, shape), before=2, after=2)
