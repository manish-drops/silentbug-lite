"""Secret detection and masking. The hardcoded-secret check uses it to find keys, and every
report uses it so that a found key is never printed in full (`sk-****abcd`)."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

_MIN_PARTIAL_LENGTH = 16


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern[str]
    prefix: str
    group: int
    min_entropy: float


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    start: int
    end: int
    value: str
    prefix: str


@dataclass(frozen=True)
class _Config:
    patterns: tuple[SecretPattern, ...]
    placeholders: tuple[str, ...]
    min_length: int
    min_entropy: float
    default_passwords: frozenset[str]


@lru_cache(maxsize=1)
def _config() -> _Config:
    raw = json.loads(
        resources.files("silentbug_lite")
        .joinpath("data/secret_patterns.json")
        .read_text(encoding="utf-8")
    )
    patterns = tuple(
        SecretPattern(
            kind=p["kind"],
            regex=re.compile(p["regex"]),
            prefix=p.get("prefix", ""),
            group=int(p.get("group", 0)),
            min_entropy=float(p.get("min_entropy", 0.0)),
        )
        for p in raw["patterns"]
    )
    return _Config(
        patterns=patterns,
        placeholders=tuple(word.lower() for word in raw["placeholders"]),
        min_length=int(raw["high_entropy"]["min_length"]),
        min_entropy=float(raw["high_entropy"]["min_entropy"]),
        default_passwords=frozenset(w.lower() for w in raw.get("default_passwords", [])),
    )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(word in lowered for word in _config().placeholders):
        return True
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%", value):
        return True  # a reference to a variable ($TOKEN, ${TOKEN}, %TOKEN%), not a value
    return len(set(value)) <= 2  # "xxxxxxxx", "00000000"


def looks_like_a_name(value: str) -> bool:
    """`TOKEN_TYPE = "access_token"` names a thing; it isn't a secret."""
    return bool(re.fullmatch(r"[a-z_\-.,]+|[A-Z_\-.,]+|https?://[^:@\s]*", value))


def looks_high_entropy(value: str) -> bool:
    """For key shapes no pattern knows: long, random-looking, mixed character classes."""
    config = _config()
    if len(value) < config.min_length or " " in value or is_placeholder(value):
        return False
    classes = sum(
        bool(re.search(pattern, value))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    return classes >= 3 and shannon_entropy(value) >= config.min_entropy


def find_secrets(text: str) -> list[SecretMatch]:
    """Every secret in `text`, non-overlapping, earliest first."""
    config = _config()
    found: list[SecretMatch] = []
    for pattern in config.patterns:
        for match in pattern.regex.finditer(text):
            start, end = match.span(pattern.group)
            if start < 0:
                continue
            value = text[start:end]
            if is_placeholder(value):
                continue
            if pattern.kind == "url_credentials" and value.lower() in config.default_passwords:
                continue  # guest:guest@localhost, postgres:postgres@db: local defaults
            if pattern.min_entropy and (
                shannon_entropy(value) < pattern.min_entropy or looks_like_a_name(value)
            ):
                continue
            found.append(SecretMatch(pattern.kind, start, end, value, pattern.prefix))
    found.sort(key=lambda m: (m.start, -(m.end - m.start)))
    result: list[SecretMatch] = []
    last_end = -1
    for match in found:
        if match.start >= last_end:
            result.append(match)
            last_end = match.end
    return result


def mask(value: str, prefix: str = "") -> str:
    if len(value) < _MIN_PARTIAL_LENGTH:
        return "****"
    shown = prefix if prefix and value.startswith(prefix) else ""
    return f"{shown}****{value[-4:]}"


def redact(text: str) -> str:
    """`text` with every secret in it masked, for anything a person or a tool will read."""
    if not text:
        return text
    matches = find_secrets(text)
    if not matches:
        return text
    out = []
    cursor = 0
    for match in matches:
        out.append(text[cursor : match.start])
        out.append(mask(match.value, match.prefix))
        cursor = match.end
    out.append(text[cursor:])
    return "".join(out)
