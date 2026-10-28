from __future__ import annotations

from pathlib import Path

import pytest

from silentbug_lite.models import Finding
from silentbug_lite.scan import scan


def fake_key(prefix: str, length: int = 40) -> str:
    """A provider-shaped key built at run time, so no realistic key sits in the source
    (and secret scanners don't flag this repository)."""
    alphabet = "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St"
    return prefix + "".join(alphabet[(i * 7) % len(alphabet)] for i in range(length))


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body.lstrip("\n"), encoding="utf-8")
    return root


@pytest.fixture
def check(tmp_path):
    """check(code, name="app.py", rule=None) -> findings in that one file."""

    def run(code: str, name: str = "app.py", rule: str | None = None) -> list[Finding]:
        folder = tmp_path / f"case{len(list(tmp_path.iterdir()))}"
        write_tree(folder, {name: code})
        found = scan(folder).findings
        return [f for f in found if rule is None or f.rule_id == rule]

    return run


@pytest.fixture(autouse=True)
def no_colour(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
