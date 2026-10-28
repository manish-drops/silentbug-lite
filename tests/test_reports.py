from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import fake_key, write_tree

from silentbug_lite import FULL_VERSION_URL
from silentbug_lite.report.json_report import to_json
from silentbug_lite.report.sarif import to_payload
from silentbug_lite.report.terminal import render
from silentbug_lite.rules import CHECKS, RULES
from silentbug_lite.scan import scan

SCHEMA = Path(__file__).parent / "data" / "sarif-2.1.0.json"


@pytest.fixture
def buggy(tmp_path):
    key = fake_key("sk-ant-")
    write_tree(
        tmp_path,
        {
            "app.py": f"""
import logging
ANTHROPIC_KEY = "{key}"

def pay(order):
    try:
        charge(order)
    except Exception:
        logging.exception("charge failed")
        return {{"status": "success"}}

def find(name):
    return db.execute(f"SELECT * FROM users WHERE name = '{{name}}'")
""",
            "broken.js": "function (\n",
        },
    )
    return scan(tmp_path), key


def test_sarif_validates_against_the_official_schema(buggy):
    jsonschema = pytest.importorskip("jsonschema")
    result, _ = buggy
    payload = to_payload(result)
    jsonschema.validate(payload, json.loads(SCHEMA.read_text(encoding="utf-8")))
    run = payload["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "silentbug-lite"
    assert driver["informationUri"] == FULL_VERSION_URL
    assert [r["id"] for r in driver["rules"]] == list(RULES)
    assert len(run["results"]) == 3
    for res in run["results"]:
        assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        location = res["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "app.py"
        assert location["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["silentbugLite/v1"]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) == 1 and "broken.js" in notes[0]["message"]["text"]


def test_sarif_fits_github_code_scanning(buggy):
    """The fields GitHub reads: levels, security-severity as a numeric string, tags."""
    result, _ = buggy
    driver = to_payload(result)["runs"][0]["tool"]["driver"]
    for rule in driver["rules"]:
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        assert len(rule["shortDescription"]["text"]) <= 1024
        props = rule["properties"]
        if "security" in props["tags"]:
            assert 0.0 <= float(props["security-severity"]) <= 10.0
        else:
            assert "security-severity" not in props


def test_no_report_contains_the_key(buggy):
    result, key = buggy
    outputs = [
        json.dumps(to_payload(result)),
        to_json(result, ".", "high"),
        render(result, ".", "high"),
    ]
    for text in outputs:
        assert key not in text
    assert "sk-ant-****" in render(result, ".", "high")


def test_terminal_report_lists_each_finding_with_its_fix(buggy):
    result, _ = buggy
    text = render(result, ".", "high")
    for finding in result.findings:
        assert f"{finding.file}:{finding.line}" in text
    assert "Fix: Use a parameterised query" in text
    assert "3 possible bugs (3 critical)." in text
    assert text.rstrip().splitlines()[-1].endswith(FULL_VERSION_URL)
    assert all(len(line) <= 100 or "|" in line or FULL_VERSION_URL in line
               for line in text.splitlines())


def test_fingerprints_ignore_line_moves(tmp_path):
    code = 'def f(x):\n    db.execute(f"SELECT * FROM t WHERE id = {x}")\n'
    write_tree(tmp_path / "a", {"app.py": code})
    write_tree(tmp_path / "b", {"app.py": "\n\n# moved down\n" + code})
    [a] = scan(tmp_path / "a").findings
    [b] = scan(tmp_path / "b").findings
    assert a.line != b.line and a.fingerprint == b.fingerprint


def test_every_check_has_rules_and_every_rule_a_check():
    assert len(CHECKS) == 5
    assert sorted(r for c in CHECKS for r in c.rules) == sorted(RULES)
