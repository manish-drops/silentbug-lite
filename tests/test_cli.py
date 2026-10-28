from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import write_tree

import silentbug_lite
from silentbug_lite import FULL_VERSION_URL, __version__
from silentbug_lite.cli import main
from silentbug_lite.rules import CHECKS

HIGH_ONLY = """
from openai import OpenAI
client = OpenAI()
def f(items):
    for i in items:
        client.responses.create(model="m", input=i)
"""
CRITICAL = 'def f(x):\n    db.execute(f"SELECT * FROM t WHERE id = {x}")\n'


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(capsys, *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_clean_project_exits_0_and_ends_with_the_one_line_pointer(project, capsys):
    write_tree(project, {"app.py": "def f():\n    return 1\n"})
    code, out, _ = run(capsys, ".")
    assert code == 0
    lines = out.strip().splitlines()
    assert lines[-1] == (
        f"silentbug-lite ran {len(CHECKS)} checks. The full silentbug adds more checks and "
        f"an AI judge: {FULL_VERSION_URL}"
    )
    assert out.count(FULL_VERSION_URL) == 1
    assert "No possible bugs found by the 5 checks." in out


def test_findings_at_or_above_fail_on_exit_1(project, capsys):
    write_tree(project, {"app.py": CRITICAL})
    code, out, _ = run(capsys, ".")
    assert code == 1
    assert "app.py:2" in out and "SQL injection" in out and "[db.sql-injection]" in out
    assert "Failing: 1 at or above 'high'" in out


@pytest.mark.parametrize(
    ("fail_on", "expected"), [("critical", 0), ("high", 1), ("low", 1), ("none", 0)]
)
def test_fail_on_levels(project, capsys, fail_on, expected):
    write_tree(project, {"app.py": HIGH_ONLY})
    code, _, _ = run(capsys, ".", "--fail-on", fail_on)
    assert code == expected


def test_usage_errors_exit_2(project, capsys):
    code, _, err = run(capsys, "does-not-exist")
    assert code == 2 and "no such file or folder" in err
    with pytest.raises(SystemExit) as exit_info:
        main(["--fail-on", "sometimes"])
    assert exit_info.value.code == 2
    write_tree(project, {"app.py": CRITICAL})
    code, _, err = run(capsys, ".", "--format", "json", "--output", "missing-dir/r.json")
    assert code == 2 and "can't write" in err


def test_internal_errors_exit_3(project, capsys, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("silentbug_lite.scan.scan", broken)
    code, _, err = run(capsys, ".")
    assert code == 3 and "internal error: RuntimeError: boom" in err


def test_json_to_stdout(project, capsys):
    write_tree(project, {"app.py": CRITICAL, "web/q.ts": "await db.query(`SELECT ${id}`);\n"})
    code, out, _ = run(capsys, ".", "--format", "json")
    payload = json.loads(out)
    assert code == 1
    assert payload["tool"] == {"name": "silentbug-lite", "version": __version__}
    assert payload["summary"]["findings"] == 2
    assert payload["summary"]["by_check"]["sql-injection"] == 2
    assert {f["file"] for f in payload["findings"]} == {"app.py", "web/q.ts"}
    first = payload["findings"][0]
    assert first["rule_id"] == "db.sql-injection" and first["fix"] and first["fingerprint"]


def test_output_file_plus_text_summary(project, capsys):
    write_tree(project, {"app.py": CRITICAL})
    code, out, _ = run(capsys, ".", "--format", "sarif", "-o", "out.sarif")
    assert code == 1
    assert json.loads((project / "out.sarif").read_text())["version"] == "2.1.0"
    assert "Report written to out.sarif" in out
    assert out.strip().splitlines()[-1].startswith("silentbug-lite ran 5 checks.")


def test_paths_are_relative_to_where_it_runs(project, capsys):
    write_tree(project, {"src/app.py": CRITICAL})
    _, out, _ = run(capsys, "src", "--format", "json")
    assert json.loads(out)["findings"][0]["file"] == "src/app.py"
    _, out, _ = run(capsys, "src/app.py", "--format", "json")
    assert json.loads(out)["findings"][0]["file"] == "src/app.py"


def test_exclude_globs_and_build_folders(project, capsys):
    write_tree(
        project,
        {"tests/test_x.py": CRITICAL, "node_modules/x/index.js": "db.query(`SELECT ${a}`)\n",
         "app.py": "x = 1\n"},
    )
    code, out, _ = run(capsys, ".", "--exclude", "tests/*")
    assert code == 0 and "1 file checked" in out


def test_unparseable_files_are_reported_not_hidden(project, capsys):
    write_tree(project, {"broken.py": "def f(:\n", "ok.py": CRITICAL})
    code, out, _ = run(capsys, ".")
    assert code == 1
    assert "Skipped 1 file:" in out and "broken.py: syntax error" in out


def test_list_checks_and_version(capsys):
    code, out, _ = run(capsys, "--list-checks")
    assert code == 0
    assert [line.split(". ", 1)[1] for line in out.splitlines() if line[0].isdigit()] == [
        c.title for c in CHECKS
    ]
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"silentbug-lite {__version__}"


def test_module_entry_point(project):
    write_tree(project, {"app.py": CRITICAL})
    package_parent = str(Path(silentbug_lite.__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": package_parent, "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run(
        [sys.executable, "-m", "silentbug_lite", ".", "--no-color"],
        capture_output=True, text=True, cwd=project, env=env, check=False,
    )
    assert done.returncode == 1 and "SQL injection" in done.stdout
