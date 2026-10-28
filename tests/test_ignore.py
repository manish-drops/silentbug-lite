from __future__ import annotations

import pytest
from conftest import write_tree

from silentbug_lite.scan import scan

SQL = 'def f(x):\n    {comment_above}\n    db.execute(f"SELECT * FROM t WHERE id = {{x}}"){comment_inline}\n'


@pytest.mark.parametrize(
    "name",
    ["db.sql-injection", "db", "sql-injection", "SQL-Injection", "errors, db.sql-injection"],
)
def test_ignore_by_rule_category_or_check(check, name):
    code = SQL.format(comment_above="pass", comment_inline=f"  # silentbug: ignore[{name}]")
    assert check(code) == []


def test_ignore_on_the_line_above_with_a_reason(tmp_path):
    code = SQL.format(
        comment_above="# silentbug-lite: ignore[db.sql-injection] reason: x is an int",
        comment_inline="",
    )
    write_tree(tmp_path, {"app.py": code})
    result = scan(tmp_path)
    assert result.findings == []
    assert [(f.rule_id, f.ignore_reason) for f in result.ignored] == [
        ("db.sql-injection", "x is an int")
    ]


def test_an_ignore_for_another_rule_or_too_far_away_does_nothing(check):
    other = SQL.format(comment_above="pass", comment_inline="  # silentbug: ignore[auth]")
    assert len(check(other)) == 1
    far = "# silentbug: ignore[db]\n\n" + SQL.format(comment_above="pass", comment_inline="")
    assert len(check(far)) == 1


def test_an_ignore_inside_a_string_is_not_a_comment(check):
    code = 'def f(x):\n    db.execute(f"SELECT * FROM t WHERE id = {x} -- silentbug: ignore[db]")\n'
    assert len(check(code)) == 1


def test_js_line_and_block_comments(check):
    code = (
        "// silentbug: ignore[db.sql-injection] reason: id is a number\n"
        "await db.query(`DELETE FROM t WHERE id = ${id}`);\n"
        "await db.query(`DELETE FROM u WHERE id = ${id}`); /* silentbug: ignore[db] */\n"
    )
    assert check(code, name="q.ts") == []
