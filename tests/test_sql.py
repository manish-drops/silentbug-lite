from __future__ import annotations

import pytest

RULE = "db.sql-injection"


@pytest.mark.parametrize(
    "line",
    [
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
        'cursor.execute("DELETE FROM users WHERE id = {}".format(user_id))',
        'session.execute(text(f"UPDATE users SET name = \'{name}\'"))',
        'User.objects.raw(f"SELECT * FROM app_user WHERE email = \'{email}\'")',
    ],
)
def test_python_sql_built_from_values(check, line):
    found = check(f"def handler(user_id, name, email):\n    {line}\n", rule=RULE)
    assert [f.line for f in found] == [2]


def test_python_sql_built_in_a_variable_first(check):
    found = check(
        """
def search(term):
    query = "SELECT * FROM items WHERE title LIKE '%" + term + "%'"
    return db.execute(query)
""",
        rule=RULE,
    )
    assert [f.line for f in found] == [3]


@pytest.mark.parametrize(
    "line",
    [
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        'cursor.execute("SELECT * FROM users")',
        'session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
        'logger.info(f"select from cache {user_id}")',
        'print("SELECT " + "1")',
    ],
)
def test_python_parameterised_or_constant_sql_is_fine(check, line):
    assert check(f"def handler(user_id):\n    {line}\n", rule=RULE) == []


def test_python_formatted_text_that_isnt_sql_is_fine(check):
    assert check('def f(x):\n    db.execute(f"{x}")\n', rule=RULE) == []


def test_js_template_literal_sql(check):
    found = check(
        "async function remove(id) {\n  await db.query(`DELETE FROM users WHERE id = ${id}`);\n}\n",
        name="users.js",
        rule=RULE,
    )
    assert [f.line for f in found] == [2]


def test_ts_concatenated_sql_through_a_variable(check):
    found = check(
        """
export async function find(name: string) {
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  return pool.query(sql);
}
""",
        name="users.ts",
        rule=RULE,
    )
    assert [f.line for f in found] == [3]


def test_js_prisma_unsafe_raw(check):
    found = check(
        "await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);\n",
        name="q.ts",
        rule=RULE,
    )
    assert len(found) == 1


@pytest.mark.parametrize(
    "line",
    [
        "await db.query('SELECT * FROM users WHERE id = $1', [id]);",
        "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;",
        "await sql`SELECT * FROM users WHERE id = ${id}`;",
        "await db.query(`SELECT * FROM users`);",
        "console.log(`select ${id}`);",
    ],
)
def test_js_parameterised_or_tagged_sql_is_fine(check, line):
    assert check(line + "\n", name="q.ts", rule=RULE) == []
