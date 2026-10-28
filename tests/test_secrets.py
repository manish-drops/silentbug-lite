from __future__ import annotations

import pytest
from conftest import fake_key

RULE = "config.hardcoded-secret"
GENERIC = "9f8a7c6e5d4b3a2f1e0d9c8b7a6f5e4d"  # random-looking, but no provider shape


@pytest.mark.parametrize("prefix", ["sk-ant-", "sk-proj-", "ghp_", "AKIA", "xoxb-"])
def test_python_provider_shaped_key(check, prefix):
    key = fake_key(prefix, 16 if prefix == "AKIA" else 40)
    if prefix == "AKIA":
        key = key.upper()
    found = check(f'CLIENT = make_client("{key}")\n', rule=RULE)
    assert len(found) == 1, prefix


def test_python_generic_secret_with_a_secret_name(check):
    found = check(f'API_KEY = "{GENERIC}"\n', rule=RULE)
    assert len(found) == 1 and found[0].message.startswith("A secret is written into the code (API_KEY).")


@pytest.mark.parametrize(
    "code",
    [
        f'client = Client(token="{GENERIC}")\n',
        f'CONFIG = {{"password": "{GENERIC}"}}\n',
        f'def connect(secret="{GENERIC}"):\n    pass\n',
    ],
)
def test_python_generic_secret_in_keywords_dicts_and_defaults(check, code):
    assert len(check(code, rule=RULE)) == 1


@pytest.mark.parametrize(
    "code",
    [
        'API_KEY = os.environ["API_KEY"]\n',
        'API_KEY = "your-api-key-here"\n',
        'PASSWORD = "changeme"\n',
        'TOKEN_TYPE = "access_token"\n',
        'TOKEN_URL = "https://auth.example.com/oauth/token"\n',
        f'COMMIT = "{GENERIC}"\n',  # random-looking, but the name isn't a secret's
    ],
)
def test_python_placeholders_names_and_lookups_are_fine(check, code):
    assert check(code, rule=RULE) == []


def test_python_generic_secret_in_a_test_file_is_fine_but_a_real_key_is_not(check):
    assert check(f'API_KEY = "{GENERIC}"\n', name="tests/test_api.py", rule=RULE) == []
    key = fake_key("sk-ant-")
    assert len(check(f'API_KEY = "{key}"\n', name="tests/test_api.py", rule=RULE)) == 1


def test_python_key_in_an_unnamed_string(check):
    key = fake_key("sk-ant-")
    found = check(f'HEADERS = ["x-api", f"Bearer {key}"]\n', rule=RULE)
    assert len(found) == 1


def test_the_key_never_appears_in_the_finding(check):
    key = fake_key("sk-ant-")
    [found] = check(f'ANTHROPIC = "{key}"\n', rule=RULE)
    assert key not in found.snippet and key not in found.message
    [generic] = check(f'x = {{"credentials": "{GENERIC}"}}\n', rule=RULE)
    assert GENERIC not in generic.snippet


def test_js_named_secret_and_provider_key(check):
    key = fake_key("sk-proj-")
    found = check(
        f'const apiKey = "{GENERIC}";\nconst cfg = {{ openai: "{key}" }};\n',
        name="config.js",
        rule=RULE,
    )
    assert [f.line for f in found] == [1, 2]


@pytest.mark.parametrize(
    "code",
    [
        "const apiKey = process.env.API_KEY;\n",
        'const apiKey = "<your key>";\n',
        f'const buildId = "{GENERIC}";\n',
        "const token = `Bearer ${session.token}`;\n",
    ],
)
def test_js_env_lookups_and_placeholders_are_fine(check, code):
    assert check(code, name="config.ts", rule=RULE) == []
