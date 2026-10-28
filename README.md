# silentbug-lite

Five checks for bugs that tests and linters usually miss, in Python and JavaScript/TypeScript:

1. An error that still returns success
2. SQL injection
3. A secret written in the code
4. An LLM call inside a loop
5. A route with no login check

It reads your code and never runs it. Python goes through the standard `ast` module, and
JavaScript/TypeScript goes through tree-sitter, so you don't need Node.js. Nothing is sent
anywhere and there is no AI involved, so the same code always gives the same result.

## Quickstart

**1. Install** (Python 3.11 or newer):

```bash
pipx install git+https://github.com/manish-drops/silentbug-lite
```

No `pipx`? Run `python -m pip install git+https://github.com/manish-drops/silentbug-lite` inside a
virtual environment.

**2. Run it** on a project folder or a single file:

```bash
silentbug-lite path/to/your-project
```

Want to see what a finding looks like first? Clone this repository and run
`silentbug-lite examples/demo`. The demo has a bug of each kind, planted on purpose.

**3. Add the GitHub Action** to check every push and pull request. Save this as
`.github/workflows/silentbug-lite.yml`:

```yaml
name: silentbug-lite
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write # only needed for upload-sarif

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: manish-drops/silentbug-lite@v0.1.0
        with:
          upload-sarif: true
```

The job fails when it finds something at or above `high`, and the findings show up in the
repository's **Security > Code scanning** tab. More options are in [GitHub Action](#github-action).

## What a run looks like

Shortened from `silentbug-lite examples/demo`:

```text
silentbug-lite 0.1.0 - 3 files checked in examples/demo (JavaScript, Python, TypeScript / Express, FastAPI)

CRITICAL  examples/demo/orders.py:40  Error still returns success  [errors.success-on-exception]
    37 |         return {"status": "ok"}
    38 |     except Exception as e:
    39 |         logging.error("payment failed: %s", e)
  > 40 |         return {"status": "success"}
    This except block returns a success value and never re-raises, so the caller can't tell the
    operation failed.
    Fix: Re-raise the error or return a failure (an error status or flag), so whoever called this
    knows it failed.

HIGH      examples/demo/orders.py:29  Route with no login check  [auth.unprotected-route]
    28 | @router.delete("/orders/{order_id}")
  > 29 | def delete_order(order_id: int):
    30 |     db.execute("DELETE FROM orders WHERE id = %s", (order_id,))
    DELETE route 'delete_order' has none of the auth checks the other routes in this file use
    (get_current_user).
    Fix: Add an authentication and permission check (a dependency, middleware or guard) before the
    handler runs.

7 possible bugs (4 critical, 3 high).
Failing: 7 at or above 'high' (--fail-on high)
```

Each finding shows the file and line, the code around it, why it was flagged, a hint for the
fix, and the rule ID in brackets. Secrets are always masked in the output.

## The five checks

### 1. Error still returns success

Rule `errors.success-on-exception`, severity critical.

An error handler that reports success. The caller (a payment provider, a retry queue, a user
looking at a "Saved!" message) is told it worked, so nothing retries and nobody looks.

```python
try:
    mark_order_paid(order_id)
except Exception as e:
    logging.error("payment failed: %s", e)
    return {"status": "success"}  # the provider sees success and never retries
```

```js
} catch (e) {
  toast.success("Saved!"); // the user is told it worked
}
```

Handlers that re-raise, pass the error on (`next(err)`, `reject`) or answer with a 4xx/5xx
status are fine.

### 2. SQL injection

Rule `db.sql-injection`, severity critical.

SQL text built from values with an f-string, `%`, `+`, `.format()` or a template literal, and
then handed to the database driver.

```python
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

```js
await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
```

Parameterised queries (`execute(sql, params)`, `$1` placeholders) and tagged templates such as
`` sql`...` `` or `` prisma.$queryRaw`...` `` are fine.

### 3. Secret written in the code

Rule `config.hardcoded-secret`, severity critical.

An API key, token or password in the source code. Anyone who can read the code has it.

```python
PAYMENTS_API_KEY = "b7f3c9e1a4d8f2b6c0e5a9d3f7b1c4e8"
```

Keys with a known shape (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, Google, Hugging Face,
SendGrid, JWTs, private keys, passwords inside URLs) always count. Any other value needs a
secret-sounding name and a random-looking value. Those are skipped in test files, where fake
keys are normal. Placeholders like `"your-api-key"` and lookups like `os.environ["API_KEY"]`
are fine.

### 4. LLM call inside a loop

Rule `ai.llm-call-in-loop`, severity high.

A paid model call made once per item: 1,000 records means 1,000 calls, and the bill and the
wait grow with your data.

```python
for ticket in tickets:
    client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": ticket}])
```

It recognises the OpenAI, Anthropic, Google Gen AI, Ollama, LiteLLM and LangChain SDKs in
Python, and OpenAI, Anthropic, Google Gen AI, Ollama, the Vercel AI SDK and LangChain.js in
JavaScript/TypeScript. Retry loops with a fixed count (`for attempt in range(3)`) and `while`
loops don't count.

### 5. Route with no login check

Rules `auth.unprotected-route` and `auth.destructive-no-auth`, severity high.

- `auth.unprotected-route`: in a file with at least three routes where most use the same auth
  check, a route that doesn't use it.
- `auth.destructive-no-auth`: a route with no auth check at all that is a `DELETE`, or whose
  name or path says delete, remove, reset, refund, transfer, ban or similar.

```python
@router.get("/orders")
def list_orders(user=Depends(get_current_user)): ...

@router.post("/orders")
def create_order(body: Order, user=Depends(get_current_user)): ...

@router.get("/orders/{order_id}/invoice")
def get_invoice(order_id: int): ...  # the other routes check the user; this one doesn't
```

```js
app.delete("/admin/users/:id", async (req, res) => { /* no auth middleware */ });
```

It reads routes from FastAPI, Flask, Django (including Django REST framework), Express,
Next.js (route handlers, `pages/api` and Server Actions) and NestJS. It takes into account
dependencies, decorators, middleware registered with `app.use`, Next.js `middleware.ts`
matchers, and NestJS guards, including global ones. Routes marked public, and login, signup,
password reset and webhook routes, are left alone. When a route matches both rules, it is
reported once.

## Options

| Option | What it does |
|---|---|
| `silentbug-lite [path]` | Checks a folder or one file. Default: the current folder |
| `--format text\|json\|sarif` | Report format. Default: `text` |
| `-o, --output FILE` | Writes the report to `FILE`. The text summary still prints to the terminal |
| `--fail-on LEVEL` | Exit with 1 when a finding is at or above `critical`, `high` (default), `medium` or `low`. `none` always exits 0 |
| `--exclude GLOB` | Skips matching paths, relative to the folder. Repeat it for more: `--exclude 'tests/*' --exclude 'scripts/*'` |
| `--no-color` | Plain text. Colours are also off when `NO_COLOR` is set or the output isn't a terminal |
| `--list-checks` | Lists the checks and their rule IDs |
| `--version` | Prints the version |

Folders like `node_modules`, `.venv`, `build`, `dist` and `.next` are always skipped, and so
are minified files and files over 1 MB. A file that can't be parsed is listed as skipped
instead of being dropped without a word.

**Exit codes:** `0` nothing at or above `--fail-on`, `1` findings at or above `--fail-on`,
`2` a usage error (unknown option, missing path, unwritable output), `3` an internal error.

**JSON** has a `summary` (counts by severity and by check) and a `findings` list with the rule,
file, line, message, fix, the masked code snippet and a stable `fingerprint` that survives code
moving up or down. **SARIF** is version 2.1.0, ready for GitHub code scanning.

## Ignoring a finding

When the code is fine as it is, add a comment on the flagged line or the line above it, with
the reason. For a decorated function the flagged line is the `def` line, as the report shows.

```python
db.execute(f"SELECT * FROM {table}")  # silentbug: ignore[db.sql-injection] reason: table comes from a fixed list
```

```js
// silentbug: ignore[auth] reason: public read-only endpoint
```

Inside the brackets you can use a rule ID (`db.sql-injection`), its category (`db`) or a check
name (`sql-injection`, `no-login-check`), and several separated by commas. Ignored findings
don't fail the run, and the JSON report lists them with their reasons. The same comment works
in the full silentbug.

## GitHub Action

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Folder to check, relative to the repository root |
| `fail-on` | `high` | Fails the job on findings at or above this severity. `none` never fails |
| `exclude` | | Glob patterns to skip, separated by spaces or new lines |
| `upload-sarif` | `false` | Uploads the findings to GitHub code scanning. Needs `security-events: write` |
| `sarif-file` | | Where to write the SARIF file. Empty means the runner's temp folder |
| `python-version` | `3.12` | Python used to run the checks, kept apart from your job's Python |

Outputs: `findings` (the number found) and `sarif-file`.

Code scanning is available on public repositories. Private repositories need GitHub's code
security features turned on; without them, leave `upload-sarif` off and read the findings in
the job log. On pull requests from forks the upload is skipped, because GitHub gives them a
read-only token; the job log still lists the findings.

## Limits

These checks match code patterns. They don't know your intent, so expect the odd finding that
is fine in context; the ignore comment is there for that. They also don't trace values across
files, and they cover only these five kinds of bugs. A clean run means none of the five
patterns was found, not that the code has no bugs.

## silentbug-lite and the full silentbug

silentbug-lite is the free, open-source part of silentbug. The checks here use the same rules
and IDs as the full version.

| | silentbug-lite | silentbug |
|---|---|---|
| Price and license | Free, MIT | Paid; the full source code under a commercial license |
| Languages | Python, JavaScript, TypeScript | Python, JavaScript, TypeScript |
| Rules | 6 (the five checks above) | 33, including these 6 |
| How findings are decided | Code patterns; every match is reported | Code patterns find suspects; an optional AI judge (a local Ollama model or a cloud model) confirms or rejects each one |
| Code sent anywhere | Never | Never with a local model or offline; with a cloud model, the code around each suspect, with secrets masked |
| Reports | Terminal, JSON, SARIF | Terminal, JSON, SARIF, HTML, Markdown, a badge and a local dashboard |
| LLM cost map | No | Yes |
| Inline ignore comments | Yes | Yes, the same syntax |
| Baseline of known findings | No | Yes |
| GitHub Action | Runs the checks and uploads SARIF | Also keeps a summary comment on the pull request and can check only changed files |

The full version is at https://code-drops-six.vercel.app/p/silentbug.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

Adding an LLM SDK is a data change in `silentbug_lite/data/llm_signatures.json`, and adding a
key shape is a change in `silentbug_lite/data/secret_patterns.json`.

## License

MIT. See [LICENSE](LICENSE).
