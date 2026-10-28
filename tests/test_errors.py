from __future__ import annotations

RULE = "errors.success-on-exception"


# --- Python: true positives -------------------------------------------------------


def test_python_dict_success_from_except(check):
    found = check(
        """
def webhook(event):
    try:
        process(event)
    except Exception as e:
        logger.error(e)
        return {"status": "success"}
""",
        rule=RULE,
    )
    assert [f.line for f in found] == [6]
    assert found[0].severity.value == "critical"


def test_python_true_from_except(check):
    found = check(
        """
def sync():
    try:
        push()
    except Exception:
        return True
""",
        rule=RULE,
    )
    assert len(found) == 1


def test_python_ok_flag_from_except(check):
    found = check(
        """
async def save(item):
    try:
        await store(item)
    except OSError:
        return {"ok": True, "id": None}
""",
        rule=RULE,
    )
    assert len(found) == 1


# --- Python: false positives ------------------------------------------------------


def test_python_handler_that_reraises_is_fine(check):
    found = check(
        """
def webhook(event):
    try:
        process(event)
    except Exception:
        if should_swallow():
            return {"status": "success"}
        raise
""",
        rule=RULE,
    )
    assert found == []


def test_python_error_shape_is_fine(check):
    found = check(
        """
def webhook(event):
    try:
        process(event)
    except Exception as e:
        return {"status": "error", "detail": str(e)}
""",
        rule=RULE,
    )
    assert found == []


def test_python_return_in_a_nested_function_is_not_the_handlers(check):
    found = check(
        """
def outer():
    try:
        work()
    except Exception:
        def later():
            return {"status": "success"}
        later()
""",
        rule=RULE,
    )
    assert found == []


def test_python_deny_check_failing_closed_is_fine(check):
    found = check(
        """
def is_token_blacklisted(token):
    try:
        return redis.exists(token)
    except RedisError:
        return True
""",
        rule=RULE,
    )
    assert found == []


def test_python_success_outside_a_handler_is_fine(check):
    assert check("def ok():\n    return {'status': 'success'}\n", rule=RULE) == []


# --- JavaScript / TypeScript ---------------------------------------------------------


def test_js_success_response_from_catch(check):
    found = check(
        """
app.post("/pay", async (req, res) => {
  try {
    await charge(req.body);
  } catch (e) {
    console.error(e);
    return res.json({ success: true });
  }
});
""",
        name="pay.js",
        rule=RULE,
    )
    assert [f.line for f in found] == [6]


def test_ts_ui_success_from_catch(check):
    found = check(
        """
export async function submit(form: Form) {
  try {
    await api.save(form);
  } catch (err) {
    toast.success("Saved!");
  }
}
""",
        name="form.ts",
        rule=RULE,
    )
    assert len(found) == 1 and "toast.success()" in found[0].message


def test_tsx_state_flag_from_catch(check):
    found = check(
        """
export function Save() {
  const [saved, setSaved] = useState(false);
  async function onClick() {
    try {
      await save();
    } catch (e) {
      setSaved(true);
    }
  }
  return <button onClick={onClick}>Save</button>;
}
""",
        name="Save.tsx",
        rule=RULE,
    )
    assert len(found) == 1


def test_js_catch_that_rethrows_or_passes_on_is_fine(check):
    found = check(
        """
async function a() {
  try { await work(); } catch (e) { log(e); throw e; }
}
app.get("/x", async (req, res, next) => {
  try { await work(); } catch (e) { next(e); return res.json({ ok: true }); }
});
""",
        name="ok.js",
        rule=RULE,
    )
    assert found == []


def test_js_error_status_response_is_fine(check):
    found = check(
        """
app.post("/pay", async (req, res) => {
  try {
    await charge(req.body);
  } catch (e) {
    return res.status(500).json({ success: false, ok: true });
  }
});
""",
        name="pay.js",
        rule=RULE,
    )
    assert found == []
