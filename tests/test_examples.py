"""Three small, realistic snippets with their expected findings, one per language."""

from __future__ import annotations

from conftest import fake_key

from silentbug_lite.rules import RULES

WEBHOOK = '''from fastapi import FastAPI
import logging
app = FastAPI()

@app.post("/webhooks/payment")
def payment_webhook(payload: dict):
    try:
        mark_order_paid(payload["order_id"])
        return {"status": "ok"}
    except Exception as e:
        logging.error("payment failed: %s", e)
        return {"status": "success"}
'''

EXPRESS = '''const express = require("express");
const app = express();
const STRIPE_KEY = "KEY";

app.delete("/admin/users/:id", async (req, res) => {
  await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ ok: true });
});

app.post("/pay", async (req, res) => {
  try {
    await charge(req.body);
  } catch (e) {
    console.error(e);
    return res.json({ success: true });
  }
});
'''

SUMMARISER = '''import OpenAI from "openai";
const client = new OpenAI();

export async function summarise(tickets: string[]) {
  const out = [];
  for (const t of tickets) {
    out.push(await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: t }] }));
  }
  return out;
}
'''


def checks_found(findings) -> list[tuple[str, int]]:
    return [(RULES[f.rule_id].check, f.line) for f in sorted(findings, key=lambda f: f.line)]


def test_payment_webhook(check):
    assert checks_found(check(WEBHOOK, name="snippet.py")) == [("success-on-exception", 12)]


def test_express_api(check):
    code = EXPRESS.replace("KEY", fake_key("sk_live_", 26))
    assert checks_found(check(code, name="snippet.js")) == [
        ("hardcoded-secret", 3),
        ("no-login-check", 5),
        ("sql-injection", 6),
        ("success-on-exception", 15),
    ]


def test_llm_summariser(check):
    assert checks_found(check(SUMMARISER, name="snippet.ts")) == [("llm-call-in-loop", 7)]
