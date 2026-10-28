from __future__ import annotations

RULE = "ai.llm-call-in-loop"


def test_python_openai_call_per_item(check):
    found = check(
        """
from openai import OpenAI
client = OpenAI()

def summarise(tickets):
    out = []
    for ticket in tickets:
        out.append(client.chat.completions.create(model="m", messages=[ticket]))
    return out
""",
        rule=RULE,
    )
    assert [f.line for f in found] == [7]
    assert "openai chat.completions.create()" in found[0].message


def test_python_anthropic_call_in_a_comprehension(check):
    found = check(
        """
import anthropic
client = anthropic.Anthropic()

def label(rows):
    return [client.messages.create(model="m", max_tokens=10, messages=[r]) for r in rows]
""",
        rule=RULE,
    )
    assert len(found) == 1


def test_python_module_level_function_and_langchain_model(check):
    found = check(
        """
import litellm
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

async def run(items):
    for item in items:
        await litellm.acompletion(model="m", messages=[item])
        llm.invoke(item)
""",
        rule=RULE,
    )
    assert [f.line for f in found] == [7, 8]


def test_python_retry_and_agent_loops_are_not_per_item(check):
    found = check(
        """
from openai import OpenAI
client = OpenAI()

def ask(prompt):
    for attempt in range(3):
        try:
            return client.responses.create(model="m", input=prompt)
        except Exception:
            continue
    while True:
        reply = client.responses.create(model="m", input=prompt)
        if reply:
            return reply
""",
        rule=RULE,
    )
    assert found == []


def test_python_single_call_and_non_llm_calls_in_loops_are_fine(check):
    found = check(
        """
from openai import OpenAI
client = OpenAI()

def batch(items):
    for item in items:
        print(item)
    return client.chat.completions.create(model="m", messages=items)
""",
        rule=RULE,
    )
    assert found == []


def test_python_without_an_llm_sdk_import_nothing_is_flagged(check):
    found = check(
        "def f(items):\n    for i in items:\n        client.chat.completions.create(x=i)\n",
        rule=RULE,
    )
    assert found == []


def test_ts_call_in_for_of_and_map(check):
    found = check(
        """
import OpenAI from "openai";
const client = new OpenAI();

export async function summarise(tickets: string[]) {
  const out = [];
  for (const t of tickets) {
    out.push(await client.chat.completions.create({ model: "m", messages: [] }));
  }
  return Promise.all(tickets.map((t) => client.responses.create({ model: "m", input: t })));
}
""",
        name="llm.ts",
        rule=RULE,
    )
    assert [f.line for f in found] == [7, 9]


def test_js_vercel_ai_sdk_function_in_a_loop(check):
    found = check(
        """
import { generateText } from "ai";
for (const doc of docs) {
  await generateText({ model, prompt: doc });
}
""",
        name="ai.mjs",
        rule=RULE,
    )
    assert len(found) == 1


def test_js_bounded_retry_loop_and_single_call_are_fine(check):
    found = check(
        """
import Anthropic from "@anthropic-ai/sdk";
const client = new Anthropic();
export async function ask(prompt) {
  for (let i = 0; i < 3; i++) {
    try { return await client.messages.create({ model: "m", messages: [prompt] }); }
    catch (e) { await sleep(1000); }
  }
}
""",
        name="ask.js",
        rule=RULE,
    )
    assert found == []
