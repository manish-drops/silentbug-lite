// An LLM helper with a cost bug planted on purpose.
import OpenAI from "openai";

const client = new OpenAI();

export async function summarise(tickets: string[]) {
  const out = [];
  for (const ticket of tickets) {
    const reply = await client.chat.completions.create({
      model: "your-model",
      messages: [{ role: "user", content: `Summarise: ${ticket}` }],
    });
    out.push(reply.choices[0].message.content);
  }
  return out;
}
