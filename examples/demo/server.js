// A small Express app with bugs planted on purpose.
const express = require("express");
const app = express();
const MAILER_API_KEY = "b7f3c9e1a4d8f2b6c0e5a9d3f7b1c4e8";

app.delete("/admin/users/:id", async (req, res) => {
  await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ ok: true });
});

app.post("/signup", async (req, res) => {
  await mailer.send(MAILER_API_KEY, req.body.email);
  res.json({ ok: true });
});
