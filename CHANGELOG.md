# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## 0.1.0 - 2026-10-28

First release.

- Five checks for Python and JavaScript/TypeScript: an error that still returns success, SQL
  injection, a secret written in the code, an LLM call inside a loop, and a route with no
  login check (FastAPI, Flask, Django, Express, Next.js, NestJS).
- Terminal, JSON and SARIF 2.1.0 output. `--output` writes the report to a file and still
  prints the summary.
- `--fail-on` sets which findings fail the run (exit code 1). Usage errors exit with 2.
- Inline ignores: `# silentbug: ignore[<rule>] reason: ...`, by rule ID, category or check name.
- Secrets are masked in every output.
- A composite GitHub Action that runs the checks and can upload the SARIF to code scanning.
