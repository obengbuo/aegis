# Aegis

**Runtime security and governance for the Model Context Protocol (MCP).**

Aegis sits between AI agents and the MCP servers they call. Every tool call
flows through Aegis, which logs it, fingerprints the server, and (Phase 2)
enforces policy and detects threats.

> AWS secures its own MCP server with IAM. Okta and Descope secure agent
> identity. Aegis secures every *other* MCP server your agents touch —
> runtime threat detection and governance across your whole MCP estate.

---

## Quick start

```bash
# 1. Python environment
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Node (needed — MCP servers ship as npx packages)
node --version            # need v18+

# 3. Configure
cp .env.example .env      # then add your ANTHROPIC_API_KEY

# 4. Run the multi-agent test stack
python -m agents.stack

# 5. See what Aegis captured
cat logs/audit.jsonl
python -m aegis.audit     # prints a summary

# 6. Run the prompt-injection test (the important one)
python -m tests.test_injection

# 7. Run unit tests
pytest
```

---

## What's in here

```
aegis/          THE PRODUCT
  wrapper.py      interception hook — every tool call passes through here
  audit.py        audit log: write / read / query
  fingerprint.py  MCP server fingerprinting (supply-chain integrity)

agents/         test agents that exercise the product
  servers.py      the 5 MCP server definitions
  stack.py        3 agents x multiple MCP servers

tests/
  test_wrapper.py    unit tests for the interception layer
  test_injection.py  the prompt-injection harness

docs/
  BUILD_PLAN.md   the 90-day plan
  MCP_NOTES.md    domain notes on MCP security

CLAUDE.md       context for Claude Code — read it first
```

---

## The five MCP servers

| Server      | Credentials | Security risk class it represents      |
|-------------|-------------|------------------------------------------|
| filesystem  | none        | path traversal, arbitrary file access    |
| fetch       | none        | SSRF, exfiltration, web prompt injection  |
| github      | PAT         | credential scope abuse, secret access     |
| postgres    | conn string | SQL injection, bulk extraction            |
| brave       | API key     | untrusted external content                |

Start with **filesystem** and **fetch** — they need no credentials and run
immediately. Add the others as you populate `.env`.

---

## Current phase

**Phase 1 (Days 1–30): Learn & Instrument.** Build the multi-agent stack,
the logging wrapper, fingerprinting, and the injection harness. Do NOT build
the policy engine, FastAPI control plane, or dashboard yet — that's Phase 2.

See `docs/BUILD_PLAN.md` for the full 90-day arc.
