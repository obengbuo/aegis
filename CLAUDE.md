# CLAUDE.md — Aegis Project Context

> This file tells Claude Code what Aegis is, how it should be built, and the
> conventions to follow. Read this fully before making changes.

## What Aegis is

Aegis is a **runtime security and governance layer for the Model Context
Protocol (MCP)**. It sits between AI agents and the MCP servers they call.
Every tool call an agent makes flows through Aegis, which:

1. **Logs** every call (audit trail) — Phase 1
2. **Fingerprints** every MCP server (supply-chain integrity) — Phase 1
3. **Enforces policy** on each call: ALLOW / DENY / INTERCEPT — Phase 2
4. **Detects threats**: prompt injection, anomalies, exfiltration — Phase 2

Aegis is NOT an identity provider (that's Descope/Okta's job — the perimeter).
Aegis is what happens AFTER an agent is authenticated — runtime defense on
every individual tool call, across every MCP server, vendor-agnostic.

One-line positioning:
"AWS secures its own MCP server with IAM. Okta and Descope secure agent
identity. Aegis secures every other MCP server your agents touch — runtime
threat detection and governance across your whole MCP estate."

## Who is building this

A solo founder (platform/DevOps engineer background, strong AWS + Kubernetes,
has shipped production SaaS). Currently learning the agent/MCP domain.
Building nights and weekends over 90 days. Treat explanations as for a
strong engineer who is NEW to agents specifically — explain MCP-specific
concepts, don't explain general software engineering.

## Tech stack — do not deviate without asking

- **Language**: Python 3.12
- **Agent framework**: Pydantic AI (`pydantic-ai-slim[mcp]`) — chosen for
  MCP-native support and minimal abstraction. Do NOT switch to LangChain.
- **LLM**: Anthropic Claude (`anthropic:claude-sonnet-4-5`)
- **MCP servers**: official `@modelcontextprotocol/server-*` npx packages
- **Control plane / API (Phase 2)**: FastAPI
- **Dashboard (Phase 2)**: Next.js 14 App Router + Tailwind + shadcn/ui
- **Storage**: JSONL files in Phase 1; Postgres (RDS) in Phase 2
- **Audit/traces**: start with JSONL, add OpenTelemetry + Jaeger later
- **IaC (Phase 2 only)**: Terraform
- **Auth (Phase 2 only)**: Clerk or WorkOS — never hand-roll auth

## The interception point — the heart of the product

Pydantic AI exposes a `process_tool_call` hook on every MCP server object.
This hook fires for EVERY tool call before it reaches the MCP server. This
single hook is the choke point on which the entire product is built:

- Phase 1: the hook logs the call and returns the result unchanged
- Phase 2: the hook evaluates policy and may block/modify/pause the call

`aegis/wrapper.py` owns this hook. It is the most important file in the repo.
Never bypass it. Every MCP server wired into any agent MUST pass
`process_tool_call=process_tool_call` from `aegis.wrapper`.

## Project structure

```
aegis-starter/
├── CLAUDE.md            <- you are here
├── README.md            <- human-facing setup
├── pyproject.toml       <- deps
├── .env.example         <- copy to .env, fill in keys
├── .gitignore
├── aegis/               <- THE PRODUCT
│   ├── __init__.py
│   ├── wrapper.py       <- interception hook (the heart)
│   ├── audit.py         <- audit log read/write/query
│   └── fingerprint.py   <- MCP server fingerprinting
├── agents/              <- test agents that exercise the product
│   ├── stack.py         <- the multi-agent, multi-MCP stack
│   └── servers.py       <- MCP server definitions
├── tests/
│   ├── test_wrapper.py
│   └── injection_samples/   <- malicious files for testing
├── docs/
│   ├── BUILD_PLAN.md    <- the 90-day plan, phase by phase
│   └── MCP_NOTES.md     <- domain notes on MCP security
└── logs/                <- audit.jsonl lands here (gitignored)
```

## Build conventions

- **Async everywhere** — Pydantic AI and MCP are async. No sync wrappers.
- **Type hints on everything** — this is a security product; types catch bugs.
- **Every tool call must be logged** — if a code path can call a tool without
  going through `process_tool_call`, that is a bug.
- **Fail closed in Phase 2** — when policy evaluation errors, DENY, never ALLOW.
- **No secrets in code** — everything via `.env` / environment variables.
- **Small commits** — each commit should be one capability, runnable.
- **Tests for the wrapper** — `aegis/wrapper.py` is the product; it gets tests.

## Current phase: Phase 1 (Days 1–30) — Learn & Instrument

Goal by day 30: a multi-agent stack calling 5+ MCP servers, every tool call
logged through Aegis, basic MCP server fingerprinting working, two public
blog posts written.

DO build now:
- The multi-agent / multi-MCP stack (`agents/stack.py`)
- The logging wrapper (`aegis/wrapper.py`)
- Audit log querying (`aegis/audit.py`)
- MCP server fingerprinting (`aegis/fingerprint.py`)
- Prompt-injection test harness (`tests/injection_samples/`)

DO NOT build yet (Phase 2, day 31+):
- The policy engine
- The FastAPI control plane
- The Next.js dashboard
- Threat-detection classifiers
- Anything deployed to AWS

If asked to build a Phase 2 item during Phase 1, push back and suggest
finishing Phase 1 first.

## How to help the founder

- When explaining MCP mechanics, be concrete — show the protocol exchange.
- Prefer working code over abstract advice.
- When something can be tested, write the test.
- Flag security implications proactively — this is a security product.
- If a request would create a way to call a tool without logging, refuse
  and explain why.
