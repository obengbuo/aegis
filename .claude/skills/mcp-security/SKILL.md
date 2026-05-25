---
name: mcp-security
description: >
  Use this skill whenever working on the Aegis codebase or any task involving
  Model Context Protocol (MCP) security — building interception layers,
  tool-call logging, MCP server fingerprinting, policy enforcement, prompt-
  injection detection, or wiring agents to MCP servers. Triggers on mentions
  of MCP servers, tool calls, agent governance, the Aegis project, or
  process_tool_call hooks.
---

# MCP Security — Skill

This skill guides building Aegis, a runtime security layer for the Model
Context Protocol. Read `CLAUDE.md` in the project root first; this skill
adds MCP-domain-specific guidance.

## Core principle: the interception point is sacred

Aegis works because EVERY tool call passes through one function:
`aegis/wrapper.py::process_tool_call`. This is Pydantic AI's official hook.

Rules:
- Every `MCPServerStdio` / `MCPServerStreamableHTTP` object MUST be created
  with `process_tool_call=process_tool_call` imported from `aegis.wrapper`.
- Never write a code path that lets an agent reach an MCP server without
  going through the hook. If asked to, refuse and explain why — a tool call
  that bypasses Aegis is, by definition, a security hole in a security
  product.
- The hook must always log, even on the error path, before re-raising.

## Phase discipline

The project has two phases. Check `docs/BUILD_PLAN.md` for the current one.

Phase 1 (Days 1-30): logging, fingerprinting, the multi-agent test stack,
the injection harness. The wrapper LOGS and PASSES THROUGH.

Phase 2 (Days 31+): policy engine, FastAPI control plane, Next.js dashboard,
threat-detection classifiers. The wrapper EVALUATES and may BLOCK.

If asked to build a Phase 2 feature during Phase 1, push back: suggest
finishing Phase 1 instrumentation first. Premature policy code is wasted
code if the audit data shows the design is wrong.

## MCP-specific knowledge

### The protocol
- MCP servers expose tools, resources, and prompts. Tools are the main
  security surface.
- Transports: stdio (local subprocess), HTTP+SSE, streamable HTTP.
- A server advertises its tools via `list_tools()`. Each tool has a name,
  a description, and an input schema. ALL THREE matter for fingerprinting —
  a changed description can smuggle a prompt injection.

### The attack surface (what Aegis defends against)
1. Unauthenticated / overscoped servers — excessive permissions
2. Prompt injection via tool OUTPUT — agent reads content containing
   instructions and obeys them
3. Supply-chain drift — a trusted server changes its tool surface
4. Tool shadowing — a malicious server's tool description manipulates the
   agent into misusing a different server
5. Token/credential abuse across servers

### What Aegis is NOT
Aegis is not an identity provider. OAuth 2.1, PKCE, SSO, consent screens —
that is the perimeter, owned by Descope/Okta/Auth0. Aegis is the RUNTIME
layer: per-tool-call decisions, continuous, vendor-agnostic. Do not build
auth/identity features into Aegis.

## Code conventions

- Python 3.12, async everywhere (MCP and Pydantic AI are async).
- Full type hints — this is a security product.
- Fail closed: in Phase 2, when policy evaluation errors, DENY.
- No secrets in code — use `.env` via python-dotenv.
- The wrapper gets unit tests. It is the product.
- Small, runnable commits — one capability each.

## When wiring up MCP servers

Zero-credential servers (use first): filesystem, fetch.
Credentialed servers: github (PAT), postgres (conn string), brave (API key).

Each represents a different risk class — keep all five in the test stack so
Aegis is exercised against diverse attack surfaces.

Common failure: `npx` MCP servers throw confusing errors on first run
(missing Node, package not found, bad args). When debugging, check Node
version first, then the exact npx package name, then the args order.

## When building the injection harness

The prompt-injection test is the most important test in Phase 1. It plants
a file containing an injection payload, runs an agent against it, and
inspects the audit log for hijacked behavior (extra/unexpected tool calls).

The audit log it produces is evidence for why Aegis must exist. Make that
output clear and screenshot-worthy — it becomes blog and pitch material.

## Security mindset

This is a security product built by a security-conscious engineer. When you
see a way the code could be abused, say so. When a design choice has a
security implication, flag it. Proactive security thinking is the job.
