# Aegis

**Runtime security for AI agents that use the Model Context Protocol.**

Aegis is a deterministic enforcement layer that sits between AI agents and
the MCP servers they call. It converts natural-language requests into
capability specs, enforces those specs at the tool-call layer with no LLM
in the enforcement path, and produces a forensic audit trail for every
decision.

**Status:** v0.1.1 — pre-production, actively developed with a design partner.

---

## Install

\`\`\`bash
pip install git+https://github.com/obengbuo/aegis.git@v0.1.1
\`\`\`

Requires Python 3.10+.

---

## Quick start

See [docs/WAXELL_INTEGRATION.md](docs/WAXELL_INTEGRATION.md) for a complete
runnable example and integration reference.

The five-line version: wrap any Pydantic AI `MCPToolset` with `wrap_toolset()`,
pass a capability spec (natural language via `propose_spec()` or hand-written
YAML via `load_spec()`), and every tool call runs through Aegis's deterministic
policy engine before reaching the MCP server.

---

## What Aegis does

- Wraps existing Pydantic AI `MCPToolset` instances with one line of code
- Converts natural-language requests to YAML capability specs via LLM (upfront, on trusted input)
- Enforces those specs at the tool-call layer with pure deterministic Python — no LLM in the enforcement path
- Provides INTERCEPT verdicts for operator-configured approval workflows
- Scans tool responses for leaked secrets (SSNs, credit cards, private keys, cloud credentials)
- Emits audit records with `run_id`, `spec_hash`, and `proposer_prompt_hash` for forensic correlation
- Exports audit events as OTLP spans for observability pipelines (Datadog, Jaeger, Splunk)
- Fingerprints MCP servers to detect supply-chain drift

Aegis is not a firewall for LLM output. It's a capability system for agent
tool use, downstream of identity, upstream of the MCP servers themselves.

---

## Architectural commitment

**Aegis's enforcement path contains no LLM.**

An LLM proposes a capability spec once, on the trusted user request, before
agent execution begins. From that point forward, every tool call is
evaluated by pure deterministic code against a static spec. The LLM never
sees tool output. The spec never widens mid-run. Enforcement decisions are
computed in microseconds and are provable by inspection.

This is the load-bearing design decision. See `docs/CAPABILITY_SPEC.md` for
the full spec format and evaluation rules.

---

## Position in the stack

Identity vendors (Okta, Auth0, Descope) prove *who* an agent is. Aegis
enforces *what* it's allowed to do once it's in.

Aegis sits one layer downstream of identity, at the runtime enforcement
boundary between agents and the MCP servers they call. It works with any
identity system, any observability stack, and any Pydantic AI-based agent
runtime.

---

## Repository layout

\`\`\`
aegis/               The library. This is what pip installs.
  wrapper.py           Tool-call interception + closure-based policy hook
  policy.py            Deterministic capability evaluator
  proposer.py          LLM-based spec proposer (runs once, upfront)
  audit.py             Structured audit log with OTLP export
  fingerprint.py       MCP server supply-chain integrity
  config.py            AegisConfig public API surface
  response_inspection.py    Deterministic response scanning

docs/                User-facing documentation
tests/               95 unit + integration tests
\`\`\`

---

## Roadmap

Next up: expanded threat detection patterns, container image, additional
MCP server-specific integrations. Contribution welcome once the API
surface stabilizes — expected around v0.2.

---

## License

MIT