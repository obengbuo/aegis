# MCP Security — Domain Notes

Working notes on the Model Context Protocol and its security surface. This
is reference material for building Aegis. Keep adding to it as you learn.

---

## What MCP is

The Model Context Protocol, introduced by Anthropic in late 2024, is a
standard for how AI agents connect to external tools and data. By 2026 it's
the de facto standard — adopted by Anthropic, OpenAI, Google, Microsoft, and
stewarded by the Linux Foundation.

An MCP **server** exposes capabilities. An MCP **client** (inside the agent)
consumes them. Three primitives:

- **Tools** — functions the agent can call (the main security surface)
- **Resources** — data the agent can read
- **Prompts** — reusable prompt templates

Transports: `stdio` (local subprocess), `HTTP + SSE`, `streamable HTTP`.
Each transport has different security implications.

---

## The MCP attack surface

### 1. Unauthenticated servers
Security researchers scanning ~2,000 public MCP servers found every verified
instance exposed its internal tool listing with no authentication. Many were
bound to `0.0.0.0`, some allowing arbitrary code execution.

### 2. Overscoping / excessive permissions
The most pervasive risk. MCP servers ship with far more permission than they
need. Excessive permissions enable OS command injection and path traversal
to sensitive files.

### 3. Prompt injection through tool output
An agent reads content (a file, a web page, a DB row) that contains
instructions. The agent treats the instructions as commands. Model-level
defenses do NOT reliably stop this — injected instructions have extracted
admin API keys in live tests. This is why a runtime layer (Aegis) is needed:
in-model defenses "cannot be the foundation on which you build your security
architecture."

### 4. Supply-chain attacks on MCP servers
A community MCP server you trust gets updated to add a malicious tool, or to
change a tool description to smuggle an injection. → Aegis fingerprinting.

### 5. Tool shadowing / confused deputy
A malicious MCP server defines a tool whose description manipulates the agent
into misusing a *different*, trusted server.

### 6. Token / credential abuse
Tokens issued for one MCP server get used against another. The spec fix is
Resource Indicators (RFC 8707) binding tokens to specific servers.

---

## Where Aegis sits

The defense stack has layers. Know which is which:

| Layer            | Concern                        | Who owns it                |
|------------------|--------------------------------|----------------------------|
| Identity / auth  | Who is this agent? OAuth 2.1   | Descope, Okta, Auth0       |
| Authorization    | What scopes at connect time?   | IdP + MCP server           |
| **Runtime (Aegis)** | **What about THIS tool call, now?** | **Aegis**          |
| Audit / forensics| What happened, provably?       | CloudTrail (AWS only), Aegis|

Identity and auth are the **perimeter** — checked at connection time.
Aegis is **runtime** — checked on every individual tool call, continuously,
across every MCP server regardless of vendor. That's the wedge.

---

## What the spec recommends (the perimeter — NOT Aegis's job)

- Separate authorization server from resource server (June 2025 spec)
- OAuth 2.1 + PKCE for all public clients
- SSO / user auth before agent action
- Consent screens, time-bound (short-lived) tokens
- Scope-based access control, progressive scoping
- Client ID Metadata Documents (CIMD) over Dynamic Client Registration (DCR)

Aegis integrates with this layer; it does not replace it.

---

## What Aegis does (the runtime layer — the product)

- **Audit**: log every tool call, immutably, queryably, vendor-agnostic
- **Fingerprint**: hash each server's tool surface, detect drift
- **Policy**: per-call ALLOW / DENY / INTERCEPT decisions
- **Threat detection**: prompt-injection scanning, output anomaly detection,
  exfiltration patterns

---

## Reading list

- modelcontextprotocol.io/specification — the full spec
- Anthropic's MCP introduction + architecture posts
- Simon Willison's blog, `mcp` tag
- OWASP GenAI Security Project — secure MCP server development guide
- HiddenLayer + Trail of Bits — MCP attack research
- Descope blog — agentic identity / MCP auth series
- Knostic + Backslash Security — the MCP server scan disclosures
