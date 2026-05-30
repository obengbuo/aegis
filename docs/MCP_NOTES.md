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

## Enforcement architecture — deterministic capability scoping

### The principle

**Aegis's enforcement path contains no LLM.** The LLM may propose a capability
spec once, before execution begins, on trusted user-supplied input. After that,
every tool call is evaluated by deterministic code against a static spec. No
LLM-as-judge, no intent classification at runtime, no mid-run renegotiation.

This is non-negotiable for the enforcement path. If you find yourself adding an
LLM call inside `evaluate()` or inside the wrapper's DENY/ALLOW branch, stop
and flag it explicitly for review. Do not quietly add it.

### The bootstrap problem

An LLM-based inspector inherits the instability of the thing being inspected.

The attack scenario: an agent reads a file containing injected instructions. If
an LLM then decides whether to allow or deny the follow-on tool call, that LLM
is reasoning from a context that is already contaminated — the injected
instructions are in the same prompt window. A sufficiently crafted injection can
cause the "inspector" LLM to conclude that the out-of-scope call is acceptable.
The inspector and the executor share the same prompt; you cannot inspect a
corrupted prompt with a prompt.

The solution: narrow the executor, don't broaden the inspector. Define the
permitted capability surface before execution begins, on input the attacker has
not yet touched (the user's task description). Lock that surface into a static
data structure. Evaluate every subsequent tool call against the static surface
using code that has no opinion about intent — only about whether the (server,
tool, args) triple matches the spec. Code has no prompt window to inject.

### Capability-based security precedent

This architecture is an instance of capability-based security, a lineage that
runs through the E programming language (Mark S. Miller, 1997) and the KeyKOS
operating system (Bomberger et al., 1980s–1990s). The core idea: a principal
has authority to perform exactly the actions for which it holds an explicit,
unforgeable capability — not because it claims a role, and not because an
authority decides at runtime that its intent appears good.

In E and KeyKOS, capabilities were first-class objects passed at object
construction time. The Aegis analogue: the capability spec is passed into
`make_process_tool_call()` as a closure argument before the agent run begins.
The agent inherits the spec at construction time; it cannot modify the spec
mid-run; it observes the outcome (ALLOW or PermissionError) but cannot appeal
or renegotiate.

Why this matters specifically for AI agents: agents are powerful but
unverifiable. You cannot inspect an LLM's internal reasoning and be certain it
will not follow an injected instruction. Capability scoping sidesteps this
problem entirely — you do not need to verify the agent's intent; you constrain
what it can do regardless of intent. The enforcement guarantee comes from the
code, not from the model.

### Implementation contract

- `aegis/policy.py::evaluate(spec, server, tool, args) -> Decision` is
  synchronous, pure, no I/O, no imports from any LLM library.
- `aegis/wrapper.py::_process()` calls `evaluate()` before `call_tool()`.
  The verdict is final. No retry logic, no LLM interpretation of the denial.
- A DENY is a first-class audit event with `status: "denied"`, `reason`, and
  `matched_rule` fields. The denial itself is governance-relevant.
- If spec loading fails (malformed YAML, schema validation error), the run is
  aborted before any tool calls happen. A malformed spec means DENY-all, never
  ALLOW-all. Fail closed.

---

## Reading list

- modelcontextprotocol.io/specification — the full spec
- Anthropic's MCP introduction + architecture posts
- Simon Willison's blog, `mcp` tag
- OWASP GenAI Security Project — secure MCP server development guide
- HiddenLayer + Trail of Bits — MCP attack research
- Descope blog — agentic identity / MCP auth series
- Knostic + Backslash Security — the MCP server scan disclosures
