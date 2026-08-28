# Aegis — Competitive Landscape

Living document. Updated as new information surfaces. Each entry: source,
what they actually do (verified, not assumed), and what it means for
Aegis's positioning.

---

## Pydantic Logfire — Agent Governance (adjacent, not competing)

**Source:** https://pydantic.dev/logfire/agent-governance (checked Aug 2026)

Pydantic — the company behind the exact framework Aegis integrates with —
ships an "Agent Governance" product inside Logfire. Important to understand
precisely, since prospects in the Pydantic AI ecosystem may bring it up.

**What it does:** Enforces policy on the *model-request path*. Spend
ceilings, DLP scanning on prompts before they leave the org's boundary,
model allow-lists — refused before the request reaches the LLM provider.
Every decision recorded in the same OpenTelemetry trace as the agent's run,
via Pydantic AI Gateway.

**What it explicitly does NOT do:** Govern MCP tool calls. Their own FAQ:
"Controlling what an agent may do at runtime: which models it can call,
how much it can spend, and what data may leave with its prompts." Nothing
about tool arguments, MCP servers, or capability scoping once the model
decides to act.

**The distinction, stated plainly:**
- Logfire governs what the agent asks the model.
- Aegis governs what the agent's tools actually do once it decides to act.

**Why this matters for positioning:** This is the most likely "obvious
competitor" objection Aegis will face from anyone already in the Pydantic
AI ecosystem — "don't you already have governance via Logfire?" The answer
is precise and technically verifiable, not a hand-wave: different layer,
different enforcement point, complementary rather than overlapping.

**Possible complementary story (not yet explored):** Logfire is
OTLP-based. Aegis already exports OTLP. A team running both could
plausibly see Aegis's tool-call decisions in the same trace as Logfire's
model-request decisions — worth exploring if a prospect asks, not yet
validated.

**Action item:** Use this distinction in the wedge sentence and in any
outreach to companies already using Pydantic AI / Logfire.

---

## Still to verify
- MintMCP
- MCPGuard
- Lasso Security
- Operant AI