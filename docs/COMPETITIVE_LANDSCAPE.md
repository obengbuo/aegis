# Aegis — Competitive Landscape

Living document. Updated as new information surfaces. Each entry: source,
what they actually do (verified, not assumed), and what it means for
Aegis's positioning.

---

## What this landscape means

1. **The category formed faster than the original 90-day plan assumed.** As
   of mid-2026 this is a contested space with funded entrants and a
   Microsoft implementation, not an empty field.

2. **"Runtime security for AI agents" is no longer differentiated
   positioning.** Multiple well-resourced companies say a version of it.
   Aegis cannot win that framing on breadth.

3. **The remaining defensible ground is narrower and deeper.** Candidates:
   a specific vertical with compliance requirements nobody else has tuned
   for; a specific class of high-consequence action (production
   infrastructure); or a depth of delegation semantics — task binding, time
   bounds, blast-radius limits — that the generalists have not built because
   their buyers have not demanded it yet.

4. **Speed and customer depth are the only real advantages available to a
   solo founder here.** Not code, not features. Whoever gets three real
   design partners deeply integrated first has something the funded
   companies cannot quickly copy.

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

## Microsoft Agent Governance Toolkit (AGT) — VERIFIED

**Source:** Microsoft engineering blog, "Securing MCP: A Control Plane for
Agent Tool Execution" (April 2026). Open source.

**What it does:** Inserts a deterministic policy engine between an agent's
decision to invoke an MCP tool and the tool actually executing. Evaluates
identity and policy context per call, returns allow / deny / human
approval, and writes append-only audit records. Supports tool scanning,
per-call policies, privilege levels, and kill switches. OpenTelemetry
integration.

Microsoft's own framing of the question it answers: *is this agent allowed
to invoke this tool, with these arguments, right now?*

**Assessment — the most architecturally significant finding in this
document.** This is structurally the same control point Aegis occupies, from
a vendor with effectively unlimited distribution, released as open source.
It is strong validation that the problem is real and the layer is correctly
identified. It is also the hardest competitive fact to argue around.

**What it does not obviously do (needs verification):** task-scoped
capability specs generated per-request, response-side inspection, or
time/blast-radius-bounded delegation. Worth reading their actual policy
schema closely before claiming any differentiation here.

**Action:** Read the AGT policy model in detail. Any claim of
differentiation against Microsoft must be specific and verifiable, not
hand-waved.

---

## Zenity — VERIFIED

**Source:** Zenity product materials; Gartner named them "Company to Beat"
in AI Agent Governance (April 2026).

**What they do:** Discovery of MCP servers and tools, live interception of
tool calls with allow / modify / block decisions, identity association,
coverage across Copilot, Salesforce, Bedrock, Claude Enterprise. Positioned
explicitly as "one control point for every MCP connection." Also covers
tool poisoning, shadow MCP servers, credential sprawl, tool drift.

**Assessment:** Closest to the full fleet-wide control-plane vision. Well
funded, analyst-recognized, enterprise sales motion already running. If
Aegis ever pitches "centralized control point for all agent tool calls,"
this is the company that answer gets compared against — and today they win
that comparison on completeness, coverage, and credibility.

**Implication:** Do not compete on breadth. Any Aegis wedge that survives
contact with Zenity has to be narrower and deeper than "control point for
agent tool calls."

---

## C1 — UNVERIFIED

**Reported:** Launched "Agent Runtime Governance." Scopes each agent to the
tools its job requires, governs every tool call against policy, ties actions
to a governed identity. Intent-based access control — permissions derived
from the task being performed rather than broad standing privileges.
Enterprise-managed authorization across MCP servers through one control
plane.

**Assessment if accurate:** Strategically the closest to Aegis's actual
thesis — task-derived permissions rather than standing privileges is
precisely the capability-spec model. Comes at it from identity/authorization
rather than runtime enforcement, but the two converge.

**Action:** Verify directly before relying on this. If accurate, this is the
company whose positioning most directly overlaps Aegis's.

---

## Noma Security — UNVERIFIED

**Reported:** "Agentic Access Control" launched June 2026. Discover, govern,
and enforce access policies for AI agents and MCP servers across the
enterprise.

**Action:** Verify.

---

## Lasso Security — UNVERIFIED

**Reported:** Agent and tool discovery, intent-aware governance, real-time
threat detection, policy enforcement, compliance/audit logging. Runtime
enforcement at proxy / API / gateway layers. Explicitly covers MCP servers
and tool calls.

**Assessment if accurate:** Broader AI-security posture with runtime
enforcement included, rather than enforcement-first. Overlaps but with a
different center of gravity.

**Action:** Verify.

---

## Ory, Lakera, Permiso — UNVERIFIED

Reported as adjacent: Ory extending authorization into agent runtime
enforcement; Lakera on runtime agent security and prompt-injection
protection; Permiso on runtime attribution and monitoring of agent activity.

**Action:** Verify if any becomes relevant to a specific conversation.

---

## MintMCP, MCPGuard — UNVERIFIED

From an earlier competitive analysis, never independently checked. MintMCP
reportedly SOC 2 Type II certified; MCPGuard reportedly an open-source
project positioning as "the missing chokepoint." Lower priority to verify
than the entries above.

---

## Still to verify
- Lasso Security
- Operant AI