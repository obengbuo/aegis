# Aegis — Wedge

Living document. The one-sentence answer to "what is this and who is it for."
Rewritten whenever customer evidence changes it — not whenever the idea
sounds better in the shower.

---

## The sentence

> **Identity proves who an agent is. Aegis decides what it's allowed to do.**

Longer form, for when one line isn't enough:

> Aegis is a deterministic capability-enforcement layer for AI agents on the
> Model Context Protocol. A natural-language request generates a capability
> spec once, upfront, on trusted input. From that point, every tool call is
> evaluated by pure deterministic code against that frozen spec — no LLM
> anywhere in the enforcement path — with a forensic audit trail tying every
> decision to the exact policy version that made it.

---

## Buyer

Platform and security engineers at companies running AI agents with real
tool-calling access in production — especially in regulated or high-stakes
environments where "prove what the agent did, and why" is a live
requirement rather than a nice-to-have.

Not: AI/ML engineers building agents. Not: risk and compliance functions
(they move too slowly to be a first buyer, per Logan Kelly's direct advice).

---

## Job to be done

An agent has been authenticated and given tool access. Something must
decide, per call, whether this specific action is within what the agent was
actually authorized to do for this specific task — and must be able to prove
that decision afterward.

---

## Who we are explicitly NOT competing with

**Identity providers (Okta, Auth0, Descope, Ory).** They answer "is this
agent allowed in." Aegis answers "what may it do once it's in." Different
layer, composable rather than overlapping. Descope's own MCP work does
scope-based checks at the token level — coarse-grained and set at
authorization time. Aegis is fine-grained and set per-task.

**Pydantic Logfire Agent Governance.** Governs the *model-request* path —
spend ceilings, DLP on prompts, model allow-lists — refusing calls before
they reach the LLM provider. Aegis governs the *tool-call* path, after the
model has already decided to act. Verified against their own product
documentation. Complementary; both are OTLP-based and could plausibly
appear in the same trace.

---

## Why build vs. buy

The enforcement logic is not exotic — a competent team could write a
policy check in a week. What is hard to replicate quickly:

- Adversarially-reviewed rule semantics (closed-world at every level:
  server, tool, arg name, arg value)
- Fail-closed behavior verified under evaluator errors, not just assumed
- Log-injection and unicode-separator defenses in the audit path
- Cryptographic correlation between policy version, prompt version, and
  every decision
- Trust-boundary separation enforced structurally in code, not by prompt

The honest version: this is a temporal advantage, not a permanent moat.
The durable asset is customer depth and the record of delegated authority
over time, not the enforcement code itself.

---

## The five-minute artifact

Run `tests/test_enforcement.py`. A real agent, on a real model, reads a
file containing a prompt injection instructing it to also read a second
file. The agent follows the injection. Aegis blocks the call at the
wrapper layer before the MCP server sees it, with the rule ID and spec
hash in the audit record. Same agent, same injection, same model — the
only difference is whether Aegis is in the path.

---

## Evidence so far

**Supporting:**

- **Qualio** (compliance software, life sciences) hand-built human-in-the-loop
  approval for sensitive tool calls — a websocket snippet wired into
  specific tool invocations, waiting on confirm/reject. That is the
  INTERCEPT mechanism, built manually because nothing offered it. Source:
  their published Pydantic case study. This is the strongest single piece
  of evidence that the problem is real and currently unmet.
- **Logan Kelly (Waxell, agent governance platform)** named MCP security
  specifically as an underserved slice, and named engineering / operations /
  security as the buyers. Has 500 Pydantic AI agents in production and
  described the fleet as heterogeneous ("different strategies on the
  pydantic side, need to be ready for anything").
- **Microsoft shipping AGT** validates that the control point is real and
  worth occupying — a large vendor independently identified the same
  missing layer.

**Complicating:**

- The category is forming fast and is more crowded than it was two months
  ago. Zenity (Gartner "Company to Beat," April 2026), C1, Noma, Lasso all
  converging on runtime tool-call governance. Microsoft AGT is open source
  and architecturally close.
- No paying customers. No completed design-partner integration. The wedge
  is reasoned, not yet validated by someone's budget.

---

## Open question — a sharper wedge?

See `docs/OPEN_QUESTIONS.md`. There is a live hypothesis that a narrower
positioning — *delegated production authority for infrastructure agents* —
would put more daylight between Aegis and the crowded "AI agent security"
center. Not yet decided. Being tested in conversations, not resolved
internally.

---

## Revision log

- **Week 7** — First formal version. Sentence lifted from the language that
  emerged while writing the site copy for aegisruntime.dev, which forced
  the articulation.
