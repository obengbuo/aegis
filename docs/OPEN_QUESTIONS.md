# Aegis — Open Questions

Decisions that are deliberately not made yet. Each has a trigger condition
— the thing that should happen before deciding, so the question resurfaces
at the right moment instead of either being forgotten or re-litigated at
11pm.

---

## 1. Positioning: general MCP governance, or delegated production authority?

**The question.** Aegis is currently positioned as runtime capability
enforcement for AI agents on MCP — general purpose. A sharper alternative
exists: *safe delegation of production authority to autonomous agents*,
with Kubernetes incident remediation as the beachhead.

The narrow version reads roughly: an SRE agent detects a failing service
and wants to restart a deployment. Aegis holds the delegation — this agent,
this incident, this namespace, these operations, this time window, these
blast-radius limits — and enforces it per call.

**Why it might be right.**
- Puts real daylight between Aegis and the crowded "AI agent security"
  center where Zenity, Noma, Lasso, and Microsoft AGT all sit.
- Strong founder-market-fit: NERC-CIP IT/OT boundary work, container build
  platform for a large Kubernetes fleet. Bounded, auditable, fail-closed
  authority near operational infrastructure is the day job.
- The framing shifts from "stop the agent doing something bad" to
  "give the agent exactly enough authority to do this task" — controlled
  enablement rather than pure prevention.

**Why it is not decided.**
- Not what any current conversation is about. Qualio is compliance
  workflows. Waxell is general fleet governance. Rohit is identity vs.
  runtime. None of the live threads raised Kubernetes.
- Requires real new engineering. The spec format does literal string
  matching only. It cannot currently express "max 8 replicas" (numeric
  bounds), "expires in 30 minutes" (time bounds), or "bound to incident
  INC-4821" (task binding). That is new work, not a messaging change.
- Would mean re-angling messaging mid-outreach with five threads in flight.

**Trigger.** Decide after enough discovery conversations to know whether the
pattern is real. Specifically: ask platform / SRE / infrastructure people
some version of *"what's stopping you from letting an AI agent make
production changes today?"* and listen. If three or more independently
describe wanting to delegate bounded authority for a specific incident or
task and not having a control they trust — that is the signal. Until then,
carry it as a hypothesis, not a plan.

**Do not** build time-bounded or blast-radius delegation semantics before
that evidence exists.

---

## 2. Licensing: stay MIT, or move to source-available?

**The question.** Aegis is MIT licensed. Anyone — including Zenity, Noma,
C1, or Microsoft — may legally take the code, modify it, ship it
commercially, and owe nothing. Nobody can alter the Aegis repo itself, but
anyone may fork and build on it.

**The case for keeping MIT.**
- The code is not the moat. Any funded team could rebuild the enforcement
  logic in a couple of weeks.
- Open source is actively doing work right now. Every outreach message
  sent this week said "public repo, pip-installable, look for yourself."
  A source-available license adds friction to exactly the evaluation step
  that currently converts interest into conversation.
- Adoption is worth more than exclusivity at zero customers.

**Alternatives if that changes.**
- **BSL** — source public and auditable, commercial use requires a separate
  agreement, converts to open source after 3-4 years. Built for precisely
  this concern. Used by HashiCorp, MongoDB, Elastic, Sentry.
- **Open core** — enforcement engine stays MIT; the eventual commercial
  layer (control plane, multi-tenancy, hosted service, dashboard) is
  licensed separately.

**Trigger.** Revisit before whichever of these comes first: taking outside
money, signing a commercial agreement with a design partner, or Catalyst
prep. Open core in particular is only decidable once it is clear which part
people will actually pay for — which is not clear yet.

**Do not** change the license mid-conversation with threads in flight. It
reads as reactive and creates confusion.

---

## 3. Naming: keep "Aegis"?

**The question.** "Aegis" is heavily used in the security space. Real
trademark and SEO friction is plausible at scale.

**Current state.** Domain `aegisruntime.dev` registered and live. Everything
— repo, LinkedIn build-in-public posts, the Waxell relationship, all five
outreach threads, the package import path — uses this name. Switching costs
are real and rising.

**Trigger.** Revisit during Catalyst prep, with the benefit of more customer
conversations and program feedback. A rename is normal pre-Series-A and not
a red flag; doing it as one clean deliberate pass beats doing it under
deadline pressure. Before committing permanently, run a proper USPTO
trademark clearance search.

---

## 4. Features audit — what is genuinely thin?

**The question.** An honest read of the current codebase against the
three-question filter:

1. Does it need to exist before the next real design-partner conversation?
2. Does it make Aegis more credible to a platform or security engineer?
3. Can it ship without breaking momentum on customer discovery?

**Known candidates, not yet prioritized.**
- Audit log has no persistence layer beyond append-only JSONL. Concurrency
  behavior under many simultaneous agents is untested and suspected weak.
- No benchmarks. Per-call latency added by Aegis is unmeasured.
- Only tested against filesystem and fetch MCP servers. Not against
  credentialed servers (GitHub, Postgres, cloud APIs) where the real risk
  lives.
- `_safe_args` truncates at 1000 chars with no PII redaction hook.
- The unnamed `process_tool_call` fallback in `wrapper.py` is effectively
  dead code kept for backward compatibility.
- Multi-server-per-agent path exists by design but has not been exercised
  end to end.
- No RBAC, SSO, multi-tenancy, or org model. Every install is standalone.

**Trigger.** Let design-partner feedback order this list. Building ahead of
that signal is guessing, and guessing wrong is how a solo founder loses a
quarter. If a conversation surfaces a specific blocker, that item jumps to
the top regardless of where it sits here.

---

## Revision log

- **Week 7** — First version. Four questions logged with explicit triggers.
