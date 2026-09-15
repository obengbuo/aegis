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

## 5. Audit-record field completeness — is a full write_record call-site pass due?

**The question.** Audit-record fields have been filled in reactively, one at a
time, each time the control plane's query API turned a documented approximation
into something it could answer exactly. Two such gaps are now closed (below).
The open question is whether to do a single deliberate pass over *every*
`write_record` call site — a dozen-plus across `wrapper.py`, `policy.py`, and
`proposer.py` — checking each record carries the fields a downstream reader
needs, rather than continuing to discover them one backend caveat at a time.

**Closed already (control-plane-driven — do not re-open).**
- `response_inspection_mode` on the `response_pattern_detected` record — **DONE**.
  Lets the control plane's `/v1/denials` view distinguish a *blocked* response
  from one merely *warned* and returned to the agent unchanged. The record
  already carried the verdict (clean/warn/block); it now also carries the
  configured mode, which is what says whether Aegis actually withheld anything.
- `run_id` on the `spec_loaded` record — both `load_spec` and `propose_spec` —
  **DONE**. Lets `/v1/runs/{run_id}` return the record that *opened* a run by
  exact `run_id` match, instead of inferring the association from this
  deployment's `spec_hash` + timestamp ordering (an inference that is knowably
  ambiguous when the same spec was loaded twice before a run). Optional
  parameter; omitted → the record is unchanged from before. Chosen as a bare
  `run_id` string rather than the whole `AegisConfig` so the loader stays free
  of any dependency on `config.py`. See CONTROL_PLANE_DESIGN.md §7.

**Paired change, waiting on the control plane.**
- `unshipped_before_configure: N` in the *batch envelope* (alongside
  `dropped_since_last_batch`), reporting records written before the control
  plane was configured. Today that gap is reported to **stderr only**, by
  `shipper._report_missed_records`. stderr is the operator's terminal, which
  during an unattended run is nobody's terminal — so the dashboard still shows
  a run whose opening record is merely absent, indistinguishable from a run
  that never had one. Putting the count on the wire is what would let
  `/v1/runs/{run_id}` say "this run's `spec_loaded` exists locally but was
  never shipped" instead of silently falling back to `spec_hash`+timestamp
  inference. **Blocked on** `/v1/records` consuming the field — adding it
  first would violate the rule at the bottom of this section. Do them as one
  paired change, library and backend together.

**Still open — the general pass.**
Whether to audit all `write_record` call sites at once. *Against:* it is
speculative — adding fields no consumer has asked for is guessing, and each of
the two fixes above came from a concrete downstream need, which is the right
forcing function. *For:* discovering these one at a time means the backend
ships a caveat, then later a migration, for each; a single pass might retire
several caveats in one release.

**Trigger.** Do the pass when a *third* control-plane caveat traces back to a
missing library field — two is coincidence, three is a pattern worth an hour of
systematic review. Until then, keep fixing them as concrete needs surface.

**Do not** add record fields no control-plane route actually consumes yet.

---

## Path representation must agree across three places, and nothing checks it

**The question.** Rule 7 does literal string equality on argument values. That
means the user's request, the proposer's emitted spec, and the agent's actual
tool call must all agree on how a file is named. Nothing enforces or checks
that agreement.

**How it surfaced.** A demo run where the request named bare filenames
("read meeting-notes.txt, agenda.txt, and action-items.txt in the sandbox").
The proposer emitted absolute paths per R3. The agent, having never seen an
absolute path, invented a `sandbox/` prefix and called
`read_text_file(path="sandbox/agenda.txt")`. All three legitimate reads were
refused. Aegis behaved correctly — the spec genuinely did not permit that
string — but the refusal reason said "not in capability spec" without
conveying that the two strings describe the same file.

The false positive lands on exactly the calls the user asked for, which is the
worst place for one.

**Why R3 doesn't cover it.** The proposer prompt's R3 governs what the
proposer *emits*. It says nothing about what the agent *calls with*, and the
agent never sees the spec.

**Candidate directions, none chosen:**
- Normalise paths at evaluation time. Rejected on the same grounds as globs in
  Week 3 — path normalisation is where traversal bypasses live.
- Have the proposer emit a clarification when the request contains relative or
  ambiguous paths, rather than resolving them silently.
- Have the denial reason detect the near-miss (same basename, different
  prefix) and say so. Doesn't prevent the refusal but makes it diagnosable.
- Document the constraint prominently in INTEGRATION.md and treat it as an
  operator responsibility.

**Trigger.** Before a design partner integrates. This will bite whoever tries
it first, and the failure looks like Aegis being broken rather than a naming
mismatch.

----

## Revision log

- **Week 7** — First version. Four questions logged with explicit triggers.
- **2026-09-14** — Added Q5 (audit-record field completeness). Logged two
  control-plane-driven fixes as done — `response_inspection_mode` on
  `response_pattern_detected`, `run_id` on `spec_loaded` — with the general
  write_record call-site review left open behind a rule-of-three trigger.
- **2026-09-15** — `run_id` on `spec_loaded` was reaching JSONL but never the
  control plane: the shipper was activated by `wrap_toolset`, which is the
  earliest point a *toolset* is known, not the earliest point the
  *destination* is known. Activation moved to `AegisConfig.__post_init__`.
  Logged `unshipped_before_configure` above as a paired change. The loader
  still takes a bare `run_id` and still has no dependency on `config.py` —
  the coupling added runs config → shipper, the other direction.
