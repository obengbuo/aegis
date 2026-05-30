# Aegis — 90-Day Build Plan

The condensed, engineer-facing version of the plan. Operating constraints:
day job continues, ~15–18 hrs/week, $1,000 budget, decision point at day 90.

This document is rewritten as of end-of-Week-2 to reflect what actually
shipped, what got deferred, and what emerged that wasn't in the original
plan. The original plan was a guess made with no domain experience; this
version is calibrated to the real terrain.

---

## Phase 1 — Learn & Instrument (Days 1–30)

Goal: a multi-agent stack calling 3+ MCP servers, every tool call logged
through Aegis, fingerprinting working, injection detection validated in
both directions, public build-in-public cadence established.

### Week 1 — Foundation (DONE)
- [x] Send the Logan follow-up email
- [x] Environment: Python 3.12, Pydantic AI, Node, project scaffold
- [x] `aegis/wrapper.py` — interception hook with closure-based server
      identity (better design than the original shared-function approach)
- [x] First agent calling the filesystem MCP server
- [x] Wire up fetch (second zero-credential server)
- [x] Prompt-injection harness — negative case (agent resists, detector
      reports clean)
- [x] Prompt-injection harness — positive case (agent gets genuinely
      hijacked, detector fires correctly)
- [x] Week 1 build-in-public post

### Week 2 — Fingerprinting & Server Lifecycle Hardening (DONE)
- [x] `aegis/fingerprint.py` — `check_server` wired into the run flow
- [x] Write your own minimal MCP server from scratch (`tools/demo_server.py`)
- [x] Demonstrate drift detection (modify a tool description, catch it)
- [x] `aegis/startup.py` — `managed_servers()` context manager:
      retry-with-backoff, fail-closed policy, `server_init_failed` as a
      first-class audit event (not in original plan, emerged from testing)
- [x] Explicit subprocess teardown with PID tracking, SIGTERM → grace →
      SIGKILL escalation, `server_teardown` audit records that prove every
      child process actually died (not in original plan; required because
      FastMCP/MCP teardown leaks `node` grandchildren on Windows)
- [x] Five failed runs, zero orphaned processes; five clean runs, zero
      orphaned processes (verified)
- [x] Week 2 build-in-public post with drift + teardown screenshots
- [x] Engaged a capability-based-security domain expert in the comments
      who is now informally shaping Phase 2 architecture

### Items deferred from the original Week 2 plan
These were in the original Week 2 plan but moved to future weeks because
they conflicted with the more urgent work that emerged:

- [ ] Read the full MCP spec end-to-end → scheduled for Week 3 Saturday
- [ ] Add GitHub, Postgres, Brave MCP servers (5 total) → Week 4 once
      capability scoping makes credentialed servers safer to wire in
- [ ] Reading list — Simon Willison, OWASP GenAI Top 10 for LLM,
      HiddenLayer, Trail of Bits, broader Descope MCP series → Weeks 3-4,
      ~1 hour per Saturday

### Week 3 — Deterministic Capability Scoping (IN PROGRESS)
The architectural pivot prompted by the LinkedIn capability-based-security
commenter. The principle locked in: **Aegis's enforcement path contains
no LLM.** The LLM may propose a capability spec once before execution;
after that, every tool call is evaluated by deterministic code against a
static spec.

- [ ] Add "Enforcement architecture — deterministic capability scoping"
      section to `docs/MCP_NOTES.md` with the bootstrap-problem reasoning
      and capability-security precedent
- [ ] Design capability spec format in `docs/CAPABILITY_SPEC.md` with three
      worked examples: read-only summarizer, web research task, file write
      task. Literal-only argument matching for v1 (no globs, no regex).
- [ ] `aegis/policy.py` — `evaluate(spec, server, tool, args) -> Decision`.
      Pure, synchronous, no I/O, no LLM. Tests first.
- [ ] `tests/test_policy.py` — coverage for: tool not in spec → DENY,
      arg not in allow-list → DENY, exact match → ALLOW, missing required
      arg → DENY, malformed spec → raises at load time, `deny_all_others`
      with unknown tool → DENY
- [ ] Wire `evaluate()` into `aegis/wrapper.py` at the Phase 2 insertion
      point. ALLOW → log and forward. DENY → audit-log with reason, raise
      `PermissionError` to the agent.
- [ ] `tests/test_enforcement.py` — rerun Week 1's positive injection
      scenario with capability spec active. Injection still lands in
      reasoning; enforcer blocks the out-of-scope call. Audit log shows
      ALLOWed read of requested file + DENIED attempt on second file.
- [ ] Saturday reading: full MCP specification end-to-end
- [ ] Week 3 build-in-public post — the audit log of a deterministically
      blocked injection is the screenshot

### Week 4 — LLM-based Capability Proposer + Reading
- [ ] Build the LLM call that reads a user request and emits a capability
      spec. Runs once at the start of an agent task, on the trusted user
      input, never on attacker-controlled tool output.
- [ ] Prove the trust boundary holds: an injection in tool output cannot
      cause the spec to widen mid-run. If the agent needs more capability,
      it halts and asks. No mid-run renegotiation.
- [ ] Add GitHub, Postgres, Brave MCP servers — capability scoping makes
      credentialed servers safer to test against
- [ ] Saturday reading: Simon Willison on MCP, OWASP GenAI Top 10 for LLM,
      one HiddenLayer or Trail of Bits MCP paper
- [ ] Polish: fix the `by_tool: '?'` audit summary issue (lifecycle records
      shouldn't render as a tool category)
- [ ] Week 4 build-in-public post

### Day 30 checkpoint
GREEN: energized, capability scoping working end-to-end, deferred reading
substantially done, ready for Phase 2. Proceed.
YELLOW: enforcement working but slower than hoped, or burning out. Cut
scope; do NOT quit Con Edison.
RED: not enjoying it / wrong wedge / life suffering. Stop or pivot.

---

## Phase 2 — Build for Real Users (Days 31–60)

Goal: take the working enforcement core and make it operable by someone
other than you. Logan sees a real demo at day 60.

### Week 5 — Approval Workflow + Audit Layer Hardening
- [ ] INTERCEPT decision path: certain tool calls require human approval
      before executing (the "halt and ask" mechanism from Week 4's design)
- [ ] OpenTelemetry traces + local Jaeger (deferred from original Week 3)
- [ ] Correlation IDs across multi-step agent runs (deferred from original
      Week 3) — critical for tracing injection attempts across tool calls

### Week 6 — Control Plane + First Deployable Form
- [ ] FastAPI control plane: load capability specs, submit approvals, query
      audit log via API
- [ ] Single-container deploy (`docker run aegis/proxy`)
- [ ] First deep technical blog post (deferred from original Week 4):
      "What I learned writing my own MCP proxy: 5 security gaps nobody
      is talking about." Published on personal blog, cross-posted to
      Hacker News and LinkedIn.

### Week 7 — Threat Detection Beyond Enforcement
- [ ] The read → enumerate → read-elsewhere attack signature detection
      (the pattern surfaced empirically in Week 1's audit logs)
- [ ] Output anomaly detection (oversized return values, unexpected
      content classes) — keep deterministic where possible
- [ ] If LLM-as-judge becomes necessary anywhere, isolate it to a separate
      module that the enforcement path can call but is not part of it

### Week 8 — Package + Demo + Logan
- [ ] Polish the dashboard (Next.js, only if needed for the demo)
- [ ] Record the 3-minute demo video
- [ ] Day 56–58: send Logan the demo email

### Day 60 checkpoint
Logan's response shape determines next move:
- Co-sell intro → take vacation, prep for first customer call
- Deeper review → schedule, prepare hard, push for customer intro
- Polite passthrough → iterate the demo, retry at day 80
- Silence → follow up at day 67, then 75, then move on

---

## Phase 3 — Validate (Days 61–90)

Goal: one design partner running Aegis in their environment.

### Week 9 — Design-partner outreach
- [ ] 30-target list: prior contacts, fintech security engineers,
      build-in-public responders, Logan intros, the capability-security
      commenter if they accepted the DM
- [ ] Send the demo + GitHub link

### Week 10 — First install
- [ ] Get Aegis running in someone else's environment within a week
- [ ] Pair on the install, log every friction point

### Week 11 — Iterate on real usage
- [ ] First design partner's friction = the product backlog

### Week 12 — Day-90 decision
- Scenario A: co-sell live, partners real → build for real, leave Con Ed
- Scenario B: promising, not conclusive → keep building on the side
- Scenario C: cool reception → consider the Waxell platform role

All three are wins. The only loss is not running the experiment.

---

## What changed in this rewrite, and why

- The original plan front-loaded the reading list and OpenTelemetry into
  Phase 1. Both got deferred because actual building exposed more urgent
  work (subprocess teardown, fail-closed startup, capability scoping).
  Honest scheduling beats aspirational scheduling.
- The "5 security gaps" technical blog post moved from Week 4 to Week 6.
  Writing it credibly requires more domain depth and a working
  enforcement story to anchor it to. Premature publication hurts more
  than late publication.
- Capability scoping (now Week 3-4) was not in the original plan at all.
  It emerged from a LinkedIn comment in Week 2 that identified the
  bootstrap problem with LLM-based intent detection. The architectural
  pivot is the most important thing that's happened in the project.
- The 5 MCP servers target dropped to 3 servers active (filesystem,
  fetch, demo). GitHub/Postgres/Brave get added in Week 4 once enforcement
  makes credentialed servers safer to wire in.
- Things that emerged but weren't in the plan now have explicit lines:
  positive-case injection harness, `managed_servers` context manager,
  subprocess teardown, `server_teardown` audit category.

---

## Budget ($1,000)

| Item                         | Spend |
|------------------------------|-------|
| Anthropic API credits        | $200  |
| Cursor / Claude Code Pro     | $60   |
| Domain                       | $20   |
| AWS (Phase 2+)               | $150  |
| LinkedIn Sales Navigator (1mo)| $100 |
| Logo + landing page design   | $200  |
| Reserve                      | $270  |

---

## Weekly rhythm

~16 hrs/week: 1 hr before work daily, 2 hrs x 3 nights, 4 hrs Saturday AM,
3 hrs Sunday PM. Sunday off from code. Date night weekly. Sleep 7+ hrs.
If family / partner / job / health breaks — pause Aegis, fix it, resume.

---

## Discipline rules carried forward from Weeks 1-2

These emerged from real mistakes and saved time both times. Keep them.

1. **Tests first when the code is the product.** `aegis/wrapper.py` got
   tests in Week 1; `aegis/policy.py` gets tests in Week 3 before the
   implementation. The interception layer and the enforcement layer are
   the product. They get tested like the product.

2. **Verify against reality, not against the description of the fix.**
   "Five clean runs, zero orphans" comes from actually counting processes,
   not from the patch notes claiming the leak is fixed. Same discipline
   applies to capability enforcement: verify the audit log shows the
   denial, don't trust the test's verdict text.

3. **Don't post on assumed wins.** Week 1's first injection test verdict
   was wrong twice before it was right. Week 2's subprocess fix needed
   three iterations. Don't post a screenshot until the underlying behavior
   is honest. The audit log is the source of truth.

4. **`secret.txt` and credential-shaped test fixtures stay out of the
   repo.** Test files use mundane content. The discipline of "build the
   minimum capability needed to prove the defense" applies to the test
   harness too, not just the product.

5. **Architecture decisions are written down in `docs/MCP_NOTES.md`
   before they're built.** The enforcement-architecture decision in Week 3
   is the first one to follow this rule formally. Future decisions go
   there too. The notes file is the design record, not just trivia.
