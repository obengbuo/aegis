# Aegis — 90-Day Build Plan

The condensed, engineer-facing version of the plan. Operating constraints:
day job continues, ~15–18 hrs/week, $1,000 budget, decision point at day 90.

---

## Phase 1 — Learn & Instrument (Days 1–30)

Goal: a multi-agent stack calling 5+ MCP servers, every tool call logged
through Aegis, fingerprinting working, two public blog posts written.

### Week 1 — Foundation
- [ ] Send the Logan follow-up email (DONE)
- [ ] Environment: Python 3.12, Pydantic AI, Node, project scaffold
- [ ] `aegis/wrapper.py` — the interception hook
- [ ] First agent calling the filesystem MCP server
- [ ] Wire up fetch (second zero-credential server)
- [ ] Run the prompt-injection harness, screenshot the audit log
- [ ] Week 1 build-in-public post

### Week 2 — MCP protocol deep dive
- [ ] Read the full MCP spec end to end
- [ ] Write your own minimal MCP server from scratch
- [ ] Add GitHub, Postgres, Brave servers to the stack (now 5 total)
- [ ] Reading list: Anthropic MCP docs, Simon Willison, OWASP GenAI,
      HiddenLayer + Trail of Bits MCP research, Descope MCP blog series

### Week 3 — Audit layer hardening
- [ ] `aegis/audit.py` — querying, summary stats (DONE in starter)
- [ ] Add OpenTelemetry traces + local Jaeger
- [ ] Correlation IDs across multi-step agent runs

### Week 4 — Fingerprinting + first blog post
- [ ] `aegis/fingerprint.py` — wire `check_server` into the run flow
- [ ] Demonstrate drift detection (modify a local MCP server, catch it)
- [ ] Publish: "What I learned writing my own MCP proxy: 5 security gaps"

### Day 30 checkpoint
GREEN: energized, prototype runs, domain understood → Phase 2.
YELLOW: slower than hoped or burning out → cut scope, do NOT quit job.
RED: not enjoying it / no progress / life suffering → stop or pivot.

---

## Phase 2 — Build (Days 31–60)

Goal: ship Aegis v0.5 — proxy + policy engine + approval workflow +
threat detection + dashboard. Logan sees a working demo.

### Week 5 — Policy engine v1
- [ ] Decision flow: ALLOW / DENY / INTERCEPT in `wrapper.py`
- [ ] Five starter policies: tool allowlist, argument allowlist, rate limit,
      PII scan, approval-required for destructive calls

### Week 6 — Approval workflow + dashboard
- [ ] FastAPI control plane
- [ ] Next.js 14 dashboard: audit view, approval queue, policy editor

### Week 7 — Threat detection
- [ ] Prompt-injection detection on tool return values
- [ ] Pattern matching + LLM-as-judge (Haiku) + output anomaly detection

### Week 8 — Package + demo
- [ ] Single-container deploy (`docker run aegis/proxy`)
- [ ] Record the 3-minute demo video
- [ ] Day 56–58: send Logan the demo email

### Day 60 checkpoint
Logan's response shape determines next move (see full plan doc).

---

## Phase 3 — Validate (Days 61–90)

Goal: one design partner running Aegis in their environment.

### Week 9 — Design-partner outreach
- [ ] 30-target list: prior contacts, fintech security engineers,
      build-in-public responders, Logan intros
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
