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

## The audit log records tool content verbatim, including credentials

**RESOLVED 2026-09-16 — do not re-open.** Both exits are closed, and the two
found while fixing them with it. Redaction is now independent of
`response_inspection_mode`: that setting governs detection output and refusal,
recording is always redacted. Four fields are scanned before being written —
`result_preview`, each argument value, a denial's `reason`, and an `error`
message — and what is scanned is the already-truncated text, because only the
truncated text can reach the log. That caps the cost at 500 characters per
response and 1000 per argument, which is what made scanning unconditionally
affordable; a full-response scan for callers who never asked for inspection
would not have been.

The `reason` exit does not go through `_safe_args`: `aegis/policy.py` builds
that string from the raw args dict, so redacting arguments does not cover it.
It is redacted in `aegis/wrapper.py` instead, which keeps all audit redaction
at one seam and keeps the enforcement path free of any scanner import.

`off` still means no `response_pattern_detected` record and nothing refused.
Injecting a new record type into every existing deployment's audit stream would
have been a behavioural change nobody asked for, which is why changing the
default to `warn` was rejected. Because there is no detection record to point
at in that case, the preview notice names the mode and how to get details
instead of naming a record that does not exist.

Verified against a live run rather than reasoned about — a real Haiku agent, a
real filesystem MCP server, default config, reading a file containing a real
private key:

```
mode: off (the default)
  spec_loaded  preview='-'
  ok           preview='[redacted: response preview matched a sensitive-data pattern. response_i'

  whole audit file contains 'BEGIN RSA PRIVATE KEY': False
  whole audit file contains the key body           : False

  agent still received the file contents (not modified by Aegis):
    Based on the content, this is an **RSA private key file**.
```

Deliberately unchanged: a `PermissionError` raised to the caller still names
the rejected value. The caller supplied it, and a denial message that hides the
value is not diagnosable. Aegis redacts what Aegis writes.

A test at `tests/test_response_inspection.py` asserted the SSN was present in
`result_preview` under `off`, pinning the leak as intended behaviour. It was
inverted deliberately and its comment now states what it pins instead.


**The question.** Every successful tool call records a `result_preview` — 500
characters of the tool's response — and every call records its arguments,
truncated at 1000 characters each. Neither is redacted unless response
inspection is enabled, and `AegisConfig.response_inspection_mode` defaults to
`"off"`. So in the shipped configuration a credential returned by a tool, or
passed to one, is written to `logs/audit.jsonl` in plain text.

This is logged as one entry rather than two because it is one defect with two
exits. Splitting them would let the worse exit hide behind the fix for the
milder one.

**How it surfaced.** While verifying MCP01's claim in
`docs/OWASP_MCP_TOP10.md` that "Aegis never writes matched secrets into its own
audit records". The redaction path is real and works — but only when inspection
is on, which it is not by default:

```
status=ok  mode=off (the default)
result_preview = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA_real_key_material_her'
*** raw private key material in the audit record: True
```

The full behaviour, verified across every mode and match tier:

| mode | response content | `ok` record | `result_preview` |
|---|---|---|---|
| `off` (default) | block-tier match | written | **raw** |
| `off` (default) | warn-tier match | written | **raw** |
| `warn` | any match | written | redacted |
| `block` | block-tier match | none — call refused | n/a |
| `block` | warn-tier match | written | redacted |
| any | no match | written | raw (correct — nothing matched) |

The redaction machinery is complete. It simply never runs at the default.

**The second exit, which is worse.** `_safe_args` in `aegis/wrapper.py`
truncates argument values and does not redact them — its own comment says "NOTE
for Phase 2: this is also where PII redaction will live." Response inspection
only ever scans responses, so an argument is logged verbatim in **every** mode,
including `block`:

```
  mode=block block-secret-in-args   records=['ok']
        raw in preview: False    raw in args: True
```

An agent calling `write_file(content=<private key>)` writes that key to the
audit log no matter how response inspection is configured. This exit is not
default-dependent, which makes it the more exposed of the two.

**Why the default is the wrong one.** A security product whose default
configuration writes the secrets it exists to protect into a plaintext file on
disk has the default backwards. The audit log is also the artifact most likely
to be shipped elsewhere — to a control plane, to an OTLP collector, into a
support ticket — so the blast radius is wider than one file.

**What redaction would cost.** `result_preview` has no programmatic consumer:
it is absent from `_OTLP_ATTRIBUTE_MAP`, unread by `audit.query` and
`audit.summary`, and referenced only in tests. Its purpose is human debugging.
Redacting it on a match costs a preview of exactly those responses that should
not have been stored, and leaves the clean-response case — nearly all traffic —
untouched.

**Candidate directions:**
- Redact unconditionally: run the scanner purely to decide what is *recorded*,
  while `response_inspection_mode` continues to govern only what is *refused*.
  Separates "what do I record" from "what do I refuse". Cost is a scan on every
  response; largely avoidable by scanning only the 500-character preview rather
  than the whole response, since only the preview can leak.
- Change the default to `warn`. One line, but it conflates recording with
  refusing, writes a new record type into every existing deployment's audit
  stream, and runs a full-response scan for everyone.
- Hash the preview, or omit it unless explicitly enabled. Destroys the
  debugging value for all responses rather than the risky ones.
- Truncate more aggressively. Does not help: a private key header is
  identifiable in its first 31 characters.

**Trigger.** Before any design partner runs Aegis against a credentialed MCP
server — GitHub, Postgres, a cloud API — which is where the risk actually
lives, and which `docs/OPEN_QUESTIONS.md` §4 already lists as untested ground.

**Do not** re-introduce a mode-dependent recording path. Detection output and
refusal are configurable; what reaches the audit log is not.

---

## Server fingerprinting is unreachable from the installed package

**The question.** `aegis/fingerprint.py` hashes an MCP server's advertised tool
surface — names, descriptions, input schemas — stores a baseline, and reports
added, removed, and modified tools against it. The module works. Nothing an
integrator installs ever calls it.

**How it surfaced.** While verifying MCP03's claim in
`docs/OWASP_MCP_TOP10.md` that drift is recomputed on every run and raises an
alert before the agent executes.

```
=== callers of fingerprint functions ===
./aegis/wrapper.py:192:    note_server_seen(server_name)
./agents/stack.py:58:        result = check_server(name, tools)

agents/ present in site-packages: False
```

`check_server()` has exactly one caller, `agents/stack.py`, and
`pyproject.toml` has `include = ["aegis*"]`, so `agents/` is not packaged. An
integrator following `docs/INTEGRATION.md` gets no drift detection at all.
What `wrap_toolset` does call is `note_server_seen()`, which adds a name to
`_seen_this_session` — a module-level set that nothing reads.

**Four separate gaps, not one.**
1. Not wired: no code path in the installed package reaches `check_server()`.
2. No alerting: `check_server()` returns a dict for its caller to inspect. It
   writes no audit record, raises nothing, and blocks nothing. `agents/stack.py`
   prints to stdout.
3. Baseline overwritten on drift (`aegis/fingerprint.py:109`), so a change is
   reported once and the next run reports `unchanged`. The one signal is
   consumed by the act of observing it.
4. No tests: no file under `tests/` references fingerprinting.

**Impact.** MCP03 coverage rests entirely on the capability spec constraining
what a poisoned tool can *do* — which is real, and is what the mapping now
claims. The supply-chain-integrity story that `fingerprint.py`'s own docstring
describes is not in effect for anyone.

**Candidate directions, none chosen:**
- Call `check_server()` from `wrap_toolset` and write an audit record on drift.
  Requires the toolset to be connected, since it needs `list_tools()` — so it
  belongs in the startup path rather than the per-call hook.
- Decide whether drift should block. Fail-closed is the house default, but a
  drifted description with an unchanged spec cannot widen what a tool may
  receive, so blocking may be the wrong severity.
- Require explicit baseline approval instead of auto-updating, so drift stays
  visible until acknowledged.
- Package `agents/` too. Rejected: it is the development stack, not product.

**Trigger.** Before making any public claim that Aegis addresses MCP supply
chain or tool poisoning through drift detection. Tracked as a roadmap item in
`README.md`. Nobody is currently relying on it, which is the only reason this
is a question rather than an incident.

---

## The SSN detector's dummy-data window suppresses real matches

**The question.** `_scan_ssn` skips any `NNN-NN-NNNN` match with `test`,
`dummy`, or `example` within 20 characters, to avoid firing on fixture data.
The window is content-blind, so an unrelated token containing one of those
words suppresses a real SSN sitting beside it.

**How it surfaced.** A probe written to check MCP01's redacted-preview examples
returned only the AWS key from a response containing both:

```
response: "key: AKIAIOSFODNN7EXAMPLE and ssn 123-45-6789"
patterns matched: [aws_access_key]        <- SSN absent
```

`AKIAIOSFODNN7EXAMPLE` — the canonical AWS documentation key — contains
`EXAMPLE`, which fell inside the SSN's 20-character window and suppressed it.

**Impact.** Low but real, and it fails open rather than closed, which is the
wrong direction for a detector. The suppression is silent: no record says a
match was discarded. Any response that legitimately contains one of the three
markers near a real SSN loses the detection.

**Candidate directions, none chosen:**
- Require the marker to be adjacent to the match rather than within 20
  characters, or require it to be a whole word.
- Require the marker to precede the match, on the theory that a label comes
  before its value.
- Drop the heuristic and accept fixture-data false positives, on the grounds
  that a detector that silently discards matches is worse than a noisy one.
- Record suppressed matches at a third tier below `warn`, so the decision is
  visible rather than invisible.

**Trigger.** Deferred. Revisit if a real deployment reports a missed SSN, or
alongside the pattern-configurability work (`response_inspection_pattern_verdicts`)
that `aegis/response_inspection.py` already names as a v2 knob — the exclusion
window is the same kind of per-pattern tuning.

---

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
- **2026-09-16** — Logged three code issues found while verifying
  `docs/OWASP_MCP_TOP10.md` against the implementation: the audit log
  recording tool content verbatim (two exits — `result_preview` at the
  default, and `args` in every mode), fingerprinting being unreachable from
  the installed package, and the SSN detector's dummy-data window suppressing
  real matches. The first is being fixed now; the other two are deferred with
  triggers.
- **2026-09-16** — Fixed the audit-log exit above. Verifying it turned up two
  more paths than the two originally reported: a denial's `reason`, built in
  `policy.py` from the raw args and so not covered by redacting arguments, and
  a tool exception's `error` text. All four are redacted at one seam in
  `wrapper.py`, independently of `response_inspection_mode`. Fingerprinting and
  the SSN window remain open with their triggers.
