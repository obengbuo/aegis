# Aegis — OWASP MCP Top 10 (2025) Coverage

This document maps Aegis against the [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/),
category by category, and states plainly what Aegis does and does not address.

**Read the "Not covered" entries first if you are evaluating this.** Aegis is a
runtime capability-enforcement layer. It sits between an agent and the MCP servers
it calls, and it decides what a tool call is allowed to do. Several categories in
the Top 10 describe risks that occur before that boundary (credential handling,
supply chain, server discovery), and Aegis does not address them. A vendor
claiming full coverage of a ten-category taxonomy with one control is not being
straight with you.

Status values used below:

| Status | Meaning |
|---|---|
| **Covered** | Aegis enforces or detects this directly, with tests |
| **Partial** | Aegis addresses part of the category; the rest needs another control |
| **Not covered** | Outside the layer Aegis operates at |

Version: v0.2.0. Taxonomy version: 2025 (working draft).

---

## Summary

| Category | Status |
|---|---|
| MCP01 — Token Mismanagement & Secret Exposure | Partial |
| MCP02 — Privilege Escalation via Scope Creep | Covered |
| MCP03 — Tool Poisoning | Partial |
| MCP04 — Software Supply Chain Attacks & Dependency Tampering | Not covered |
| MCP05 — Command Injection & Execution | Partial |
| MCP06 — Intent Flow Subversion | Covered |
| MCP07 — Insufficient Authentication & Authorization | Partial |
| MCP08 — Lack of Audit and Telemetry | Covered |
| MCP09 — Shadow MCP Servers | Not covered |
| MCP10 — Context Injection & Over-Sharing | Partial |

Three covered, five partial, two not covered.

---

## MCP01 — Token Mismanagement & Secret Exposure

**The risk.** Hard-coded credentials, long-lived tokens, and secrets stored in
model memory or protocol logs. Attackers retrieve them through prompt injection,
compromised context, or debug traces.

**Status: Partial.**

**What Aegis does — when you turn it on.** Response inspection is
`AegisConfig.response_inspection_mode`, and it defaults to **`off`**. Nothing in
this section happens until an operator sets it to `warn` or `block`.

With it on, Aegis scans tool *responses* before they reach the model, using
deterministic pattern matching for credential-shaped content:

| Pattern | Tier |
|---|---|
| Private key headers (`-----BEGIN … PRIVATE KEY-----`) | block |
| AWS access key IDs (`AKIA` + 16 uppercase/digit) | block |
| Luhn-valid card numbers (13–19 digits) | block |
| AWS secret-shaped strings (40 base64-ish chars near an `aws_secret` marker) | warn |
| SSN-shaped values (`NNN-NN-NNNN`) | warn |

In `block` mode a response containing a **block**-tier match is refused and
never reaches the model. In `warn` mode, and for warn-tier matches in either
mode, the detection is recorded and the response is passed through unchanged.
Aegis never edits a response — the only choices are pass or refuse.

This addresses the specific path where a secret sitting in a file or a database
row is read by an agent and enters model context, where it becomes retrievable by
prompt injection. Cutting that path at the response boundary is the part of MCP01
that a runtime layer can address.

**Detection caveat.** The SSN pattern deliberately skips any match with `test`,
`dummy`, or `example` within 20 characters, to avoid firing on fixture data. That
window is content-blind, so an unrelated token containing one of those words —
`AKIAIOSFODNN7EXAMPLE`, for instance — will suppress a real SSN that happens to
sit beside it. A deliberate false-positive trade, and a real detection gap.

**What reaches the audit log.** When response inspection is enabled, a detection
records a redacted preview and never the matched value: `'XXX-XX-1234'` for an
SSN, `'AKIA...MPLE'` for an access key. The allowed call's own record has its
response preview replaced with a pointer to the detection record, so the audit
trail does not become the leak.

**With response inspection off — the default — none of that applies.** Every
successful tool call records a `result_preview` of the response, truncated at 500
characters and otherwise verbatim. A private key returned by a tool lands in
`logs/audit.jsonl` in plain text. If tool responses in your environment may
contain credentials, the audit log is in scope for secret handling and you should
set `response_inspection_mode` accordingly.

(One cosmetic note, in case you see it in a record: the AWS-secret preview's
leading characters are taken from the start of the 40-character candidate window,
which can begin mid-token, so the prefix is not always the key's own first four
characters. It reveals nothing either way.)

**What it does not do.** Aegis does not manage, issue, rotate, or scan for
credentials at rest. It does not inspect MCP server configuration for hard-coded
tokens, and it has no view into how an MCP server authenticates upstream. Secret
management and secret scanning in source control remain separate, necessary
controls.

---

## MCP02 — Privilege Escalation via Scope Creep

**The risk.** Permissions granted to an agent expand over time, intentionally for
convenience or accidentally through configuration drift, until the agent holds
broad privileges. An over-privileged agent acts autonomously and can make
unlabelled changes or access data without review.

**Status: Covered.** This is the category Aegis was built for.

**What Aegis does.** Every tool call is evaluated against a capability spec before
it reaches the MCP server. The spec is a static document listing the exact
`(server, tool, argument, permitted values)` combinations allowed for one task.
Evaluation is pure deterministic code with no LLM in the path: nine ordered
rules, deny by default. Rules 1–8 decide ALLOW or DENY on the first rule that
matches; rule 9 (operator intercepts, see MCP07) is then overlaid on an ALLOW
and can only downgrade it to INTERCEPT, never rescue a DENY.

Specifically against scope creep:

- **Deny-by-default at every level.** An unlisted server, tool, argument name, or
  argument value is refused. The spec must enumerate what is permitted; nothing is
  inherited or implied.
- **Literal matching only.** No globs, no regex, no path normalisation. A permitted
  value is an exact string. This eliminates the pattern-bypass class rather than
  attempting to sanitise it.
- **Per-task specs are the default shape.** `propose_spec` generates a spec for
  one task from the user's request; it is validated, frozen for the run, and
  never persisted, so there is no standing grant to drift. Aegis also supports
  `load_spec`, which reads a pre-authored operator policy from a YAML file —
  that *is* a long-lived permission set and it can drift like any checked-in
  config. What Aegis guarantees for both is attribution rather than
  immutability: every denial records the SHA-256 hash of the spec that produced
  it, so which policy version governed a decision is a matter of record.
- **No mid-run widening.** Once frozen, nothing can broaden a spec during
  execution. Tool output cannot influence policy.
- **Explicit waivers, visibly recorded.** Where an operator needs a weaker posture
  (`deny_all_others: false`, or `allow_any` on an argument), the resulting decision
  carries a distinct rule identifier in the audit record. A waiver is greppable and
  distinguishable from an ordinary allow.

**Two findings submitted to the working group.** While verifying this document's
own claims against the code, we found two scope-enforcement failures that occur
at *definition* time rather than through drift, and which MCP02's current text
does not describe:

1. A collection-valued argument (for example `read_multiple_files(paths=[...])`)
   cannot be constrained by literal matching against a single permitted value. Left
   unconstrained, it silently voids path scoping for that tool while the
   surrounding policy still looks tight.
2. Type confusion where a policy engine that stringifies values before comparison
   allows a *string* to satisfy a constraint written for a *list*.

Both are fixed in Aegis: collections are matched element-wise with every element
required to match, empty collections are denied, and arguments whose type the
engine cannot reason about precisely are denied rather than coerced. An
unconstrained collection is denied rather than passed through, and the waiver
that permits one is per-argument and recorded.

Both are filed with the OWASP MCP Top 10 project as
[issue #62](https://github.com/OWASP/www-project-mcp-top-10/issues/62).

---

## MCP03 — Tool Poisoning

**The risk.** An adversary compromises the tools an agent depends on, injecting
malicious or misleading content to manipulate model behaviour. Includes rug-pull
attacks where a server serves clean tool descriptions at install time and modified
ones later.

**Status: Partial** — and the coverage rests on the capability spec, not on drift
detection. Read the fingerprinting caveat below before relying on this entry.

**What Aegis does.** The capability spec constrains what a poisoned tool can
*do*. A tool whose description has been altered to induce different behaviour
still cannot be called with arguments outside the spec, and a tool that was never
in the spec cannot be called at all. Rug-pulling a description does not widen
what the tool is permitted to receive, because the spec is frozen before the run
and tool metadata is not an input to policy.

That is the whole of what is enforced today for this category.

**Fingerprinting exists but is not wired in.** `aegis/fingerprint.py` hashes a
server's advertised tool surface — names, descriptions, and input schemas —
stores a baseline, and reports added, removed, and modified tools on a
subsequent comparison. It works, but `check_server()` is called only from
`agents/stack.py`, the development test stack, which `pip install` does not
include. **An integrator following `docs/INTEGRATION.md` gets no drift
detection**: `wrap_toolset` records that a server was used and nothing more.
There is also no alerting mechanism — `check_server()` returns a dict for its
caller to inspect; it writes no audit record and blocks nothing.

Two further limitations, for when it is wired in: a detected drift overwrites
the stored baseline, so a change is reported once and the next run reports
"unchanged"; and there is no test coverage for the module. Both are tracked in
the README roadmap.

**What it does not do.** Aegis does not analyse tool descriptions for malicious
content at install time, does not verify tool manifest signatures, and does not
detect a server that was poisoned before a baseline was taken. A first-contact
fingerprint records whatever is there; it establishes a baseline, not
trustworthiness. Static scanning of tool descriptions before first connection is a
complementary control.

---

## MCP04 — Software Supply Chain Attacks & Dependency Tampering

**The risk.** A compromised dependency alters agent behaviour or introduces
execution-level backdoors.

**Status: Not covered.**

Aegis operates at runtime on tool calls. It has no view into how an MCP server or
an agent framework was built, what dependencies they pull, or whether any of them
were tampered with. Dependency pinning, SBOM generation, artifact signing, and
provenance verification are separate controls at a different point in the
lifecycle.

The tool-surface fingerprinting described under MCP03 would detect a
*behavioural* change in a server's advertised tools, which may in some cases be
the downstream symptom of a compromised dependency. That would be a side effect,
not a supply chain control, and should not be relied on as one — doubly so given
it is not currently wired into the enforcement path at all.

---

## MCP05 — Command Injection & Execution

**The risk.** An agent constructs and executes commands, scripts, API calls, or
code using untrusted input without validation.

**Status: Partial.**

**What Aegis does.** Aegis constrains the *arguments* of every tool call against
permitted literal values. Where a tool takes a command, a path, or a query as an
argument, and the spec enumerates permitted values, an injected value is refused
before the MCP server executes anything.

The argument-level rules do specific work here. An argument not named in the spec
is denied even if the tool is permitted, so an injected extra parameter cannot ride
along on an otherwise valid call. Argument values are compared as exact strings
with no normalisation, so encoding tricks and traversal sequences do not resolve
into a permitted value. And arguments whose type the engine cannot reason about are
denied rather than coerced into a comparable form.

**What it does not do.** Aegis does not parse or sanitise command strings, and it
makes no judgement about whether a permitted value is itself dangerous. If a spec
permits an argument value that the MCP server then handles unsafely, Aegis allows
it — the spec said so. Input validation inside the MCP server, and sandboxed
execution, remain necessary.

The protection is only as tight as the spec. A spec that enumerates broad
permitted values provides correspondingly broad protection.

---

## MCP06 — Intent Flow Subversion

**The risk.** Formerly listed as prompt injection via contextual payloads. Content
that becomes text in the model's context carries instructions the model follows,
diverting it from the user's intent. The interpreter is the model; the payload is
text.

**Status: Covered**, with an important framing caveat.

**What Aegis does.** Aegis does not attempt to detect prompt injection. It makes
successful injection unable to produce an out-of-scope action.

The architectural commitment is that **the enforcement path contains no LLM**. A
capability spec is generated once, before execution, from the user's trusted
request. From that point the spec is frozen and every tool call is evaluated by
deterministic code. Tool output — the channel injection arrives through — cannot
influence policy, because nothing in the enforcement path reads it as instruction.

This matters because the alternative approach, using a model to classify whether a
tool call reflects the user's intent, inherits the vulnerability it is meant to
detect: an injection convincing enough to divert the agent may also convince the
classifier.

**Demonstrated.** Aegis's test suite includes a live scenario where a model with no
protective system prompt reads a file containing an injected instruction, follows
it, and attempts a read of a file the user never requested. The call is refused at
the wrapper with a rule identifier before the MCP server receives it.

**The caveat, stated plainly.** Aegis does not prevent the model from being
subverted. The injection lands; the model's reasoning is diverted; it decides to do
something it should not. Aegis constrains the blast radius to what the spec
permits. Injection that causes harm entirely within the model's *output* — a
misleading summary, a wrong recommendation — is untouched by this control.

---

## MCP07 — Insufficient Authentication & Authorization

**The risk.** MCP servers, tools, or agents fail to verify identities or enforce
access controls during interactions.

**Status: Partial.** Aegis covers authorization at the argument level. It does not
do authentication.

**What Aegis does.** Aegis answers "what is this agent allowed to do" at a
granularity below what OAuth scoping reaches. OAuth 2.1 with resource indicators —
the direction the MCP specification has taken — establishes *which tools* an agent
may call. Aegis governs *what arguments* those tools may be called with, which is
where file paths, database targets, and API endpoints are actually bounded.

The two compose. Aegis assumes an identity layer exists upstream and makes no
attempt to replace it.

Aegis also supports human-in-the-loop authorization: an operator can mark specific
`(server, tool)` pairs as requiring approval. A matching call is suspended, an
approval callback is invoked, and the call proceeds only on an affirmative
response. Both the interception and the outcome are recorded, and an approved call
carries a flag distinguishing it from one that was never intercepted.

**What it does not do.** Aegis does not authenticate agents, issue or validate
tokens, manage identity, or implement RBAC. An unauthenticated agent that reaches
Aegis will be evaluated against whatever spec is active. Identity is a prerequisite,
not something Aegis provides.

---

## MCP08 — Lack of Audit and Telemetry

**The risk.** Limited telemetry from MCP servers and agents impedes investigation
and incident response. Detailed logs of tool invocations and immutable audit trails
are needed.

**Status: Covered.**

**What Aegis does.** Every decision produces an audit record, written before the
outcome is returned to the agent. A tool-call record carries the server, tool,
arguments, and the decision. Fields vary by record type rather than being
uniform, and the variation is deliberate:

| Field | Which records carry it |
|---|---|
| `call_id`, `ts`, `status` | all |
| `run_id` | every record the wrapper writes; on `spec_loaded` only when passed to the loader; absent from the proposer's error records and from server start/teardown records |
| `server` | tool-call records and server start/teardown records |
| `tool`, `args` | tool-call records only |
| `matched_rule` | every denial, intercept, and waiver — absent on a clean allow |
| `spec_hash` | denials, intercepts, policy-evaluation errors, and `spec_loaded` |
| `latency_ms` | `ok` and `error` only — a denied call never executed, so there is no duration to report |
| `proposer_prompt_hash` | the proposer's own records (`spec_loaded` when proposed, clarification requests, validation failures) — never a per-call record |

Three properties beyond basic logging:

- **Provenance.** Denial and intercept records carry the SHA-256 hash of the
  capability spec that produced them. Allowed calls are attributed through the
  run's `spec_loaded` record, which carries the same hash and — when the spec was
  LLM-generated — the hash of the prompt version that produced it. An
  investigator can establish which policy version made a given decision months
  later, following `run_id` to the opening record, without relying on deployment
  records. The chain is per-run, not per-record.
- **Correlation.** Every record the wrapper writes shares a run identifier, so a
  run can be reconstructed in order. The `spec_loaded` record joins that run by
  exact match only if the caller passed `run_id` to `load_spec`/`propose_spec`,
  which is an optional argument; omit it and the association falls back to
  inference from `spec_hash` and timestamp ordering. Pass it — see
  [CONTROL_PLANE.md](CONTROL_PLANE.md).
- **Waiver visibility.** Decisions made under a weakened posture (`deny_all_others:
  false`, or `allow_any` on an argument) carry a distinct rule identifier on the
  record, so a query for records with a non-null `matched_rule` returns every
  denial and every waiver, and nothing else.

Records are written locally as JSONL and, when configured, exported as OpenTelemetry
spans into an existing observability pipeline. An optional self-hosted control plane
aggregates records across agents into Postgres with a query API, a run-reconstruction
endpoint, and a read-only web view.

The control plane is never in the enforcement path. If it is unreachable, tool calls
are still evaluated, decisions are still correct, and records still land locally.

Gaps in the shipped stream are accounted for rather than silent, with one
exception. Records dropped because the in-memory ship queue overflowed, and
batches abandoned because the backend rejected them with a 4xx, are both counted
and reported to the backend as `dropped_since_last_batch` on the next successful
batch — so the centralised view shows a hole as a hole. A 4xx also prints once to
stderr naming the status and what to check; a transient 5xx retries with backoff
and reports only if it persists. The exception: records written *before* a control
plane was configured are reported on stderr only and never shipped, because
putting that count on the wire needs a backend field that does not exist yet. That
is tracked in `docs/OPEN_QUESTIONS.md`. JSONL retains every record in all cases.

**What it does not do.** The audit trail is append-only by convention, not
cryptographically immutable. There is no hash chain or signature over the record
sequence. An attacker with write access to the log or the database could alter
history, and Aegis would not detect it. Where tamper-evidence is a requirement,
shipping records to a WORM store or an append-only external system is necessary.

---

## MCP09 — Shadow MCP Servers

**The risk.** Unapproved MCP deployments operating outside formal security
governance, often with default credentials and permissive configurations.

**Status: Not covered.**

Aegis governs agents it is wired into. It has no discovery capability and no
network-level visibility, so it cannot find MCP servers an organisation does not
know about. An agent running without Aegis is unaffected by Aegis.

The audit trail records every server an instrumented agent connects to, which
gives an inventory of *known* servers in use. That is useful for reconciliation
against an approved list, but it is not discovery, and it says nothing about
deployments that were never instrumented.

Network scanning, egress monitoring, and registry enforcement are the controls for
this category.

---

## MCP10 — Context Injection & Over-Sharing

**The risk.** Shared, persistent, or insufficiently scoped context windows leak
sensitive information between tasks, users, or agents.

**Status: Partial.**

**What Aegis does.** Aegis constrains what enters context in the first place. A
per-task capability spec means an agent reads only what its current task permits,
so material from an unrelated task or tenant is not retrievable unless the spec
permits it. This is scoping at the ingress point rather than isolation within the
context window.

Response inspection can provide a second boundary: credential-shaped content in a
tool response can be blocked before it enters context. It is off by default — see
MCP01 for the patterns, the tiers, and what the audit log records in each mode.
With it off, a tool response that enters context is also previewed into
`logs/audit.jsonl`, raw, up to 500 characters.

**What it does not do.** Aegis has no visibility into the context window itself. It
does not isolate, partition, or expire context; it does not prevent information
already in context from being shared onward; and it enforces no tenant boundary
inside a model session. Context lifecycle and cross-tenant isolation are handled by
the agent framework, not by a tool-call enforcement layer.

---

## What this means in practice

No single control closes this taxonomy. Aegis is one layer: it decides what a tool
call may do, refuses what falls outside that, and records the decision in a way that
survives investigation.

Deployed alongside identity (MCP07 authentication), secret management (MCP01),
supply chain controls (MCP04), and server discovery (MCP09), it covers a specific
and currently underserved slice: the boundary between an agent being authorised to
act and the action actually reaching a system.

Corrections welcome. If a status above is wrong, or a claim does not reproduce,
please open an issue.

---

*Aegis is MIT licensed. Source: https://github.com/obengbuo/aegis*
