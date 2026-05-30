# Aegis Capability Spec Format — v1

Design document. Written before any Python. Review this before locking in the
implementation of `aegis/policy.py`.

---

## What a capability spec is

A YAML file that declares, for a single agent task run, which `(server, tool,
args)` combinations are permitted. Aegis evaluates every intercepted tool call
against the active spec before forwarding it to the server.

One spec = one task. A spec is not reused across runs. It is created by a
trusted principal (initially the user; in Week 4, by the LLM proposer running
on trusted user input) and passed into the run at construction time.

---

## Top-level format

```yaml
# Human-readable name for this task run. Required.
task: "<short description>"

# If true, any (server, tool) pair not explicitly listed is DENIED.
# Omitting this field defaults to true. Setting it to false is explicitly
# documented as a weaker posture and will be noted in the audit log.
deny_all_others: true

# Map of permitted servers. Required (must have at least one entry).
servers:
  <server_name>:
    tools:
      <tool_name>:
        # The args block is optional.
        #
        # Absent (or null): the tool may be called ONLY with zero arguments.
        # Use this exclusively for tools that genuinely take no arguments
        # (e.g. list_allowed_directories). Any non-empty call is DENIED.
        #
        # Present: exhaustively lists every argument the call may supply.
        # Any argument in the call that is NOT listed here is DENIED.
        # The spec author must name every arg the agent will pass, including
        # optional ones.
        args:
          <arg_name>:
            # Optional. If present: the argument value must equal one of
            # these strings exactly (literal match, v1 — no globs, no regex).
            # If absent: the argument must be present in the call but its
            # value is unconstrained.
            must_match_one_of:
              - "<literal_value_1>"
              - "<literal_value_2>"
          <unconstrained_arg_name>: ~
          # ~ (YAML null) means: arg must be present, any value is allowed.
```

---

## Evaluation rules (the contract policy.py must implement)

Evaluated in order. First matching DENY wins; all checks must pass for ALLOW.

**1. Server not listed.**
If `deny_all_others: true` and the call's server name is not a key under
`servers:` → **DENY** (`reason: "server not in capability spec"`)

**2. Tool not listed.**
The server is listed but the tool name is not a key under
`servers.<server>.tools` → **DENY** (`reason: "tool not in capability spec"`)

**3. No args block, call has arguments.**
The tool is listed, has no `args` block (or `args` is null), but the actual
call provides one or more arguments → **DENY**
(`reason: "tool declared zero-arg but call supplied args: [<names>]"`)
This covers tools that genuinely take no arguments. Any agent-supplied arg is
unexpected and treated as a violation.

**4. No args block, call has zero arguments.**
The tool is listed, has no `args` block, and the actual call has no arguments
→ **ALLOW** unconditionally.

**5. Missing required arg.**
The tool has an `args` block and an argument listed there is absent from the
actual call → **DENY**
(`reason: "required arg '<name>' missing from call"`)
If it's listed in the spec, the spec author considered it important enough to
name. A missing value cannot be verified.

**6. Extra arg — arg in call not listed in spec.**
The actual call provides an argument whose name does not appear in the spec's
`args` block → **DENY**
(`reason: "arg '<name>' not in capability spec"`)
The spec exhaustively declares what the tool call looks like. Unlisted args
are not "allowed by default" — they are unknown and therefore denied. This is
the closed-world assumption applied to the argument surface.

**7. Arg value not in allow-list.**
An argument is present in both the call and the spec, and the spec has
`must_match_one_of`, but the call's value is not in that list → **DENY**
(`reason: "arg '<name>' value '<val>' not in capability spec"`)

**8. All checks pass → ALLOW.**

### Decision fields contract

- `verdict`: `"ALLOW"` or `"DENY"`.
- `reason`: always a non-empty string.
  - **On ALLOW, `reason` is always the fixed string `"all checks passed"`.** A
    fixed string makes ALLOW decisions cheaply comparable in logs without parsing.
  - On DENY, `reason` is a human-readable description of the specific violation.
    Attacker-controlled values (arg names from the call, arg values from the call)
    are `repr()`-escaped before interpolation, so they cannot inject newlines or
    other control characters into the reason string or the JSON audit record.
- `matched_rule`: identifies which rule fired.
  - On DENY: a stable kebab-case string, e.g. `"rule-6-extra-arg"`.
  - On a normal ALLOW (all rules passed): `None`.
  - **On a weak-posture ALLOW** (server or tool not listed, `deny_all_others:
    false`): `"rule-1-bypassed-weak-posture"` or `"rule-2-bypassed-weak-posture"`.
    A non-`None` value here makes these bypass events greppable in the audit log,
    distinct from enforcement-passed ALLOWs that earned their `None`.

### Rule 5 / Rule 6 ordering rationale

When a call is simultaneously missing a required arg (Rule 5) and carrying an
unexpected arg (Rule 6), the current implementation evaluates Rule 5 first.
This is a conscious choice, not incidental code order.

**Argument for Rule 6 first** (the alternative): an unexpected arg in a call is
a stronger attack signal — it represents an attempt to extend the call's
capability beyond what the spec names. Missing args are more often a
misconfiguration. Surfacing the injection signal first makes the audit log more
useful for threat detection.

**Why Rule 5 fires first** (the adopted choice): a call missing a required arg
is fundamentally incomplete — its constrained args cannot be fully verified, and
the denial reason is spec-controlled (the arg name comes from the spec, not from
the call). When both conditions apply, "missing required arg X" is more
actionable for the spec author than "unexpected arg Y", which may be noise or
may be an injection, but provides no useful signal for fixing the call. Newline
injection via the unexpected arg name is already neutralized by `repr()`
escaping, so the security concern that motivates putting Rule 6 first does not
apply.

Phase 2 threat detection (Week 7) can surface Rule 6 patterns across multiple
calls as a separate anomaly signal without changing the per-call denial ordering.

### The closed-world assumption at every level

```
deny_all_others: true
   → unknown server          = DENY
   → unlisted tool           = DENY
args block present
   → unlisted arg in call    = DENY     ← Rule 6 (new in this revision)
   → missing listed arg      = DENY
   → value not in allow-list = DENY     (if must_match_one_of is set)
```

The v1 cost: specs must be verbose. Every arg the agent will ever pass must
appear in the spec, even optional ones. This is an intentional trade — bypass
surface is zero; spec maintenance cost is explicit and visible.

### The "spec is silent on this case" table

| What is silent                              | Verdict |
|---------------------------------------------|---------|
| Server not in `servers:`                    | DENY    |
| Tool not in `tools:`                        | DENY    |
| Arg in call not in `args:` block            | DENY    |
| Arg in spec with no `must_match_one_of`     | value unconstrained; ALLOW on any value |
| Tool listed with no `args:` block           | ALLOW only if call has zero args |

---

## Spec validation (load-time, not evaluate-time)

Before any tool calls happen, the spec is validated:

- Valid YAML
- `task` is a non-empty string
- `servers` is a non-empty dict
- `deny_all_others` is a boolean (if present)
- Each tool entry: if `args` is present and non-null, it is a dict
- Each arg entry: if `must_match_one_of` is present, it is a non-empty list
  of strings
- **If `deny_all_others: false`, the `task` field must contain the substring
  `deny_all_others=false` (case-insensitive).** This is a belt-and-suspenders
  check: it forces the spec author to acknowledge the weaker posture in plain
  text rather than silently setting a boolean. A spec with `deny_all_others:
  false` but no acknowledgment in `task` is rejected with a clear error.

A spec that fails validation raises `SpecValidationError` at load time and
aborts the run before any tool calls are made. `evaluate()` only ever receives
a pre-validated spec — the Python type system enforces this.

---

## Spec lifecycle — how a spec is associated with a run

The spec flows into the enforcement path through the same closure pattern used
for server identity. No global state; no mutable shared object.

```python
# At run setup: load and validate the spec once.
spec = load_spec("specs/summarize_meeting_notes.yaml")  # raises on invalid

# Pass the spec into each server's hook at construction time.
filesystem = MCPToolset(
    ...,
    process_tool_call=make_process_tool_call("filesystem", spec),
)
fetch = MCPToolset(
    ...,
    process_tool_call=make_process_tool_call("fetch", spec),
)
```

`make_process_tool_call(server_name, spec)` closes over both `server_name`
and `spec`. The returned hook function carries both values. Each server gets
its own hook instance; all hooks in a run share the same spec object (which is
read-only after validation).

`spec` is optional (defaults to `None`). When `None`, the wrapper operates in
Phase 1 mode: log-only, no enforcement. This preserves backward compatibility
with Phase 1 test harnesses that construct servers without a spec.

### The `spec_loaded` audit record

When `load_spec()` succeeds, it writes one audit record before returning the
spec. This anchors every run to the spec that governed it:

```json
{
  "status": "spec_loaded",
  "task": "summarize meeting-notes.txt",
  "deny_all_others": true,
  "spec_hash": "e3b0c44298fc1c149afb..."
}
```

`spec_hash` is the SHA-256 of the raw YAML bytes (before parsing). It lets
you reconstruct exactly which spec was active for any audit run, even if the
file on disk has changed since.

This record has no `server` or `tool` fields. In `audit.summary()` it routes
to `by_lifecycle`, not `by_tool`, alongside `server_init_failed` and
`server_teardown`.

```python
# Phase 1 — no spec, log-only (backward compatible)
filesystem = MCPToolset(
    ...,
    process_tool_call=make_process_tool_call("filesystem"),
)

# Phase 2 — spec provided, enforcement active
filesystem = MCPToolset(
    ...,
    process_tool_call=make_process_tool_call("filesystem", spec),
)
```

The spec is never passed from agent logic, tool output, or any runtime-derived
value. It is always derived from a file on disk (or a literal dict in tests)
that is loaded once before the agent run begins. This preserves the trust
boundary: the spec is set by the user (trusted), not by the agent (potentially
compromised).

---

## Example 1 — Read-only file summarizer

**Task**: Summarize the contents of `meeting-notes.txt`. The agent may
enumerate allowed directories and read exactly one file.

Tool names verified against `logs/audit_phase1.jsonl`.

```yaml
task: "summarize meeting-notes.txt"
deny_all_others: true

servers:
  filesystem:
    tools:
      list_allowed_directories:
        # No args block — this tool takes zero arguments (verified in logs).
        # Any call that supplies arguments is DENIED.
      read_text_file:
        args:
          path:
            must_match_one_of:
              - "/home/user/aegis-sandbox/meeting-notes.txt"
```

**What this blocks:**
- Any write, edit, move, or delete tool (not listed → DENY)
- `read_text_file` on any path other than `meeting-notes.txt`
- `list_directory`, `search_files`, `get_file_info` (not listed → DENY)
- Any call to the `fetch` or `demo` server (server not listed → DENY)
- Any unexpected arg on `read_text_file` beyond `path` (Rule 6 → DENY)

**Why `list_allowed_directories` has no args block:** the audit log confirms
it is always called with zero arguments. An args block would be misleading.
Under Rule 3, any non-empty call is already denied.

**The injection scenario:** the injected content tells the agent to also read
`project-update.txt`. The agent decides to call `read_text_file` with
`path=/home/user/aegis-sandbox/project-update.txt`. Rule 7 fires: value
`project-update.txt` is not in `must_match_one_of`. → DENY. The agent
observes a `PermissionError`, cannot read the second file, and the injection
is neutralized at the enforcement layer.

---

## Example 2 — Web fetch task

**Task**: Fetch a specific approved URL and return its content for summarization.

```yaml
task: "fetch and summarize https://example.com/report"
deny_all_others: true

servers:
  fetch:
    tools:
      fetch:
        args:
          url:
            must_match_one_of:
              - "https://example.com/report"
```

**What this blocks:**
- Fetching any URL the agent was not given (injection redirects the agent to
  an attacker-controlled URL → Rule 7 → DENY)
- Any filesystem or other server access (server not listed → DENY)

**Note on optional args:** `mcp-server-fetch` accepts optional args like
`max_length` and `raw`. Under Rule 6, if the agent passes these and they are
not listed in the spec, the call is DENIED. If the task legitimately needs
them, list them explicitly:

```yaml
      fetch:
        args:
          url:
            must_match_one_of:
              - "https://example.com/report"
          max_length: ~   # required to be present; any integer value allowed
```

This is the v1 verbosity cost. The spec author must anticipate every arg the
agent will pass. In Week 4, the LLM proposer will generate these specs from
the user's task description and will need to enumerate optional args correctly.

**Note on URL canonicalization:** `must_match_one_of` is a string equality
check. `https://example.com/report` and `https://example.com/report/` are
different values. The spec must use the exact string the agent will pass.
Trailing slashes, query strings, and fragments are significant. This is a
known rough edge of literal-only matching, deferred to v2.

---

## Example 3 — File write task

**Task**: Read a data file, generate a report, and write it to a specific output
path. The agent may read one input and write one output.

```yaml
task: "generate report from data.csv and write to report.txt"
deny_all_others: true

servers:
  filesystem:
    tools:
      read_text_file:
        args:
          path:
            must_match_one_of:
              - "/home/user/aegis-sandbox/data.csv"
      write_file:
        args:
          path:
            must_match_one_of:
              - "/home/user/aegis-sandbox/report.txt"
          content: ~
          # content: ~ means: arg must be present, any value is allowed.
          # You cannot enumerate valid content in advance — the agent generates
          # it. What you enforce is WHERE the content goes, not WHAT it says.
```

**What this blocks:**
- Reading any file other than `data.csv`
- Writing to any path other than `report.txt` — blocks injection-driven writes
  to `~/.ssh/authorized_keys`, `.env`, or any other sensitive destination
- Any call that supplies an arg not listed (e.g. an unexpected `encoding` arg
  on `write_file` → Rule 6 → DENY)
- `list_allowed_directories` (not listed → DENY under deny_all_others)
- Any call to `fetch` or `demo`

**Why `content: ~` instead of a value constraint:** the destination (the `path`
arg) is the enforcement point for write operations. The content is generated
by the agent and cannot be enumerated in advance. Constraining the destination
while leaving content unconstrained is the correct split: you prevent the
agent from writing to dangerous paths while allowing it to write what it
legitimately produces.

**A note on write operations and least privilege:** write tools should appear
in a spec only when the task explicitly requires writing. A summarizer spec
should never include `write_file` even if the filesystem server is available.
The spec enforces least privilege at the task level, not just the server level.

---

## Design decisions and rationale

### Rule 6 — why unlisted args are DENY, not pass-through

The original design (v0) allowed unlisted args to pass through silently. This
was changed because: closing the arg-value bypass surface (via `must_match_one_of`)
while leaving the arg-shape surface open is incomplete. An attacker who can
inject an unexpected argument — even on an otherwise-allowed tool call — has a
channel to influence the call's behavior in ways the spec author did not
anticipate. Literal-only matching is only meaningful if the set of arguments is
also closed.

The cost: specs must enumerate every arg the agent will pass, including optional
ones. This is the v1 verbosity trade. Week 4's LLM proposer will automate this
enumeration, so the human cost is temporary.

### Rule 3 — why no-args-block means zero-arg-only

An absent args block could mean "allow any arguments" or "allow no arguments."
"Allow any arguments" is dangerous on a tool that happens to be sensitive (a
future tool we add might accept a `path` arg that the no-args convention would
leave unconstrained). Zero-args is the safer default and matches the only real
use case for an absent block: tools that genuinely take no arguments. Tools
that accept arguments must have an explicit args block, making the spec
self-documenting.

### Why literal-only argument matching in v1

Glob and regex patterns introduce a class of bypass attacks. A pattern like
`*.txt` matches `../../etc/passwd.txt` on a symlinked filesystem. A regex like
`^/workspace/.*` can be coerced with carefully crafted paths. Literal matching
eliminates this class entirely. The cost is explicit enumeration, which is
correct for sensitive resources. Glob and regex can be added in v2 after the
literal path is proven and the bypass surface is understood.

### Why `deny_all_others: true` is the default

The cost of a false positive (agent can't call an unlisted tool) is visible
and correctable: add the tool to the spec and re-run. The cost of a false
negative (agent calls an unlisted tool that shouldn't be called) may be
invisible until after damage is done. Unknown = denied.

### Why specs are validated at load time

A malformed spec that reaches `evaluate()` has two bad outcomes: ALLOW
(if the malformation causes a check to be skipped) or DENY-everything (if
every evaluation throws). Catching the error before any tool calls happen
produces a clear `SpecValidationError` and aborts the run cleanly. It also
prevents an attack where a corrupted spec is crafted to skip a policy check
and fall through to ALLOW.

### What this design does NOT handle in v1

- **Glob / regex arg matching** — deferred explicitly. Literal-only is v1.
- **Argument type validation** — the spec does not check that `path` is a
  string or `count` is an integer. Type enforcement happens at the MCP server.
- **Cross-call constraints** — "read X before writing Y." The spec evaluates
  each call independently. Sequence constraints are Phase 2+.
- **INTERCEPT decision** — the ALLOW / DENY binary is v1. A third verdict
  (pause and ask a human) is Week 5.
- **Scope inheritance / role hierarchies** — one flat spec per run. No nesting.
