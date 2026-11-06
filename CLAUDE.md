# CLAUDE.md — Aegis project context

> Read this before making changes. Last rewritten 2026-11-06, at v0.2.1.

## What Aegis is

Aegis is **deterministic capability enforcement for AI agents on the Model
Context Protocol (MCP)**.

> Identity proves who an agent is. Aegis decides what it's allowed to do.

The flow:

1. Before a run, a capability spec is either generated from a plain-language
   request (`propose_spec`) or loaded from YAML (`load_spec`).
2. The spec is validated, hashed, and frozen.
3. Every tool call is checked against the spec by plain deterministic code:
   ordered rules in `policy.py` (numbered 1–9; there is no rule 4, and rule 8 is
   the clean allow), deny by default, exact match at every level (server,
   tool, argument name, argument value).
4. Allowed calls reach the MCP server. Denied calls never do. Intercepted calls
   go to an operator-supplied approval callback.
5. Every decision is written to a forensic audit record that carries `run_id`,
   `spec_hash`, and the rule that fired.

Status: v0.2.1, MIT, pre-production, installable with pip. No paying
customers or pilots yet. Positioning and strategy live in `docs/WEDGE.md` and
`docs/OPEN_QUESTIONS.md`.

## Architectural invariants: never break these

- **No LLM in the enforcement path.** The proposer runs once, before the run,
  on trusted input only. It never sees tool output and never runs mid-task.
- **The trust boundary is enforced in code, not by prompt.** The user request
  goes only into the user turn. Tool schemas are module constants.
- **Fail closed.** If policy evaluation errors, the call is denied, never
  allowed.
- **No tool call bypasses the wrapper.** Every MCP toolset is wrapped with
  `wrap_toolset()` (`aegis/wrapper.py`). A code path that calls a tool without
  going through it is a security bug.
- **Observability never breaks enforcement.** If the OTLP collector or the
  control plane is down, calls are still evaluated and logged to local JSONL.
- **The control plane observes; it never decides.** No code path in
  `aegis-controlplane` may influence an enforcement decision.
- **Secrets never land in the audit log.** Arguments, previews, denial reasons
  and errors are redacted in every inspection mode (`_safe_*` in `wrapper.py`).

## Who is building this

Obeng Buo is the solo founder. Background is platform/DevOps engineering
(AWS, Kubernetes, NERC-CIP IT/OT boundary work). Explain MCP- and
agent-specific mechanics concretely; don't explain general software
engineering.

## Honesty rule for docs

Every claim in a doc, README, site page or post must be true of the code at
HEAD. Check claims against the code before writing them. The project has
caught a non-running example, a rule that never fired, and twelve overstated
OWASP claims this way. When something is documented but not built, say so
explicitly. For example, server fingerprinting exists but is **not wired into
the installed package**, so don't claim drift detection.

## Layout

```
aegis/                   THE PRODUCT (public API in __init__.py)
  __init__.py            wrap_toolset, AegisConfig, propose_spec, load_spec,
                         CapabilitySpec, SpecValidationError, AegisApprovalRequired
  wrapper.py             interception + redaction; the most important file
  policy.py              spec models, validation, the ordered rules
  proposer.py            NL request -> spec (one Claude call, trusted input only)
  proposer_prompts.py    the proposer prompt; hashed into every spec_loaded record
  response_inspection.py secret/PII pattern detection (off | warn | block)
  audit.py               JSONL audit records
  shipper.py             optional OTLP / control-plane shipping, fire-and-forget
  config.py              AegisConfig
  startup.py             fail-closed MCP server startup and teardown
  fingerprint.py         server fingerprinting (NOT wired in; see OPEN_QUESTIONS)
agents/                  dev test stack (stack.py, servers.py); not shipped
tools/                   demo scripts (demo_end_to_end.py, demo_server.py, ...)
tests/                   pytest; "integration" marker = live model calls
docs/                    CAPABILITY_SPEC, INTEGRATION, CONTROL_PLANE,
                         OWASP_MCP_TOP10, OPEN_QUESTIONS, WEDGE, COMPETITIVE_LANDSCAPE
```

Sibling repos, all under `C:\Users\kbuo1\OneDrive\Documents\DevOps\`:
- `aegis-controlplane`: optional self-hosted audit aggregation (FastAPI,
  Postgres, read-only UI).
- `aegis-reference-env`: Northgate Power & Light demo, a Kubernetes
  incident-remediation agent under enforcement. Not yet published.
- `aegis-runtime`: the aegisruntime.dev website.

## Stack

- Python >= 3.10 (developed on 3.12). Async everywhere.
- Pydantic AI (`pydantic-ai-slim[mcp]`). Do not switch to LangChain.
- Proposer model: `claude-sonnet-4-6` (`aegis/proposer.py`). Tests use Haiku.
- MCP servers are the official `@modelcontextprotocol/server-*` npx packages.

## Conventions

- Type hints on everything.
- Small commits, one capability each, each runnable.
- Tests for every behaviour change in `wrapper.py` or `policy.py`. Run them
  with `.venv/Scripts/python.exe -m pytest -q -m "not integration"`.
- No secrets in code. Everything goes through `.env` (ignored, as are `.env.*`).
- Record undecided design questions in `docs/OPEN_QUESTIONS.md`, each with a
  trigger condition, rather than deciding them silently.
- Release: bump `pyproject.toml` and `aegis/__init__.py`, update the pinned
  `@vX.Y.Z` in README and INTEGRATION, then push an annotated tag.

## Open work

The consolidated to-do list lives outside this repo:
`C:\Users\kbuo1\OneDrive\Documents\DevOps\Aegis Runtime LLC\MASTER_TODO.md`.
Update it rather than starting new lists.

## How to help

- Be concrete about MCP mechanics; show the protocol exchange.
- Prefer working code and a test over abstract advice.
- Flag security implications proactively. This is a security product.
- Refuse any change that creates an unlogged or unenforced path to a tool, and
  explain why.
