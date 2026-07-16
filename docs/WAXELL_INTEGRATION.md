# Aegis — Waxell Integration Quick Start

## Install

```bash
pip install git+https://github.com/obengbuo/aegis.git@v0.1.0
```

## Five-minute integration

```python
from pathlib import Path
from aegis import wrap_toolset, AegisConfig

def approve_sensitive_call(server, tool, args, decision) -> bool:
    # Wire this into your own approval system (Slack, PagerDuty, dashboard).
    return your_approval_system.request(server, tool, args, decision.reason)

config = AegisConfig(
    sandbox_root=Path("/var/waxell/agent-sandbox"),
    otlp_endpoint="https://otel-collector.waxell.internal:4318",
    approval_callback=approve_sensitive_call,
    response_inspection_mode="warn",  # "off" | "warn" | "block"
)

# your_toolset is any existing MCPToolset your agent already uses.
governed_toolset = wrap_toolset(your_toolset, "your-server-name", config=config)
# governed_toolset IS your_toolset — wrap_toolset mutates in place and
# returns it for chaining. Don't keep a separate un-enforced reference.
```

## Constructing capability specs

```python
from aegis import propose_spec, load_spec

spec = propose_spec("Read config.yaml and summarize it", sandbox_root=Path("/var/waxell/sandbox"))
# or, for a pre-authored operator policy:
spec = load_spec("specs/config_reader.yaml")
```

## Reading the audit log

JSONL lands at `logs/audit.jsonl` (configurable via `AegisConfig.log_path`
in a later release). If `otlp_endpoint` is set, the same events are also
emitted as OTLP spans. Every record carries `run_id` — grep by it to
reconstruct one agent run's full tool-call sequence.

## Configuring your observability layer

Point `AegisConfig.otlp_endpoint` at your collector (Datadog, Jaeger,
Splunk — anything OTLP-compatible). Export uses `BatchSpanProcessor`, so
retries and transient failures are handled by the SDK transparently — an
unreachable collector never blocks or fails a tool call; it only logs to
stderr and moves on.

## Handling intercepts

When a call matches an operator-configured intercept rule and no
`approval_callback` is set, Aegis raises `AegisApprovalRequired`. The call's
arguments are on **`exc.call_args`, not `exc.args`** — `Exception` already
owns `.args` for its default string representation, so `call_args` avoids
that collision. `exc.server`, `exc.tool`, and `exc.decision` are also
available. Wire `AegisConfig.approval_callback` (see above) for automatic,
in-band handling instead of catching this exception.

## Response inspection modes

`AegisConfig.response_inspection_mode`:
- `"off"` (default) — no scanning, zero cost.
- `"warn"` — matches are logged (`status: "response_pattern_detected"`,
  with per-pattern redacted previews) but the response is still returned.
- `"block"` — block-tier matches (private keys, AWS access keys, Luhn-valid
  credit cards) additionally raise `PermissionError` instead of returning
  the response. SSNs and AWS-secret-shaped strings are warn-tier and never
  block. Response content is never modified — only allowed or blocked.

## Where to file issues

Private GitHub Issues: https://github.com/obengbuo/aegis/issues.
If urgent, DM Stone directly on LinkedIn.

## Notes for production deployment

- `run_id` fallback is per-process when no `AegisConfig` is supplied.
  Recommended: construct an explicit `AegisConfig` per agent run so
  correlation reflects real run boundaries, not process lifetime.
- Anthropic API overload (HTTP 529) surfaces as `pydantic_ai.exceptions.
  ModelHTTPError`. Retry with backoff on your side — Aegis wraps tool
  calls, not model calls, so this is outside its enforcement path.
