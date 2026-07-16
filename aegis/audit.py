"""
aegis/audit.py — the audit log: write, read, and query tool-call records.

Phase 1: append-only JSONL file at logs/audit.jsonl.
Phase 2: this module's interface stays the same, but the backend becomes
Postgres (RDS). Keep the public functions stable so the swap is painless.

OTLP (Week 5 Stream 2): JSONL is the durable local record; OTLP is an
additive, best-effort mirror for Waxell's observe layer (Datadog / Jaeger /
Splunk — all OTLP-compatible). OTLP export failures never raise out of
write_record — the same fail-open contract as the rest of this module's
audit path, deliberately the mirror image of policy evaluation's
fail-closed contract in wrapper.py. An unreachable collector must never
block or fail a tool call whose enforcement decision has already been made.

The OpenTelemetry SDK is imported lazily, only on the first write_record
call that actually carries an otlp_endpoint. Callers that never configure
OTLP pay zero import cost for it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterator

LOG_PATH = Path("logs/audit.jsonl")

# Populated on first write_record() call that carries an otlp_endpoint.
# Cached for the process lifetime — OTLP exporters are meant to be reused,
# not rebuilt per call.
_otlp_tracer: Any = None

# record key -> OTLP span attribute name. Only keys present (and non-None)
# in a given record are set — most records populate a subset of these.
_OTLP_ATTRIBUTE_MAP: dict[str, str] = {
    "server": "aegis.server",
    "tool": "aegis.tool",
    "status": "aegis.status",
    "matched_rule": "aegis.matched_rule",
    "spec_hash": "aegis.spec_hash",
    "proposer_prompt_hash": "aegis.proposer_prompt_hash",
    "call_id": "aegis.call_id",
    "run_id": "aegis.run_id",
    "latency_ms": "aegis.latency_ms",
    "reason": "aegis.reason",
}

# Statuses that represent an actual outbound MCP call (vs. an Aegis-internal
# policy/lifecycle decision). Drives SpanKind — CLIENT for the former,
# INTERNAL for everything else.
_CLIENT_STATUSES = {"ok", "error"}


def _get_or_create_tracer(otlp_endpoint: str) -> Any:
    """Return the cached OTLP tracer, building it on first use.

    Imports the OpenTelemetry SDK here, not at module load, so importing
    aegis.audit stays cheap when OTLP is never configured.
    """
    global _otlp_tracer
    if _otlp_tracer is not None:
        return _otlp_tracer

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
    trace.set_tracer_provider(provider)
    _otlp_tracer = trace.get_tracer("aegis")
    return _otlp_tracer


def _emit_otlp_span(record: dict[str, Any], otlp_endpoint: str) -> None:
    """Mirror one audit record as an OTLP span. Never raises.

    Observability must never break enforcement — the tool call this record
    describes has already happened (or already been denied) by the time
    this runs. A collector being down is not a reason to fail a call that
    already succeeded, nor a reason to hide that a call was denied.
    """
    try:
        from opentelemetry.trace import SpanKind

        tracer = _get_or_create_tracer(otlp_endpoint)
        status = record.get("status", "unknown")
        kind = SpanKind.CLIENT if status in _CLIENT_STATUSES else SpanKind.INTERNAL

        with tracer.start_as_current_span(status, kind=kind) as span:
            for key, attr_name in _OTLP_ATTRIBUTE_MAP.items():
                value = record.get(key)
                if value is not None:
                    span.set_attribute(attr_name, value)
    except Exception as exc:  # noqa: BLE001 — OTLP export must never break enforcement
        print(f"[aegis] OTLP export failed: {exc}", file=sys.stderr)


def write_record(
    record: dict[str, Any],
    otlp_endpoint: str | None = None,
    run_id: str | None = None,
) -> None:
    """Append one tool-call record to the audit log.

    When otlp_endpoint is set, also mirrors the record as an OTLP span
    (best-effort — see _emit_otlp_span). Existing callers that omit
    otlp_endpoint are unaffected: JSONL only, no OTLP attempted.

    run_id is a convenience for callers that don't already embed it in
    record (wrapper.py's _process embeds it in base_record directly, so it
    won't also pass this). When given, it's merged into the record before
    writing, so it lands in both JSONL and — via _OTLP_ATTRIBUTE_MAP — the
    OTLP span's aegis.run_id attribute.
    """
    if run_id is not None:
        record = {**record, "run_id": run_id}

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    if otlp_endpoint:
        _emit_otlp_span(record, otlp_endpoint)


def read_records() -> Iterator[dict[str, Any]]:
    """Yield every record in the audit log, oldest first."""
    if not LOG_PATH.exists():
        return
    with LOG_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def query(
    *,
    server: str | None = None,
    tool: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Filter audit records. All filters are optional and ANDed together.

    Example:
        query(server="filesystem", status="error")
    """
    results: list[dict[str, Any]] = []
    for rec in read_records():
        if server is not None and rec.get("server") != server:
            continue
        if tool is not None and rec.get("tool") != tool:
            continue
        if status is not None and rec.get("status") != status:
            continue
        results.append(rec)
    return results


_LIFECYCLE_STATUSES = {"server_init_failed", "server_teardown", "spec_loaded"}


def summary() -> dict[str, Any]:
    """Quick stats over the whole audit log — useful for a CLI dashboard."""
    total = 0
    by_status: dict[str, int] = {}
    by_server: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    by_lifecycle: dict[str, int] = {}

    for rec in read_records():
        total += 1
        status = rec.get("status", "?")
        by_status[status] = by_status.get(status, 0) + 1
        by_server[rec.get("server", "?")] = by_server.get(rec.get("server", "?"), 0) + 1

        if status in _LIFECYCLE_STATUSES:
            by_lifecycle[status] = by_lifecycle.get(status, 0) + 1
        else:
            tool = rec.get("tool", "?")
            by_tool[tool] = by_tool.get(tool, 0) + 1

    return {
        "total_calls": total,
        "by_status": by_status,
        "by_server": by_server,
        "by_tool": by_tool,
        "by_lifecycle": by_lifecycle,
    }


if __name__ == "__main__":
    # `python -m aegis.audit` prints a quick summary
    import pprint
    pprint.pprint(summary())
