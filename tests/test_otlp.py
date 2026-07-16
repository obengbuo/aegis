"""
tests/test_otlp.py — OTLP audit-event mirroring (Week 5 Stream 2).

No network endpoint is ever used. Every test that needs to observe an
emitted span injects an in-memory tracer directly into audit._otlp_tracer,
bypassing _get_or_create_tracer's real OTLPSpanExporter construction
entirely — that's the intended seam: _get_or_create_tracer only builds a
real exporter on a cache miss, so pre-seeding the cache with a fake tracer
means write_record's OTLP path runs for real while never touching a socket.
"""

from __future__ import annotations

import json
import sys

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

from aegis import audit


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")
    yield tmp_path / "audit.jsonl"


@pytest.fixture
def otlp_capture(monkeypatch):
    """Inject an in-memory OTLP tracer, bypassing the real network exporter.

    SimpleSpanProcessor (not BatchSpanProcessor) exports synchronously on
    span end, so spans are visible to the test immediately after
    write_record() returns — no flush/wait needed.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("aegis-test")
    monkeypatch.setattr(audit, "_otlp_tracer", tracer)
    return exporter


def test_otlp_span_emitted_on_write_record(otlp_capture, temp_log):
    record = {
        "call_id": "abc-123",
        "server": "filesystem",
        "tool": "read_text_file",
        "status": "ok",
        "latency_ms": 12.5,
    }
    audit.write_record(record, otlp_endpoint="http://collector.example:4318")

    spans = otlp_capture.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.attributes["aegis.server"] == "filesystem"
    assert span.attributes["aegis.tool"] == "read_text_file"
    assert span.attributes["aegis.status"] == "ok"
    assert span.attributes["aegis.call_id"] == "abc-123"
    assert span.attributes["aegis.latency_ms"] == 12.5

    # JSONL still wrote too — OTLP is additive, not a replacement.
    lines = temp_log.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["call_id"] == "abc-123"


def test_otlp_span_kind_internal_for_policy_events(otlp_capture, temp_log):
    record = {
        "call_id": "deny-1",
        "server": "filesystem",
        "tool": "write_file",
        "status": "denied",
        "reason": "tool not in capability spec",
        "matched_rule": "rule-2-tool-not-listed",
        "spec_hash": "deadbeef",
    }
    audit.write_record(record, otlp_endpoint="http://collector.example:4318")

    spans = otlp_capture.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].kind == SpanKind.INTERNAL
    assert spans[0].attributes["aegis.matched_rule"] == "rule-2-tool-not-listed"
    assert spans[0].attributes["aegis.reason"] == "tool not in capability spec"


def test_otlp_span_kind_client_for_mcp_calls(otlp_capture, temp_log):
    record = {
        "call_id": "ok-1",
        "server": "fetch",
        "tool": "fetch_url",
        "status": "ok",
        "latency_ms": 42.0,
    }
    audit.write_record(record, otlp_endpoint="http://collector.example:4318")

    spans = otlp_capture.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].kind == SpanKind.CLIENT


def test_otlp_export_failure_does_not_break_write_record(monkeypatch, temp_log, capsys):
    class ExplodingTracer:
        def start_as_current_span(self, *args, **kwargs):
            raise RuntimeError("simulated collector failure")

    monkeypatch.setattr(audit, "_otlp_tracer", ExplodingTracer())

    record = {"call_id": "boom-1", "server": "filesystem", "tool": "read_text_file", "status": "ok"}

    # Must not raise.
    audit.write_record(record, otlp_endpoint="http://unreachable.example:4318")

    # JSONL still has the record.
    lines = temp_log.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["call_id"] == "boom-1"

    # stderr carries the failure notice.
    captured = capsys.readouterr()
    assert "[aegis] OTLP export failed" in captured.err
    assert "simulated collector failure" in captured.err


def test_no_otlp_when_endpoint_is_none(otlp_capture, temp_log):
    record = {"call_id": "no-otlp-1", "server": "filesystem", "tool": "read_text_file", "status": "ok"}

    audit.write_record(record)  # no otlp_endpoint at all

    assert len(otlp_capture.get_finished_spans()) == 0
    lines = temp_log.read_text().splitlines()
    assert len(lines) == 1


def test_end_to_end_wrap_toolset_with_otlp_endpoint(otlp_capture, temp_log, tmp_path):
    import asyncio

    from fastmcp.client.transports import StdioTransport
    from pydantic_ai.mcp import MCPToolset

    from aegis import AegisConfig, wrap_toolset

    config = AegisConfig(sandbox_root=tmp_path, otlp_endpoint="http://collector.example:4318")
    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrap_toolset(toolset, "filesystem", config=config)

    async def fake_call_tool(tool_name, args):
        return "file contents"

    class FakeCtx:
        ...

    result = asyncio.run(
        toolset.process_tool_call(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})
    )
    assert result == "file contents"

    spans = otlp_capture.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].attributes["aegis.server"] == "filesystem"
    assert spans[0].attributes["aegis.tool"] == "read_text_file"
    assert spans[0].attributes["aegis.status"] == "ok"
    assert spans[0].kind == SpanKind.CLIENT
