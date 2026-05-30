"""
tests/test_wrapper.py — unit tests for the Aegis interception layer.

The wrapper is the product. It gets tests. Run with: pytest tests/
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegis import audit, wrapper
from aegis.policy import CapabilitySpec


class FakeCtx:
    """Minimal stand-in for pydantic_ai.RunContext.

    The real RunContext carries deps, model, usage, agent, tool_name (the
    TOOL name, not the server name), etc.  wrapper._process does not read
    from ctx — server identity comes from the make_process_tool_call closure
    — so FakeCtx needs no fields.  It exists solely to satisfy the type slot.
    """


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    test_log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", test_log)
    yield test_log


def test_successful_call_is_logged(temp_log):
    async def fake_call_tool(tool_name, args):
        return {"ok": True, "echo": args}

    hook = wrapper.make_process_tool_call("filesystem")

    async def run():
        return await hook(FakeCtx(), fake_call_tool, "read_file", {"path": "/x"})

    result = asyncio.run(run())
    assert result == {"ok": True, "echo": {"path": "/x"}}

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "ok"
    assert records[0]["tool"] == "read_file"
    assert records[0]["server"] == "filesystem"
    assert "latency_ms" in records[0]


def test_failed_call_is_logged_and_reraised(temp_log):
    async def failing_call_tool(tool_name, args):
        raise ValueError("boom")

    hook = wrapper.make_process_tool_call("github")

    async def run():
        return await hook(FakeCtx(), failing_call_tool, "create_issue", {})

    with pytest.raises(ValueError, match="boom"):
        asyncio.run(run())

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "error"
    assert "boom" in records[0]["error"]


def test_oversized_args_are_truncated(temp_log):
    big_value = "A" * 5000

    async def fake_call_tool(tool_name, args):
        return "done"

    hook = wrapper.make_process_tool_call("postgres")

    async def run():
        return await hook(FakeCtx(), fake_call_tool, "query", {"sql": big_value})

    asyncio.run(run())
    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert "truncated" in records[0]["args"]["sql"]
    assert len(records[0]["args"]["sql"]) < 5000


def test_wrapper_logs_args_safely_against_newline_injection(temp_log):
    """Arg values containing newlines must not produce multi-line JSONL records.

    json.dumps escapes \\n within string values to \\\\n, so each call produces
    exactly one line regardless of what values the agent passes.
    """
    evil_value = "first line\nsecond line\nthird line"

    async def fake_call_tool(tool_name, args):
        return "done"

    hook = wrapper.make_process_tool_call("filesystem")

    async def run():
        return await hook(FakeCtx(), fake_call_tool, "read_text_file", {"path": evil_value})

    asyncio.run(run())

    raw = temp_log.read_text()
    lines = raw.splitlines()

    # Exactly one JSONL record — embedded newlines must not split the line.
    assert len(lines) == 1, f"expected 1 line, got {len(lines)}: {raw!r}"

    # The line must round-trip cleanly through json.loads.
    record = json.loads(lines[0])
    assert record["status"] == "ok"
    assert record["tool"] == "read_text_file"

    # The raw newline must not appear unescaped in the serialised line.
    assert "\n" not in lines[0]

    # The arg value (possibly truncated) must still be recoverable.
    assert "first line" in record["args"]["path"]


# ---------------------------------------------------------------------------
# Helpers for policy-enforcement tests
# ---------------------------------------------------------------------------


def _allow_spec(spec_hash: str = "testhash001") -> CapabilitySpec:
    """Spec that allows filesystem/read_text_file with a single 'path' arg."""
    return CapabilitySpec.model_validate({
        "task": "test task",
        "deny_all_others": True,
        "servers": {
            "filesystem": {
                "tools": {
                    "read_text_file": {
                        "args": {"path": None},
                    }
                }
            }
        },
        "spec_hash": spec_hash,
    })


# ---------------------------------------------------------------------------
# Policy-enforcement tests (Phase 2 wiring)
# ---------------------------------------------------------------------------


def test_wrapper_with_no_spec_preserves_phase1_behavior(temp_log):
    """make_process_tool_call without spec behaves identically to Phase 1."""
    async def fake_call_tool(tool_name, args):
        return {"ok": True}

    hook = wrapper.make_process_tool_call("filesystem")  # no spec

    async def run():
        return await hook(FakeCtx(), fake_call_tool, "any_tool", {"x": "y"})

    result = asyncio.run(run())
    assert result == {"ok": True}

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "ok"
    assert records[0]["server"] == "filesystem"
    assert records[0]["tool"] == "any_tool"


def test_wrapper_with_spec_allows_matching_call(temp_log):
    """A call that satisfies the spec is forwarded and logged with status ok."""
    spec = _allow_spec()
    called: list[tuple[str, dict]] = []

    async def fake_call_tool(tool_name, args):
        called.append((tool_name, args))
        return "file contents"

    hook = wrapper.make_process_tool_call("filesystem", spec=spec)

    async def run():
        return await hook(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/sandbox/notes.txt"})

    result = asyncio.run(run())
    assert result == "file contents"
    assert len(called) == 1

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "ok"


def test_wrapper_with_spec_denies_unlisted_tool(temp_log):
    """A tool not in the spec is denied; call_tool is never invoked."""
    spec = _allow_spec()
    call_tool = MagicMock()

    hook = wrapper.make_process_tool_call("filesystem", spec=spec)

    async def run():
        return await hook(FakeCtx(), call_tool, "write_file", {"path": "/x", "content": "y"})

    with pytest.raises(PermissionError):
        asyncio.run(run())

    assert not call_tool.called

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "denied"
    assert records[0]["matched_rule"] == "rule-2-tool-not-listed"


def test_wrapper_with_spec_denies_extra_arg(temp_log):
    """An extra arg not listed in the spec is denied; call_tool is never invoked."""
    spec = _allow_spec()
    call_tool = MagicMock()

    hook = wrapper.make_process_tool_call("filesystem", spec=spec)

    async def run():
        return await hook(FakeCtx(), call_tool, "read_text_file", {"path": "/x", "encoding": "utf-8"})

    with pytest.raises(PermissionError):
        asyncio.run(run())

    assert not call_tool.called

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "denied"
    assert records[0]["matched_rule"] == "rule-6-extra-arg"


def test_wrapper_fails_closed_on_evaluator_exception(temp_log, monkeypatch):
    """If evaluate() raises, the call is denied and call_tool is never invoked."""
    spec = _allow_spec()
    call_tool = MagicMock()

    def boom(*args, **kwargs):
        raise RuntimeError("simulated")

    monkeypatch.setattr(wrapper, "evaluate", boom)

    hook = wrapper.make_process_tool_call("filesystem", spec=spec)

    async def run():
        return await hook(FakeCtx(), call_tool, "read_text_file", {"path": "/x"})

    with pytest.raises(PermissionError, match="policy evaluation failed"):
        asyncio.run(run())

    assert not call_tool.called

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "policy_evaluation_error"
    assert "RuntimeError" in records[0]["error"]
    assert "simulated" in records[0]["error"]


def test_wrapper_denied_audit_record_contains_spec_hash(temp_log):
    """denied and policy_evaluation_error records carry spec_hash for investigation."""
    spec = _allow_spec(spec_hash="deadbeef1234")
    call_tool = MagicMock()

    hook = wrapper.make_process_tool_call("filesystem", spec=spec)

    async def run():
        return await hook(FakeCtx(), call_tool, "unlisted_tool", {})

    with pytest.raises(PermissionError):
        asyncio.run(run())

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["spec_hash"] == "deadbeef1234"
