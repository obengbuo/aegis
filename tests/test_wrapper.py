"""
tests/test_wrapper.py — unit tests for the Aegis interception layer.

The wrapper is the product. It gets tests. Run with: pytest tests/
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from aegis import audit, wrapper


class FakeCtx:
    """Stand-in for the Pydantic AI run context."""

    def __init__(self, server_name: str) -> None:
        self.tool_name = server_name


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    test_log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", test_log)
    yield test_log


def test_successful_call_is_logged(temp_log):
    async def fake_call_tool(tool_name, args):
        return {"ok": True, "echo": args}

    async def run():
        return await wrapper.process_tool_call(
            FakeCtx("filesystem"), fake_call_tool, "read_file", {"path": "/x"}
        )

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

    async def run():
        return await wrapper.process_tool_call(
            FakeCtx("github"), failing_call_tool, "create_issue", {}
        )

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

    async def run():
        return await wrapper.process_tool_call(
            FakeCtx("postgres"), fake_call_tool, "query", {"sql": big_value}
        )

    asyncio.run(run())
    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert "truncated" in records[0]["args"]["sql"]
    assert len(records[0]["args"]["sql"]) < 5000
