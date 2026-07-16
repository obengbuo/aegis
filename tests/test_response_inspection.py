"""
tests/test_response_inspection.py — sensitive-data scanning of tool responses
(Week 5 Stream 5), plus wrapper integration.

Regex-level tests call scan_response() directly — no wrapper, no MCPToolset.
Wrapper-integration tests exercise the full path through wrapper.wrap_toolset.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis import audit, wrapper
from aegis.config import AegisConfig
from aegis.response_inspection import scan_response


class FakeCtx:
    """Minimal stand-in for pydantic_ai.RunContext — see tests/test_wrapper.py."""


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    test_log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", test_log)
    return test_log


_CTX = {"server": "filesystem", "tool": "read_text_file", "call_id": "test-call-id"}

# A widely-used Luhn-valid test Visa number. Flipping the last digit alone
# is guaranteed to break Luhn (the final digit is never doubled, so it
# contributes to the checksum total directly — changing it by any amount
# other than a multiple of 10 breaks a total that was == 0 mod 10).
_VALID_CC = "4111111111111111"
_INVALID_CC = "4111111111111112"


# ---------------------------------------------------------------------------
# Regex-level tests
# ---------------------------------------------------------------------------


def test_ssn_pattern_detected():
    result = scan_response("Customer SSN: 123-45-6789 on file.", _CTX)
    assert result.verdict == "warn"
    ssn_matches = [m for m in result.patterns_matched if m.pattern_name == "ssn"]
    assert len(ssn_matches) == 1
    assert ssn_matches[0].match_repr == repr("XXX-XX-6789")


def test_ssn_dummy_pattern_not_flagged():
    result = scan_response("SSN: 000-00-0000 (dummy)", _CTX)
    assert result.verdict == "clean"
    assert result.patterns_matched == []


def test_credit_card_luhn_pass_detected():
    result = scan_response(f"Card on file: {_VALID_CC}", _CTX)
    assert result.verdict == "block"
    cc_matches = [m for m in result.patterns_matched if m.pattern_name == "credit_card"]
    assert len(cc_matches) == 1
    assert cc_matches[0].match_repr == repr("XXXX-XXXX-XXXX-1111")


def test_credit_card_luhn_fail_not_detected():
    result = scan_response(f"Random digits: {_INVALID_CC}", _CTX)
    assert result.verdict == "clean"
    assert result.patterns_matched == []


def test_private_key_header_detected():
    body = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOwIBAAJBAKz9notarealkeybody1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = scan_response(body, _CTX)
    assert result.verdict == "block"
    pk_matches = [m for m in result.patterns_matched if m.pattern_name == "private_key"]
    assert len(pk_matches) == 1
    assert pk_matches[0].match_repr == repr("-----BEGIN RSA PRIVATE KEY-----...")


def test_aws_access_key_detected():
    result = scan_response("key=AKIAIOSFODNN7EXAMPLE", _CTX)
    assert result.verdict == "block"
    aws_matches = [m for m in result.patterns_matched if m.pattern_name == "aws_access_key"]
    assert len(aws_matches) == 1
    assert aws_matches[0].match_repr == repr("AKIA...MPLE")


def test_match_repr_never_contains_raw_data():
    """Load-bearing: a failure here means the audit log leaks the exact
    data response inspection exists to protect."""
    ssn_raw = "123-45-6789"
    cc_raw = _VALID_CC
    aws_raw = "AKIAIOSFODNN7EXAMPLE"
    pk_secret_body = "MIIBOwIBAAJBAKSECRETKEYMATERIALDONOTLEAK1234567890"

    body = (
        f"SSN: {ssn_raw}\n"
        f"Card: {cc_raw}\n"
        f"Key: {aws_raw}\n"
        f"-----BEGIN RSA PRIVATE KEY-----\n{pk_secret_body}\n-----END RSA PRIVATE KEY-----"
    )
    result = scan_response(body, _CTX)

    by_pattern = {m.pattern_name: m for m in result.patterns_matched}
    assert set(by_pattern) == {"ssn", "credit_card", "aws_access_key", "private_key"}

    assert ssn_raw not in by_pattern["ssn"].match_repr
    assert cc_raw not in by_pattern["credit_card"].match_repr
    assert aws_raw not in by_pattern["aws_access_key"].match_repr
    assert pk_secret_body not in by_pattern["private_key"].match_repr

    for match in result.patterns_matched:
        assert match.match_repr  # every preview is non-empty


def test_clean_response_returns_clean_verdict():
    result = scan_response("Just a normal summary of the meeting notes.", _CTX)
    assert result.verdict == "clean"
    assert result.patterns_matched == []


# ---------------------------------------------------------------------------
# Wrapper integration
# ---------------------------------------------------------------------------


def _wrapped_toolset(server_name: str, config: AegisConfig | None = None) -> MCPToolset:
    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrapper.wrap_toolset(toolset, server_name, config=config)
    return toolset


def test_wrapper_response_inspection_off_by_default(temp_log, tmp_path):
    """No config at all, and a config with mode='off' explicitly — neither
    scans; the response returns untouched and no detection record appears."""
    async def fake_call_tool(tool_name, args):
        return "Customer SSN: 123-45-6789"

    # No config at all (Phase 1 mode style call).
    hook = wrapper.make_process_tool_call("filesystem")

    async def run_no_config():
        return await hook(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})

    result = asyncio.run(run_no_config())
    assert result == "Customer SSN: 123-45-6789"

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "ok"
    assert "123-45-6789" in records[0]["result_preview"]  # no scan ran, nothing redacted

    # Explicit config with mode="off" — same behavior.
    config = AegisConfig(sandbox_root=tmp_path, response_inspection_mode="off")
    toolset = _wrapped_toolset("filesystem", config=config)

    async def run_off_config():
        return await toolset.process_tool_call(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/y"})

    result2 = asyncio.run(run_off_config())
    assert result2 == "Customer SSN: 123-45-6789"

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 2
    assert all(r["status"] == "ok" for r in records)


def test_wrapper_response_inspection_warn_mode_logs_but_returns(temp_log, tmp_path):
    config = AegisConfig(sandbox_root=tmp_path, response_inspection_mode="warn")
    toolset = _wrapped_toolset("filesystem", config=config)

    async def fake_call_tool(tool_name, args):
        return "Customer SSN: 123-45-6789"

    async def run():
        return await toolset.process_tool_call(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})

    result = asyncio.run(run())
    assert result == "Customer SSN: 123-45-6789"  # returned unmodified to the agent

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    statuses = [r["status"] for r in records]
    assert "response_pattern_detected" in statuses
    assert "ok" in statuses

    detected = next(r for r in records if r["status"] == "response_pattern_detected")
    assert detected["response_inspection_verdict"] == "warn"
    assert any(p["name"] == "ssn" for p in detected["patterns"])

    ok_record = next(r for r in records if r["status"] == "ok")
    assert "123-45-6789" not in ok_record["result_preview"]  # audit log doesn't leak it either


def test_wrapper_response_inspection_block_mode_raises(temp_log, tmp_path):
    config = AegisConfig(sandbox_root=tmp_path, response_inspection_mode="block")
    toolset = _wrapped_toolset("filesystem", config=config)

    async def fake_call_tool(tool_name, args):
        return f"Card on file: {_VALID_CC}"

    async def run():
        return await toolset.process_tool_call(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})

    with pytest.raises(PermissionError, match="response blocked"):
        asyncio.run(run())

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "response_pattern_detected"
    assert records[0]["response_inspection_verdict"] == "block"
    assert _VALID_CC not in json.dumps(records[0])  # not even the audit record leaks it


def test_wrapper_response_inspection_block_only_blocks_block_tier(temp_log, tmp_path):
    """mode='block' does not block warn-tier-only matches (SSN alone) — only
    calls whose overall verdict is 'block' get raised."""
    config = AegisConfig(sandbox_root=tmp_path, response_inspection_mode="block")
    toolset = _wrapped_toolset("filesystem", config=config)

    async def fake_call_tool(tool_name, args):
        return "Customer SSN: 123-45-6789"

    async def run():
        return await toolset.process_tool_call(FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})

    result = asyncio.run(run())
    assert result == "Customer SSN: 123-45-6789"

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    statuses = [r["status"] for r in records]
    assert "response_pattern_detected" in statuses
    assert "ok" in statuses
    detected = next(r for r in records if r["status"] == "response_pattern_detected")
    assert detected["response_inspection_verdict"] == "warn"
