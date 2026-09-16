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
from aegis.policy import CapabilitySpec
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
    blocks; the response returns untouched and no detection record appears.

    `off` suppresses detection OUTPUT, not redaction. It used to suppress both,
    which meant the shipped default wrote credential material into the audit
    log verbatim — see "The audit log records tool content verbatim" in
    docs/OPEN_QUESTIONS.md. The preview is now redacted in every mode; what
    `off` still means is that no response_pattern_detected record is written
    and nothing is ever refused.
    """
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
    # INVERTED, deliberately: this line used to assert the SSN was present,
    # pinning the leak as intended behaviour. What it pins now is that `off`
    # governs detection output and refusal, not what reaches the log.
    assert "123-45-6789" not in records[0]["result_preview"]

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
    # The configured mode rides the record too, so downstream can distinguish
    # "warned and returned" from "blocked" — here the response was returned.
    assert detected["response_inspection_mode"] == "warn"
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
    # block verdict AND block mode => the response was actually withheld.
    assert records[0]["response_inspection_mode"] == "block"
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
    # The case the field exists for: mode is "block" but the verdict is only
    # "warn", so the response was returned unchanged. Without the mode a reader
    # seeing verdict="warn" cannot know block mode was even in force; with both,
    # it's unambiguous that nothing was withheld.
    assert detected["response_inspection_mode"] == "block"


# ---------------------------------------------------------------------------
# AUDIT-LOG REDACTION.
#
# Aegis writes four free-text fields that can carry agent- or tool-supplied
# content, and all four used to carry it verbatim:
#
#   result_preview  500 chars of the response      leaked at the default only
#   args            1000 chars per argument        leaked in EVERY mode
#   reason          a denial's explanation         leaked in EVERY mode
#   error           a tool exception's message     leaked in EVERY mode
#
# The last three are not mode-dependent: an operator who read the docs,
# understood the risk and chose `block` still got the secret on disk. And the
# reason is built in aegis/policy.py from the RAW args dict, not from
# _safe_args, so fixing the argument path does not cover it.
#
# All four are now scanned before they are written. What is scanned is the
# TRUNCATED text, because only the truncated text can reach the log — a secret
# past the truncation point was never going to be recorded. Detection output
# and refusal remain governed by response_inspection_mode; recording does not.
#
# See "The audit log records tool content verbatim" in docs/OPEN_QUESTIONS.md.
# ---------------------------------------------------------------------------

_KEY = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAreal_key_material"
_SSN_TEXT = "Customer SSN: 123-45-6789"

_ALL_MODES = ["off", "warn", "block"]


def _spec_for(tool: str, arg: str, permitted: list[str] | None = None):
    """A spec permitting fs/<tool> with one argument, optionally constrained."""
    from aegis.policy import CapabilitySpec

    entry = {"must_match_one_of": permitted} if permitted else None
    return CapabilitySpec.model_validate({
        "task": "t",
        "servers": {"fs": {"tools": {tool: {"args": {arg: entry}}}}},
        "spec_hash": "REDACTHASH",
    })


def _records(temp_log) -> list[dict]:
    return [json.loads(line) for line in temp_log.read_text().splitlines()]


def _only(temp_log, status: str) -> dict:
    hits = [r for r in _records(temp_log) if r["status"] == status]
    assert len(hits) == 1, f"expected one {status}; got {[r['status'] for r in _records(temp_log)]}"
    return hits[0]


# --- result_preview: the default-dependent exit -----------------------------


@pytest.mark.parametrize("payload", [_KEY, _SSN_TEXT], ids=["block-tier", "warn-tier"])
def test_preview_is_redacted_with_inspection_off(temp_log, payload):
    """THE REGRESSION TEST. mode defaults to off; the preview must still not
    carry credential material."""
    async def tool(name, args):
        return payload

    hook = wrapper.make_process_tool_call("fs", spec=_spec_for("read", "path"))
    result = asyncio.run(hook(FakeCtx(), tool, "read", {"path": "/x"}))

    # The response itself is never modified — that contract is unchanged.
    assert result == payload

    record = _only(temp_log, "ok")
    assert "PRIVATE KEY" not in record["result_preview"]
    assert "123-45-6789" not in record["result_preview"]
    assert "[redacted" in record["result_preview"]
    # ...and the notice points somewhere useful, since with inspection off
    # there is no response_pattern_detected record to point at.
    assert "response_inspection_mode" in record["result_preview"]
    # off still means no detection output.
    assert [r["status"] for r in _records(temp_log)] == ["ok"]


def test_clean_response_preview_is_untouched_in_every_mode(temp_log, tmp_path):
    """Redaction must not cost the preview on ordinary traffic, which is
    nearly all of it."""
    body = "just some ordinary file contents, nothing sensitive here"

    async def tool(name, args):
        return body

    for i, mode in enumerate(_ALL_MODES):
        hook = wrapper.make_process_tool_call(
            "fs", spec=_spec_for("read", "path"), response_inspection_mode=mode)
        asyncio.run(hook(FakeCtx(), tool, "read", {"path": f"/x{i}"}))

    previews = [r["result_preview"] for r in _records(temp_log) if r["status"] == "ok"]
    assert len(previews) == 3
    assert all(p == body for p in previews), previews


def test_only_the_recorded_preview_is_scanned(temp_log):
    """A secret past the 500-character truncation point never reaches the log,
    so it must not trigger redaction of a preview that is genuinely clean.
    This is what keeps the scan cheap: 500 characters, not the whole response.
    """
    async def tool(name, args):
        return ("x" * 600) + _KEY

    hook = wrapper.make_process_tool_call("fs", spec=_spec_for("read", "path"))
    asyncio.run(hook(FakeCtx(), tool, "read", {"path": "/x"}))

    preview = _only(temp_log, "ok")["result_preview"]
    assert "PRIVATE KEY" not in preview       # never recorded in the first place
    assert "[redacted" not in preview         # and so not redacted either
    assert preview.startswith("xxx")


# --- args: leaked in every mode --------------------------------------------


@pytest.mark.parametrize("mode", _ALL_MODES)
def test_argument_value_is_redacted_in_every_mode(temp_log, mode):
    """Not default-dependent: response inspection never scanned arguments, so
    `block` leaked exactly as much as `off`."""
    async def tool(name, args):
        return "written"

    hook = wrapper.make_process_tool_call(
        "fs", spec=_spec_for("write", "content"), response_inspection_mode=mode)
    asyncio.run(hook(FakeCtx(), tool, "write", {"content": _KEY}))

    record = _only(temp_log, "ok")
    assert "PRIVATE KEY" not in json.dumps(record["args"])
    assert "[redacted" in record["args"]["content"]


def test_only_the_offending_argument_is_redacted(temp_log):
    """Per-value, not per-record: a secret in one argument must not blind an
    investigator to the others."""
    async def tool(name, args):
        return "written"

    spec = CapabilitySpec.model_validate({
        "task": "t",
        "servers": {"fs": {"tools": {"write": {"args": {"path": None, "content": None}}}}},
        "spec_hash": "H",
    })
    hook = wrapper.make_process_tool_call("fs", spec=spec)
    asyncio.run(hook(FakeCtx(), tool, "write", {"path": "/sandbox/out.txt", "content": _KEY}))

    args = _only(temp_log, "ok")["args"]
    assert args["path"] == "/sandbox/out.txt"      # untouched
    assert "[redacted" in args["content"]


# --- reason: built in policy.py, so the args fix cannot cover it ------------


@pytest.mark.parametrize("mode", _ALL_MODES)
def test_denial_reason_is_redacted_in_every_mode(temp_log, mode):
    """Rule 7's reason embeds the rejected value. The value is the thing that
    was rejected, so it is exactly the thing most likely to be a credential
    the agent should not have been passing."""
    async def tool(name, args):
        raise AssertionError("must never be called")

    hook = wrapper.make_process_tool_call(
        "fs", spec=_spec_for("write", "content", ["benign"]),
        response_inspection_mode=mode)
    with pytest.raises(PermissionError):
        asyncio.run(hook(FakeCtx(), tool, "write", {"content": _KEY}))

    record = _only(temp_log, "denied")
    assert "PRIVATE KEY" not in record["reason"]
    assert "[redacted" in record["reason"]
    assert "PRIVATE KEY" not in json.dumps(record["args"])
    # matched_rule survives, so the denial is still diagnosable.
    assert record["matched_rule"] == "rule-7-value-not-allowed"


def test_ordinary_denial_reason_is_untouched(temp_log):
    """Redaction must not cost the reason on ordinary denials."""
    async def tool(name, args):
        raise AssertionError("must never be called")

    hook = wrapper.make_process_tool_call("fs", spec=_spec_for("write", "content", ["benign"]))
    with pytest.raises(PermissionError):
        asyncio.run(hook(FakeCtx(), tool, "write", {"content": "/etc/passwd"}))

    reason = _only(temp_log, "denied")["reason"]
    assert "/etc/passwd" in reason
    assert "[redacted" not in reason


def test_collection_element_denial_reason_is_redacted(temp_log):
    """The element-wise branch of rule 7 embeds the offending element."""
    async def tool(name, args):
        raise AssertionError("must never be called")

    hook = wrapper.make_process_tool_call("fs", spec=_spec_for("batch", "items", ["benign"]))
    with pytest.raises(PermissionError):
        asyncio.run(hook(FakeCtx(), tool, "batch", {"items": [_KEY]}))

    record = _only(temp_log, "denied")
    assert "PRIVATE KEY" not in record["reason"]
    assert "[redacted" in record["reason"]


# --- error: a tool exception's own message ----------------------------------


@pytest.mark.parametrize("mode", _ALL_MODES)
def test_tool_exception_message_is_redacted_in_every_mode(temp_log, mode):
    """An upstream server that echoes the offending value back in its error
    text would otherwise put it in the log, whatever the mode."""
    async def tool(name, args):
        raise RuntimeError(f"upstream rejected {_KEY}")

    hook = wrapper.make_process_tool_call(
        "fs", spec=_spec_for("write", "content"), response_inspection_mode=mode)
    with pytest.raises(RuntimeError):
        asyncio.run(hook(FakeCtx(), tool, "write", {"content": "benign"}))

    record = _only(temp_log, "error")
    assert "PRIVATE KEY" not in record["error"]
    assert "[redacted" in record["error"]


def test_ordinary_tool_error_is_untouched(temp_log):
    async def tool(name, args):
        raise FileNotFoundError("no such file: /sandbox/missing.txt")

    hook = wrapper.make_process_tool_call("fs", spec=_spec_for("write", "content"))
    with pytest.raises(FileNotFoundError):
        asyncio.run(hook(FakeCtx(), tool, "write", {"content": "benign"}))

    error = _only(temp_log, "error")["error"]
    assert "missing.txt" in error
    assert "[redacted" not in error


# --- the enabled modes are unchanged ---------------------------------------


def test_warn_mode_still_writes_a_detection_record_and_points_at_it(temp_log, tmp_path):
    """Regression guard: the recording change must not alter what the enabled
    modes do. warn still detects, still returns, and its preview notice still
    points at the detection record rather than at the mode."""
    async def tool(name, args):
        return _SSN_TEXT

    config = AegisConfig(sandbox_root=tmp_path, response_inspection_mode="warn")
    toolset = _wrapped_toolset("fs", config=config)
    result = asyncio.run(
        toolset.process_tool_call(FakeCtx(), tool, "read_text_file", {"path": "/x"}))

    assert result == _SSN_TEXT
    statuses = [r["status"] for r in _records(temp_log)]
    assert "response_pattern_detected" in statuses

    preview = _only(temp_log, "ok")["result_preview"]
    assert "123-45-6789" not in preview
    assert "response_pattern_detected" in preview
