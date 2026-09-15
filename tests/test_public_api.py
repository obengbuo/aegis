"""
tests/test_public_api.py — the public integration contract.

These tests exercise aegis's public surface exactly as an external
integrator would: `from aegis import ...`, never aegis.wrapper / aegis.policy
/ aegis.proposer directly. This file is the executable spec for what Week 5
Stream 1 ships.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import yaml
from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis import (
    AegisConfig,
    CapabilitySpec,
    SpecValidationError,
    audit,
    load_spec,
    propose_spec,
    proposer,
    wrap_toolset,
)


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")


class _FakeCtx:
    """Minimal RunContext stand-in — the wrapper never reads from it."""


# --- offline Anthropic doubles, so propose_spec runs without a live call -----


class _FakeBlock:
    def __init__(self, name, tool_input):
        self.type = "tool_use"
        self.name = name
        self.input = tool_input


class _FakeResponse:
    def __init__(self, blocks):
        self.content = blocks


class _FakeMessages:
    def __init__(self, response):
        self._response = response

    def create(self, **kwargs):
        return self._response


class _FakeAnthropic:
    def __init__(self, response):
        self.messages = _FakeMessages(response)


def _install_fake_anthropic(monkeypatch, blocks):
    response = _FakeResponse(blocks)
    monkeypatch.setattr(proposer.anthropic, "Anthropic", lambda *a, **k: _FakeAnthropic(response))


def _valid_spec_yaml() -> str:
    return yaml.dump({
        "task": "read one file",
        "servers": {"filesystem": {"tools": {"read_text_file": {"args": {"path": None}}}}},
    })


def test_all_six_public_symbols_import_successfully():
    """The exact import statement docs/INTEGRATION.md tells integrators to use."""
    assert callable(wrap_toolset)
    assert callable(propose_spec)
    assert callable(load_spec)
    assert issubclass(SpecValidationError, Exception)
    assert {"sandbox_root", "log_path", "run_id", "otlp_endpoint"} <= set(
        AegisConfig.__dataclass_fields__
    )
    assert "spec_hash" in CapabilitySpec.model_fields


def test_wrap_toolset_mutates_input_toolset():
    """wrap_toolset mutates in place and returns the same object.

    This is a deliberate contract, not an accident: process_tool_call is a
    plain mutable attribute on MCPToolset, so mutating in place cannot drop
    any other configuration (nothing is reconstructed). Callers must not
    keep a separate reference to the pre-wrap toolset expecting it to stay
    un-enforced — there is only one object. This test pins that semantic so
    a future refactor can't silently switch to reconstruction.
    """
    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    assert toolset.process_tool_call is None

    wrapped = wrap_toolset(toolset, "filesystem")

    assert wrapped is toolset
    assert toolset.process_tool_call is not None


def test_end_to_end_facade_config_spec_and_wrap(tmp_path):
    """AegisConfig + load_spec + wrap_toolset, exactly as an integrator chains them.

    Uses a hand-authored spec fixture via load_spec rather than propose_spec
    to avoid a live Anthropic call in a unit test.
    """
    sandbox_root = tmp_path / "sandbox"
    sandbox_root.mkdir()
    config = AegisConfig(sandbox_root=sandbox_root)
    assert config.run_id is not None

    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(
        yaml.dump(
            {
                "task": "read one file",
                "servers": {
                    "filesystem": {
                        "tools": {"read_text_file": {"args": {"path": None}}}
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    spec = load_spec(spec_file)
    assert isinstance(spec, CapabilitySpec)

    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrapped = wrap_toolset(toolset, "filesystem", spec=spec, config=config)

    assert wrapped.process_tool_call is not None


# ---------------------------------------------------------------------------
# run_id correlation: spec_loaded <-> the run's tool calls
# ---------------------------------------------------------------------------


def test_load_spec_run_id_matches_wrapper_tool_call_run_id(tmp_path):
    """THE property the control plane needs: the run_id on the spec_loaded
    record that OPENS a run equals the run_id the wrapper stamps on the tool
    calls in that same run. A single AegisConfig feeds both — load_spec(...,
    run_id=config.run_id) and wrap_toolset(..., config=config) — so the link
    is exact, not an inference the backend has to reconstruct.
    """
    config = AegisConfig(sandbox_root=tmp_path)

    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(_valid_spec_yaml(), encoding="utf-8")
    spec = load_spec(spec_file, run_id=config.run_id)

    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrap_toolset(toolset, "filesystem", spec=spec, config=config)

    async def fake_call_tool(tool_name, args):
        return "file contents"

    asyncio.run(
        toolset.process_tool_call(_FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})
    )

    records = [json.loads(line) for line in audit.LOG_PATH.read_text().splitlines()]
    spec_loaded = next(r for r in records if r["status"] == "spec_loaded")
    ok = next(r for r in records if r["status"] == "ok")

    assert spec_loaded["run_id"] == ok["run_id"] == config.run_id


def test_propose_spec_run_id_matches_wrapper_tool_call_run_id(tmp_path, monkeypatch):
    """Same link, via the proposer's own spec_loaded record. Offline: the
    Anthropic call is faked so no live request is made."""
    config = AegisConfig(sandbox_root=tmp_path)
    _install_fake_anthropic(
        monkeypatch, [_FakeBlock("emit_capability_spec", {"spec_yaml": _valid_spec_yaml()})]
    )

    spec = propose_spec("read a file", tmp_path, run_id=config.run_id)

    toolset = MCPToolset(StdioTransport("python", ["-c", "pass"]))
    wrap_toolset(toolset, "filesystem", spec=spec, config=config)

    async def fake_call_tool(tool_name, args):
        return "file contents"

    asyncio.run(
        toolset.process_tool_call(_FakeCtx(), fake_call_tool, "read_text_file", {"path": "/x"})
    )

    records = [json.loads(line) for line in audit.LOG_PATH.read_text().splitlines()]
    spec_loaded = next(r for r in records if r["status"] == "spec_loaded" and r.get("proposed"))
    ok = next(r for r in records if r["status"] == "ok")

    assert spec_loaded["run_id"] == ok["run_id"] == config.run_id


def test_propose_spec_omits_run_id_when_not_supplied(tmp_path, monkeypatch):
    """Backward compatible: propose_spec with no run_id emits a record with no
    run_id key, exactly as before."""
    _install_fake_anthropic(
        monkeypatch, [_FakeBlock("emit_capability_spec", {"spec_yaml": _valid_spec_yaml()})]
    )

    propose_spec("read a file", tmp_path)  # no run_id

    records = [json.loads(line) for line in audit.LOG_PATH.read_text().splitlines()]
    spec_loaded = next(r for r in records if r["status"] == "spec_loaded" and r.get("proposed"))
    assert "run_id" not in spec_loaded
