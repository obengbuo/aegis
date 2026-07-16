"""
tests/test_public_api.py — the Waxell integration contract.

These tests exercise aegis's public surface exactly as an external
integrator would: `from aegis import ...`, never aegis.wrapper / aegis.policy
/ aegis.proposer directly. This file is the executable spec for what Week 5
Stream 1 ships.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastmcp.client.transports import StdioTransport
from pydantic_ai.mcp import MCPToolset

from aegis import (
    AegisConfig,
    CapabilitySpec,
    SpecValidationError,
    load_spec,
    propose_spec,
    wrap_toolset,
)
from aegis import audit


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file for each test."""
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")


def test_all_six_public_symbols_import_successfully():
    """The exact import statement Waxell's integration doc will use."""
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
    """AegisConfig + load_spec + wrap_toolset, exactly as Waxell would chain them.

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
