"""
tests/test_policy.py — unit tests for the deterministic capability enforcer.

Tests are written against the evaluation rules documented in
docs/CAPABILITY_SPEC.md. Each rule has at least one ALLOW and one DENY case.

Run with: pytest tests/test_policy.py -v
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from aegis import audit
from aegis.policy import (
    CapabilitySpec,
    Decision,
    SpecValidationError,
    evaluate,
    load_spec,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def temp_log(tmp_path, monkeypatch):
    """Redirect the audit log to a temp file so load_spec tests are isolated."""
    test_log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_PATH", test_log)
    return test_log


def _spec(
    servers: dict,
    *,
    task: str = "test task",
    deny_all_others: bool = True,
    intercepts: list | None = None,
) -> CapabilitySpec:
    """Build a CapabilitySpec from a raw dict — mirrors what YAML loading produces."""
    data = {"task": task, "deny_all_others": deny_all_others, "servers": servers}
    if intercepts is not None:
        data["intercepts"] = intercepts
    return CapabilitySpec.model_validate(data)


def _constrained_spec() -> CapabilitySpec:
    """Spec that allows filesystem/read_text_file on exactly one path."""
    return _spec({
        "filesystem": {
            "tools": {
                "read_text_file": {
                    "args": {
                        "path": {"must_match_one_of": ["/sandbox/notes.txt"]},
                    }
                }
            }
        }
    })


def _zero_arg_spec() -> CapabilitySpec:
    """Spec that allows filesystem/list_allowed_directories (no args)."""
    return _spec({
        "filesystem": {
            "tools": {
                "list_allowed_directories": None,
            }
        }
    })


def _write_spec() -> CapabilitySpec:
    """Spec with a constrained path arg and an unconstrained content arg."""
    return _spec({
        "filesystem": {
            "tools": {
                "write_file": {
                    "args": {
                        "path": {"must_match_one_of": ["/sandbox/out.txt"]},
                        "content": None,  # required, any value
                    }
                }
            }
        }
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALLOW_REASON = "all checks passed"


def _assert_allow(d: Decision, *, matched_rule: str | None = None) -> None:
    """Assert a clean ALLOW with the canonical reason and expected matched_rule."""
    assert d.verdict == "ALLOW"
    assert d.reason == _ALLOW_REASON
    assert d.matched_rule == matched_rule


# ---------------------------------------------------------------------------
# Rule 1 — server not listed
# ---------------------------------------------------------------------------


def test_rule1_deny_unlisted_server():
    spec = _constrained_spec()
    d = evaluate(spec, "fetch", "fetch", {"url": "https://example.com"})
    assert d.verdict == "DENY"
    assert "fetch" in d.reason
    assert d.matched_rule == "rule-1-server-not-listed"


def test_rule1_allow_listed_server_passes_through():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/notes.txt"})
    _assert_allow(d)


def test_rule1_deny_all_others_false_allows_unlisted_server():
    spec = _spec(
        {"filesystem": {"tools": {"read_text_file": None}}},
        task="test task [deny_all_others=false]",
        deny_all_others=False,
    )
    d = evaluate(spec, "fetch", "fetch", {"url": "https://x.com"})
    # Weak-posture bypass must carry a stable matched_rule — not None — so it
    # is greppable in the audit log.
    _assert_allow(d, matched_rule="rule-1-bypassed-weak-posture")


# ---------------------------------------------------------------------------
# Rule 2 — tool not listed
# ---------------------------------------------------------------------------


def test_rule2_deny_unlisted_tool():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "write_file", {"path": "/sandbox/out.txt", "content": "x"})
    assert d.verdict == "DENY"
    assert "write_file" in d.reason
    assert d.matched_rule == "rule-2-tool-not-listed"


def test_rule2_deny_all_others_false_allows_unlisted_tool():
    spec = _spec(
        {"filesystem": {"tools": {}}},
        task="test task [deny_all_others=false]",
        deny_all_others=False,
    )
    d = evaluate(spec, "filesystem", "any_tool", {"x": "1"})
    _assert_allow(d, matched_rule="rule-2-bypassed-weak-posture")


# ---------------------------------------------------------------------------
# Rule 3 — zero-arg tool called with arguments
# ---------------------------------------------------------------------------


def test_rule3_deny_zero_arg_tool_called_with_args():
    spec = _zero_arg_spec()
    d = evaluate(spec, "filesystem", "list_allowed_directories", {"path": "/"})
    assert d.verdict == "DENY"
    assert "zero-arg" in d.reason
    assert "path" in d.reason
    assert d.matched_rule == "rule-3-zero-arg-violation"


def test_rule3_deny_multiple_unexpected_args():
    spec = _zero_arg_spec()
    d = evaluate(spec, "filesystem", "list_allowed_directories", {"a": "1", "b": "2"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-3-zero-arg-violation"


# ---------------------------------------------------------------------------
# Rule 4 — zero-arg tool called with zero arguments
# ---------------------------------------------------------------------------


def test_rule4_allow_zero_arg_tool_called_with_no_args():
    spec = _zero_arg_spec()
    d = evaluate(spec, "filesystem", "list_allowed_directories", {})
    _assert_allow(d)


def test_rule4_empty_args_block_with_no_args_allow():
    # args: {} is treated the same as no args block when the call has no args.
    spec = _spec({"filesystem": {"tools": {"some_tool": {"args": {}}}}})
    d = evaluate(spec, "filesystem", "some_tool", {})
    _assert_allow(d)


def test_rule4_empty_args_block_with_args_deny():
    # args: {} with a non-empty call → rule-6 fires (extra arg not in spec).
    spec = _spec({"filesystem": {"tools": {"some_tool": {"args": {}}}}})
    d = evaluate(spec, "filesystem", "some_tool", {"unexpected": "val"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-6-extra-arg"


# ---------------------------------------------------------------------------
# Rule 5 — missing required arg
# ---------------------------------------------------------------------------


def test_rule5_deny_missing_required_arg():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {})
    assert d.verdict == "DENY"
    assert "path" in d.reason
    assert d.matched_rule == "rule-5-missing-required-arg"


def test_rule5_deny_missing_one_of_two_required_args():
    spec = _write_spec()
    # write_file requires 'path' and 'content'; supply only 'path'.
    d = evaluate(spec, "filesystem", "write_file", {"path": "/sandbox/out.txt"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-5-missing-required-arg"


# ---------------------------------------------------------------------------
# Rule 6 — extra arg not listed in spec
# ---------------------------------------------------------------------------


def test_rule6_deny_extra_arg():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {
        "path": "/sandbox/notes.txt",
        "encoding": "utf-8",  # not in spec
    })
    assert d.verdict == "DENY"
    assert "encoding" in d.reason
    assert d.matched_rule == "rule-6-extra-arg"


def test_rule6_deny_extra_arg_even_when_constrained_arg_matches():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {
        "path": "/sandbox/notes.txt",
        "surprise": "x",
    })
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-6-extra-arg"


# ---------------------------------------------------------------------------
# Rule 7 — arg value not in allow-list
# ---------------------------------------------------------------------------


def test_rule7_deny_value_not_in_allow_list():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/evil.txt"})
    assert d.verdict == "DENY"
    assert "evil.txt" in d.reason
    assert d.matched_rule == "rule-7-value-not-allowed"


def test_rule7_allow_single_value_matches():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/notes.txt"})
    _assert_allow(d)


def test_rule7_allow_one_of_many_values():
    spec = _spec({
        "filesystem": {
            "tools": {
                "read_text_file": {
                    "args": {
                        "path": {
                            "must_match_one_of": [
                                "/sandbox/a.txt",
                                "/sandbox/b.txt",
                                "/sandbox/c.txt",
                            ]
                        }
                    }
                }
            }
        }
    })
    for path in ["/sandbox/a.txt", "/sandbox/b.txt", "/sandbox/c.txt"]:
        d = evaluate(spec, "filesystem", "read_text_file", {"path": path})
        _assert_allow(d)


def test_rule7_deny_when_no_value_matches_multi():
    spec = _spec({
        "filesystem": {
            "tools": {
                "read_text_file": {
                    "args": {
                        "path": {
                            "must_match_one_of": ["/sandbox/a.txt", "/sandbox/b.txt"]
                        }
                    }
                }
            }
        }
    })
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/evil.txt"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-value-not-allowed"


# ---------------------------------------------------------------------------
# Rule 7 — unconstrained arg (None entry = required, any value)
# ---------------------------------------------------------------------------


def test_unconstrained_arg_allows_any_value():
    spec = _write_spec()
    for content in ("hello", "", "A" * 10_000, "none", "null", "0"):
        d = evaluate(spec, "filesystem", "write_file", {
            "path": "/sandbox/out.txt",
            "content": content,
        })
        assert d.verdict == "ALLOW", f"unexpected DENY for content={content!r}: {d.reason}"
        assert d.reason == _ALLOW_REASON


def test_unconstrained_arg_still_required():
    spec = _write_spec()
    d = evaluate(spec, "filesystem", "write_file", {"path": "/sandbox/out.txt"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-5-missing-required-arg"


# ---------------------------------------------------------------------------
# Rule 8 — all checks pass
# ---------------------------------------------------------------------------


def test_rule8_allow_exact_match():
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/notes.txt"})
    _assert_allow(d)


def test_rule8_allow_constrained_and_unconstrained_args():
    spec = _write_spec()
    d = evaluate(spec, "filesystem", "write_file", {
        "path": "/sandbox/out.txt",
        "content": "generated report text",
    })
    _assert_allow(d)


# ---------------------------------------------------------------------------
# Decision dataclass properties
# ---------------------------------------------------------------------------


def test_decision_is_frozen():
    d = Decision(verdict="DENY", reason="test", matched_rule="rule-1-server-not-listed")
    with pytest.raises(Exception):
        d.verdict = "ALLOW"  # type: ignore[misc]


def test_decision_matched_rule_is_none_on_normal_allow():
    # Regular (non-weak-posture) ALLOWs must have matched_rule=None.
    spec = _constrained_spec()
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/notes.txt"})
    assert d.verdict == "ALLOW"
    assert d.matched_rule is None


def test_decision_matched_rule_is_not_none_on_weak_posture_allow():
    # Weak-posture ALLOWs carry a non-None stable matched_rule so they are
    # greppable in the audit log as distinct from enforcement-passed ALLOWs.
    spec = _spec(
        {"filesystem": {"tools": {}}},
        task="test [deny_all_others=false]",
        deny_all_others=False,
    )
    d = evaluate(spec, "demo", "some_tool", {})
    assert d.verdict == "ALLOW"
    assert d.matched_rule is not None
    assert "bypassed-weak-posture" in d.matched_rule


# ---------------------------------------------------------------------------
# Log-injection defense — attacker-controlled strings must not inject newlines
# ---------------------------------------------------------------------------


def test_rule6_reason_no_newline_injection_via_arg_name():
    """An attacker-crafted arg name cannot inject a newline into the reason string."""
    spec = _constrained_spec()
    evil_arg = "injected\nstatus: ok\nfake: record"
    d = evaluate(spec, "filesystem", "read_text_file", {
        "path": "/sandbox/notes.txt",
        evil_arg: "value",
    })
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-6-extra-arg"
    # The reason itself must be a single line — no raw newlines.
    assert "\n" not in d.reason
    # And it must JSON-encode to a single-line string (no newlines in the JSON repr).
    assert "\n" not in json.dumps(d.reason)


def test_rule7_reason_no_newline_injection_via_arg_value():
    """An attacker-crafted arg value cannot inject a newline into the reason string."""
    spec = _constrained_spec()
    evil_value = "/sandbox/notes.txt\nstatus: ok\nfake: record"
    d = evaluate(spec, "filesystem", "read_text_file", {"path": evil_value})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-value-not-allowed"
    assert "\n" not in d.reason
    assert "\n" not in json.dumps(d.reason)


def test_rule5_reason_safe_for_attacker_controlled_arg_name():
    """A spec arg name with a newline in the YAML (unlikely but defensive) doesn't escape."""
    # Build a spec whose arg name contains a newline — only possible via
    # model_validate, not real YAML, but verifies the reason is still clean.
    spec = _spec({
        "filesystem": {
            "tools": {
                "read_text_file": {
                    "args": {
                        "path\nextra": {"must_match_one_of": ["/sandbox/notes.txt"]},
                    }
                }
            }
        }
    })
    d = evaluate(spec, "filesystem", "read_text_file", {})  # missing the arg
    assert d.verdict == "DENY"
    assert "\n" not in d.reason


def test_repr_defense_against_unicode_line_separators():
    """U+2028, U+2029, and \\r in attacker-controlled arg names and values are escaped.

    These characters can act as line terminators in certain contexts (JS engines,
    some log parsers). repr() escapes them to \\u2028, \\u2029, and \\r so they
    cannot split a reason string across lines.
    """
    spec = _constrained_spec()
    unicode_line_separators = [
        (" ", "U+2028 LINE SEPARATOR"),
        (" ", "U+2029 PARAGRAPH SEPARATOR"),
        ("\r", "carriage return"),
    ]

    for evil_char, description in unicode_line_separators:
        # Rule 6: evil char in arg name
        evil_arg = f"injected{evil_char}fake"
        d = evaluate(spec, "filesystem", "read_text_file", {
            "path": "/sandbox/notes.txt",
            evil_arg: "value",
        })
        assert d.verdict == "DENY", description
        assert d.matched_rule == "rule-6-extra-arg", description
        assert evil_char not in d.reason, (
            f"{description} must not appear raw in reason (Rule 6), got: {d.reason!r}"
        )

        # Rule 7: evil char in arg value
        evil_value = f"/sandbox/notes.txt{evil_char}fake"
        d = evaluate(spec, "filesystem", "read_text_file", {"path": evil_value})
        assert d.verdict == "DENY", description
        assert d.matched_rule == "rule-7-value-not-allowed", description
        assert evil_char not in d.reason, (
            f"{description} must not appear raw in reason (Rule 7), got: {d.reason!r}"
        )


# ---------------------------------------------------------------------------
# Intercepts (Week 5 Stream 4) — INTERCEPT verdict and its precedence rules
# ---------------------------------------------------------------------------


def test_evaluate_returns_intercept_when_matching_rule():
    """A call that would ALLOW under rules 1-8, but matches an intercept rule,
    is downgraded to INTERCEPT — not ALLOW, not DENY."""
    spec = _spec(
        {
            "filesystem": {
                "tools": {
                    "write_file": {
                        "args": {
                            "path": {"must_match_one_of": ["/sandbox/out.txt"]},
                            "content": None,
                        }
                    }
                }
            }
        },
        intercepts=[{"server": "filesystem", "tool": "write_file"}],
    )
    d = evaluate(spec, "filesystem", "write_file", {"path": "/sandbox/out.txt", "content": "x"})
    assert d.verdict == "INTERCEPT"
    assert d.matched_rule == "rule-9-intercept-required"
    assert "filesystem" in d.reason and "write_file" in d.reason


def test_intercept_does_not_override_deny():
    """An intercept rule on a (server, tool) pair that isn't even in servers:
    must not rescue the call into INTERCEPT — it's still DENY (rule-2)."""
    spec = _spec(
        {"filesystem": {"tools": {"read_text_file": None}}},
        intercepts=[{"server": "filesystem", "tool": "write_file"}],
    )
    d = evaluate(spec, "filesystem", "write_file", {"path": "/x", "content": "y"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-2-tool-not-listed"


def test_intercept_only_matches_exact_server_and_tool():
    """An intercept on (filesystem, write_file) must not affect an unrelated,
    otherwise-allowed call to (filesystem, read_file)."""
    spec = _spec(
        {
            "filesystem": {
                "tools": {
                    "read_text_file": {
                        "args": {"path": {"must_match_one_of": ["/sandbox/notes.txt"]}},
                    }
                }
            }
        },
        intercepts=[{"server": "filesystem", "tool": "write_file"}],
    )
    d = evaluate(spec, "filesystem", "read_text_file", {"path": "/sandbox/notes.txt"})
    _assert_allow(d)


# ---------------------------------------------------------------------------
# load_spec — valid spec
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


def test_load_spec_returns_capability_spec(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "summarize meeting-notes.txt",
        "deny_all_others": True,
        "servers": {
            "filesystem": {
                "tools": {
                    "read_text_file": {
                        "args": {"path": {"must_match_one_of": ["/s/notes.txt"]}}
                    }
                }
            }
        },
    })
    spec = load_spec(f)
    assert isinstance(spec, CapabilitySpec)
    assert spec.task == "summarize meeting-notes.txt"
    assert spec.deny_all_others is True


def test_load_spec_emits_spec_loaded_audit_record(tmp_path, temp_log):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "test audit record",
        "servers": {"filesystem": {"tools": {"read_text_file": None}}},
    })
    spec = load_spec(f)

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    r = records[0]
    assert r["status"] == "spec_loaded"
    assert r["task"] == "test audit record"
    assert r["deny_all_others"] is True
    assert r["spec_hash"] == spec.spec_hash


def test_load_spec_stamps_run_id_when_supplied(tmp_path, temp_log):
    """A run_id passed to load_spec rides the spec_loaded record, so the
    control plane can link the record that opened a run to that run's calls."""
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "test run_id present",
        "servers": {"filesystem": {"tools": {"read_text_file": None}}},
    })
    load_spec(f, run_id="run-abc-123")

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "spec_loaded"
    assert records[0]["run_id"] == "run-abc-123"


def test_load_spec_omits_run_id_when_not_supplied(tmp_path, temp_log):
    """Without a run_id the record is exactly as it was before the feature —
    no run_id key at all. Backward compatible for callers that pass only a path."""
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "test run_id absent",
        "servers": {"filesystem": {"tools": {"read_text_file": None}}},
    })
    load_spec(f)  # no run_id

    records = [json.loads(line) for line in temp_log.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["status"] == "spec_loaded"
    assert "run_id" not in records[0]


def test_load_spec_hash_matches_sha256_of_raw_bytes(tmp_path):
    f = tmp_path / "spec.yaml"
    raw = b"task: hash test\nservers:\n  filesystem:\n    tools:\n      read_text_file:\n"
    f.write_bytes(raw)
    spec = load_spec(f)
    expected = hashlib.sha256(raw).hexdigest()
    assert spec.spec_hash == expected


def test_load_spec_hash_is_stable_across_two_loads(tmp_path):
    """Loading the same file twice must produce the same hash."""
    f = tmp_path / "spec.yaml"
    raw = b"task: stable hash\nservers:\n  filesystem:\n    tools:\n      read_text_file:\n"
    f.write_bytes(raw)
    spec1 = load_spec(f)
    spec2 = load_spec(f)
    assert spec1.spec_hash == spec2.spec_hash
    assert spec1.spec_hash != ""


def test_load_spec_hash_changes_on_one_byte_change(tmp_path):
    """A one-byte change to the YAML must produce a different hash."""
    f = tmp_path / "spec.yaml"
    raw1 = b"task: original\nservers:\n  filesystem:\n    tools:\n      read_text_file:\n"
    f.write_bytes(raw1)
    spec1 = load_spec(f)

    raw2 = raw1.replace(b"original", b"modified")
    assert raw1 != raw2
    f.write_bytes(raw2)
    spec2 = load_spec(f)

    assert spec1.spec_hash != spec2.spec_hash


def test_load_spec_deny_all_others_defaults_to_true(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "no deny_all_others key",
        "servers": {"filesystem": {"tools": {"read_text_file": None}}},
    })
    spec = load_spec(f)
    assert spec.deny_all_others is True


def test_load_spec_parses_intercepts_field(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "write and delete under supervision",
        "servers": {
            "filesystem": {
                "tools": {
                    "write_file": {"args": {"path": None, "content": None}},
                    "delete_file": {"args": {"path": None}},
                }
            }
        },
        "intercepts": [
            {"server": "filesystem", "tool": "write_file"},
            {"server": "filesystem", "tool": "delete_file"},
        ],
    })
    spec = load_spec(f)
    assert len(spec.intercepts) == 2
    assert {(r.server, r.tool) for r in spec.intercepts} == {
        ("filesystem", "write_file"),
        ("filesystem", "delete_file"),
    }


def test_load_spec_intercepts_empty_by_default(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "no intercepts key",
        "servers": {"filesystem": {"tools": {"read_text_file": None}}},
    })
    spec = load_spec(f)
    assert spec.intercepts == []


# ---------------------------------------------------------------------------
# load_spec — validation errors (must raise at load time, not at evaluate time)
# ---------------------------------------------------------------------------


def test_load_spec_raises_on_yaml_parse_error(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("task: [unclosed bracket\n", encoding="utf-8")
    with pytest.raises(SpecValidationError, match="parse error"):
        load_spec(f)


def test_load_spec_raises_on_missing_task(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {"servers": {"filesystem": {"tools": {"read_text_file": None}}}})
    with pytest.raises(SpecValidationError):
        load_spec(f)


def test_load_spec_raises_on_missing_servers(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {"task": "missing servers"})
    with pytest.raises(SpecValidationError):
        load_spec(f)


def test_load_spec_raises_on_empty_must_match_one_of(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "empty allow-list",
        "servers": {
            "filesystem": {
                "tools": {
                    "read_text_file": {
                        "args": {"path": {"must_match_one_of": []}}
                    }
                }
            }
        },
    })
    with pytest.raises(SpecValidationError):
        load_spec(f)


def test_load_spec_raises_on_deny_all_others_false_without_acknowledgment(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "some task without the acknowledgment substring",
        "deny_all_others": False,
        "servers": {"filesystem": {"tools": {"read_text_file": None}}},
    })
    with pytest.raises(SpecValidationError, match="deny_all_others=false"):
        load_spec(f)


def test_load_spec_allow_deny_all_others_false_with_acknowledgment(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "open fetch task [deny_all_others=false]",
        "deny_all_others": False,
        "servers": {"fetch": {"tools": {"fetch": {"args": {"url": None}}}}},
    })
    spec = load_spec(f)
    assert spec.deny_all_others is False


def test_load_spec_acknowledgment_is_case_insensitive(tmp_path):
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {
        "task": "open task [DENY_ALL_OTHERS=FALSE]",
        "deny_all_others": False,
        "servers": {"fetch": {"tools": {"fetch": None}}},
    })
    spec = load_spec(f)
    assert spec.deny_all_others is False


def test_load_spec_raises_on_nonexistent_file(tmp_path):
    with pytest.raises(SpecValidationError, match="cannot read"):
        load_spec(tmp_path / "does_not_exist.yaml")


def test_load_spec_raises_when_yaml_is_not_a_mapping(tmp_path):
    f = tmp_path / "spec.yaml"
    f.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(SpecValidationError):
        load_spec(f)


# ---------------------------------------------------------------------------
# load_spec — no audit record is written when validation fails
# ---------------------------------------------------------------------------


def test_load_spec_no_audit_record_on_failure(tmp_path, temp_log):
    """Pydantic validation failure must not write an audit record."""
    f = tmp_path / "spec.yaml"
    _write_yaml(f, {"task": "bad"})  # missing 'servers'
    with pytest.raises(SpecValidationError):
        load_spec(f)
    assert not temp_log.exists() or temp_log.read_text().strip() == ""


def test_load_spec_no_audit_record_on_yaml_parse_error(tmp_path, temp_log):
    """YAML parse failure must not write an audit record (earlier failure path)."""
    f = tmp_path / "bad.yaml"
    f.write_text("task: [unclosed bracket\n", encoding="utf-8")
    with pytest.raises(SpecValidationError, match="parse error"):
        load_spec(f)
    assert not temp_log.exists() or temp_log.read_text().strip() == ""


# ---------------------------------------------------------------------------
# Rule 7 — ARGUMENT VALUE TYPES.
#
# Rule 7 used to compare str(value) against the literal allow-list. Sound for
# a scalar; for anything else it compared a Python repr, which meant:
#
#   * an UNCONSTRAINED non-scalar was permitted outright — a spec entry of
#     `paths: null` on read_multiple_files allowed
#     ["C:/Windows/System32/config/SAM"];
#   * a collection could not be constrained in any usable way (listing the
#     elements denied every call; listing str(the list) worked but was
#     order-dependent);
#   * types collapsed — the literal STRING "['/s/a.txt']" satisfied a
#     constraint written for the LIST ['/s/a.txt'].
#
# docs/CAPABILITY_SPEC.md claims literal matching makes the bypass surface
# zero. These tests are what make that claim true rather than aspirational.
#
# The table below is the specification, and DENY is its default: a value
# shape added to it without matching handling in evaluate() fails. That is
# the point — it catches the class, not the one reported instance.
# ---------------------------------------------------------------------------


def _arg_spec(entry) -> CapabilitySpec:
    """filesystem/read with a single arg 'a' whose spec entry is `entry`."""
    return _spec({"filesystem": {"tools": {"read": {"args": {"a": entry}}}}})


def _d(entry, value) -> Decision:
    return evaluate(_arg_spec(entry), "filesystem", "read", {"a": value})


class _Exotic:
    """A type nobody enumerated, whose __str__ mimics an allowed value."""

    def __str__(self) -> str:
        return "/sandbox/a.txt"


# Every shape that is not a scalar.
_NON_SCALAR = [
    pytest.param(["/sandbox/a.txt"], id="list-one"),
    pytest.param(["/sandbox/a.txt", "/sandbox/b.txt"], id="list-many"),
    pytest.param([], id="list-empty"),
    pytest.param(("/sandbox/a.txt",), id="tuple"),
    pytest.param({"/sandbox/a.txt"}, id="set"),
    pytest.param(frozenset({"/sandbox/a.txt"}), id="frozenset"),
    pytest.param({"path": "/sandbox/a.txt"}, id="dict"),
    pytest.param({}, id="dict-empty"),
    pytest.param([["/sandbox/a.txt"]], id="nested-list"),
    pytest.param([{"path": "/sandbox/a.txt"}], id="list-of-dict"),
    pytest.param(b"/sandbox/a.txt", id="bytes"),
    pytest.param(bytearray(b"/sandbox/a.txt"), id="bytearray"),
    pytest.param(_Exotic(), id="exotic-object"),
]

_ALLOWED_ELEMENTS = {"must_match_one_of": ["/sandbox/a.txt", "/sandbox/b.txt"]}


# --- the class: an unconstrained arg must never admit a non-scalar ----------


@pytest.mark.parametrize("value", _NON_SCALAR)
def test_unconstrained_arg_never_allows_a_non_scalar(value):
    """THE CLASS TEST. `a: null` means "any value" only for scalars. For
    anything else the operator could not have expressed a constraint, so
    permitting it is a silent bypass; fail closed instead."""
    d = _d(None, value)
    assert d.verdict == "DENY", f"{type(value).__name__} was ALLOWed unconstrained"
    assert d.matched_rule is not None


@pytest.mark.parametrize("value", _NON_SCALAR)
def test_empty_constraint_block_never_allows_a_non_scalar(value):
    """`a: {}` is the other way to say "no constraint named" and must behave
    identically — otherwise the bypass just moves one key over."""
    d = _d({}, value)
    assert d.verdict == "DENY", f"{type(value).__name__} was ALLOWed with an empty ArgSpec"


@pytest.mark.parametrize("value", _NON_SCALAR)
def test_a_constraint_is_never_satisfied_by_the_repr_of_a_non_scalar(value):
    """Kills the str() collapse: a constraint listing the value's own repr
    must not admit it. This is what let a string impersonate a list."""
    d = _d({"must_match_one_of": [str(value)]}, value)
    assert d.verdict != "ALLOW", (
        f"{type(value).__name__} matched a constraint containing its own repr"
    )


def test_a_string_cannot_impersonate_a_list():
    """The type-confusion case stated directly. A constraint written for the
    list ['/sandbox/a.txt'] must not be satisfied by the string that happens
    to render identically."""
    entry = {"must_match_one_of": ["/sandbox/a.txt"]}
    assert _d(entry, ["/sandbox/a.txt"]).verdict == "ALLOW"    # the list: intended
    assert _d(entry, "['/sandbox/a.txt']").verdict == "DENY"   # the string: not


# --- the reported instance -------------------------------------------------


def test_unconstrained_list_arg_does_not_permit_an_arbitrary_path():
    """The reported bypass, verbatim: an operator whose agent batches into
    read_multiple_files adds the tool, cannot constrain the list, leaves it
    unconstrained, and has silently removed path scoping for that tool."""
    spec = _spec({
        "filesystem": {"tools": {"read_multiple_files": {"args": {"paths": None}}}}
    })
    d = evaluate(spec, "filesystem", "read_multiple_files",
                 {"paths": ["C:/Windows/System32/config/SAM"]})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-unconstrained-collection"


# --- B: collections become constrainable ------------------------------------


def test_collection_allowed_when_every_element_is_listed():
    _assert_allow(_d(_ALLOWED_ELEMENTS, ["/sandbox/a.txt"]))
    _assert_allow(_d(_ALLOWED_ELEMENTS, ["/sandbox/a.txt", "/sandbox/b.txt"]))
    _assert_allow(_d(_ALLOWED_ELEMENTS, ("/sandbox/b.txt",)))


def test_collection_denied_when_any_element_is_unlisted():
    d = _d(_ALLOWED_ELEMENTS, ["/sandbox/a.txt", "/etc/shadow"])
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-value-not-allowed"
    assert "/etc/shadow" in d.reason, "the reason must name the offending element"


def test_collection_matching_is_order_independent():
    """Element-wise membership, not repr comparison — so the same set of
    files passes in any order. The old str(list) behaviour did not."""
    _assert_allow(_d(_ALLOWED_ELEMENTS, ["/sandbox/a.txt", "/sandbox/b.txt"]))
    _assert_allow(_d(_ALLOWED_ELEMENTS, ["/sandbox/b.txt", "/sandbox/a.txt"]))


def test_empty_collection_is_denied_explicitly():
    """[] satisfies "every element is listed" vacuously. Some tools read an
    empty list as "all", so deny rather than reason about whether the no-op
    is harmless."""
    d = _d(_ALLOWED_ELEMENTS, [])
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-empty-collection"


def test_nested_collection_is_denied_even_when_constrained():
    d = _d(_ALLOWED_ELEMENTS, [["/sandbox/a.txt"]])
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-unsupported-arg-type"


def test_mapping_is_denied_even_when_constrained():
    d = _d(_ALLOWED_ELEMENTS, {"path": "/sandbox/a.txt"})
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-unsupported-arg-type"


def test_exotic_type_whose_str_matches_is_still_denied():
    """Exhaustiveness probe: _Exotic.__str__ returns an allowed value. A type
    the classifier does not know must not be admitted on the strength of its
    __str__."""
    d = _d(_ALLOWED_ELEMENTS, _Exotic())
    assert d.verdict == "DENY"
    assert d.matched_rule == "rule-7-unsupported-arg-type"


# --- A: scalars are untouched ----------------------------------------------


def test_scalar_behaviour_is_unchanged():
    """Part A of the fix is "change nothing for scalars"; pin that."""
    _assert_allow(_d(_ALLOWED_ELEMENTS, "/sandbox/a.txt"))
    assert _d(_ALLOWED_ELEMENTS, "/sandbox/evil.txt").matched_rule == "rule-7-value-not-allowed"
    _assert_allow(_d(None, "anything at all"))      # unconstrained scalar: still ALLOW
    _assert_allow(_d(None, ""))
    _assert_allow(_d(None, 0))
    _assert_allow(_d(None, False))
    _assert_allow(_d(None, None))


# --- D: the explicit, greppable escape hatch --------------------------------


@pytest.mark.parametrize("value", _NON_SCALAR)
def test_allow_any_permits_any_shape_but_names_itself(value):
    """allow_any keeps list-taking tools usable after C. The difference from
    the bug is that it is explicit in the spec and greppable in the audit
    log, following the rule-N-bypassed-* idiom already used for weak
    posture."""
    d = _d({"allow_any": True}, value)
    assert d.verdict == "ALLOW"
    assert d.matched_rule == "rule-7-bypassed-allow-any", (
        "an allow_any bypass must not masquerade as an enforcement-passed ALLOW"
    )


def test_allow_any_is_not_the_default():
    """Defaulting to allow_any would preserve the vulnerability silently,
    which is the entire bug."""
    from aegis.policy import ArgSpec

    assert ArgSpec().allow_any is False
    assert ArgSpec(must_match_one_of=["/sandbox/a.txt"]).allow_any is False


def test_allow_any_does_not_excuse_a_missing_or_extra_arg():
    """allow_any relaxes the VALUE check only. Rule 5 still requires the arg
    to be present, and rule 6 still rejects unlisted args."""
    spec = _arg_spec({"allow_any": True})
    assert evaluate(spec, "filesystem", "read", {}).matched_rule == "rule-5-missing-required-arg"
    assert evaluate(
        spec, "filesystem", "read", {"a": ["x"], "b": "y"}
    ).matched_rule == "rule-6-extra-arg"


def test_allow_any_with_must_match_one_of_is_rejected():
    """The two are contradictory: one says "any value", the other names the
    permitted values. Silently preferring either would make a spec lie about
    what it permits."""
    with pytest.raises(Exception):
        _arg_spec({"allow_any": True, "must_match_one_of": ["/sandbox/a.txt"]})


# --- reason-string safety, same contract as rules 5/6/7 ---------------------


def test_collection_denial_reason_repr_escapes_attacker_controlled_elements():
    """Elements come from the tool call and are attacker-controlled, so they
    are repr()'d before reaching the reason string or the JSON audit record —
    the same defence rules 6 and 7 already apply to scalar values."""
    d = _d(_ALLOWED_ELEMENTS, ["/sandbox/a.txt", "evil\nstatus: ok"])
    assert d.verdict == "DENY"
    assert "\n" not in d.reason
    assert "\\n" in d.reason
