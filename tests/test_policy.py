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
