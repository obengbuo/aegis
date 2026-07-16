"""
aegis/policy.py — deterministic capability enforcer.

THE ENFORCEMENT PATH CONTAINS NO LLM. See docs/MCP_NOTES.md §
"Enforcement architecture — deterministic capability scoping."

evaluate() is the hot path: pure, synchronous, no I/O, no await, no LLM import.
load_spec() runs once at run start, validates the spec, and emits one audit record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegis.audit import write_record


class SpecValidationError(Exception):
    """Raised when a capability spec fails validation at load time.

    Never reaches evaluate() — the type system ensures only valid specs arrive.
    """


# ---------------------------------------------------------------------------
# Spec schema (Pydantic models, frozen after validation)
# ---------------------------------------------------------------------------


class ArgSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    must_match_one_of: list[str] | None = None

    @field_validator("must_match_one_of")
    @classmethod
    def non_empty_allow_list(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and len(v) == 0:
            raise ValueError("must_match_one_of cannot be an empty list")
        return v


class ToolSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    # None → zero-arg tool. Calls with any args are denied via Rule 3
    #         (matched_rule="rule-3-zero-arg-violation"). Prefer this for tools
    #         that genuinely take no arguments.
    #
    # {}   → empty constraint set. Calls with any args are denied via Rule 6
    #         (matched_rule="rule-6-extra-arg"). Both None and {} deny the same
    #         calls, but the audit log distinguishes spec author intent:
    #         None = "this tool is zero-arg by design";
    #         {} = "this tool is allowed but I named no arg constraints."
    #
    # {...} → exhaustive arg list; any arg not listed in the call is DENIED.
    args: dict[str, ArgSpec | None] | None = None


class ServerSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    # A tool mapped to None means: listed, zero-arg
    tools: dict[str, ToolSpec | None]


class InterceptRule(BaseModel):
    """One (server, tool) pair that requires operator approval before it can
    proceed, even when the capability rules (1-8) would otherwise ALLOW it.

    Exact match only — same literal-only philosophy as must_match_one_of.
    This is operator policy, not proposer judgment: propose_spec() never
    emits this field. See aegis/proposer_prompts.py.
    """

    model_config = ConfigDict(frozen=True)

    server: str
    tool: str


class CapabilitySpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    task: str
    deny_all_others: bool = True
    servers: dict[str, ServerSpec]
    intercepts: list[InterceptRule] = Field(default_factory=list)
    spec_hash: str = ""  # set by load_spec(); not present in YAML

    @model_validator(mode="after")
    def acknowledge_weaker_posture(self) -> "CapabilitySpec":
        if not self.deny_all_others:
            if "deny_all_others=false" not in self.task.lower():
                raise ValueError(
                    "deny_all_others is false but task field does not contain "
                    "'deny_all_others=false' (case-insensitive). Add this substring "
                    "to the task description to acknowledge the weaker posture."
                )
        return self


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    verdict: Literal["ALLOW", "DENY", "INTERCEPT"]
    reason: str
    matched_rule: str | None


class AegisApprovalRequired(Exception):
    """Raised when a call is INTERCEPTed and no approval_callback is configured.

    Carries everything an integrator needs to build their own approval flow:
    which call was intercepted, its arguments, and the Decision that
    triggered the intercept (matched_rule is always "rule-9-intercept-required"
    here, since that's the only rule that produces an INTERCEPT verdict).

    The tool call's arguments are exposed as call_args, not args: Exception
    already owns .args (the tuple passed to Exception.__init__, used by its
    default __str__/__repr__) — assigning a dict to self.args here would be
    silently overwritten by super().__init__() below, and reordering the two
    assignments would instead silently break str(exc)/repr(exc). call_args
    avoids the collision entirely.
    """

    def __init__(self, server: str, tool: str, args: dict[str, Any], decision: Decision) -> None:
        self.server = server
        self.tool = tool
        self.call_args = args
        self.decision = decision
        super().__init__(f"Aegis intercepted {server}.{tool} — operator approval required")


# ---------------------------------------------------------------------------
# evaluate — the hot path
# ---------------------------------------------------------------------------


def evaluate(
    spec: CapabilitySpec,
    server: str,
    tool: str,
    args: dict[str, Any],
) -> Decision:
    """Evaluate one tool call against a capability spec.

    Pure and synchronous. No I/O, no network, no LLM. Returns a Decision.
    The enforcement path contains no LLM; see MCP_NOTES.md for the reasoning.

    Two layers: rules 1-8 (_evaluate_capability_rules) decide ALLOW/DENY.
    Intercepts are then overlaid on top of that result — they can only
    downgrade an ALLOW to INTERCEPT, never rescue a DENY. See "Precedence
    rules" in docs/CAPABILITY_SPEC.md's Intercepts section.
    """
    decision = _evaluate_capability_rules(spec, server, tool, args)
    if decision.verdict != "ALLOW":
        return decision

    for rule in spec.intercepts:
        if rule.server == server and rule.tool == tool:
            return Decision(
                verdict="INTERCEPT",
                reason=f"call to '{server}.{tool}' requires operator approval per capability spec",
                matched_rule="rule-9-intercept-required",
            )

    return decision


def _evaluate_capability_rules(
    spec: CapabilitySpec,
    server: str,
    tool: str,
    args: dict[str, Any],
) -> Decision:
    """Rules 1-8 — the ALLOW/DENY capability engine, unchanged by Stream 4.
    evaluate() overlays intercepts on top of whatever this returns.
    """
    # Rule 1: server not in spec
    if server not in spec.servers:
        if spec.deny_all_others:
            return Decision(
                verdict="DENY",
                reason=f"server '{server}' not in capability spec",
                matched_rule="rule-1-server-not-listed",
            )
        return Decision(
            verdict="ALLOW",
            reason="all checks passed",
            matched_rule="rule-1-bypassed-weak-posture",
        )

    server_spec = spec.servers[server]

    # Rule 2: tool not in spec
    if tool not in server_spec.tools:
        if spec.deny_all_others:
            return Decision(
                verdict="DENY",
                reason=f"tool '{tool}' not in capability spec for server '{server}'",
                matched_rule="rule-2-tool-not-listed",
            )
        return Decision(
            verdict="ALLOW",
            reason="all checks passed",
            matched_rule="rule-2-bypassed-weak-posture",
        )

    tool_entry = server_spec.tools[tool]  # ToolSpec | None
    args_spec = tool_entry.args if tool_entry is not None else None

    # Rules 3 & 4: no args block (zero-arg tool)
    if args_spec is None:
        if args:
            safe_names = [repr(k) for k in sorted(args.keys())]
            return Decision(
                verdict="DENY",
                reason=f"tool '{tool}' declared zero-arg but call supplied args: {safe_names}",
                matched_rule="rule-3-zero-arg-violation",
            )
        return Decision(verdict="ALLOW", reason="all checks passed", matched_rule=None)

    # Rule 5: missing required arg (in spec, not in call)
    # arg_name comes from spec (trusted), but repr() is applied defensively
    # in case a malformed spec was constructed in-memory with a control char.
    for arg_name in args_spec:
        if arg_name not in args:
            return Decision(
                verdict="DENY",
                reason=f"required arg {arg_name!r} missing from call",
                matched_rule="rule-5-missing-required-arg",
            )

    # Rule 6: extra arg (in call, not in spec)
    # arg_name is attacker-controlled (from the tool call) — repr() to prevent
    # newline injection into the reason string and the audit log.
    for arg_name in args:
        if arg_name not in args_spec:
            return Decision(
                verdict="DENY",
                reason=f"arg {arg_name!r} not in capability spec",
                matched_rule="rule-6-extra-arg",
            )

    # Rule 7: value not in allow-list
    # Both arg_name (spec-controlled) and call_value (attacker-controlled)
    # are repr()'d so neither can inject newlines into the reason string.
    for arg_name, arg_entry in args_spec.items():
        if arg_entry is not None and arg_entry.must_match_one_of is not None:
            call_value = str(args[arg_name])
            if call_value not in arg_entry.must_match_one_of:
                return Decision(
                    verdict="DENY",
                    reason=f"arg {arg_name!r} value {call_value!r} not in capability spec",
                    matched_rule="rule-7-value-not-allowed",
                )

    # Rule 8: all checks pass
    return Decision(verdict="ALLOW", reason="all checks passed", matched_rule=None)


# ---------------------------------------------------------------------------
# load_spec — runs once at the start of a run
# ---------------------------------------------------------------------------


def load_spec(path: str | Path) -> CapabilitySpec:
    """Load and validate a capability spec from a YAML file.

    Raises SpecValidationError on any error (missing file, bad YAML, schema
    violation). Never returns an invalid spec.

    On success, writes one spec_loaded audit record so every run has an
    immutable anchor to the spec that governed it.
    """
    path = Path(path)

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SpecValidationError(f"cannot read spec file '{path}': {exc}") from exc

    spec_hash = hashlib.sha256(raw).hexdigest()

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise SpecValidationError(f"spec YAML parse error in '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise SpecValidationError(
            f"spec must be a YAML mapping, got {type(data).__name__!r} in '{path}'"
        )

    try:
        spec = CapabilitySpec.model_validate({**data, "spec_hash": spec_hash})
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        raise SpecValidationError(f"spec validation failed in '{path}': {errors}") from exc

    write_record({
        "status": "spec_loaded",
        "task": spec.task,
        "deny_all_others": spec.deny_all_others,
        "spec_hash": spec.spec_hash,
    })

    return spec
