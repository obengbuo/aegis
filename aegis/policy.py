"""
aegis/policy.py — deterministic capability enforcer.

THE ENFORCEMENT PATH CONTAINS NO LLM. See docs/MCP_NOTES.md §
"Enforcement architecture — deterministic capability scoping."

evaluate() is the hot path: pure, synchronous, no I/O, no await, no LLM import.
load_spec() runs once at run start, validates the spec, and emits one audit record.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegis.audit import write_record


# ---------------------------------------------------------------------------
# Argument value classification — what rule 7 is able to reason about.
#
# Rule 7 compares str(value) against literal strings. For a scalar that is a
# faithful, stable rendering of the value. For a container it is a PYTHON
# REPR, which is not a value any operator wrote down: it made collections
# effectively unconstrainable, made matching order-dependent, and collapsed
# types — the literal string "['/s/a.txt']" satisfied a constraint written for
# the list ['/s/a.txt'].
#
# So the value is classified first, and anything the engine cannot reason
# about is denied. This is the same reasoning as Rule 3's: see
# docs/CAPABILITY_SPEC.md on why an absent args block means zero-arg rather
# than any-arg. "Allow any value" is not a default worth inferring.
_SCALAR_TYPES = (str, int, float, bool, type(None))
_COLLECTION_TYPES = (list, tuple, set, frozenset)

# Classification outcomes. "collection" means a collection OF SCALARS — one
# level deep and no deeper, because an element that is itself a container
# would put str() back in the matching path.
_ArgKind = Literal["scalar", "collection", "unsupported"]


def _classify_arg_value(value: Any) -> _ArgKind:
    """Classify one argument value. Pure; no I/O. Fails closed by default:
    a type not named here is "unsupported", so adding a new container type to
    Python cannot silently widen what a spec permits."""
    if isinstance(value, _SCALAR_TYPES):
        return "scalar"
    if isinstance(value, _COLLECTION_TYPES):
        if all(isinstance(element, _SCALAR_TYPES) for element in value):
            return "collection"
        return "unsupported"
    return "unsupported"


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

    # Opt out of value checking for this one argument. Defaults to False, and
    # deliberately has no "safe" default that could be inferred: an argument
    # whose value is unchecked is a hole in the spec, so saying so has to be a
    # keystroke the operator typed.
    #
    # It exists because rule 7 denies an unconstrained collection (see
    # _evaluate_capability_rules), which would otherwise leave list-taking
    # tools unusable rather than merely unconstrainable. Every call permitted
    # by it carries matched_rule="rule-7-bypassed-allow-any", so the weakening
    # is greppable in the audit log instead of looking like a clean ALLOW —
    # the same treatment weak-posture bypasses get.
    allow_any: bool = False

    @field_validator("must_match_one_of")
    @classmethod
    def non_empty_allow_list(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and len(v) == 0:
            raise ValueError("must_match_one_of cannot be an empty list")
        return v

    @model_validator(mode="after")
    def allow_any_excludes_an_allow_list(self) -> "ArgSpec":
        if self.allow_any and self.must_match_one_of is not None:
            raise ValueError(
                "allow_any and must_match_one_of are mutually exclusive: one says "
                "any value is permitted, the other names the permitted values. "
                "Silently preferring either would make the spec misstate what it allows."
            )
        return self


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

    # Rule 7: argument values.
    #
    # Scalars compare literally against must_match_one_of, as they always
    # have. Collections compare ELEMENT-WISE — every element must be listed,
    # which makes a list-valued argument constrainable for the first time and
    # is order-independent, unlike the old str(value) comparison. Anything the
    # engine cannot reason about is denied. An unconstrained collection is
    # denied too: it would permit any value, and unlike a scalar the operator
    # had no way to say otherwise.
    #
    # Both arg_name (spec-controlled) and every value or element
    # (attacker-controlled) are repr()'d so neither can inject newlines into
    # the reason string or the JSON audit record.
    bypassed_allow_any = False

    for arg_name, arg_entry in args_spec.items():
        value = args[arg_name]

        # allow_any: this argument's value is deliberately unchecked. Recorded
        # below so the call is greppable rather than looking like a clean pass.
        if arg_entry is not None and arg_entry.allow_any:
            bypassed_allow_any = True
            continue

        allow_list = arg_entry.must_match_one_of if arg_entry is not None else None
        kind = _classify_arg_value(value)

        if kind == "unsupported":
            return Decision(
                verdict="DENY",
                reason=(
                    f"arg {arg_name!r} has type {type(value).__name__!r}, which a "
                    f"capability spec cannot express a literal constraint for; "
                    f"set allow_any on this arg to permit it explicitly"
                ),
                matched_rule="rule-7-unsupported-arg-type",
            )

        if kind == "collection":
            if allow_list is None:
                return Decision(
                    verdict="DENY",
                    reason=(
                        f"arg {arg_name!r} is a collection with no must_match_one_of; "
                        f"leaving it unconstrained would permit any value. List the "
                        f"permitted elements, or set allow_any to say so explicitly"
                    ),
                    matched_rule="rule-7-unconstrained-collection",
                )
            if len(value) == 0:
                return Decision(
                    verdict="DENY",
                    reason=(
                        f"arg {arg_name!r} is an empty collection; it matches nothing "
                        f"in the capability spec, and some tools read an empty "
                        f"collection as 'all'"
                    ),
                    matched_rule="rule-7-empty-collection",
                )
            for element in value:
                if str(element) not in allow_list:
                    return Decision(
                        verdict="DENY",
                        reason=(
                            f"arg {arg_name!r} element {str(element)!r} "
                            f"not in capability spec"
                        ),
                        matched_rule="rule-7-value-not-allowed",
                    )
            continue

        # scalar
        if allow_list is not None and str(value) not in allow_list:
            return Decision(
                verdict="DENY",
                reason=f"arg {arg_name!r} value {str(value)!r} not in capability spec",
                matched_rule="rule-7-value-not-allowed",
            )

    # Rule 8: all checks pass. A clean ALLOW earns matched_rule=None; an ALLOW
    # that only passed because a value check was waived says which waiver,
    # exactly as the weak-posture bypasses above do.
    if bypassed_allow_any:
        return Decision(
            verdict="ALLOW",
            reason="all checks passed",
            matched_rule="rule-7-bypassed-allow-any",
        )
    return Decision(verdict="ALLOW", reason="all checks passed", matched_rule=None)


# ---------------------------------------------------------------------------
# load_spec — runs once at the start of a run
# ---------------------------------------------------------------------------


def load_spec(path: str | Path, run_id: str | None = None) -> CapabilitySpec:
    """Load and validate a capability spec from a YAML file.

    Raises SpecValidationError on any error (missing file, bad YAML, schema
    violation). Never returns an invalid spec.

    On success, writes one spec_loaded audit record so every run has an
    immutable anchor to the spec that governed it.

    run_id, when supplied, is stamped onto that spec_loaded record so the
    control plane can link the record that OPENED a run to the tool-call
    records that followed it — pass the same AegisConfig.run_id you thread
    into wrap_toolset. It is a single correlation id, not the whole config,
    deliberately: this loader needs exactly one field, and taking a bare
    string keeps policy.py free of any dependency on config.py. Omit it
    (Phase 1 callers, or a load with no run yet) and the record is unchanged
    from before — no run_id key at all.
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
        "call_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "status": "spec_loaded",
        "task": spec.task,
        "deny_all_others": spec.deny_all_others,
        "spec_hash": spec.spec_hash,
    }, run_id=run_id)  # write_record adds run_id only when it is not None

    return spec
