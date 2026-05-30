"""
aegis/proposer.py — LLM-based capability spec proposer.

propose_spec() runs once, before agent execution, on trusted user input.
THE PROPOSER IS NOT IN THE ENFORCEMENT PATH.

Trust boundary (enforced structurally, not just by prompt):
  - user_request flows ONLY into the user-role message content.
  - sandbox_root flows ONLY into the system-role message (with the prompt).
  - Nothing from user_request is allowed to reach the system message or the
    tool schemas. This is verifiable: see how system and messages are built.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import anthropic
import yaml
from dotenv import load_dotenv
from pydantic import ValidationError

from aegis.audit import write_record
from aegis.policy import CapabilitySpec, SpecValidationError
from aegis.proposer_prompts import PROPOSER_PROMPT_HASH, SYSTEM_PROMPT

# Idempotent: no-op if ANTHROPIC_API_KEY is already in the environment.
# Makes the module self-contained so callers don't need to pre-load dotenv.
load_dotenv()

# Bare Anthropic API model string (no "anthropic:" prefix — that form is
# Pydantic AI-specific, as seen in test_enforcement.py's HAIKU constant).
# Source: Claude Code system context, which lists Sonnet 4.6 model ID as
# "claude-sonnet-4-6" (no dated suffix, unlike Haiku's "claude-haiku-4-5-20251001").
_MODEL = "claude-sonnet-4-6"

# Tool schemas presented to the model. These are constants — nothing from
# user_request or sandbox_root flows into them.
_TOOLS: list[anthropic.types.ToolParam] = [
    {
        "name": "emit_capability_spec",
        "description": (
            "Emit a valid Aegis capability spec YAML granting exactly the permissions "
            "required for the user's task and nothing more."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "spec_yaml": {
                    "type": "string",
                    "description": "The complete capability spec as a YAML string.",
                },
            },
            "required": ["spec_yaml"],
        },
    },
    {
        "name": "request_clarification",
        "description": (
            "Request clarification from the operator when the user request is "
            "ambiguous or cannot safely be mapped to a minimum-capability spec."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": (
                        "One specific question that, when answered, lets you write "
                        "a correct minimum-capability spec."
                    ),
                },
            },
            "required": ["question"],
        },
    },
]


def propose_spec(user_request: str, sandbox_root: Path) -> CapabilitySpec:
    """Propose a minimum capability spec from a natural-language user request.

    Calls Anthropic once with tool_choice="any" to force a structured response.
    Validates the returned YAML through the same Pydantic machinery as load_spec.
    Returns a frozen CapabilitySpec on success.

    Raises:
        SpecValidationError: if the model requests clarification, returns no
            tool call, emits invalid YAML, or the YAML fails schema validation.

    Trust boundary: user_request is passed only as the user-role message.
    sandbox_root is embedded only in the system-role context alongside the
    system prompt. Neither flows into tool schemas or across roles.
    """
    # ── System message: operator-controlled content only ─────────────────────
    # sandbox_root is trusted (operator-supplied). It is prepended to the system
    # prompt so the model sees it as part of the fixed context, not the user turn.
    # user_request is NOT present here.
    system = f"sandbox_root: {sandbox_root}\n\n{SYSTEM_PROMPT}"

    # ── User message: untrusted content only ──────────────────────────────────
    # user_request goes here and nowhere else. The system message is already
    # closed before this value is referenced.
    messages: list[anthropic.types.MessageParam] = [
        {"role": "user", "content": user_request},
    ]

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=_MODEL,
        max_tokens=2048,
        system=system,
        messages=messages,
        tools=_TOOLS,
        tool_choice={"type": "any"},  # forces a tool call; prose is not allowed
    )

    # ── Extract the tool call ─────────────────────────────────────────────────
    tool_use_block = next(
        (block for block in response.content if block.type == "tool_use"),
        None,
    )
    if tool_use_block is None:
        raise SpecValidationError("proposer returned no tool call")

    tool_name: str = tool_use_block.name
    tool_input: dict = tool_use_block.input  # type: ignore[assignment]

    # ── request_clarification ─────────────────────────────────────────────────
    if tool_name == "request_clarification":
        question: str = tool_input.get("question", "(no question provided)")
        write_record({
            "status": "spec_clarification_requested",
            "question": question,
            # user_request is repr()'d to prevent newline injection into the
            # audit record, then truncated to keep the log readable.
            "user_request": repr(user_request[:1000]),
            "proposer_prompt_hash": PROPOSER_PROMPT_HASH,
        })
        raise SpecValidationError(f"proposer requested clarification: {question}")

    # ── unknown tool (defensive; should not happen with tool_choice="any") ────
    if tool_name != "emit_capability_spec":
        raise SpecValidationError(
            f"proposer called unexpected tool: {tool_name!r}"
        )

    # ── emit_capability_spec: validate through the same machinery as load_spec ─
    spec_yaml: str = tool_input.get("spec_yaml", "")
    raw_bytes = spec_yaml.encode()
    spec_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        data = yaml.safe_load(spec_yaml)
    except yaml.YAMLError as exc:
        write_record({
            "status": "proposer_validation_failed",
            "error": f"YAML parse error: {exc}",
            "proposer_prompt_hash": PROPOSER_PROMPT_HASH,
        })
        raise SpecValidationError(
            f"proposer emitted invalid YAML: {exc}"
        ) from exc

    if not isinstance(data, dict):
        err = f"YAML root must be a mapping, got {type(data).__name__!r}"
        write_record({
            "status": "proposer_validation_failed",
            "error": err,
            "proposer_prompt_hash": PROPOSER_PROMPT_HASH,
        })
        raise SpecValidationError(f"proposer emitted invalid spec: {err}")

    try:
        spec = CapabilitySpec.model_validate({**data, "spec_hash": spec_hash})
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        write_record({
            "status": "proposer_validation_failed",
            "error": errors,
            "proposer_prompt_hash": PROPOSER_PROMPT_HASH,
        })
        raise SpecValidationError(
            f"proposer emitted invalid spec: {errors}"
        ) from exc

    # ── Audit — mirrors load_spec's spec_loaded record + proposer provenance ──
    write_record({
        "status": "spec_loaded",
        "task": spec.task,
        "deny_all_others": spec.deny_all_others,
        "spec_hash": spec.spec_hash,
        "proposer_prompt_hash": PROPOSER_PROMPT_HASH,
        "proposed": True,
    })

    return spec
