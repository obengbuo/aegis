"""
tests/test_import_graph.py — pins the lazy import seams at module load.

Three dependencies are reached only through function-local imports:

  * aegis.shipper — imported inside aegis.audit.write_record and inside
    AegisConfig.__post_init__, never at module level.
  * opentelemetry — imported inside aegis.audit._get_or_create_tracer.
  * anthropic — imported inside aegis.proposer._anthropic(), on the first
    propose_spec() call or the first access to aegis.proposer.anthropic.
    anthropic 2.x imports opentelemetry as a side effect of being imported,
    so a module-level `import anthropic` silently breaks the opentelemetry
    seam above as well.

Those function-local imports are what keep config.py's "no runtime imports
from other aegis.* modules" property true, keep `import aegis` cheap for
callers who configure neither a control plane nor OTLP, and keep the
config -> shipper -> audit edges acyclic. All three hold today and would keep
holding if someone promoted one of those imports to module level — right up
until the day it wouldn't. This file is the tripwire.

Checks that care about load order run in a FRESH interpreter: by the time
pytest imports this module the whole package is already resident, so
asserting on this process's sys.modules would prove nothing.

NOTE on what is deliberately NOT asserted: httpx is a transitive dependency
of anthropic/pydantic-ai and is already resident, so "httpx not imported" is
not a claim this repo can make. The faithful statement of the lazy HTTP seam
is that the client BUILDER is never invoked — tested in
test_shipper.py::test_unconfigured_builds_no_client_no_queue_no_thread.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import types
from pathlib import Path

import pytest

from aegis import audit, proposer
from aegis.policy import SpecValidationError

_AEGIS = Path(__file__).resolve().parent.parent / "aegis"

# Modules whose module-level scope must stay free of aegis.* imports.
# config.py: so it can be imported first by aegis/__init__.py with no cycle
#            risk, and so AegisConfig.__post_init__'s function-local
#            `from aegis import shipper` (Part A) cannot become a load-time
#            edge config -> shipper -> audit.
# shipper.py: so the far end of that edge cannot import back.
_NO_AEGIS_AT_MODULE_LEVEL = ["config.py", "shipper.py"]


def _run(code: str) -> str:
    """Execute code in a fresh interpreter; return stdout. Fails loudly."""
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, (
        f"subprocess exited {proc.returncode}\n--- stdout ---\n{proc.stdout}"
        f"\n--- stderr ---\n{proc.stderr}"
    )
    return proc.stdout.strip()


def _module_level_aegis_imports(path: Path) -> list[str]:
    """Names of aegis.* modules imported at this file's MODULE level.

    Walks only top-level statements, so function-local imports (the lazy
    seams) are correctly invisible. `if TYPE_CHECKING:` blocks are descended
    into but their imports are excluded: they are never executed at runtime,
    which is exactly how shipper.py may reference AegisConfig for typing
    without creating a real edge.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []

    for node in tree.body:
        if isinstance(node, ast.If):  # TYPE_CHECKING guard — not runtime
            continue
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.startswith("aegis")]
        elif isinstance(node, ast.ImportFrom):
            # `from aegis import shipper` -> module "aegis", names the submodule
            if (node.module or "").startswith("aegis"):
                found += [f"{node.module}.{a.name}" for a in node.names]

    return found


@pytest.mark.parametrize("filename", _NO_AEGIS_AT_MODULE_LEVEL)
def test_no_module_level_aegis_imports(filename):
    """THE TRIPWIRE. The precise failure this guards: someone promotes
    `from aegis import shipper` out of AegisConfig.__post_init__ to the top of
    config.py. It works — until an import order exists where it doesn't."""
    offenders = _module_level_aegis_imports(_AEGIS / filename)
    assert offenders == [], (
        f"aegis/{filename} imports {offenders} at module level. Move it inside "
        f"the function that needs it (see AegisConfig.__post_init__ and "
        f"aegis.audit.write_record) or put it under TYPE_CHECKING."
    )


@pytest.mark.parametrize("filename", _NO_AEGIS_AT_MODULE_LEVEL)
def test_module_executes_with_no_aegis_package_present(filename):
    """Runtime complement to the AST check: load the file as an isolated
    module, by path, in a process where the aegis package is never imported.
    Anything it needed from a peer at import time would raise here."""
    out = _run(
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('_isolated', r'{_AEGIS / filename}')\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['_isolated'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        "print(','.join(sorted(m for m in sys.modules if m.startswith('aegis'))) or 'none')\n"
    )
    assert out == "none", f"aegis/{filename} loaded aegis modules at import time: {out}"


def test_import_aegis_does_not_pull_in_shipper_or_opentelemetry():
    """`import aegis` must not drag in the lazily-imported modules."""
    out = _run(
        "import aegis, sys; "
        "print(','.join(sorted(m for m in ('aegis.shipper', 'opentelemetry') "
        "if m in sys.modules)) or 'none')"
    )
    assert out == "none", f"`import aegis` eagerly imported: {out}"


def test_import_aegis_does_not_import_anthropic():
    """`import aegis` must not import the Anthropic SDK.

    The proposer is the only consumer of anthropic and is not in the
    enforcement path, so a caller who never proposes a spec must not pay for
    the SDK — nor for what the SDK drags in. anthropic 2.x imports
    opentelemetry when it is imported, so a module-level `import anthropic`
    in aegis/proposer.py is exactly what broke the opentelemetry seam above
    on a fresh install (aegis pins only anthropic>=0.40.0).

    Asserted directly on anthropic rather than only via opentelemetry, so the
    seam stays pinned whatever a future anthropic release does or doesn't
    import. Any anthropic.* submodule implies the top-level package, so
    checking that one name is sufficient.
    """
    out = _run(
        "import aegis, sys; "
        "print('anthropic' if 'anthropic' in sys.modules else 'none')"
    )
    assert out == "none", f"`import aegis` eagerly imported: {out}"


def test_proposer_anthropic_attribute_resolves_lazily_to_the_real_module():
    """aegis.proposer.anthropic stays a working attribute: absent from
    sys.modules after import, then the real SDK module on first access.

    Existing offline tests rely on it (monkeypatch.setattr(proposer.anthropic,
    "Anthropic", ...) in test_public_api.py and test_shipper.py), so making the
    import lazy must not make the attribute disappear.
    """
    out = _run(
        "import sys\n"
        "import aegis.proposer as p\n"
        "assert 'anthropic' not in sys.modules, 'anthropic imported at load time'\n"
        "mod = p.anthropic\n"
        "assert mod is sys.modules['anthropic'], 'attribute is not the real SDK module'\n"
        "assert p.anthropic is mod, 'second access returned a different object'\n"
        "print('lazy')\n"
    )
    assert out.endswith("lazy")


def test_propose_spec_uses_a_patched_module_level_anthropic(tmp_path, monkeypatch):
    """Replacing aegis.proposer.anthropic wholesale is honoured at call time.

    Guards against the naive fix — a bare `import anthropic` inside
    propose_spec — which would bind a local name and silently bypass any
    test double installed on the module. Offline: no SDK client is built.
    """
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit.jsonl")

    calls: list[dict] = []

    class _Block:
        type = "tool_use"
        name = "request_clarification"
        input = {"question": "which file?"}

    class _Messages:
        def create(self, **kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(content=[_Block()])

    class _Client:
        messages = _Messages()

    fake_sdk = types.SimpleNamespace(Anthropic=lambda *a, **k: _Client())
    monkeypatch.setattr(proposer, "anthropic", fake_sdk)

    with pytest.raises(SpecValidationError, match="proposer requested clarification"):
        proposer.propose_spec("read the file", tmp_path)

    assert len(calls) == 1, "propose_spec did not go through the patched module"


def test_config_construction_resolves_the_lazy_shipper_import():
    """The Part A edge, exercised cold: constructing an AegisConfig that
    declares a control plane must resolve its function-local `from aegis import
    shipper` and activate shipping — in a process where nothing has imported
    aegis.shipper yet. A cycle or a partially-initialised package would surface
    here and nowhere else.
    """
    out = _run(
        "from pathlib import Path\n"
        "from aegis import AegisConfig\n"
        "import sys\n"
        "assert 'aegis.shipper' not in sys.modules, 'shipper imported too early'\n"
        "AegisConfig(sandbox_root=Path('.'), control_plane_url='http://cp.invalid')\n"
        "from aegis import shipper\n"
        "assert shipper._active_shipper is not None, 'construction did not activate shipping'\n"
        "shipper.shutdown(timeout=1.0)\n"
        "print('activated')\n"
    )
    assert out.endswith("activated")
