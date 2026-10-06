"""Tests for extension activation wiring (Tasks 3, 5, 6, phase 2d).

Original four scenarios (Task 3):
  (a) _extension_states populated correctly after import (all-on, all-active).
  (b) _discovery_call_count == 0 after import (builtin-on paths skip discovery).
  (c) kubernetes profile pure-unit: all-off config → all states "off", zero register calls.
  (d) _discover_api_groups direct unit: fake ApisApi, cache hit, read-only spy.

Task 5 additions:
  (e) Konflux tools present in the MCP tool manager.
  (f) Real konflux EXTENSION in off mode never calls register().

Task 6 additions:
  (g) Tekton + OpenShift tool names present in the MCP tool manager (presence pin).
  (h) Kubernetes profile real extension off-mode: zero register_server_tool calls.
  (i) BUILTIN_PROFILES invariant: no extensions value equals "auto".
  (j) Subprocess real-import absence: kubernetes profile → 12 extension tool names absent.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


# ── (a) Extension states after import ─────────────────────────────────────────

def test_extension_states_after_import(server):
    """All three extensions must be 'active' for the flipped konflux profile."""
    assert server._extension_states == {
        ("konflux", "kubernetes"): "active",
        ("openshift", "kubernetes"): "active",
        ("tekton", "kubernetes"): "active",
    }


# ── (b) Discovery helper never invoked during import ──────────────────────────

def test_discovery_not_invoked_at_import(server):
    """Built-in on/off paths skip _discover_api_groups entirely."""
    assert server._discovery_call_count == 0


# ── (c) Kubernetes profile — pure unit ────────────────────────────────────────

def test_kubernetes_profile_all_off():
    """activate_extensions with all-off config → all states off, zero register calls."""
    from core.extension import activate_extensions, ToolRegistry, DetectContext
    from core.profiles import BUILTIN_PROFILES

    register_calls: list[str] = []

    class SpyExt:
        def __init__(self, name: str) -> None:
            self.name = name

        async def detect(self, ctx: DetectContext) -> bool:  # noqa: ARG002
            return True

        def register(self, reg: ToolRegistry) -> None:  # noqa: ARG002
            register_calls.append(self.name)

    cfg = BUILTIN_PROFILES["kubernetes"]

    fake_mcp = SimpleNamespace(add_tool=lambda fn: None)
    fake_server = SimpleNamespace(log_tool_execution=lambda fn: fn)
    facade = ToolRegistry(
        server_module=fake_server,
        mcp=fake_mcp,
        config=cfg,
        adapters=None,
        packs={},
    )

    async def _noop_discover(instance: str) -> frozenset:  # noqa: ARG001
        return frozenset()

    ctx = DetectContext(
        config=cfg,
        adapters=None,
        instance="kubernetes",
        discover_api_groups=_noop_discover,
    )

    spies = [SpyExt("tekton"), SpyExt("openshift"), SpyExt("konflux")]
    states = activate_extensions(cfg, spies, facade, ctx)

    assert states == {
        ("tekton", "kubernetes"): "off",
        ("openshift", "kubernetes"): "off",
        ("konflux", "kubernetes"): "off",
    }
    assert register_calls == [], "register() must not be called when mode is off"


# ── (d) _discover_api_groups direct unit ─────────────────────────────────────

def test_discover_api_groups_unit(server, monkeypatch):
    """Fake ApisApi: first call hits API; second serves from cache; wrapper is read-only."""
    from core.readonly_client import ReadOnlyK8sClient, WriteOperationError

    fake_versions = SimpleNamespace(
        groups=[SimpleNamespace(name="apps"), SimpleNamespace(name="batch")]
    )

    call_log: list[str] = []

    class FakeApisApi:
        def get_api_versions(self_inner, **kwargs):  # noqa: N805
            call_log.append("get_api_versions")
            return fake_versions

        def create_pod(self_inner, *a, **kw):  # noqa: N805
            raise AssertionError("write method must never be called through read-only client")

    fake_client = SimpleNamespace(ApisApi=FakeApisApi)

    # Isolate cache and counter for this test (monkeypatch restores on teardown).
    # Use "" (default instance) so _resolve_k8s routes via _DefaultClientView.apis_api,
    # which constructs ReadOnlyK8sClient.wrap(client.ApisApi()) with the monkeypatched
    # client — matching the per-instance routing introduced in phase 2e Task 4.
    monkeypatch.setattr(server, "_discovery_cache", {})
    monkeypatch.setattr(server, "_discovery_call_count", 0)
    monkeypatch.setattr(server, "client", fake_client)

    # First call — real API hit (uses _resolve_k8s("") → _DefaultClientView.apis_api)
    result = asyncio.run(server._discover_api_groups(""))
    assert result == frozenset({"apps", "batch"})
    assert server._discovery_call_count == 1
    assert len(call_log) == 1

    # Second call — served from cache (keyed by "" in _discovery_cache)
    result2 = asyncio.run(server._discover_api_groups(""))
    assert result2 == frozenset({"apps", "batch"})
    assert server._discovery_call_count == 1  # unchanged
    assert len(call_log) == 1  # no second API call

    # Read-only guarantee: ReadOnlyK8sClient blocks write verbs
    wrapped = ReadOnlyK8sClient.wrap(FakeApisApi())
    with pytest.raises(WriteOperationError):
        wrapped.create_pod()


# ── (e) Konflux tools registered under session server (konflux profile) ───────

def test_pipeline_tracer_registered_in_tool_manager(server):
    """pipeline_tracer must appear in the MCP tool manager after activation."""
    assert "pipeline_tracer" in server.mcp._tool_manager._tools, (
        "pipeline_tracer not registered; extension relocation broke tool registration"
    )


def test_ci_cd_baselining_registered_in_tool_manager(server):
    """ci_cd_performance_baselining_tool must appear in the MCP tool manager after activation."""
    assert "ci_cd_performance_baselining_tool" in server.mcp._tool_manager._tools, (
        "ci_cd_performance_baselining_tool not registered; extension relocation broke tool registration"
    )


# ── (f) Kubernetes profile (mode=off): REAL extension → no registration ───────

def test_konflux_real_extension_off_mode_registers_nothing():
    """When mode='off', the REAL _KonfluxExtension.register() must never be called.

    This is the failing-first TDD gate: the real EXTENSION replaces the stub
    which registered nothing.  With mode='off', activate_extensions must skip
    register() even for the fully-implemented EXTENSION.
    """
    from types import SimpleNamespace

    from core.extension import DetectContext, ToolRegistry, activate_extensions
    from core.profiles import BUILTIN_PROFILES
    from extensions.konflux import EXTENSION as real_konflux

    tool_calls: list[str] = []

    class SpyRegistry(ToolRegistry):
        def tool(self):
            def decorator(fn):
                tool_calls.append(fn.__name__)
                return fn
            return decorator

    cfg = BUILTIN_PROFILES["kubernetes"]  # all extensions off
    fake_mcp = SimpleNamespace(add_tool=lambda fn: None)
    fake_server = SimpleNamespace(log_tool_execution=lambda fn: fn)
    facade = SpyRegistry(
        server_module=fake_server,
        mcp=fake_mcp,
        config=cfg,
        adapters=None,
        packs={},
    )

    async def _noop_discover(instance: str) -> frozenset:
        return frozenset()

    ctx = DetectContext(
        config=cfg,
        adapters=None,
        instance="kubernetes",
        discover_api_groups=_noop_discover,
    )

    states = activate_extensions(cfg, [real_konflux], facade, ctx)

    assert states == {("konflux", "kubernetes"): "off"}
    assert tool_calls == [], (
        f"register() invoked in off mode; tool calls: {tool_calls}"
    )


# ── (g) Tekton + OpenShift tool names in session server tool manager ──────────

_TEKTON_TOOLS = frozenset({
    "list_pipelineruns",
    "list_taskruns",
    "get_pipelinerun_logs",
    "analyze_failed_pipeline",
    "list_recent_pipeline_runs",
    "find_pipeline",
    "get_tekton_pipeline_runs_status",
})
_OPENSHIFT_TOOLS = frozenset({
    "get_etcd_logs",
    "get_machine_config_pool_status",
    "get_openshift_cluster_operator_status",
})


@pytest.mark.parametrize("name", sorted(_TEKTON_TOOLS | _OPENSHIFT_TOOLS))
def test_tekton_openshift_tool_registered(server, name):
    """All 10 tekton+openshift tool names must appear in the MCP tool manager."""
    assert name in server.mcp._tool_manager._tools, (
        f"{name!r} missing from tool manager; tekton/openshift extension gating broke"
    )


# ── (h) Kubernetes profile — real tekton+openshift EXTENSIONs in off mode ────

def test_tekton_openshift_real_extension_off_mode_no_register():
    """With mode='off', REAL tekton+openshift EXTENSIONs must not call register_server_tool.

    This is the TDD gate: before the real detect+register implementation the
    stubs do nothing, but after Task 6 the EXTENSIONs have real bodies.
    activate_extensions must still suppress both when the mode is 'off'.
    """
    from core.extension import DetectContext, ToolRegistry, activate_extensions
    from core.profiles import BUILTIN_PROFILES
    from extensions.openshift import EXTENSION as real_openshift
    from extensions.tekton import EXTENSION as real_tekton

    server_tool_calls: list[str] = []

    class SpyRegistry(ToolRegistry):
        def register_server_tool(self, name: str) -> None:  # type: ignore[override]
            server_tool_calls.append(name)

    cfg = BUILTIN_PROFILES["kubernetes"]  # tekton=off, openshift=off, konflux=off
    fake_mcp = SimpleNamespace(add_tool=lambda fn: None)
    fake_server = SimpleNamespace(log_tool_execution=lambda fn: fn)
    facade = SpyRegistry(
        server_module=fake_server,
        mcp=fake_mcp,
        config=cfg,
        adapters=None,
        packs={},
    )

    async def _noop_discover(instance: str) -> frozenset:
        return frozenset()

    ctx = DetectContext(
        config=cfg,
        adapters=None,
        instance="kubernetes",
        discover_api_groups=_noop_discover,
    )

    states = activate_extensions(cfg, [real_tekton, real_openshift], facade, ctx)

    assert states == {
        ("tekton", "kubernetes"): "off",
        ("openshift", "kubernetes"): "off",
    }
    assert server_tool_calls == [], (
        f"register_server_tool() invoked in off mode; calls: {server_tool_calls}"
    )


# ── (i) BUILTIN_PROFILES invariant: no extension pinned to "auto" ─────────────

def test_no_builtin_profile_uses_auto():
    """No built-in profile should pin any extension to 'auto'.

    'auto' is the default runtime fallback — pinning it in a profile would
    make the profile semantics ambiguous and bypass the stable on/off gate
    that the kubernetes profile relies on.  This test guards against an
    accidental future edit.
    """
    from core.profiles import BUILTIN_PROFILES

    for profile_name, cfg in BUILTIN_PROFILES.items():
        for ext_name, mode in cfg.extensions.items():
            assert mode != "auto", (
                f"BUILTIN_PROFILES[{profile_name!r}].extensions[{ext_name!r}] == 'auto'; "
                "builtin profiles must use 'on' or 'off' only"
            )


# ── (j) Subprocess real-import absence: kubernetes profile ───────────────────

import os
import subprocess
import sys
import textwrap
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]

_ALL_EXTENSION_TOOLS = sorted(_TEKTON_TOOLS | _OPENSHIFT_TOOLS | {
    "pipeline_tracer",
    "ci_cd_performance_baselining_tool",
})

_CONTROL_TOOL = "list_namespaces"  # a kubernetes-scoped tool that must be present


@pytest.mark.slow
def test_kubernetes_profile_extension_tools_absent_subprocess(tmp_path):
    """With LUMINO_PROFILE=kubernetes the 12 extension tools must NOT be registered.

    Spawns a fresh interpreter so server-mcp.py module-level init runs under
    the kubernetes profile without polluting the session-fixture import.
    """
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text("""\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: fake
contexts:
- context: {cluster: fake, user: fake}
  name: fake
current-context: fake
users:
- name: fake
  user: {token: "fake-token"}
""")

    script = textwrap.dedent(f"""\
        import importlib.util, sys
        sys.path.insert(0, {str(_REPO_ROOT / "src")!r})
        spec = importlib.util.spec_from_file_location(
            "server_mcp_kube", {str(_REPO_ROOT / "src" / "server-mcp.py")!r}
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["server_mcp_kube"] = mod
        spec.loader.exec_module(mod)
        tools = sorted(mod.mcp._tool_manager._tools.keys())
        print("\\n".join(tools))
    """)

    env = {
        **os.environ,
        "KUBECONFIG": str(kubeconfig),
        "KUBEARCHIVE_ENABLED": "false",
        "LUMINO_DISABLE_TELEMETRY": "1",
        "LUMINO_PROFILE": "kubernetes",
        "LUMINO_CONFIG": "",
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": "",
    }
    env.pop("LUMINO_CONFIG", None)

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )

    if result.returncode != 0:
        pytest.fail(
            f"Subprocess import failed (returncode={result.returncode}).\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}\n\n"
            "Falling back: absence cannot be verified via subprocess; "
            "unit-level absence test (h) still covers the off-mode gate."
        )

    registered = set(result.stdout.strip().splitlines())

    # Control: a kubernetes-native tool must be present
    assert _CONTROL_TOOL in registered, (
        f"Control tool {_CONTROL_TOOL!r} absent — import or profile may have failed.\n"
        f"Registered tools: {sorted(registered)}"
    )

    # Extension tools must all be absent
    present = [t for t in _ALL_EXTENSION_TOOLS if t in registered]
    assert present == [], (
        f"Extension tools present under kubernetes profile (expected none): {present}\n"
        f"All registered: {sorted(registered)}"
    )
