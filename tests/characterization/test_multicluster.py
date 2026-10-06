"""Phase 2e Task 2: dial-free kubeconfig-context discovery + connection state.

Uses the session-scoped `server` fixture from conftest.py (harness kubeconfig:
one context 'fake', current — so discovery adds zero sibling instances).

Tests (a)-(e): connection-state initialization + discovery mechanics.
F2 inline test: demonstrates the guard logic is needed (tests core primitives).
Integration test (multi_server fixture): exercises the SHIPPED activation block
against a real multi-context kubeconfig — kills the guard-deletion and
per-sibling-dial mutants that survive zero-sibling fixtures.
"""
import sys
from pathlib import Path

import pytest

# src/ must be on the path for core.* imports in F2 unit test (which doesn't
# use the server fixture that would otherwise add it).
_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from core.config_types import ResolvedConfig, SourceConfig
from core.registry import SourceEntry, ADAPTER_CAPABILITIES, build_registry


# ─── (a) _k8s_conn_state after import (single-context harness) ───────────────

def test_k8s_conn_state_default_is_connected(server):
    """The default kubernetes instance is marked 'connected' at import time.

    The harness kubeconfig has one context ('fake', current) → no new instances
    discovered → _k8s_conn_state contains exactly the default entry.
    """
    assert hasattr(server, "_k8s_conn_state"), (
        "server must expose _k8s_conn_state dict"
    )
    assert server._k8s_conn_state == {"kubernetes": "connected"}, (
        f"Expected {{'kubernetes': 'connected'}}, got {server._k8s_conn_state!r}"
    )


# ─── (b) R3 inertness spy: _dial_call_count == 0 after import ────────────────

def test_dial_count_zero_after_import(server):
    """Discovery must be dial-free: _dial_call_count must be 0 after module load.

    The default path uses _DefaultClientView (no dial).
    Discovery calls list_kube_config_contexts (kubeconfig read, no network I/O).
    """
    assert server._dial_call_count == 0, (
        f"Expected _dial_call_count=0 after import, got {server._dial_call_count}. "
        "Discovery or default-path initialization must not dial."
    )


# ─── (c) unit: discovery excludes current context, returns sorted ─────────────

def test_discover_excludes_current_and_sorts(server, monkeypatch):
    """_discover_kube_contexts returns non-current context names, name-sorted.

    Fake list_kube_config_contexts: 3 contexts, current = ctx-b.
    Expected: ["ctx-a", "ctx-c"] (ctx-b excluded, sorted).
    """
    def fake_lkcc(config_file=None):
        contexts = [
            {"name": "ctx-a", "context": {"cluster": "fake"}},
            {"name": "ctx-b", "context": {"cluster": "fake"}},
            {"name": "ctx-c", "context": {"cluster": "fake"}},
        ]
        active = {"name": "ctx-b", "context": {"cluster": "fake"}}
        return contexts, active

    monkeypatch.setattr(server.config, "list_kube_config_contexts", fake_lkcc)
    result = server._discover_kube_contexts()
    assert result == ["ctx-a", "ctx-c"], (
        f"Expected ['ctx-a', 'ctx-c'] (current ctx-b excluded, sorted), got {result!r}"
    )


# ─── (d) toggle off → [] ─────────────────────────────────────────────────────

def test_discover_toggle_off_returns_empty(server):
    """discover_contexts=False in source options → _discover_kube_contexts returns []."""
    cfg = ResolvedConfig(
        profile="test",
        sources={"kubernetes": SourceConfig(
            adapter="kubernetes",
            options={"discover_contexts": False},
        )},
    )
    result = server._discover_kube_contexts(cfg=cfg)
    assert result == [], (
        f"Expected [] when discover_contexts=False, got {result!r}"
    )


# ─── (e) missing kubeconfig → [] without exception ───────────────────────────

def test_discover_exception_returns_empty_no_raise(server, monkeypatch):
    """If list_kube_config_contexts raises (missing file / parse error), return []."""
    def raise_exc(config_file=None):
        raise FileNotFoundError("~/.kube/config not found (test-injected)")

    monkeypatch.setattr(server.config, "list_kube_config_contexts", raise_exc)
    # Must not raise
    result = server._discover_kube_contexts()
    assert result == [], (
        f"Expected [] on exception (non-fatal), got {result!r}"
    )


# ─── F2 inline test (demonstrates guard primitives, does NOT exec activation) ─

def test_f2_guard_primitives_inline():
    """Discovery with a context named 'kubernetes' (non-current) must not crash.

    The activation loop guards with `if ctx not in existing` before calling
    add_instance, so a collision never reaches the ValueError path.
    """
    cfg = ResolvedConfig(
        profile="test",
        sources={"kubernetes": SourceConfig(adapter="kubernetes")},
    )
    reg = build_registry(cfg)

    # Simulate what _discover_kube_contexts would return (includes collision)
    discovered = ["kubernetes", "extra-cluster"]  # "kubernetes" is a duplicate!
    existing = {e.name for e in reg.entries()}

    # Verify add_instance raises WITHOUT the guard (proving the guard is needed)
    with pytest.raises(ValueError, match="kubernetes"):
        reg.add_instance(SourceEntry(
            name="kubernetes",
            adapter="kubernetes",
            capabilities=ADAPTER_CAPABILITIES["kubernetes"],
            state="configured",
        ))

    # Rebuild to get a fresh registry (add_instance above was rejected cleanly)
    reg = build_registry(cfg)
    existing = {e.name for e in reg.entries()}
    added = []
    k8s_caps = reg.get("kubernetes").capabilities
    for ctx in discovered:
        if ctx in existing:
            continue  # collision guard — this is what the activation block does
        reg.add_instance(SourceEntry(
            name=ctx, adapter="kubernetes",
            capabilities=k8s_caps, state="configured",
        ))
        added.append(ctx)

    assert "kubernetes" not in added, (
        "Collision guard must skip 'kubernetes' — it was already in the registry"
    )
    assert "extra-cluster" in added, (
        "'extra-cluster' is a new name — activation should add it"
    )


# ─── F9 fixture-pin verification ─────────────────────────────────────────────

def test_kube_config_default_location_pinned_in_characterization_conftest(server):
    """Verify that KUBE_CONFIG_DEFAULT_LOCATION is pinned to the harness kubeconfig.

    The characterization conftest pins KUBE_CONFIG_DEFAULT_LOCATION to prevent
    dev-machine kubeconfig bleed. If the server imported cleanly (no real-context
    discovery from ~/.kube/config), _k8s_conn_state has exactly one entry.
    This test confirms the harness isolation holds.
    """
    # If the pin weren't in place, a real ~/.kube/config would have been read
    # during module import, and _k8s_conn_state would have extra entries.
    assert set(server._k8s_conn_state.keys()) == {"kubernetes"}, (
        f"Expected only 'kubernetes' in _k8s_conn_state keys; got "
        f"{sorted(server._k8s_conn_state.keys())}. "
        "Real kubeconfig contexts may have leaked (KUBE_CONFIG_DEFAULT_LOCATION not pinned)."
    )


# ─── Integration test: multi-context kubeconfig — kills both surviving mutants ──
#
# Mutant 1 (guard deletion): delete `if _ctx in _k8s_existing: continue` lines
#   in the activation block → add_instance("kubernetes") raises ValueError at
#   module load → this fixture's exec_module call raises → test fails.
#
# Mutant 2 (per-sibling dial): add `_build_k8s_client_set(_ctx)` in the loop
#   body → _dial_call_count increments once per sibling → assertion (d) fails.
#
# Both mutants survive the zero-sibling fixtures (single-context harness kubeconfig
# means the loop body never executes).

_MULTI_CONTEXT_KUBECONFIG = """\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: fake
contexts:
- context: {cluster: fake, user: fake}
  name: fake-current
- context: {cluster: fake, user: fake}
  name: kubernetes
- context: {cluster: fake, user: fake}
  name: zz-sibling
current-context: fake-current
users:
- name: fake
  user: {token: "fake-token"}
"""

import importlib.util
import os as _os


@pytest.fixture(scope="module")
def multi_server(tmp_path_factory):
    """Load server-mcp.py with a multi-context kubeconfig (module-scoped).

    Kubeconfig: current=fake-current, siblings=kubernetes (collision) + zz-sibling.
    This fixture exercises the SHIPPED activation block, not a simulated loop.
    Pins KUBE_CONFIG_DEFAULT_LOCATION so discovery reads only the harness file.
    """
    kubeconfig = tmp_path_factory.mktemp("kube_multi") / "config"
    kubeconfig.write_text(_MULTI_CONTEXT_KUBECONFIG)

    _orig = {
        "KUBECONFIG": _os.environ.get("KUBECONFIG"),
        "KUBEARCHIVE_ENABLED": _os.environ.get("KUBEARCHIVE_ENABLED"),
        "LUMINO_DISABLE_TELEMETRY": _os.environ.get("LUMINO_DISABLE_TELEMETRY"),
        "LUMINO_CONFIG": _os.environ.get("LUMINO_CONFIG"),
        "LUMINO_PROFILE": _os.environ.get("LUMINO_PROFILE"),
    }
    _os.environ["KUBECONFIG"] = str(kubeconfig)
    _os.environ["KUBEARCHIVE_ENABLED"] = "false"
    _os.environ.setdefault("LUMINO_DISABLE_TELEMETRY", "1")
    _os.environ.pop("LUMINO_CONFIG", None)
    _os.environ.pop("LUMINO_PROFILE", None)

    # F9 pin: prevent _discover_kube_contexts from falling back to ~/.kube/config
    _orig_kube_loc = None
    try:
        from kubernetes.config import kube_config as _k8s_kube_config
        _orig_kube_loc = _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION
        _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = str(kubeconfig)
    except Exception:
        pass

    sys.path.insert(0, str(_SRC))
    spec = importlib.util.spec_from_file_location(
        "server_mcp_multicluster_integration", _SRC / "server-mcp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_multicluster_integration"] = mod
    spec.loader.exec_module(mod)  # Mutant 1 (guard deletion): this line raises ValueError

    yield mod

    for key, orig in _orig.items():
        if orig is None:
            _os.environ.pop(key, None)
        else:
            _os.environ[key] = orig
    if _orig_kube_loc is not None:
        try:
            from kubernetes.config import kube_config as _k8s_kube_config
            _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = _orig_kube_loc
        except Exception:
            pass
    try:
        sys.path.remove(str(_SRC))
    except ValueError:
        pass
    sys.modules.pop("server_mcp_multicluster_integration", None)


def test_multicluster_sibling_in_registry(multi_server):
    """(a) 'zz-sibling' is added to the registry with default=False and the
    same capabilities tuple as the default kubernetes entry."""
    registry = multi_server._source_registry
    names = {e.name for e in registry.entries()}
    assert "zz-sibling" in names, (
        f"Expected 'zz-sibling' in registry after multi-context discovery; "
        f"got: {sorted(names)}"
    )
    entry = registry.get("zz-sibling")
    assert entry.default is False, (
        "'zz-sibling' must not be marked as the default instance"
    )
    default_caps = registry.get("kubernetes").capabilities
    assert entry.capabilities == default_caps, (
        f"'zz-sibling' capabilities {entry.capabilities!r} must match "
        f"the default kubernetes entry's {default_caps!r}"
    )


def test_multicluster_sibling_conn_state_unconnected(multi_server):
    """(b) 'zz-sibling' has _k8s_conn_state == 'unconnected'."""
    state = multi_server._k8s_conn_state.get("zz-sibling")
    assert state == "unconnected", (
        f"Expected _k8s_conn_state['zz-sibling'] == 'unconnected', got {state!r}"
    )


def test_multicluster_collision_kubernetes_skipped(multi_server):
    """(c) The 'kubernetes' kubeconfig context was SKIPPED by the collision guard.

    The builtin konfux profile already registers a source named 'kubernetes'.
    Discovery returns 'kubernetes' as a non-current context, but the guard
    (`if _ctx in _k8s_existing: continue`) must skip it — exactly one
    'kubernetes' entry in the registry, import did not raise.
    """
    registry = multi_server._source_registry
    entries = [e for e in registry.entries() if e.name == "kubernetes"]
    assert len(entries) == 1, (
        f"Expected exactly 1 'kubernetes' entry in registry (collision guard); "
        f"found {len(entries)}: {entries}"
    )
    # "kubernetes" must still be the default (not a freshly-added duplicate)
    assert entries[0].default is True, (
        "The original 'kubernetes' entry (from build_registry) must carry default=True"
    )


def test_multicluster_dial_count_zero(multi_server):
    """(d) _dial_call_count == 0: discovery never dials — kills the per-sibling-dial mutant.

    A mutant that calls _build_k8s_client_set(_ctx) in the activation loop
    would increment _dial_call_count once per non-colliding sibling ('zz-sibling'),
    making this assertion fail.
    """
    assert multi_server._dial_call_count == 0, (
        f"Expected _dial_call_count=0 (dial-free discovery), "
        f"got {multi_server._dial_call_count}. "
        "Discovery must never call _build_k8s_client_set."
    )


@pytest.mark.asyncio
async def test_multicluster_lazy_construction_at_call_time(multi_server):
    """(Task 6) A discovered sibling is constructed ONLY when a tool first
    addresses it — not at import. Calling list_pods_in_namespace(source=
    'zz-sibling') dials exactly once (0 -> 1) and returns a STRUCTURED error
    (the sibling points at 127.0.0.1:1 which refuses), never an exception."""
    before = multi_server._dial_call_count
    result = await multi_server.list_pods_in_namespace(
        namespace="any", source="zz-sibling")
    after = multi_server._dial_call_count
    assert after == before + 1, (
        f"Lazy construction must dial exactly once at call time; "
        f"dial count {before} -> {after}")
    # list-returning tool → [error_dict] shape, never a raised exception
    assert isinstance(result, list) and result, f"expected non-empty list, got {result!r}"
    assert "error" in result[0], f"expected structured error entry, got {result[0]!r}"
    # Second call is served from the construct-once cache (no re-dial of a
    # successfully-built set) — but this build FAILED, so it is not cached;
    # a retry dials again. Either way the FIRST call proved call-time laziness.


# ─── Task 3: source= per-instance dispatch on the 4-tool kubernetes slice ────
#
# Three test families:
#   (a) Unknown source → per-tool error SHAPE (F1 round-1 contract)
#   (b) Dispatch reality: named instance → fake ClientSet used, NOT module globals
#   (c) Default-path identity: no source → module-global (harness-patched) fake used

import sys as _sys
from pathlib import Path as _Path

_REPO_ROOT = _Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"
_TESTS = _REPO_ROOT / "tests"
if str(_SRC) not in _sys.path:
    _sys.path.insert(0, str(_SRC))
if str(_TESTS) not in _sys.path:
    _sys.path.insert(0, str(_TESTS))

from core.registry import SourceEntry
from characterization.k8s_fakes import FakeApi, items_list, NS, POD, PIPELINERUN, EVENT


# ─── (a) Unknown source → per-tool error shape ──────────────────────────────

@pytest.mark.asyncio
async def test_list_namespaces_unknown_source_returns_dict(server):
    """list_namespaces(source='no-such') → error dict with F1 keys (F-08 fix)."""
    result = await server.list_namespaces(source="no-such-cluster")
    assert isinstance(result, dict), f"Expected dict (F-08 fix), got {type(result).__name__}"
    assert "error" in result and "requested_source" in result and "known_kubernetes_instances" in result, (
        f"Missing F1 keys in error dict: {sorted(result)}"
    )
    assert result["requested_source"] == "no-such-cluster"


@pytest.mark.asyncio
async def test_list_pods_unknown_source_returns_list_dict(server):
    """list_pods_in_namespace(source='no-such') → [error_dict] with F1 keys."""
    result = await server.list_pods_in_namespace(namespace="team-a", source="no-such-cluster")
    assert isinstance(result, list), f"Expected list, got {type(result).__name__}"
    assert len(result) == 1, f"Expected 1-element list, got {len(result)}"
    err = result[0]
    assert isinstance(err, dict), f"Entry must be dict, got {type(err).__name__}"
    assert "error" in err and "requested_source" in err and "known_kubernetes_instances" in err, (
        f"Missing F1 keys in error dict: {sorted(err)}"
    )
    assert err["requested_source"] == "no-such-cluster"


@pytest.mark.asyncio
async def test_get_kubernetes_resource_unknown_source_returns_string(server):
    """get_kubernetes_resource(source='no-such') → string starting 'Error: unknown source'."""
    result = await server.get_kubernetes_resource(
        resource_type="pod", name="p", source="no-such-cluster"
    )
    assert isinstance(result, str), f"Expected str, got {type(result).__name__}: {result!r}"
    assert result.startswith("Error: unknown source"), (
        f"String must start with error prefix; got: {result!r}"
    )


@pytest.mark.asyncio
async def test_search_resources_unknown_source_returns_dict(server):
    """search_resources_by_labels(source='no-such') → error dict with F1 keys."""
    result = await server.search_resources_by_labels(
        resource_types=["pods"],
        label_selectors=[{"key": "app", "value": "x", "operator": "equals"}],
        namespaces=["default"],
        source="no-such-cluster",
    )
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert "error" in result and "requested_source" in result and "known_kubernetes_instances" in result, (
        f"Missing F1 keys in error dict: {sorted(result)}"
    )
    assert result["requested_source"] == "no-such-cluster"


# ─── (b) Dispatch reality ───────────────────────────────────────────────────
#
# Pattern: register a unique named instance (unique per test to avoid duplicate-
# name collisions in the session-scoped registry), inject a pre-built fake
# K8sClientSet into _k8s_instances, monkeypatch module globals to unconfigured
# FakeApi instances (any call → AttributeError), call tool with that source,
# assert result is consistent with the FAKE's configured methods (not the global).


def _register_fake_instance(server, monkeypatch, name: str, fake_cs):
    """Helper: add 'name' to the registry and pre-cache fake_cs in _k8s_instances."""
    k8s_caps = server._source_registry.get("kubernetes").capabilities
    monkeypatch.setitem(
        server._source_registry._entries,
        name,
        SourceEntry(name=name, adapter="kubernetes", capabilities=k8s_caps, state="configured"),
    )
    monkeypatch.setitem(server._k8s_instances, name, fake_cs)


def _make_cs(server, **overrides):
    """Build a K8sClientSet with all 8 fields; overrides replace defaults (FakeApi())."""
    fields = dict(
        core_api=FakeApi(), apps_api=FakeApi(), custom_api=FakeApi(),
        batch_api=FakeApi(), storage_api=FakeApi(), networking_api=FakeApi(),
        autoscaling_api=FakeApi(), apis_api=FakeApi(),
    )
    fields.update(overrides)
    return server.K8sClientSet(**fields)


@pytest.mark.asyncio
async def test_list_namespaces_dispatches_to_named_instance(server, monkeypatch):
    """list_namespaces(source='t3-ns') calls ctx fake core_api, NOT the module global."""
    # Poison module global: any call → AttributeError (proves it is not touched)
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())
    monkeypatch.setattr(server, "_namespace_cache", {})

    fake_core = FakeApi(list_namespace=items_list([NS("ctx-b-namespace")]))
    fake_cs = _make_cs(server, core_api=fake_core)
    _register_fake_instance(server, monkeypatch, "t3-ns", fake_cs)

    result = await server.list_namespaces(source="t3-ns")
    assert result == ["ctx-b-namespace"], (
        f"Expected ['ctx-b-namespace'] from fake core_api; got {result!r}"
    )


@pytest.mark.asyncio
async def test_list_pods_dispatches_to_named_instance(server, monkeypatch):
    """list_pods_in_namespace(source='t3-pods') calls ctx fake core_api."""
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    pod_list = items_list([POD("ctx-pod-1", "team-b")])
    fake_core = FakeApi(list_namespaced_pod=pod_list)
    fake_cs = _make_cs(server, core_api=fake_core)
    _register_fake_instance(server, monkeypatch, "t3-pods", fake_cs)

    result = await server.list_pods_in_namespace(namespace="team-b", source="t3-pods")
    names = [p["name"] for p in result if "name" in p]
    assert "ctx-pod-1" in names, (
        f"Expected ctx-pod-1 from fake core_api; got names={names!r}, result={result!r}"
    )


@pytest.mark.asyncio
async def test_get_kubernetes_resource_dispatches_to_named_instance(server, monkeypatch):
    """get_kubernetes_resource(source='t3-gkr') uses ctx fake core_api, not module global."""
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())
    monkeypatch.setattr(server, "k8s_apps_api", FakeApi())
    monkeypatch.setattr(server, "k8s_batch_api", FakeApi())
    monkeypatch.setattr(server, "k8s_autoscaling_api", FakeApi())
    monkeypatch.setattr(server, "k8s_storage_api", FakeApi())
    monkeypatch.setattr(server, "k8s_custom_api", FakeApi())

    fake_core = FakeApi(read_namespaced_pod=POD("ctx-pod-gkr", "team-b"))
    fake_cs = _make_cs(server, core_api=fake_core)
    _register_fake_instance(server, monkeypatch, "t3-gkr", fake_cs)

    result = await server.get_kubernetes_resource(
        resource_type="pod", name="ctx-pod-gkr", namespace="team-b", source="t3-gkr"
    )
    assert isinstance(result, str) and not result.startswith("Error"), (
        f"Expected successful resource summary; got {result!r}"
    )
    assert "ctx-pod-gkr" in result, (
        f"Expected pod name in result; got {result!r}"
    )


@pytest.mark.asyncio
async def test_search_resources_dispatches_to_named_instance(server, monkeypatch):
    """search_resources_by_labels(source='t3-srbl') uses ctx fake, not module global."""
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())
    monkeypatch.setattr(server, "k8s_apps_api", FakeApi())
    monkeypatch.setattr(server, "k8s_batch_api", FakeApi())
    monkeypatch.setattr(server, "k8s_custom_api", FakeApi())

    pod_list = items_list([POD("ctx-search-pod", "team-c")])
    fake_core = FakeApi(list_namespaced_pod=pod_list)
    fake_cs = _make_cs(server, core_api=fake_core)
    _register_fake_instance(server, monkeypatch, "t3-srbl", fake_cs)

    result = await server.search_resources_by_labels(
        resource_types=["pods"],
        label_selectors=[{"key": "app", "value": "ctx-search-pod", "operator": "equals"}],
        namespaces=["team-c"],
        source="t3-srbl",
    )
    assert isinstance(result, dict) and "search_summary" in result, (
        f"Expected search result dict; got {result!r}"
    )
    found_names = [r.get("metadata", {}).get("name") for r in result.get("resources", [])]
    assert "ctx-search-pod" in found_names, (
        f"Expected ctx-search-pod from fake core_api; found_names={found_names!r}"
    )


# ─── (c) Default-path identity ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_namespaces_default_path_uses_module_global(server, monkeypatch):
    """list_namespaces() (no source) → module-global k8s_core_api is called."""
    fake_global = FakeApi(list_namespace=items_list([NS("default-ns")]))
    monkeypatch.setattr(server, "k8s_core_api", fake_global)
    monkeypatch.setattr(server, "_namespace_cache", {})

    result = await server.list_namespaces()
    assert result == ["default-ns"], (
        f"Default path must use module-global k8s_core_api; got {result!r}"
    )


@pytest.mark.asyncio
async def test_list_pods_default_path_uses_module_global(server, monkeypatch):
    """list_pods_in_namespace() (no source) → module-global k8s_core_api is called."""
    pod_list = items_list([POD("global-pod", "team-a")])
    fake_global = FakeApi(list_namespaced_pod=pod_list)
    monkeypatch.setattr(server, "k8s_core_api", fake_global)

    result = await server.list_pods_in_namespace(namespace="team-a")
    names = [p["name"] for p in result if "name" in p]
    assert "global-pod" in names, (
        f"Default path must use module-global; got names={names!r}"
    )


@pytest.mark.asyncio
async def test_get_kubernetes_resource_default_path_uses_module_global(server, monkeypatch):
    """get_kubernetes_resource() (no source) → module-global k8s_core_api is called."""
    fake_global = FakeApi(read_namespaced_pod=POD("global-pod", "team-a"))
    monkeypatch.setattr(server, "k8s_core_api", fake_global)
    for attr in ("k8s_apps_api", "k8s_batch_api", "k8s_autoscaling_api",
                 "k8s_storage_api", "k8s_custom_api"):
        monkeypatch.setattr(server, attr, FakeApi())

    result = await server.get_kubernetes_resource(
        resource_type="pod", name="global-pod", namespace="team-a"
    )
    assert "global-pod" in result, (
        f"Default path must use module-global k8s_core_api; got {result!r}"
    )


@pytest.mark.asyncio
async def test_search_resources_default_path_uses_module_global(server, monkeypatch):
    """search_resources_by_labels() (no source) → module-global k8s_core_api is called."""
    pod_list = items_list([POD("global-search-pod", "team-a")])
    fake_global = FakeApi(list_namespaced_pod=pod_list)
    monkeypatch.setattr(server, "k8s_core_api", fake_global)
    for attr in ("k8s_apps_api", "k8s_batch_api", "k8s_custom_api"):
        monkeypatch.setattr(server, attr, FakeApi())

    result = await server.search_resources_by_labels(
        resource_types=["pods"],
        label_selectors=[{"key": "app", "value": "global-search-pod", "operator": "equals"}],
        namespaces=["team-a"],
    )
    assert isinstance(result, dict) and "search_summary" in result
    found_names = [r.get("metadata", {}).get("name") for r in result.get("resources", [])]
    assert "global-search-pod" in found_names, (
        f"Default path must use module-global; found_names={found_names!r}"
    )


# ─── Task 4: per-instance extension detection + connected-only refresh ────────
#
# Three test families (RED → GREEN after Task 4 implementation):
#   (a) synthetic two-instance state: instance A has tekton.dev, B doesn't →
#       per-instance detection states differ
#   (b) union pin (R6, mutation-mandated): both A and B detect tekton →
#       7 tools registered ONCE in shared facade (not 14, no error)
#   (c) refresh skips unconnected: spy confirms _detect_ctx is never called
#       for an instance whose _k8s_conn_state == "unconnected"

from core.extension import DetectContext, ToolRegistry, detect_and_register
from core.config_types import ResolvedConfig
from extensions.tekton import EXTENSION as tekton_ext
from extensions.tekton import TOOLS as TEKTON_TOOLS
from unittest.mock import MagicMock


def _make_fresh_facade(server, monkeypatch):
    """Build a fresh ToolRegistry backed by the real server module.

    Pre-captures the 7 tekton server attrs so monkeypatch reverts them.
    Returns (facade, fresh_cfg).
    """
    for name in TEKTON_TOOLS:
        if hasattr(server, name):
            monkeypatch.setattr(server, name, getattr(server, name))

    fresh_cfg = ResolvedConfig(profile="test", extensions={"tekton": "auto"})
    fresh_facade = ToolRegistry(
        server_module=server,
        mcp=MagicMock(),
        config=fresh_cfg,
        adapters=server._source_registry,
        packs={},
    )
    return fresh_facade, fresh_cfg


# ─── (a) Per-instance detection states ───────────────────────────────────────

@pytest.mark.asyncio
async def test_per_instance_detection_states(server, monkeypatch):
    """(a) Instance A has tekton.dev, B doesn't → detect states differ per instance.

    Uses real tekton EXTENSION + real detect_and_register against fake facades.
    After per-instance detection:
      (tekton, "A") == "active"
      (tekton, "B") == "not-detected: absent"
    """
    fresh_facade, fresh_cfg = _make_fresh_facade(server, monkeypatch)

    async def discover_A(instance: str) -> frozenset:
        return frozenset({"tekton.dev"})

    async def discover_B(instance: str) -> frozenset:
        return frozenset()

    ctx_A = DetectContext(
        config=fresh_cfg, adapters=server._source_registry,
        instance="A", discover_api_groups=discover_A,
    )
    ctx_B = DetectContext(
        config=fresh_cfg, adapters=server._source_registry,
        instance="B", discover_api_groups=discover_B,
    )

    state_A, newly_A = await detect_and_register(tekton_ext, fresh_facade, ctx_A)
    state_B, _       = await detect_and_register(tekton_ext, fresh_facade, ctx_B)

    assert state_A == "active", (
        f"Expected 'active' for instance A (has tekton.dev); got {state_A!r}"
    )
    assert state_B == "not-detected: absent", (
        f"Expected 'not-detected: absent' for instance B (no tekton.dev); got {state_B!r}"
    )
    assert sorted(newly_A) == sorted(TEKTON_TOOLS), (
        f"Instance A must register all 7 tekton tools; got {newly_A!r}"
    )


# ─── (b) Union pin: both instances detect tekton → 7 tools registered ONCE ──

@pytest.mark.asyncio
async def test_union_registration_deduplicated(server, monkeypatch):
    """(b) Both A and B detect tekton → exactly 7 tools in shared facade, none duplicate.

    Mutation-mandated: if facade.registered were a list (not dict), duplicate
    keys would accumulate to 14. The dict key-overwrite keeps it at 7.
    """
    fresh_facade, fresh_cfg = _make_fresh_facade(server, monkeypatch)

    async def discover_both(instance: str) -> frozenset:
        return frozenset({"tekton.dev"})

    ctx_A = DetectContext(
        config=fresh_cfg, adapters=server._source_registry,
        instance="A", discover_api_groups=discover_both,
    )
    ctx_B = DetectContext(
        config=fresh_cfg, adapters=server._source_registry,
        instance="B", discover_api_groups=discover_both,
    )

    _, newly_A = await detect_and_register(tekton_ext, fresh_facade, ctx_A)
    _, newly_B = await detect_and_register(tekton_ext, fresh_facade, ctx_B)

    assert len(fresh_facade.registered) == len(TEKTON_TOOLS), (
        f"Expected {len(TEKTON_TOOLS)} registered tools (union, no duplicates); "
        f"got {len(fresh_facade.registered)}: {sorted(fresh_facade.registered)}"
    )
    assert sorted(newly_A) == sorted(TEKTON_TOOLS), (
        f"First registration (A) must add all {len(TEKTON_TOOLS)} tools; got {newly_A!r}"
    )
    assert newly_B == [], (
        f"Second registration (B) must add 0 new tools (already registered); got {newly_B!r}"
    )


# ─── (c) refresh skips unconnected instance ──────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_skips_unconnected_instance(server, monkeypatch):
    """(c) Unconnected instance → _detect_ctx never called for it (spy).

    Monkeypatches _k8s_conn_state with "kubernetes":"connected" and
    "fake-cluster":"unconnected".  A spy on _detect_ctx records all calls.
    After refresh_capabilities, "fake-cluster" must not appear in the spy log.
    """
    detect_ctx_calls: list = []

    fresh_cfg = ResolvedConfig(profile="test", extensions={"tekton": "auto"})
    fresh_facade, _ = _make_fresh_facade(server, monkeypatch)

    async def noop_discover(instance: str) -> frozenset:
        return frozenset()  # no tekton.dev → detect() → False → "not-detected: absent"

    def spy_detect_ctx(instance: str = "kubernetes") -> DetectContext:
        detect_ctx_calls.append(instance)
        return DetectContext(
            config=fresh_cfg,
            adapters=server._source_registry,
            instance=instance,
            discover_api_groups=noop_discover,
        )

    monkeypatch.setattr(server, "_lumino_config", fresh_cfg)
    monkeypatch.setattr(server, "_extension_states", {})
    monkeypatch.setattr(server, "_extension_facade", fresh_facade)
    monkeypatch.setattr(server, "_detect_ctx", spy_detect_ctx)
    monkeypatch.setattr(server, "_k8s_conn_state", {
        "kubernetes": "connected",
        "fake-cluster": "unconnected",
    })

    await server.refresh_capabilities()

    assert "fake-cluster" not in detect_ctx_calls, (
        f"refresh must never call _detect_ctx for unconnected instances; "
        f"spy recorded: {detect_ctx_calls}"
    )


# ─── (d) asyncio.to_thread cancellability pin (round-1 F3) ──────────────────
#
# Mutant: revert `await asyncio.to_thread(apis_api.get_api_versions)` to a bare
# `apis_api.get_api_versions()` inside _discover_api_groups.
#
# With to_thread (correct): the blocking call runs in a thread pool; asyncio
# wait_for fires at timeout_s → state "not-detected: timeout"; test completes
# in ~0.2 s.
#
# Without to_thread (mutant): the blocking call runs IN the event loop; the
# loop is frozen; asyncio.wait_for cannot fire; test hangs until OS kills it.
# Running with `timeout 10 pytest ...` demonstrates this (exit code 124).

import threading as _threading


@pytest.mark.asyncio
async def test_to_thread_detect_timeout_cancellable(server, monkeypatch):
    """Pin that asyncio.to_thread wraps get_api_versions in _discover_api_groups.

    A get_api_versions that blocks on a threading.Event (never set during the
    test body; set in finally so the thread exits cleanly) proves that the
    2-second detect timeout is genuinely cancellable only when the call runs
    in a thread.

    With to_thread (correct): asyncio.wait_for(0.2 s) inside detect_and_register
    fires → state == "not-detected: timeout"; completes promptly (<< 2 s).
    Outer asyncio.wait_for(2 s) is a safety net — it must not be the one that
    fires.

    Without to_thread (mutant): the sync call freezes the event loop; the
    inner 0.2 s timeout cannot fire; the outer 2 s guard also cannot fire;
    the test hangs — confirmed by running with `timeout 10 pytest ...`
    (exit code 124, SIGKILL).
    """
    import asyncio as _asyncio

    block_event = _threading.Event()

    class _BlockingApisApi:
        def get_api_versions(self, **kwargs):
            block_event.wait()  # hangs until finally-block sets the event
            return type("_V", (), {"groups": []})()

    class _FakeClient:
        ApisApi = _BlockingApisApi

    # Isolate the discovery cache and counter for this test.
    monkeypatch.setattr(server, "_discovery_cache", {})
    monkeypatch.setattr(server, "_discovery_call_count", 0)
    # Route _DefaultClientView.apis_api through the blocking fake.
    # _DefaultClientView.apis_api constructs ReadOnlyK8sClient.wrap(client.ApisApi())
    # where `client` is the module-level global overridden here.
    monkeypatch.setattr(server, "client", _FakeClient())

    fresh_facade, fresh_cfg = _make_fresh_facade(server, monkeypatch)

    # Use the REAL _discover_api_groups so the to_thread path is exercised.
    # instance="" → _resolve_k8s("") → _DefaultClientView() → blocking apis_api.
    ctx = DetectContext(
        config=fresh_cfg,
        adapters=server._source_registry,
        instance="",
        discover_api_groups=server._discover_api_groups,
    )

    try:
        # Outer guard (2 s): if to_thread is missing the inner 0.2 s timeout
        # cannot cancel a frozen event loop — this guard documents expected
        # latency but cannot itself rescue a blocked loop (see module docstring).
        state, _ = await _asyncio.wait_for(
            detect_and_register(tekton_ext, fresh_facade, ctx, timeout_s=0.2),
            timeout=2.0,
        )
    finally:
        block_event.set()  # unblock the thread; prevents thread leak after test

    assert state == "not-detected: timeout", (
        f"Expected 'not-detected: timeout' from a permanently-blocking "
        f"get_api_versions; got {state!r}. "
        "If the test HUNG instead of failing here, asyncio.to_thread is absent "
        "from _discover_api_groups and the event loop was frozen."
    )


# ─── Task 5: connect_cluster meta-tool ───────────────────────────────────────
#
# Negative tests: each error code, _dial_call_count unchanged for pure rejections.
# Positive test: fake dial + canned detection → success shape, list_changed once,
# instance in list_sources with connection "connected", secret-absence assertion.

import json as _json
import logging as _logging
import types as _types
from types import SimpleNamespace as _SN

from core.config_types import ResolvedConfig as _RC, SourceConfig as _SC


def _cfg_with_roots(roots, env_allowlist=None, cluster_registry=None):
    """Build a minimal ResolvedConfig with credential_ref_roots set."""
    opts = {"credential_ref_roots": roots}
    if env_allowlist is not None:
        opts["credential_ref_env_allowlist"] = env_allowlist
    if cluster_registry is not None:
        opts["cluster_registry"] = cluster_registry
    return _RC(
        profile="test",
        sources={"kubernetes": _SC(adapter="kubernetes", options=opts)},
        extensions={},  # no extensions → detection skipped in connect_cluster
    )


def _cfg_env_only(env_allowlist, cluster_registry=None):
    """Config with env_allowlist but no path roots."""
    opts = {"credential_ref_roots": [], "credential_ref_env_allowlist": env_allowlist}
    if cluster_registry is not None:
        opts["cluster_registry"] = cluster_registry
    return _RC(
        profile="test",
        sources={"kubernetes": _SC(adapter="kubernetes", options=opts)},
        extensions={},
    )


# ── Negative: raw kubeconfig body → raw_credential_rejected ──────────────────

@pytest.mark.asyncio
async def test_connect_cluster_raw_kubeconfig_body_rejected(server):
    """A raw kubeconfig body is rejected with raw_credential_rejected.

    Contains 'apiVersion:' and newlines → scheme-first check fails (no known
    prefix), raw heuristic fires → raw_credential_rejected.
    _dial_call_count must be unchanged (pure ref rejection — no dial).
    """
    raw = "apiVersion: v1\nkind: Config\nclusters: []\n"
    before = server._dial_call_count
    result = await server.connect_cluster(name="raw-test", credential_ref=raw)
    assert result.get("code") == "raw_credential_rejected", (
        f"Expected raw_credential_rejected; got {result}"
    )
    assert server._dial_call_count == before, (
        "Pure ref rejection must not increment _dial_call_count"
    )


# ── Negative: unknown scheme → unknown_ref_scheme ────────────────────────────

@pytest.mark.asyncio
async def test_connect_cluster_unknown_scheme(server):
    """'foo:bar' has no known scheme prefix and doesn't look raw → unknown_ref_scheme."""
    before = server._dial_call_count
    result = await server.connect_cluster(name="unk-test", credential_ref="foo:bar")
    assert result.get("code") == "unknown_ref_scheme", (
        f"Expected unknown_ref_scheme; got {result}"
    )
    assert server._dial_call_count == before


# ── Negative: malformed kubeconfig ref → bad_ref_grammar ─────────────────────

@pytest.mark.asyncio
async def test_connect_cluster_bad_grammar_kubeconfig_no_context(server):
    """'kubeconfig:/x' has the prefix but no '#<context>' → bad_ref_grammar."""
    before = server._dial_call_count
    result = await server.connect_cluster(
        name="gram-test", credential_ref="kubeconfig:/x"
    )
    assert result.get("code") == "bad_ref_grammar", (
        f"Expected bad_ref_grammar; got {result}"
    )
    assert server._dial_call_count == before


# ── Negative: path outside allowlist → ref_outside_allowlist ─────────────────

@pytest.mark.asyncio
async def test_connect_cluster_path_outside_allowlist(server, monkeypatch):
    """kubeconfig path not under any credential_ref_roots → ref_outside_allowlist.

    The harness profile has no credential_ref_roots (empty list by default),
    so any kubeconfig/secret path ref is rejected.
    """
    before = server._dial_call_count
    # Use harness server directly — default config has no roots
    result = await server.connect_cluster(
        name="al-test", credential_ref="kubeconfig:/some/path#ctx"
    )
    assert result.get("code") == "ref_outside_allowlist", (
        f"Expected ref_outside_allowlist; got {result}"
    )
    assert server._dial_call_count == before


@pytest.mark.asyncio
async def test_connect_cluster_allowlist_prefix_boundary(server, monkeypatch, tmp_path):
    """Whole-branch review Minor: a root '/creds' must NOT admit a sibling
    '/creds-evil/token'. The prefix check requires a real path-separator
    boundary, so a path in a name-prefixed sibling dir is rejected."""
    root = tmp_path / "creds"
    root.mkdir()
    sibling = tmp_path / "creds-evil"
    sibling.mkdir()
    (sibling / "kubeconfig").write_text("x")

    cfg = _cfg_with_roots(roots=[str(root)])
    monkeypatch.setattr(server, "_lumino_config", cfg)
    before = server._dial_call_count
    # Sibling dir shares the "creds" name prefix but is NOT under the root.
    result = await server.connect_cluster(
        name="boundary-test",
        credential_ref=f"kubeconfig:{sibling}/kubeconfig#ctx")
    assert result.get("code") == "ref_outside_allowlist", (
        f"prefix-sibling must be rejected; got {result}")
    assert server._dial_call_count == before  # rejected pre-dial
    # Control: a path genuinely under the root passes the allowlist (it then
    # fails later on context_not_found/dial — NOT ref_outside_allowlist).
    (root / "kubeconfig").write_text("x")
    result2 = await server.connect_cluster(
        name="boundary-ok", credential_ref=f"kubeconfig:{root}/kubeconfig#ctx")
    assert result2.get("code") != "ref_outside_allowlist", (
        f"path under root must pass the allowlist; got {result2}")


# ── Negative: secret: without cluster_registry entry → missing_cluster_registry_entry

@pytest.mark.asyncio
async def test_connect_cluster_missing_cluster_registry(server, monkeypatch, tmp_path):
    """secret: ref passes allowlist but cluster_registry has no entry → missing_cluster_registry_entry."""
    # Create a dummy directory under a configured root
    secret_dir = tmp_path / "secrets" / "my-cluster"
    secret_dir.mkdir(parents=True)

    cfg = _cfg_with_roots(roots=[str(tmp_path)])
    monkeypatch.setattr(server, "_lumino_config", cfg)

    before = server._dial_call_count
    result = await server.connect_cluster(
        name="reg-test", credential_ref=f"secret:{secret_dir}"
    )
    assert result.get("code") == "missing_cluster_registry_entry", (
        f"Expected missing_cluster_registry_entry; got {result}"
    )
    assert server._dial_call_count == before


# ── Negative: duplicate name → duplicate_name ────────────────────────────────

@pytest.mark.asyncio
async def test_connect_cluster_duplicate_name(server, monkeypatch, tmp_path):
    """Connecting with a name already in the registry → duplicate_name.

    'kubernetes' is always in the registry (default instance).
    Uses a root of '/' so the path allowlist passes before the duplicate check.
    """
    cfg = _cfg_with_roots(roots=["/"])
    monkeypatch.setattr(server, "_lumino_config", cfg)

    before = server._dial_call_count
    result = await server.connect_cluster(
        name="kubernetes", credential_ref="kubeconfig:/some/path#ctx"
    )
    assert result.get("code") == "duplicate_name", (
        f"Expected duplicate_name; got {result}"
    )
    assert server._dial_call_count == before


# ── Positive: fake dial + canned detection → success ─────────────────────────

@pytest.mark.asyncio
async def test_connect_cluster_success_shape(server, monkeypatch, tmp_path, caplog):
    """connect_cluster success path: correct shape, list_changed once, instance connected.

    Also asserts that a bearer token value is absent from json.dumps(result)
    and from captured log records (secret-absence guarantee).
    """
    # ─ Config with credential_ref_roots so kubeconfig path passes allowlist ───
    cfg = _cfg_with_roots(roots=[str(tmp_path)])
    monkeypatch.setattr(server, "_lumino_config", cfg)

    # ─ Write a minimal kubeconfig under tmp_path ──────────────────────────────
    kube_path = tmp_path / "cluster.kubeconfig"
    fake_token = "s3cr3t-bearer-tok3n-xyz"
    kube_path.write_text(f"""\
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:9999
  name: t5-cluster
contexts:
- context:
    cluster: t5-cluster
    user: t5-user
  name: t5-context
current-context: t5-context
users:
- name: t5-user
  user:
    token: "{fake_token}"
""")

    # ─ Fake _build_k8s_client_set (the dial + probe site) ─────────────────────
    # The blocking function calls _build_k8s_client_set(context, path) then
    # cs.apis_api.get_api_versions().  Supply a fake that returns immediately.
    _probe_return = _SN(groups=[])
    _fake_apis = FakeApi(get_api_versions=_probe_return)
    _fake_cs = server.K8sClientSet(
        core_api=FakeApi(), apps_api=FakeApi(), custom_api=FakeApi(),
        batch_api=FakeApi(), storage_api=FakeApi(), networking_api=FakeApi(),
        autoscaling_api=FakeApi(), apis_api=_fake_apis,
    )

    def fake_build(context, kubeconfig_path=None):
        # Mirror the real function: increment _dial_call_count
        server._dial_call_count += 1
        return _fake_cs

    monkeypatch.setattr(server, "_build_k8s_client_set", fake_build)

    # ─ Capture send_tool_list_changed calls ───────────────────────────────────
    list_changed_calls = []

    class _FakeSession:
        async def send_tool_list_changed(self):
            list_changed_calls.append(1)

    class _FakeMcpCtx:
        session = _FakeSession()

    original_mcp = server.mcp

    class _FakeMcp:
        _tool_manager = original_mcp._tool_manager

        def get_context(self):
            return _FakeMcpCtx()

        # Delegate any other attribute lookup to the real mcp
        def __getattr__(self, item):
            return getattr(original_mcp, item)

    monkeypatch.setattr(server, "mcp", _FakeMcp())

    # ─ Use a name unique to this test run ─────────────────────────────────────
    unique_name = "t5-success-cluster"
    # Clean up registry entry from a previous test run in the same session
    server._source_registry._entries.pop(unique_name, None)
    server._k8s_conn_state.pop(unique_name, None)
    server._k8s_instances.pop(unique_name, None)

    # ─ Call connect_cluster (capture logs via pytest caplog) ──────────────────
    result = await server.connect_cluster(
        name=unique_name,
        credential_ref=f"kubeconfig:{kube_path}#t5-context",
    )

    # ─ Assertions ─────────────────────────────────────────────────────────────
    assert result.get("connected") is True, (
        f"Expected connected=True; got {result}"
    )
    assert result["name"] == unique_name, (
        f"Expected name={unique_name!r}; got {result.get('name')!r}"
    )
    assert isinstance(result.get("extensions"), dict), (
        f"Expected extensions dict; got {result.get('extensions')!r}"
    )
    assert isinstance(result.get("tools_added"), list), (
        f"Expected tools_added list; got {result.get('tools_added')!r}"
    )

    # list_changed sent exactly once
    assert len(list_changed_calls) == 1, (
        f"Expected send_tool_list_changed called once; got {len(list_changed_calls)}"
    )

    # Instance visible in list_sources with connection "connected"
    list_result = await server.list_sources()
    sources = {s["name"]: s for s in list_result["sources"]}
    assert unique_name in sources, (
        f"Expected {unique_name!r} in list_sources; got {sorted(sources)}"
    )
    assert sources[unique_name].get("connection") == "connected", (
        f"Expected connection=connected; got {sources[unique_name]}"
    )

    # Secret-absence: fake token must not appear in result or captured log records
    result_json = _json.dumps(result)
    assert fake_token not in result_json, (
        f"Bearer token leaked into json.dumps(result): {result_json[:200]}"
    )
    assert fake_token not in caplog.text, (
        f"Bearer token leaked into log records: {caplog.text[:200]}"
    )


# ─── Task 5 security fixes: TLS fail-closed, rollback, token-path pin ────────

# ── TLS fail-closed: no ca_file must NOT set verify_ssl=False ────────────────

def test_build_k8s_client_set_from_token_tls_fail_closed(server):
    """_build_k8s_client_set_from_token without ca_file must NOT disable TLS verification.

    IMPORTANT 1 guard: verify_ssl must stay at its secure default (True).
    Providing ca_file=None must NOT produce a configuration with verify_ssl=False,
    which would expose the bearer token to MITM.

    We capture the Configuration object by monkeypatching ApiClient to record it.
    """
    import threading as _threading

    captured_configs = []

    original_api_client = server.client.ApiClient

    class _CapturingApiClient(original_api_client):
        def __init__(self, configuration=None, **kwargs):
            captured_configs.append(configuration)
            super().__init__(configuration=configuration, **kwargs)

    # Save and restore so the patch doesn't bleed
    original = server.client.ApiClient
    server.client.ApiClient = _CapturingApiClient
    try:
        try:
            server._build_k8s_client_set_from_token(
                "https://127.0.0.1:1", "fake-token", ca_file=None
            )
        except Exception:
            pass  # connection failure is expected; we only care about config

        assert captured_configs, "ApiClient was never constructed — test setup wrong"
        cfg = captured_configs[0]
        assert getattr(cfg, "verify_ssl", True) is not False, (
            "SECURITY: _build_k8s_client_set_from_token must NOT set verify_ssl=False "
            "when ca_file is absent — fail-closed TLS is required."
        )
    finally:
        server.client.ApiClient = original


# ── Dial-failure → instance rolled back, name retryable ──────────────────────

@pytest.mark.asyncio
async def test_connect_cluster_dial_failure_rolls_back(server, monkeypatch, tmp_path):
    """Dial failure → instance rolled back from registry; same-name retry reaches dial again.

    IMPORTANT 2: add_instance happens before dial; on dial_failed the instance
    must be REMOVED from registry and conn_state so the name is cleanly retryable.

    Uses extensions={"tekton": "auto"} so mutation (d) (detection before dial) would
    set _extension_states for the failed instance — the assertion below kills that mutant.
    """
    from core.config_types import ResolvedConfig as _RCd, SourceConfig as _SCd

    # IMPORTANT: include an extension (tekton=auto) so mutation (d) — detection
    # before dial — would set _extension_states entries for the failed instance.
    cfg = _RCd(
        profile="test",
        sources={"kubernetes": _SCd(adapter="kubernetes",
                                   options={"credential_ref_roots": ["/"]})},
        extensions={"tekton": "auto"},
    )
    monkeypatch.setattr(server, "_lumino_config", cfg)

    # Canned detect_and_register so detection doesn't hit the real network.
    # With production code (detection after dial): NEVER called on dial failure.
    # With mutation (d) (detection before dial): CALLED → sets _extension_states.
    detection_calls = []

    async def spy_detect(ext, facade, ctx, timeout_s=2.0):
        detection_calls.append(ctx.instance)
        return ("not-detected: absent", [])

    monkeypatch.setattr(server, "detect_and_register", spy_detect)

    unique_name = "t5-dialfail-cluster"
    server._source_registry._entries.pop(unique_name, None)
    server._k8s_conn_state.pop(unique_name, None)
    server._k8s_instances.pop(unique_name, None)

    dial_calls = []

    def fake_build_fail(context, kubeconfig_path=None):
        server._dial_call_count += 1
        dial_calls.append("dial")
        raise ConnectionError("connection refused (test-injected)")

    monkeypatch.setattr(server, "_build_k8s_client_set", fake_build_fail)

    before = server._dial_call_count

    # First call: expect dial_failed
    result = await server.connect_cluster(
        name=unique_name, credential_ref="kubeconfig:/any/path#ctx"
    )
    assert result.get("code") == "dial_failed", (
        f"Expected dial_failed; got {result}"
    )
    assert server._dial_call_count > before, "Dial must have been attempted"

    # Instance MUST be rolled back from registry
    assert unique_name not in server._source_registry._entries, (
        "Dial failure must remove instance from registry (zombie-instance prevention)"
    )
    # conn_state must be absent (not left as error:...)
    assert unique_name not in server._k8s_conn_state, (
        "Dial failure must remove conn_state entry (clean retry semantics)"
    )
    # No extension states set for the failed instance (detection must not run on dial failure)
    # Mutation (d) — detection before dial — would set _extension_states here even on failure
    assert not any(
        k[1] == unique_name for k in server._extension_states
    ), "Dial failure must not set _extension_states for the failed instance"
    assert unique_name not in detection_calls, (
        "Dial failure must not trigger detection (extension detection guards partial-registration)"
    )

    # Retry: same name must reach the dial again (not duplicate_name)
    result2 = await server.connect_cluster(
        name=unique_name, credential_ref="kubeconfig:/any/path#ctx"
    )
    assert result2.get("code") == "dial_failed", (
        f"Retry should reach dial again (not duplicate_name); got {result2}"
    )
    assert len(dial_calls) == 2, (
        f"Expected 2 dial attempts (first + retry); got {len(dial_calls)}"
    )


# ── Token-path secret-absence: env: scheme with canned detection ─────────────

@pytest.mark.asyncio
async def test_connect_cluster_env_token_path_secret_absence(server, monkeypatch, caplog):
    """connect_cluster with env: scheme: token never appears in result or logs.

    IMPORTANT 3 token-path pin: the env: path reads os.environ[var] inside the
    blocking thread and passes it to _build_k8s_client_set_from_token, which
    must never store the token value in the result dict or log it.

    Also verifies tools_added is populated by monkeypatching detect_and_register
    to return a canned ("active", [one_existing_tool_name]) so the rebind step
    runs without requiring a fresh facade.  This exercises the full
    dial → detection → rebind → notify path while keeping the fixture minimal.
    """
    from core.config_types import ResolvedConfig as _RC2, SourceConfig as _SC2

    fake_token = "t3st-b3ar3r-s3cr3t-xyz123"
    unique_name = "t5-env-cluster-tok"

    # Config: env allowlist + cluster_registry + tekton=auto
    cfg = _RC2(
        profile="test",
        sources={"kubernetes": _SC2(
            adapter="kubernetes",
            options={
                "credential_ref_roots": [],
                "credential_ref_env_allowlist": ["LUMINO_T5_SECRET_TEST"],
                "cluster_registry": {unique_name: {"server": "https://127.0.0.1:9998"}},
            },
        )},
        extensions={"tekton": "auto"},
    )
    monkeypatch.setattr(server, "_lumino_config", cfg)
    monkeypatch.setenv("LUMINO_T5_SECRET_TEST", fake_token)

    # Fake _build_k8s_client_set_from_token: returns immediately without network I/O.
    # The token is received here but NEVER stored or logged.
    _probe_sn = _SN(groups=[])
    _fake_apis = FakeApi(get_api_versions=_probe_sn)
    _fake_cs = server.K8sClientSet(
        core_api=FakeApi(), apps_api=FakeApi(), custom_api=FakeApi(),
        batch_api=FakeApi(), storage_api=FakeApi(), networking_api=FakeApi(),
        autoscaling_api=FakeApi(), apis_api=_fake_apis,
    )

    def fake_build_token(server_url, token, ca_file=None):
        server._dial_call_count += 1
        return _fake_cs

    monkeypatch.setattr(server, "_build_k8s_client_set_from_token", fake_build_token)

    # Canned detect_and_register: returns one "newly added" tool name that IS
    # already in _extension_facade.registered (from startup 'on' registration).
    # This exercises the rebind step without needing a fresh facade.
    _canned_tool_name = "analyze_failed_pipeline"  # a real tekton tool in the facade

    async def fake_detect_and_register(ext, facade, ctx, timeout_s=2.0):
        if ctx.instance == unique_name and ext.name == "tekton":
            return ("active", [_canned_tool_name])
        return ("not-detected: absent", [])

    monkeypatch.setattr(server, "detect_and_register", fake_detect_and_register)

    # Clean up state from any previous test run in this session
    server._source_registry._entries.pop(unique_name, None)
    server._k8s_conn_state.pop(unique_name, None)
    server._k8s_instances.pop(unique_name, None)
    for k in [k for k in server._extension_states if k[1] == unique_name]:
        del server._extension_states[k]

    result = await server.connect_cluster(
        name=unique_name,
        credential_ref="env:LUMINO_T5_SECRET_TEST",
    )

    assert result.get("connected") is True, (
        f"Expected connected=True; got {result}"
    )

    # tools_added must be non-empty (canned detection returns one tool name)
    tools_added = result.get("tools_added", [])
    assert len(tools_added) > 0, (
        f"Expected tools_added non-empty (canned detect_and_register returned one); "
        f"got {tools_added!r}"
    )
    assert _canned_tool_name in tools_added, (
        f"Expected {_canned_tool_name!r} in tools_added; got {tools_added!r}"
    )

    # Secret-absence: token must not appear in result JSON or captured log records.
    # The token travels through os.environ → _token local var → fake_build_token arg.
    # None of these paths should put it in the result dict or logs.
    result_json = _json.dumps(result)
    assert fake_token not in result_json, (
        f"SECURITY: bearer token leaked into json.dumps(result): {result_json[:300]}"
    )
    assert fake_token not in caplog.text, (
        f"SECURITY: bearer token leaked into log records: {caplog.text[:300]}"
    )

# ── Task 7 (phase2eb): dial_failed secret-absence pin ────────────────────────


@pytest.mark.asyncio
async def test_connect_cluster_dial_failed_secret_absence(
    server, monkeypatch, tmp_path, caplog
):
    """dial_failed path: exception message sentinel NEVER appears in result or logs.

    IMPORTANT 4 (§4.7 dial_failed pin): _build_k8s_client_set raises with a
    sentinel string embedded in the exception message.  The connect_cluster
    exception handler must NOT echo str(exc) back in the result dict — doing
    so would expose any secrets that a k8s/urllib3 error string might carry
    (Authorization header leakage is theoretically possible via urllib3
    MaxRetryError messages that include the full URL or headers).

    Contract: result["error"] must be the exception CLASS name + a static
    hint string, never str(exc).  caplog must also be clean.
    """
    SENTINEL = "sk-FAKE-SENTINEL-9x7"
    unique_name = "t7-dialfail-sentinel"

    # Config: credential_ref_roots points at tmp_path so the allowlist passes.
    cfg = _cfg_with_roots(roots=[str(tmp_path)])
    monkeypatch.setattr(server, "_lumino_config", cfg)

    # Write any file under tmp_path so realpath resolves and the path string
    # is non-empty; the file content does not matter (_build_k8s_client_set
    # is patched before it reads anything).
    kube_file = tmp_path / "sentinel-test.kubeconfig"
    kube_file.write_text("# placeholder\n")

    # _build_k8s_client_set raises with the sentinel embedded in the message.
    def fake_build_sentinel(context, kubeconfig_path=None):
        server._dial_call_count += 1
        raise ConnectionError(
            f"apiserver unreachable: token={SENTINEL}"
        )

    monkeypatch.setattr(server, "_build_k8s_client_set", fake_build_sentinel)

    # Clean state from any prior run in this session.
    server._source_registry._entries.pop(unique_name, None)
    server._k8s_conn_state.pop(unique_name, None)
    server._k8s_instances.pop(unique_name, None)
    for k in [k for k in server._extension_states if k[1] == unique_name]:
        del server._extension_states[k]

    # Capture DEBUG and above for the lumino-mcp logger so a leak at any level
    # is detected (caplog defaults to WARNING, which would miss INFO/DEBUG leaks).
    caplog.set_level(_logging.DEBUG, logger="lumino-mcp")

    result = await server.connect_cluster(
        name=unique_name,
        credential_ref=f"kubeconfig:{kube_file}#fake-ctx",
    )

    # Must reach the dial and return dial_failed.
    assert result.get("code") == "dial_failed", (
        f"Expected code=dial_failed; got {result}"
    )

    # Log leg must not be vacuous: the dial_failed warning must have fired,
    # confirming that the log assertion below has real teeth.
    dial_fail_records = [
        r for r in caplog.records if "dial failed" in r.getMessage()
    ]
    assert dial_fail_records, (
        "Expected at least one 'dial failed' log record from connect_cluster; "
        f"got records: {[r.getMessage() for r in caplog.records]}"
    )

    # SECURITY: sentinel must not appear in json.dumps(result).
    result_json = _json.dumps(result)
    assert SENTINEL not in result_json, (
        f"SECURITY: sentinel leaked into json.dumps(result): {result_json[:300]}"
    )

    # SECURITY: sentinel must not appear in any captured log record.
    assert SENTINEL not in caplog.text, (
        f"SECURITY: sentinel leaked into log records: {caplog.text[:300]}"
    )


# ─── Task 2 (phase2eb): source= + extension gating + dispatch on 10 tools ────
#
# Step 1 (RED) test families:
#   (a) M5 shape: unknown source → per-tool F1 error shape (both _err AND _gerr)
#   (b) M1 gate wiring: tekton active on A not B → shape + dispatch
#   (c) Dispatch reality: representative 5 with poisoned-global spy
#   (d) Default-path identity: no source → module-global fake used
#   (e) Dead-cluster bound: get_etcd_logs with blocking ClientSet → cancellable

import asyncio as _asyncio
import threading as _threading
import functools as _functools


# ─── Shared helper ───────────────────────────────────────────────────────────

def _register_t2_instance(server, monkeypatch, name: str, fake_cs,
                           ext: str = "tekton", ext_state: str = "active"):
    """Register `name` in registry + _k8s_instances + optionally set extension state."""
    k8s_caps = server._source_registry.get("kubernetes").capabilities
    monkeypatch.setitem(
        server._source_registry._entries, name,
        SourceEntry(name=name, adapter="kubernetes", capabilities=k8s_caps, state="configured"),
    )
    monkeypatch.setitem(server._k8s_instances, name, fake_cs)
    if ext_state is not None:
        monkeypatch.setitem(server._extension_states, (ext, name), ext_state)


# ─── (a) M5 shape tests: unknown source → per-tool error shapes ─────────────

@pytest.mark.asyncio
async def test_t2_m5_list_pipelineruns_unknown_source_list_shape(server):
    """list_pipelineruns(source='t2-nope') → [err_dict] (err shape per F1)."""
    result = await server.list_pipelineruns(namespace="team-a", source="t2-nope")
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert result, "Expected non-empty list"
    err = result[0]
    assert "error" in err and "known_kubernetes_instances" in err, (
        f"F1 keys missing from _err shape: {sorted(err)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_list_taskruns_unknown_source_list_shape(server):
    """list_taskruns(source='t2-nope') → [err_dict] (err shape per F1)."""
    result = await server.list_taskruns(namespace="team-a", source="t2-nope")
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert result, "Expected non-empty list"
    err = result[0]
    assert "error" in err and "known_kubernetes_instances" in err, (
        f"F1 keys missing from _err shape: {sorted(err)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_get_etcd_logs_unknown_source_dict_str_shape(server):
    """get_etcd_logs(source='t2-nope') → {"error": str} — no list-valued keys."""
    result = await server.get_etcd_logs(source="t2-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result, f"Missing 'error' key: {result}"
    assert isinstance(result["error"], str), f"error must be str: {result}"
    assert "known_kubernetes_instances" not in result, (
        f"Dict[str,str] shape must NOT include list-valued keys: {result}"
    )


@pytest.mark.asyncio
async def test_t2_m5_list_recent_pipeline_runs_unknown_source_flat_dict(server):
    """list_recent_pipeline_runs(source='t2-nope') → {"error": str} flat dict."""
    result = await server.list_recent_pipeline_runs(source="t2-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result, f"Missing 'error' key: {result}"
    assert isinstance(result["error"], str), f"error must be str: {result}"
    # Must NOT have 'pipeline_runs' key (wrong error shape per F1)
    assert "pipeline_runs" not in result, (
        f"list_recent_pipeline_runs error shape must be flat; got keys: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_get_pipelinerun_logs_unknown_source_verbatim_err(server):
    """get_pipelinerun_logs(source='t2-nope') → _err verbatim (all F1 keys present)."""
    result = await server.get_pipelinerun_logs(
        pipelinerun_name="pr-1", namespace="team-a", source="t2-nope"
    )
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result and "known_kubernetes_instances" in result, (
        f"_err verbatim must include known_kubernetes_instances: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_analyze_failed_pipeline_unknown_source_verbatim_err(server):
    """analyze_failed_pipeline(source='t2-nope') → _err verbatim."""
    result = await server.analyze_failed_pipeline(
        namespace="team-a", pipeline_run="pr-1", source="t2-nope"
    )
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result and "known_kubernetes_instances" in result, (
        f"_err verbatim must include known_kubernetes_instances: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_find_pipeline_unknown_source_verbatim_err(server):
    """find_pipeline(source='t2-nope') → _err verbatim."""
    result = await server.find_pipeline(
        pipeline_id_pattern="build", source="t2-nope"
    )
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result and "known_kubernetes_instances" in result, (
        f"_err verbatim must include known_kubernetes_instances: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_get_tekton_pipeline_runs_status_unknown_source_verbatim(server):
    """get_tekton_pipeline_runs_status(source='t2-nope') → _err verbatim."""
    result = await server.get_tekton_pipeline_runs_status(source="t2-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result and "known_kubernetes_instances" in result, (
        f"_err verbatim must include known_kubernetes_instances: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_get_machine_config_pool_status_unknown_source_verbatim(server):
    """get_machine_config_pool_status(source='t2-nope') → _err verbatim."""
    result = await server.get_machine_config_pool_status(source="t2-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result and "known_kubernetes_instances" in result, (
        f"_err verbatim must include known_kubernetes_instances: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_get_openshift_cluster_operator_status_unknown_source_verbatim(server):
    """get_openshift_cluster_operator_status(source='t2-nope') → _err verbatim."""
    result = await server.get_openshift_cluster_operator_status(source="t2-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result and "known_kubernetes_instances" in result, (
        f"_err verbatim must include known_kubernetes_instances: {sorted(result)}"
    )


# M5 _gerr shape: gate-blocked (known instance, extension not active) ─────────

@pytest.mark.asyncio
async def test_t2_m5_gerr_list_pipelineruns_gate_blocked_list_shape(server, monkeypatch):
    """Gate blocks list_pipelineruns → [gerr_dict] shape (extension NOT active)."""
    name = "t2-gate-plr"
    fake_cs = _make_cs(server)
    _register_t2_instance(server, monkeypatch, name, fake_cs,
                          ext="tekton", ext_state="not-detected: absent")

    result = await server.list_pipelineruns(namespace="team-a", source=name)
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert result, "Expected non-empty list (gate error)"
    err = result[0]
    assert "error" in err and "extension" in err, (
        f"_gerr shape must have 'extension' key: {sorted(err)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_gerr_get_etcd_logs_gate_blocked_dict_str_shape(server, monkeypatch):
    """Gate blocks get_etcd_logs → {"error": str} — strips list-valued keys."""
    name = "t2-gate-etcd"
    fake_cs = _make_cs(server)
    _register_t2_instance(server, monkeypatch, name, fake_cs,
                          ext="openshift", ext_state="not-detected: absent")

    result = await server.get_etcd_logs(source=name)
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result, f"Missing 'error' key in gerr dict: {result}"
    assert isinstance(result["error"], str), f"error must be str"
    assert "known_kubernetes_instances" not in result, (
        f"Dict[str,str] shape must NOT include list-valued keys: {sorted(result)}"
    )


@pytest.mark.asyncio
async def test_t2_m5_gerr_list_recent_pipeline_runs_gate_blocked_flat_dict(server, monkeypatch):
    """Gate blocks list_recent_pipeline_runs → {"error": str} flat dict."""
    name = "t2-gate-lrpr"
    fake_cs = _make_cs(server)
    _register_t2_instance(server, monkeypatch, name, fake_cs,
                          ext="tekton", ext_state="not-detected: absent")

    result = await server.list_recent_pipeline_runs(source=name)
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result, f"Missing 'error' key: {result}"
    assert "pipeline_runs" not in result, (
        f"Flat error dict must not have 'pipeline_runs': {sorted(result)}"
    )


# ─── (b) M1 gate wiring: tekton active on A not B ────────────────────────────

@pytest.mark.asyncio
async def test_t2_m1_gate_b_rejected_a_dispatched_list_pipelineruns(server, monkeypatch):
    """Tekton active on ctx-A but not ctx-B.

    list_pipelineruns(source='ctx-B') → [gate_error_dict] (tekton not active).
    list_pipelineruns(source='ctx-A') → [] or data (gate passes, dispatch used).
    """
    # Fake ClientSet for A: returns empty pipeline runs
    fake_custom_a = FakeApi(list_namespaced_custom_object={"items": []})
    fake_cs_a = _make_cs(server, custom_api=fake_custom_a)
    fake_cs_b = _make_cs(server)  # will not be reached if gate blocks

    _register_t2_instance(server, monkeypatch, "t2-gate-ctxA", fake_cs_a,
                          ext="tekton", ext_state="active")
    _register_t2_instance(server, monkeypatch, "t2-gate-ctxB", fake_cs_b,
                          ext="tekton", ext_state="not-detected: absent")

    # Poison module globals so we can verify dispatch uses _clients
    monkeypatch.setattr(server, "k8s_custom_api", FakeApi())  # any method → AttributeError

    # B rejected by gate
    result_b = await server.list_pipelineruns(namespace="team-a", source="t2-gate-ctxB")
    assert isinstance(result_b, list), f"Expected list, got {type(result_b)}"
    assert result_b, "Expected non-empty list (gate error)"
    assert "extension" in result_b[0], (
        f"Gate error must have 'extension' key: {result_b[0]}"
    )

    # A passes gate and dispatches to fake_cs_a (not the poisoned global)
    result_a = await server.list_pipelineruns(namespace="team-a", source="t2-gate-ctxA")
    assert isinstance(result_a, list), f"Expected list from ctx-A; got {type(result_a)}"
    # result_a may be [] (empty) or data; must NOT be a gate error
    if result_a:
        assert "extension" not in result_a[0], (
            f"ctx-A should NOT get gate error; got: {result_a[0]}"
        )


# ─── (c) Dispatch reality: representative 5 with poisoned-global spy ─────────

@pytest.mark.asyncio
async def test_t2_dispatch_list_pipelineruns_uses_ctx_client(server, monkeypatch):
    """list_pipelineruns(source='t2d-plr') uses _clients.custom_api, not module global.

    Strengthened: fake returns a distinctive PipelineRun; assertion demands the run's
    name appear in the result — an error dict (from the poisoned global) must FAIL.
    """
    monkeypatch.setattr(server, "k8s_custom_api", FakeApi())  # poison

    _plr = PIPELINERUN("dispatch-spy-plr", "team-a", succeeded=True)
    fake_custom = FakeApi(list_namespaced_custom_object={"items": [_plr]})
    fake_cs = _make_cs(server, custom_api=fake_custom)
    _register_t2_instance(server, monkeypatch, "t2d-plr", fake_cs,
                          ext="tekton", ext_state="active")

    result = await server.list_pipelineruns(namespace="team-a", source="t2d-plr")
    assert isinstance(result, list), f"Expected list; got {type(result)}"
    assert result, f"Expected non-empty list from fake custom_api; got {result!r}"
    names = [r.get("name") for r in result if isinstance(r, dict)]
    assert "dispatch-spy-plr" in names, (
        f"Expected 'dispatch-spy-plr' from fake custom_api; got names={names!r}, "
        f"result={result!r}. An error-dict means the poisoned global was used."
    )


@pytest.mark.asyncio
async def test_t2_dispatch_get_pipelinerun_logs_uses_ctx_client(server, monkeypatch):
    """get_pipelinerun_logs(source='t2d-gpl') uses _clients.core_api for pod listing and log fetch.

    Strengthened: fake returns one pod and a recording read_namespaced_pod_log.
    Asserts the helper-mediated log-fetch contact (get_all_pod_logs) is OBSERVED on
    the fake, AND distinctive log content appears in the result — an error or no-pods
    info response must FAIL both checks.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())  # poison

    DISTINCTIVE_LOG = "dispatch-spy-log-xkcd-327"
    log_fetch_calls = []

    def fake_read_pod_log(**kwargs):
        log_fetch_calls.append(kwargs)
        return DISTINCTIVE_LOG

    pr_pod = POD("pr-1-build-pod", "team-a")
    fake_core = FakeApi(
        list_namespaced_pod=_SN(items=[pr_pod]),
        read_namespaced_pod=pr_pod,
        read_namespaced_pod_log=fake_read_pod_log,
    )
    fake_cs = _make_cs(server, core_api=fake_core)
    _register_t2_instance(server, monkeypatch, "t2d-gpl", fake_cs,
                          ext="tekton", ext_state="active")

    result = await server.get_pipelinerun_logs(
        pipelinerun_name="pr-1", namespace="team-a", source="t2d-gpl",
        tail_lines=10,  # non-adaptive mode: avoids asyncio.sleep(0.2) delay
    )
    assert isinstance(result, dict), f"Expected dict; got {type(result)}"
    assert "error" not in result, (
        f"Expected successful log result (not error from poisoned global); got {result!r}"
    )
    assert "info" not in result, (
        f"Expected pods-found path (not no-pods info); got {result!r}"
    )
    assert log_fetch_calls, (
        "read_namespaced_pod_log was never called — "
        "helper-mediated log-fetch contact (get_all_pod_logs) not observed on fake"
    )
    assert DISTINCTIVE_LOG in str(result), (
        f"Expected {DISTINCTIVE_LOG!r} in result; got {result!r}. "
        "Log content missing means the fake was not used for log fetching."
    )


@pytest.mark.asyncio
async def test_t2_dispatch_analyze_failed_pipeline_list_taskruns_partial(server, monkeypatch):
    """analyze_failed_pipeline spy: list_taskruns_func hop uses source=source (partial).

    The indirected seam: get_pipeline_details receives functools.partial(list_taskruns,
    source=source). When called as list_taskruns_func(ns, pr), that becomes
    list_taskruns(ns, pr, source=source). The spy captures source=.
    """
    monkeypatch.setattr(server, "k8s_custom_api", FakeApi())  # poison

    tr_spy_calls = []

    async def _spy_list_taskruns(namespace, pipeline_run=None, source=""):
        tr_spy_calls.append({"source": source})
        return []  # no task runs

    monkeypatch.setattr(server, "list_taskruns", _spy_list_taskruns)

    # Succeeded PipelineRun: analyze_failed_pipeline calls list_taskruns_func then
    # returns {"error": "Pipeline did not fail"} — task spy IS called at this point
    _fake_pr = {
        "metadata": {"name": "pr-1", "labels": {}, "namespace": "team-a"},
        "spec": {},
        "status": {
            "conditions": [{"type": "Succeeded", "status": "True",
                            "reason": "Succeeded", "message": "done"}],
            "startTime": "2026-07-20T09:00:00Z",
            "completionTime": "2026-07-20T09:05:00Z",
        },
    }
    fake_custom = FakeApi(get_namespaced_custom_object=_fake_pr)
    fake_cs = _make_cs(server, custom_api=fake_custom)
    _register_t2_instance(server, monkeypatch, "t2d-afp", fake_cs,
                          ext="tekton", ext_state="active")

    result = await server.analyze_failed_pipeline(
        namespace="team-a", pipeline_run="pr-1", source="t2d-afp"
    )
    # Succeeded pipeline → "did not fail" error
    assert isinstance(result, dict), f"Expected dict; got {type(result)}"

    # The spy must have been called with source="t2d-afp" (proving partial binding)
    assert tr_spy_calls, "list_taskruns_func was never called (spy not triggered)"
    assert tr_spy_calls[0]["source"] == "t2d-afp", (
        f"list_taskruns_func must be partial(list_taskruns, source='t2d-afp'); "
        f"spy recorded source={tr_spy_calls[0]['source']!r}"
    )


@pytest.mark.asyncio
async def test_t2_dispatch_get_etcd_logs_uses_ctx_client(server, monkeypatch):
    """get_etcd_logs(source='t2d-etcd') uses _clients.core_api, not module global.

    Strengthened: fake returns one etcd-named pod and a recording read_namespaced_pod_log.
    Asserts the recorder was called AND distinctive log content appears in the result —
    an error result (from the poisoned global's except path) must FAIL both checks.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())  # poison

    DISTINCTIVE_LOG = "dispatch-etcd-spy-log-xkcd-327"
    log_fetch_calls = []

    def fake_read_pod_log(**kwargs):
        log_fetch_calls.append(kwargs)
        return DISTINCTIVE_LOG

    etcd_pod = POD("etcd-master-0", "openshift-etcd")
    fake_core = FakeApi(
        list_namespaced_pod=_SN(items=[etcd_pod]),
        read_namespaced_pod_log=fake_read_pod_log,
    )
    fake_cs = _make_cs(server, core_api=fake_core)
    _register_t2_instance(server, monkeypatch, "t2d-etcd", fake_cs,
                          ext="openshift", ext_state="active")

    result = await server.get_etcd_logs(source="t2d-etcd")
    assert isinstance(result, dict), f"Expected dict; got {type(result)}"
    assert log_fetch_calls, (
        "read_namespaced_pod_log was never called — "
        "the fake core_api log-read contact was not observed on the fake"
    )
    assert DISTINCTIVE_LOG in str(result), (
        f"Expected {DISTINCTIVE_LOG!r} in result; got {result!r}. "
        "Log content missing means the poisoned global was used instead of the fake."
    )


@pytest.mark.asyncio
async def test_t2_dispatch_get_openshift_cluster_operator_status_uses_ctx_client(
    server, monkeypatch
):
    """get_openshift_cluster_operator_status(source='t2d-ocos') uses _clients.custom_api.

    Strengthened: fake returns a distinctive clusteroperator item; assertion demands
    its name appear in operator_status — an empty operator_status (produced by the
    poisoned global's except handler) must FAIL.
    """
    monkeypatch.setattr(server, "k8s_custom_api", FakeApi())  # poison

    def fake_list_cluster_custom(**kwargs):
        if kwargs.get("plural") == "clusteroperators":
            return {"items": [{
                "metadata": {"name": "dispatch-spy-op"},
                "status": {"conditions": [], "versions": [], "relatedObjects": []},
            }]}
        return {"items": []}  # clusterversions → cluster_info uses fallback defaults

    fake_custom = FakeApi(list_cluster_custom_object=fake_list_cluster_custom)
    fake_cs = _make_cs(server, custom_api=fake_custom)
    _register_t2_instance(server, monkeypatch, "t2d-ocos", fake_cs,
                          ext="openshift", ext_state="active")

    result = await server.get_openshift_cluster_operator_status(source="t2d-ocos")
    assert isinstance(result, dict), f"Expected dict; got {type(result)}"
    assert "operator_status" in result, (
        f"Expected operator_status in result; got {sorted(result)}"
    )
    op_names = [op.get("name") for op in result.get("operator_status", [])]
    assert "dispatch-spy-op" in op_names, (
        f"Expected 'dispatch-spy-op' in operator names; got {op_names!r}. "
        "An empty operator_status means the poisoned global's except handler ran."
    )


# ─── (d) Default-path identity: no source → module-global used ───────────────

@pytest.mark.asyncio
async def test_t2_default_path_list_pipelineruns(server, monkeypatch):
    """list_pipelineruns() (no source) uses module-global k8s_custom_api."""
    fake_custom = FakeApi(list_namespaced_custom_object={"items": []})
    monkeypatch.setattr(server, "k8s_custom_api", fake_custom)

    result = await server.list_pipelineruns(namespace="team-a")
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    # Result should be [] (empty, from fake) not an error
    assert result == [], f"Expected empty list from fake custom_api; got {result}"


# ─── (e) Dead-cluster bound: get_etcd_logs cancellable via to_thread ─────────

@pytest.mark.asyncio
async def test_t2_get_etcd_logs_to_thread_cancellable(server, monkeypatch):
    """After async conversion, get_etcd_logs is cancellable via asyncio.wait_for.

    A permanently-blocking list_namespaced_pod proves asyncio.to_thread is used:
    - WITH to_thread: event loop is free → wait_for(0.2s) fires → TimeoutError raised.
    - WITHOUT to_thread (sync blocking in event loop): loop is frozen → wait_for cannot
      fire → test hangs (never reaches the assertion).

    2e Task-4 precedent: same cancellability proof as _discover_api_groups.
    """
    block_evt = _threading.Event()

    class _BlockingCore:
        def list_namespaced_pod(self, **kw):
            block_evt.wait()  # blocks until unblocked in finally
            return _SN(items=[])

        def read_namespaced_pod_log(self, **kw):  # in case etcd pods are found
            block_evt.wait()
            return ""

    k8s_caps = server._source_registry.get("kubernetes").capabilities
    monkeypatch.setitem(
        server._source_registry._entries, "t2-dead",
        SourceEntry(name="t2-dead", adapter="kubernetes", capabilities=k8s_caps, state="configured"),
    )
    fake_cs = _make_cs(server, core_api=_BlockingCore())
    monkeypatch.setitem(server._k8s_instances, "t2-dead", fake_cs)
    monkeypatch.setitem(server._extension_states, ("openshift", "t2-dead"), "active")

    try:
        with pytest.raises(_asyncio.TimeoutError):
            await _asyncio.wait_for(
                server.get_etcd_logs(source="t2-dead"),
                timeout=0.2,
            )
    finally:
        block_evt.set()  # unblock the thread so it exits cleanly after test


# ─── Task 3 (phase2eb): k8s-leg upgrade (leaves) + core/aggregator source= ───
#
# Test families:
#   (a) Unknown source → Dict error for each of the 5 new-param tools
#   (b) M4 spy: per-aggregator + per-leaf dispatch — fake ClientSet used, NOT globals
#   (c) Core-2 dispatch reality with fake ClientSet
#   (d) Default-path identity for core-2 tools
#
# Line numbers in this block use "t3b-" prefix to avoid session-registry collisions.

import datetime as _dt


def _make_t3b_cs(server, **overrides):
    """Build a K8sClientSet with all 8 fields; overrides replace defaults (FakeApi())."""
    fields = dict(
        core_api=FakeApi(), apps_api=FakeApi(), custom_api=FakeApi(),
        batch_api=FakeApi(), storage_api=FakeApi(), networking_api=FakeApi(),
        autoscaling_api=FakeApi(), apis_api=FakeApi(),
    )
    fields.update(overrides)
    return server.K8sClientSet(**fields)


def _register_t3b_instance(server, monkeypatch, name: str, fake_cs):
    """Register a named k8s instance (no extension state needed for core/aggregator tools)."""
    k8s_caps = server._source_registry.get("kubernetes").capabilities
    monkeypatch.setitem(
        server._source_registry._entries, name,
        SourceEntry(name=name, adapter="kubernetes", capabilities=k8s_caps, state="configured"),
    )
    monkeypatch.setitem(server._k8s_instances, name, fake_cs)


# ─── (a) Unknown source → Dict error ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_t3_check_resource_constraints_unknown_source_dict_error(server):
    """check_resource_constraints(source='t3b-nope') → dict with 'error' key."""
    result = await server.check_resource_constraints(namespace="test-ns", source="t3b-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert "error" in result, f"Missing 'error' key: {result}"


@pytest.mark.asyncio
async def test_t3_check_cluster_certificate_health_unknown_source_dict_error(server):
    """check_cluster_certificate_health(source='t3b-nope') → dict with 'error' key."""
    result = await server.check_cluster_certificate_health(source="t3b-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert "error" in result, f"Missing 'error' key: {result}"


@pytest.mark.asyncio
async def test_t3_conservative_namespace_overview_unknown_source_dict_error(server):
    """conservative_namespace_overview(source='t3b-nope') → dict with 'error' key."""
    result = await server.conservative_namespace_overview(namespace="test-ns", source="t3b-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert "error" in result, f"Missing 'error' key: {result}"


@pytest.mark.asyncio
async def test_t3_adaptive_namespace_investigation_unknown_source_dict_error(server):
    """adaptive_namespace_investigation(source='t3b-nope') → dict with 'error' key."""
    result = await server.adaptive_namespace_investigation(namespace="test-ns", source="t3b-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert "error" in result, f"Missing 'error' key: {result}"


@pytest.mark.asyncio
async def test_t3_investigate_tls_unknown_source_dict_error(server):
    """investigate_tls_certificate_issues(source='t3b-nope') → dict with 'error' key."""
    result = await server.investigate_tls_certificate_issues(source="t3b-nope")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert "error" in result, f"Missing 'error' key: {result}"


# ─── (b) M4 spy: leaf dispatch ───────────────────────────────────────────────
#
# Pattern: register fake ClientSet under "t3b-leaf"; poison module globals;
# call leaf with source="t3b-leaf"; assert fake recorder was hit AND positive
# payload (not a poisoned-global AttributeError) landed in result.


@pytest.mark.asyncio
async def test_t3_smart_get_namespace_events_k8s_dispatch(server, monkeypatch):
    """smart_get_namespace_events(source='t3b-sge') dispatches to fake core_api.

    Poisoned module global: any call → AttributeError, proving it is never touched.
    Fake list_namespaced_event returns a distinctive event; recorder verifies the
    full chain: smart_get_namespace_events → _get_namespace_events_internal → fake.
    """
    # Poison module global
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    # Build recording fake
    event_calls = []

    def recording_list_event(*args, **kwargs):
        event_calls.append(1)
        return items_list([EVENT("Warning", "spy-t3b-sge-DISTINCTIVE", "spy-ns")])

    fake_core = FakeApi(list_namespaced_event=recording_list_event)
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-sge", fake_cs)

    result = await server.smart_get_namespace_events(
        namespace="spy-ns",
        time_period="6h",
        source="t3b-sge",
    )

    assert isinstance(result, dict), f"Expected dict result, got {type(result).__name__}: {result!r}"
    assert "error" not in result, (
        f"Expected no top-level error; got error from {result!r}. "
        "If poisoned global was used, FakeApi raises AttributeError → error dict."
    )
    assert event_calls, (
        "list_namespaced_event recorder was never called — "
        "smart_get_namespace_events did not reach _get_namespace_events_internal via fake."
    )


@pytest.mark.asyncio
async def test_t3_smart_summarize_pod_logs_k8s_dispatch(server, monkeypatch):
    """smart_summarize_pod_logs(source='t3b-ssp') dispatches to fake core_api.

    Uses tail_lines=10 to force manual mode (skip _quick_volume_estimate).
    Poisoned module global; recorder on read_namespaced_pod_log proves dispatch.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    log_fetch_calls = []

    def recording_log_read(*args, **kwargs):
        log_fetch_calls.append(1)
        return "ERROR: spy-t3b-ssp-DISTINCTIVE"

    fake_core = FakeApi(
        read_namespaced_pod=POD("spy-pod", "spy-ns"),
        read_namespaced_pod_log=recording_log_read,
    )
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-ssp", fake_cs)

    result = await server.smart_summarize_pod_logs(
        namespace="spy-ns",
        pod_name="spy-pod",
        tail_lines=10,  # manual mode: bypasses _quick_volume_estimate
        source="t3b-ssp",
    )

    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert "error" not in result, (
        f"Expected successful log analysis; got error. "
        "If poisoned global was used, read_namespaced_pod raises AttributeError → error."
    )
    assert log_fetch_calls, (
        "read_namespaced_pod_log recorder never called — "
        "smart_summarize_pod_logs did not reach get_pod_logs via fake core_api."
    )


# ─── (b) M4 spy: aggregator dispatch ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_t3_conservative_namespace_overview_dispatches_to_fake(server, monkeypatch):
    """conservative_namespace_overview(source='t3b-cno') — full chain via fake.

    Chain: conservative_namespace_overview
      → list_pods_in_namespace(source=source)     [records list_namespaced_pod]
      → smart_summarize_pod_logs(source=source)   [records read_namespaced_pod_log]
    Both recorders must fire; module global must NOT be touched.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    list_pod_calls = []

    def recording_list_pod(*args, **kwargs):
        list_pod_calls.append(1)
        return items_list([POD("t3b-cno-pod", "spy-ns")])

    log_fetch_calls = []

    def recording_log_read(*args, **kwargs):
        log_fetch_calls.append(1)
        return "spy-t3b-cno-log"

    fake_core = FakeApi(
        list_namespaced_pod=recording_list_pod,
        read_namespaced_pod=POD("t3b-cno-pod", "spy-ns"),
        read_namespaced_pod_log=recording_log_read,
    )
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-cno", fake_cs)

    result = await server.conservative_namespace_overview(
        namespace="spy-ns",
        source="t3b-cno",
    )

    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert "overview" in result, (
        f"Expected 'overview' key in result (proves tool ran to completion); got: {sorted(result)}"
    )
    assert list_pod_calls, (
        "list_namespaced_pod recorder never called — "
        "list_pods_in_namespace(source=source) did not propagate source to fake."
    )
    assert log_fetch_calls, (
        "read_namespaced_pod_log recorder never called — "
        "smart_summarize_pod_logs(source=source) did not dispatch via fake."
    )


@pytest.mark.asyncio
async def test_t3_adaptive_namespace_investigation_dispatches_to_fake(server, monkeypatch):
    """adaptive_namespace_investigation(source='t3b-ani') — full chain via fake.

    Chain: adaptive_namespace_investigation
      → list_pods_in_namespace(source=source)            [records list_namespaced_pod]
      → smart_get_namespace_events(source=source)        [records list_namespaced_event]
      → analyze_single_pod → smart_summarize_pod_logs(source=source) [records log_read]
    All three recorders must fire.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    list_pod_calls = []

    def recording_list_pod(*args, **kwargs):
        list_pod_calls.append(1)
        return items_list([POD("t3b-ani-pod", "spy-ns")])

    event_calls = []

    def recording_list_event(*args, **kwargs):
        event_calls.append(1)
        return items_list([EVENT("Warning", "t3b-ani-event", "spy-ns")])

    log_fetch_calls = []

    def recording_log_read(*args, **kwargs):
        log_fetch_calls.append(1)
        return "spy-t3b-ani-log"

    fake_core = FakeApi(
        list_namespaced_pod=recording_list_pod,
        list_namespaced_event=recording_list_event,
        read_namespaced_pod=POD("t3b-ani-pod", "spy-ns"),
        read_namespaced_pod_log=recording_log_read,
    )
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-ani", fake_cs)

    result = await server.adaptive_namespace_investigation(
        namespace="spy-ns",
        source="t3b-ani",
    )

    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert "investigation_summary" in result, (
        f"Expected 'investigation_summary' key (proves tool completed); got: {sorted(result)}"
    )
    assert list_pod_calls, (
        "list_namespaced_pod recorder never called — list_pods_in_namespace source not propagated."
    )
    assert event_calls, (
        "list_namespaced_event recorder never called — smart_get_namespace_events source not propagated."
    )
    assert log_fetch_calls, (
        "read_namespaced_pod_log recorder never called — "
        "smart_summarize_pod_logs(source=source) in analyze_single_pod not dispatching via fake."
    )


@pytest.mark.asyncio
async def test_t3_investigate_tls_dispatches_to_fake(server, monkeypatch):
    """investigate_tls_certificate_issues(source='t3b-itls') — full 5-hop chain via fake.

    Chain: investigate_tls_certificate_issues
      → list_namespaces(source=source)              [records list_namespace; 1 API call —
                                                     detect_tekton's internal list_namespaces
                                                     call hits the namespace cache, so only
                                                     the first call reaches the fake API]
      → detect_tekton_namespaces(source=source)     [spy verifies source= kwarg — M4-mutation (a)]
      → list_pods_in_namespace(source=source)       [records list_namespaced_pod]
      → smart_summarize_pod_logs(source=source)     [records read_namespaced_pod_log — M4-mutation (b)]
      → smart_get_namespace_events(source=source)   [records list_namespaced_event — M4-mutation (c)]
    All five propagation hops guarded; EVENT("t3b-tls-event") flows into certificate_events.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())
    monkeypatch.setattr(server, "_namespace_cache", {})

    list_ns_calls = []

    def recording_list_namespace(*args, **kwargs):
        list_ns_calls.append(1)
        return items_list([NS("t3b-tls-ns")])

    list_pod_calls = []

    def recording_list_pod(*args, **kwargs):
        list_pod_calls.append(1)
        return items_list([POD("t3b-tls-pod", "t3b-tls-ns")])

    log_fetch_calls = []

    def recording_log_read(*args, **kwargs):
        log_fetch_calls.append(1)
        return "spy-t3b-tls-log"

    event_calls = []

    def recording_list_event(*args, **kwargs):
        event_calls.append(1)
        return items_list([EVENT("Warning", "t3b-tls-event", "t3b-tls-ns")])

    fake_core = FakeApi(
        list_namespace=recording_list_namespace,
        list_namespaced_pod=recording_list_pod,
        read_namespaced_pod=POD("t3b-tls-pod", "t3b-tls-ns"),
        read_namespaced_pod_log=recording_log_read,
        list_namespaced_event=recording_list_event,
    )
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-itls", fake_cs)

    # Hop (a) spy: detect_tekton_namespaces internally calls list_namespaces(source=source),
    # but that second list_namespaces call hits the populated namespace cache (no extra API
    # contact).  A wrapper spy on the function itself is therefore the only reliable guard
    # for whether source= is forwarded to detect_tekton_namespaces — kills M4-mutation (a).
    detect_tekton_calls = []
    _orig_detect_tekton = server.detect_tekton_namespaces

    async def spy_detect_tekton(*args, **kwargs):
        detect_tekton_calls.append(kwargs.get("source", args[0] if args else ""))
        return await _orig_detect_tekton(*args, **kwargs)

    monkeypatch.setattr(server, "detect_tekton_namespaces", spy_detect_tekton)

    result = await server.investigate_tls_certificate_issues(source="t3b-itls")

    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert "analysis_summary" in result, (
        f"Expected 'analysis_summary' key (proves tool completed); got: {sorted(result)}"
    )
    # Hop 1: list_namespaces(source=source) — exactly 1 API call; 2nd call hits cache.
    assert list_ns_calls, (
        "list_namespace recorder never called — list_namespaces source not propagated to fake."
    )
    # Hop 2: list_pods_in_namespace(source=source).
    assert list_pod_calls, (
        "list_namespaced_pod recorder never called — "
        "list_pods_in_namespace source not propagated to fake."
    )
    # Hop (a): detect_tekton_namespaces(source=source) — spy must fire with the right source.
    assert detect_tekton_calls, (
        "detect_tekton_namespaces spy never fired — investigate_tls did not call it."
    )
    assert detect_tekton_calls[0] == "t3b-itls", (
        f"detect_tekton_namespaces received source={detect_tekton_calls[0]!r}, "
        f"expected 't3b-itls' — source= kwarg was dropped from the detect_tekton call."
    )
    # Hop (b): smart_summarize_pod_logs(source=source) → read_namespaced_pod_log on fake.
    assert log_fetch_calls, (
        "read_namespaced_pod_log recorder never called — "
        "smart_summarize_pod_logs(source=source) not dispatching via fake."
    )
    # Hop (c): smart_get_namespace_events(source=source) → list_namespaced_event on fake.
    assert event_calls, (
        "list_namespaced_event recorder never called — "
        "smart_get_namespace_events source not propagated to fake."
    )
    # Positive fake-payload: EVENT message "t3b-tls-event" contains "tls", so
    # investigate_tls classifies it as a certificate_event — proves the event data
    # flowed through the full fake-dispatch chain into the result dict.
    assert result.get("certificate_events"), (
        "certificate_events is empty — fake TLS event ('t3b-tls-event') not detected; "
        "check smart_get_namespace_events source= propagation (hop c)."
    )
    assert result["certificate_events"][0]["namespace"] == "t3b-tls-ns", (
        f"certificate_events[0].namespace={result['certificate_events'][0].get('namespace')!r}; "
        "expected 't3b-tls-ns' — fake event content did not flow through correctly."
    )


# ─── (c) Core-2 dispatch reality ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_t3_check_resource_constraints_dispatches_to_fake(server, monkeypatch):
    """check_resource_constraints(source='t3b-crc') uses fake core_api, not module global.

    Supplies empty pod list + empty quotas so the tool completes without needing
    read_namespaced_pod.  Recorder on list_namespaced_pod verifies dispatch.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    list_pod_calls = []

    def recording_list_pod(*args, **kwargs):
        list_pod_calls.append(1)
        return items_list([])  # empty: skip read_namespaced_pod

    def empty_rq(*args, **kwargs):
        return items_list([])

    fake_core = FakeApi(
        read_namespace=NS("spy-ns"),
        list_namespaced_pod=recording_list_pod,
        list_namespaced_resource_quota=empty_rq,
    )
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-crc", fake_cs)

    result = await server.check_resource_constraints(
        namespace="spy-ns",
        source="t3b-crc",
    )

    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert "status" in result, (
        f"Expected 'status' key (tool completed); got: {sorted(result)}"
    )
    assert "error" not in result, (
        f"Expected no error (fake dispatched correctly); got {result!r}. "
        "Poisoned global would raise AttributeError → error dict."
    )
    assert list_pod_calls, (
        "list_namespaced_pod recorder never called — "
        "check_resource_constraints did not dispatch to fake core_api."
    )


@pytest.mark.asyncio
async def test_t3_check_cluster_certificate_health_dispatches_to_fake(server, monkeypatch):
    """check_cluster_certificate_health(source='t3b-cch') uses fake core_api, not global.

    Supplies empty namespace list so the scan loop completes without scanning secrets.
    Recorder on list_namespace verifies the one global read was dispatched.
    """
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())

    list_ns_calls = []

    def recording_list_namespace(*args, **kwargs):
        list_ns_calls.append(1)
        return items_list([])  # empty: skip secret scanning loop

    fake_core = FakeApi(list_namespace=recording_list_namespace)
    fake_cs = _make_t3b_cs(server, core_api=fake_core)
    _register_t3b_instance(server, monkeypatch, "t3b-cch", fake_cs)

    result = await server.check_cluster_certificate_health(source="t3b-cch")

    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert "scan_summary" in result, (
        f"Expected 'scan_summary' key (tool completed); got: {sorted(result)}"
    )
    assert "error" not in result, (
        f"Expected no error; got {result!r}. "
        "Poisoned global would raise AttributeError → error dict."
    )
    assert list_ns_calls, (
        "list_namespace recorder never called — "
        "check_cluster_certificate_health did not dispatch to fake core_api."
    )


# ─── M3: renamed-default source (Task 4) ─────────────────────────────────────
#
# A config whose kubernetes source is named 'prod-hub' instead of 'kubernetes'.
# Before Task-4 fixes, 5 literal-"kubernetes" instance-key sites produce wrong
# keys / wrong lookups when the default source is renamed.
#
# Mutation evidence (in task-4-report.md):
#   Site (1) list_sources extension-state key      → test_m3_list_sources_*
#   Site (2) refresh_capabilities report key       → test_m3_refresh_capabilities_*
#   Site (5) _detect_ctx default arg               → test_m3_extension_states_* + test_m3_detect_ctx_*

_PROD_HUB_KUBECONFIG = """\
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
"""

_PROD_HUB_CONFIG_YAML = """\
profile: custom
sources:
  prod-hub:
    adapter: kubernetes
    discover_contexts: false
extensions:
  tekton: "on"
"""


@pytest.fixture(scope="module")
def prod_hub_server(tmp_path_factory):
    """Load server-mcp.py with a config whose kubernetes source is named 'prod-hub'.

    This is the M3 renamed-default integration fixture.  It exercises whether
    literal-'kubernetes' instance-key sites have been made dynamic via
    _source_registry.default_kubernetes_instance().

    discover_contexts: false keeps module load clean (no sibling contexts added).
    tekton: on populates _extension_states so key-correctness is detectable.
    """
    kubeconfig = tmp_path_factory.mktemp("kube_prod_hub") / "config"
    kubeconfig.write_text(_PROD_HUB_KUBECONFIG)

    config_yaml = tmp_path_factory.mktemp("cfg_prod_hub") / "lumino.yaml"
    config_yaml.write_text(_PROD_HUB_CONFIG_YAML)

    _orig = {
        "KUBECONFIG": _os.environ.get("KUBECONFIG"),
        "KUBEARCHIVE_ENABLED": _os.environ.get("KUBEARCHIVE_ENABLED"),
        "LUMINO_DISABLE_TELEMETRY": _os.environ.get("LUMINO_DISABLE_TELEMETRY"),
        "LUMINO_CONFIG": _os.environ.get("LUMINO_CONFIG"),
        "LUMINO_PROFILE": _os.environ.get("LUMINO_PROFILE"),
    }
    _os.environ["KUBECONFIG"] = str(kubeconfig)
    _os.environ["KUBEARCHIVE_ENABLED"] = "false"
    _os.environ.setdefault("LUMINO_DISABLE_TELEMETRY", "1")
    _os.environ["LUMINO_CONFIG"] = str(config_yaml)
    _os.environ.pop("LUMINO_PROFILE", None)

    _orig_kube_loc = None
    try:
        from kubernetes.config import kube_config as _k8s_kube_config
        _orig_kube_loc = _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION
        _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = str(kubeconfig)
    except Exception:
        pass

    sys.path.insert(0, str(_SRC))
    spec = importlib.util.spec_from_file_location(
        "server_mcp_prod_hub", _SRC / "server-mcp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_prod_hub"] = mod
    spec.loader.exec_module(mod)

    yield mod

    for key, orig in _orig.items():
        if orig is None:
            _os.environ.pop(key, None)
        else:
            _os.environ[key] = orig
    if _orig_kube_loc is not None:
        try:
            from kubernetes.config import kube_config as _k8s_kube_config
            _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = _orig_kube_loc
        except Exception:
            pass
    try:
        sys.path.remove(str(_SRC))
    except ValueError:
        pass
    sys.modules.pop("server_mcp_prod_hub", None)


# ─── (a) import clean: default anchor is 'prod-hub' ──────────────────────────

def test_m3_default_anchor_is_prod_hub(prod_hub_server):
    """The registry marks 'prod-hub' as the default kubernetes instance.

    build_registry() is already dynamic — this is a sanity prerequisite confirming
    that the module loaded cleanly with the renamed source.
    """
    assert prod_hub_server._source_registry.default_kubernetes_instance() == "prod-hub", (
        "Expected 'prod-hub' as default kubernetes instance; "
        f"got {prod_hub_server._source_registry.default_kubernetes_instance()!r}"
    )


# ─── (b) extension_states keys use 'prod-hub', not 'kubernetes' ──────────────

def test_m3_extension_states_keyed_by_prod_hub(prod_hub_server):
    """activate_extensions stores state under ('tekton', 'prod-hub'), not 'kubernetes'.

    Before fix (site 5): _detect_ctx() returns literal 'kubernetes' →
    activate_extensions produces ('tekton', 'kubernetes') key.
    After fix: None-default resolved inside → 'prod-hub' → correct key.
    """
    states = prod_hub_server._extension_states
    assert any(k[1] == "prod-hub" for k in states), (
        f"Expected at least one key with instance 'prod-hub'; "
        f"got keys: {sorted(states)}.  "
        "Site 5 (_detect_ctx default arg) not yet fixed."
    )
    assert not any(k[1] == "kubernetes" for k in states), (
        f"Found 'kubernetes' instance key in extension states: {sorted(states)}.  "
        "Default instance should be 'prod-hub' — literal default not yet replaced."
    )


# ─── (b) list_sources: state comes from the 'prod-hub' key ──────────────────

@pytest.mark.asyncio
async def test_m3_list_sources_extension_state_active(prod_hub_server):
    """list_sources reports 'active' for tekton when both keys use 'prod-hub'.

    Fails when sites (1) and (5) disagree: activation stored ('tekton', 'prod-hub')
    but lookup reads ('tekton', 'kubernetes') → state 'off'.  Both must be fixed.
    """
    result = await prod_hub_server.list_sources()
    ext_by_name = {e["name"]: e for e in result["extensions"]}
    assert "tekton" in ext_by_name, (
        f"Expected 'tekton' in extensions list; got {list(ext_by_name)}"
    )
    assert ext_by_name["tekton"]["state"] == "active", (
        f"Expected state='active' for tekton (configured 'on'); "
        f"got {ext_by_name['tekton']['state']!r}.  "
        "Sites (1) and (5) must both use _source_registry.default_kubernetes_instance()."
    )


# ─── (c) refresh_capabilities: report key uses 'prod-hub' ────────────────────

@pytest.mark.asyncio
async def test_m3_refresh_capabilities_extension_state_active(prod_hub_server):
    """refresh_capabilities returns 'active' for tekton when both keys use 'prod-hub'.

    Fails when sites (2) and (5) disagree — activation stores 'prod-hub' key but
    the return statement reads 'kubernetes' literal → state 'off'.
    """
    result = await prod_hub_server.refresh_capabilities()
    ext_by_name = {e["name"]: e for e in result["extensions"]}
    assert "tekton" in ext_by_name, (
        f"Expected 'tekton' in extensions; got {list(ext_by_name)}"
    )
    assert ext_by_name["tekton"]["state"] == "active", (
        f"Expected state='active' for tekton; "
        f"got {ext_by_name['tekton']['state']!r}.  "
        "Sites (2) and (5) must both use _source_registry.default_kubernetes_instance()."
    )


# ─── (d) discovery toggle honored from sources.prod-hub.options ──────────────

def test_m3_discover_contexts_honors_prod_hub_toggle(prod_hub_server, monkeypatch):
    """_discover_kube_contexts honors discover_contexts=False on the 'prod-hub' source.

    Before fix (site 3): cfg.sources.get('kubernetes') → None (no 'kubernetes' key) →
    toggle missed → kubeconfig reader is called → siblings returned (non-empty).
    After fix: cfg.sources.get('prod-hub') → SourceConfig → toggle=False → [].
    """
    toggle_cfg = ResolvedConfig(
        profile="test",
        sources={"prod-hub": SourceConfig(
            adapter="kubernetes",
            options={"discover_contexts": False},
        )},
    )

    # Fake reader that returns a sibling — called only if toggle is missed
    reader_called = []

    def fake_lkcc(config_file=None):
        reader_called.append(True)
        contexts = [
            {"name": "sibling-A", "context": {"cluster": "fake"}},
            {"name": "prod-hub",  "context": {"cluster": "fake"}},
        ]
        return contexts, {"name": "prod-hub", "context": {"cluster": "fake"}}

    monkeypatch.setattr(prod_hub_server.config, "list_kube_config_contexts", fake_lkcc)

    result = prod_hub_server._discover_kube_contexts(cfg=toggle_cfg)

    assert result == [], (
        f"Expected [] (discover_contexts=False honored for 'prod-hub'); "
        f"got {result!r}.  "
        "Site 3 (cfg.sources.get literal 'kubernetes') not yet fixed."
    )
    assert not reader_called, (
        "kubeconfig reader was called despite discover_contexts=False.  "
        "The toggle was missed because site 3 still uses the 'kubernetes' literal."
    )


# ─── (e) _detect_ctx() no-arg resolves to 'prod-hub' ────────────────────────

def test_m3_detect_ctx_no_arg_targets_prod_hub(prod_hub_server):
    """_detect_ctx() with no argument produces instance='prod-hub', not 'kubernetes'.

    Before fix (site 5): literal default 'kubernetes' → ctx.instance == 'kubernetes'.
    After fix: None default resolved inside the function body at call time.
    """
    ctx = prod_hub_server._detect_ctx()
    assert ctx.instance == "prod-hub", (
        f"Expected ctx.instance='prod-hub', got {ctx.instance!r}.  "
        "Site 5 (_detect_ctx default arg literal) not yet replaced with None+resolve."
    )


# ─── (f) Site-4 pin: connect_cluster option-bag uses renamed default source ──

@pytest.mark.asyncio
async def test_m3_connect_cluster_allowlist_uses_prod_hub(
    prod_hub_server, monkeypatch, tmp_path
):
    """Site 4 option-bag lookup reads opts from the renamed default source ('prod-hub').

    Before fix: _lumino_config.sources.get("kubernetes") returns None (the config
    only has a 'prod-hub' key) → opts = {} → credential_ref_roots = [] →
    ref_outside_allowlist for every kubeconfig:/secret: ref.

    After fix: sources.get(_source_registry.default_kubernetes_instance()) resolves
    to sources.get('prod-hub') → SourceConfig whose options carry the seeded root →
    the path passes the allowlist → _build_k8s_client_set is invoked.

    Positive assertion: builder_calls non-empty proves the allowlist stage passed
    (the ref reached the dial phase), regardless of any later outcome.
    Negative assertion: code != 'ref_outside_allowlist' is the direct kill
    condition for the literal-'kubernetes' mutant at server-mcp.py:1189.
    """
    root = tmp_path / "creds"
    root.mkdir()

    # Config: only 'prod-hub' key (no 'kubernetes' key).
    # extensions={} causes Step 6 to skip all detection (_mode == 'off' for all).
    cfg = _RC(
        profile="custom",
        sources={"prod-hub": _SC(
            adapter="kubernetes",
            options={"credential_ref_roots": [str(root)]},
        )},
        extensions={},
    )
    monkeypatch.setattr(prod_hub_server, "_lumino_config", cfg)

    # Minimal kubeconfig with the named context, written under the seeded root.
    kube_path = root / "cluster.kubeconfig"
    kube_path.write_text("""\
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:9
  name: m3c-cluster
contexts:
- context:
    cluster: m3c-cluster
    user: m3c-user
  name: m3c-context
current-context: m3c-context
users:
- name: m3c-user
  user:
    token: "fake-token"
""")

    # Spy: captures the call that proves the allowlist was passed.
    builder_calls = []
    _probe_sn = _SN(groups=[])
    _fake_apis = FakeApi(get_api_versions=_probe_sn)
    _fake_cs = prod_hub_server.K8sClientSet(
        core_api=FakeApi(), apps_api=FakeApi(), custom_api=FakeApi(),
        batch_api=FakeApi(), storage_api=FakeApi(), networking_api=FakeApi(),
        autoscaling_api=FakeApi(), apis_api=_fake_apis,
    )

    def fake_build_m3c(context, kubeconfig_path=None):
        prod_hub_server._dial_call_count += 1
        builder_calls.append({"context": context, "path": str(kubeconfig_path)})
        return _fake_cs

    monkeypatch.setattr(prod_hub_server, "_build_k8s_client_set", fake_build_m3c)

    # Clean up any residue from a previous run in the same session.
    unique_name = "m3c-allowlist-cluster"
    prod_hub_server._source_registry._entries.pop(unique_name, None)
    prod_hub_server._k8s_conn_state.pop(unique_name, None)
    prod_hub_server._k8s_instances.pop(unique_name, None)
    for k in [k for k in prod_hub_server._extension_states if k[1] == unique_name]:
        del prod_hub_server._extension_states[k]

    result = await prod_hub_server.connect_cluster(
        name=unique_name,
        credential_ref=f"kubeconfig:{kube_path}#m3c-context",
    )

    # Positive assertion: builder invoked → allowlist stage was passed.
    # Mutant (literal "kubernetes"): sources.get("kubernetes") → None → opts = {}
    # → roots = [] → rejected pre-dial (builder_calls stays empty).
    assert builder_calls, (
        f"_build_k8s_client_set was never invoked — the allowlist check rejected "
        f"the ref before reaching the dial.  result={result!r}.  "
        "Site 4 (server-mcp.py:1189) must use "
        "_source_registry.default_kubernetes_instance(), not the literal 'kubernetes'."
    )
    # Negative assertion: the mutant always returns this code for any kubeconfig: ref.
    assert result.get("code") != "ref_outside_allowlist", (
        f"ref_outside_allowlist returned — allowlist check used the wrong source name.  "
        f"With a 'prod-hub'-keyed config (no 'kubernetes' key), "
        f"sources.get('kubernetes') → None → opts = {{}} → roots = [] → rejected.  "
        f"Full result: {result}"
    )


# ── Phase 2e-b Task 5: kubeconfig_dir scan tests ─────────────────────────────
#
# Module-exec fixture kubedir_server exercises the shipped activation block with
# a kubeconfig_dir containing four files:
#   a.yaml         - ctx ctx-alpha (unique)
#   b.kubeconfig   - ctx ctx-alpha (cross-file collision → b#ctx-alpha)
#                    ctx ctx-beta  (unique)
#   c.kubeconfig   - ctx kubernetes (registry collision → c#kubernetes)
#   c.yaml         - ctx kubernetes (c#kubernetes now taken → fully skipped)
#   malformed.yaml - invalid YAML → skipped, scan continues
#
# Expected registry additions (name-sorted): b#ctx-alpha, c#kubernetes, ctx-alpha, ctx-beta
# Mutations tested: (i) collision guard removed, (ii) scan when option absent,
#                   (iii) _resolve_k8s ignores _kubeconfig_dir_paths

_KUBEDIR_HARNESS_KUBECONFIG = """\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: harness
contexts:
- context: {cluster: harness, user: harness}
  name: harness
current-context: harness
users:
- name: harness
  user: {token: "harness-token"}
"""

_KUBEDIR_FILE_A = """\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: fake
contexts:
- context: {cluster: fake, user: fake}
  name: ctx-alpha
current-context: ctx-alpha
users:
- name: fake
  user: {token: "fake-token"}
"""

_KUBEDIR_FILE_B = """\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: fake
contexts:
- context: {cluster: fake, user: fake}
  name: ctx-alpha
- context: {cluster: fake, user: fake}
  name: ctx-beta
current-context: ctx-alpha
users:
- name: fake
  user: {token: "fake-token"}
"""

_KUBEDIR_FILE_K8S = """\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: fake
contexts:
- context: {cluster: fake, user: fake}
  name: kubernetes
current-context: kubernetes
users:
- name: fake
  user: {token: "fake-token"}
"""


@pytest.fixture(scope="module")
def kubedir_server(tmp_path_factory):
    """Load server-mcp with kubeconfig_dir set; exercises the shipped activation block.

    Files in kubeconfig_dir (sorted: a.yaml, b.kubeconfig, c.kubeconfig, c.yaml, malformed.yaml):
      a.yaml         → ctx ctx-alpha (unique, registered as ctx-alpha)
      b.kubeconfig   → ctx ctx-alpha (collision → b#ctx-alpha); ctx ctx-beta (unique)
      c.kubeconfig   → ctx kubernetes (registry collision → c#kubernetes)
      c.yaml         → ctx kubernetes (c#kubernetes now taken → fully skipped, no raise)
      malformed.yaml → invalid YAML → skipped, scan continues

    discover_contexts: false prevents KUBECONFIG siblings from blending in.
    F9 pin: KUBE_CONFIG_DEFAULT_LOCATION set to the harness kubeconfig.
    """
    kube_dir = tmp_path_factory.mktemp("kubedir")
    (kube_dir / "a.yaml").write_text(_KUBEDIR_FILE_A)
    (kube_dir / "b.kubeconfig").write_text(_KUBEDIR_FILE_B)
    (kube_dir / "c.kubeconfig").write_text(_KUBEDIR_FILE_K8S)
    (kube_dir / "c.yaml").write_text(_KUBEDIR_FILE_K8S)       # both c.* → c#kubernetes taken → c.yaml skipped
    (kube_dir / "malformed.yaml").write_text("not: [valid kubeconfig")

    kubeconfig = tmp_path_factory.mktemp("kube_kubedir") / "config"
    kubeconfig.write_text(_KUBEDIR_HARNESS_KUBECONFIG)

    config_yaml = tmp_path_factory.mktemp("cfg_kubedir") / "lumino.yaml"
    config_yaml.write_text(
        "profile: custom\n"
        "sources:\n"
        "  kubernetes:\n"
        "    adapter: kubernetes\n"
        "    discover_contexts: false\n"
        f"    kubeconfig_dir: '{kube_dir}'\n"
    )

    _orig = {
        "KUBECONFIG": _os.environ.get("KUBECONFIG"),
        "KUBEARCHIVE_ENABLED": _os.environ.get("KUBEARCHIVE_ENABLED"),
        "LUMINO_DISABLE_TELEMETRY": _os.environ.get("LUMINO_DISABLE_TELEMETRY"),
        "LUMINO_CONFIG": _os.environ.get("LUMINO_CONFIG"),
        "LUMINO_PROFILE": _os.environ.get("LUMINO_PROFILE"),
    }
    _os.environ["KUBECONFIG"] = str(kubeconfig)
    _os.environ["KUBEARCHIVE_ENABLED"] = "false"
    _os.environ.setdefault("LUMINO_DISABLE_TELEMETRY", "1")
    _os.environ["LUMINO_CONFIG"] = str(config_yaml)
    _os.environ.pop("LUMINO_PROFILE", None)

    # F9 pin: prevent discovery from falling back to ~/.kube/config
    _orig_kube_loc = None
    try:
        from kubernetes.config import kube_config as _k8s_kube_config
        _orig_kube_loc = _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION
        _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = str(kubeconfig)
    except Exception:
        pass

    sys.path.insert(0, str(_SRC))
    spec = importlib.util.spec_from_file_location(
        "server_mcp_kubedir", _SRC / "server-mcp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_kubedir"] = mod
    spec.loader.exec_module(mod)  # raises ValueError if collision guard is missing

    yield mod

    for key, orig in _orig.items():
        if orig is None:
            _os.environ.pop(key, None)
        else:
            _os.environ[key] = orig
    if _orig_kube_loc is not None:
        try:
            from kubernetes.config import kube_config as _k8s_kube_config
            _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = _orig_kube_loc
        except Exception:
            pass
    try:
        sys.path.remove(str(_SRC))
    except ValueError:
        pass
    sys.modules.pop("server_mcp_kubedir", None)


# ─── (a) Disjoint contexts → both registered, unconnected, dial-free ─────────

def test_kubedir_disjoint_contexts_registered(kubedir_server):
    """(a) ctx-alpha (a.yaml) and ctx-beta (b.kubeconfig) both registered, unconnected."""
    names = {e.name for e in kubedir_server._source_registry.entries()}
    assert "ctx-alpha" in names, (
        f"ctx-alpha missing from registry; got: {sorted(names)}"
    )
    assert "ctx-beta" in names, (
        f"ctx-beta missing from registry; got: {sorted(names)}"
    )
    assert kubedir_server._k8s_conn_state.get("ctx-alpha") == "unconnected", (
        f"ctx-alpha conn_state != 'unconnected'; got {kubedir_server._k8s_conn_state.get('ctx-alpha')!r}"
    )
    assert kubedir_server._k8s_conn_state.get("ctx-beta") == "unconnected", (
        f"ctx-beta conn_state != 'unconnected'; got {kubedir_server._k8s_conn_state.get('ctx-beta')!r}"
    )


def test_kubedir_dial_count_zero(kubedir_server):
    """(a) kubeconfig_dir scan is dial-free: _dial_call_count == 0 after module load."""
    assert kubedir_server._dial_call_count == 0, (
        f"Expected _dial_call_count=0 (dial-free scan); got {kubedir_server._dial_call_count}. "
        "kubeconfig_dir scan must not call _build_k8s_client_set."
    )


# ─── (b) Cross-file collision → deterministic stem# rename ───────────────────

def test_kubedir_collision_cross_file_renamed(kubedir_server):
    """(b) b.kubeconfig's ctx-alpha collides with a.yaml's; registered as b#ctx-alpha."""
    names = {e.name for e in kubedir_server._source_registry.entries()}
    assert "b#ctx-alpha" in names, (
        f"Expected 'b#ctx-alpha' (collision rename for b.kubeconfig/ctx-alpha); "
        f"got: {sorted(names)}"
    )
    # The path in _kubeconfig_dir_paths["ctx-alpha"] must point to a.yaml (first file)
    assert "ctx-alpha" in kubedir_server._kubeconfig_dir_paths, (
        "_kubeconfig_dir_paths missing 'ctx-alpha'"
    )
    orig_ctx, orig_path = kubedir_server._kubeconfig_dir_paths["ctx-alpha"]
    assert "a.yaml" in orig_path, (
        f"ctx-alpha must map to a.yaml (first file sorted); got path={orig_path!r}"
    )
    assert orig_ctx == "ctx-alpha", (
        f"_kubeconfig_dir_paths must store ORIGINAL context name; got {orig_ctx!r}"
    )


# ─── (c) Registry collision (kubernetes) + full-skip path ────────────────────

def test_kubedir_registry_collision_renamed_and_fully_skipped(kubedir_server):
    """(c) c.kubeconfig's 'kubernetes' → c#kubernetes; c.yaml's 'kubernetes' → fully skipped.

    c.kubeconfig sorted before c.yaml (k < y):
      c.kubeconfig: ctx kubernetes → 'kubernetes' in registry → try c#kubernetes → add.
      c.yaml:       ctx kubernetes → 'kubernetes' in registry → try c#kubernetes → TAKEN → skip.
    No exception raised in either case (F2 import-crash guard).
    """
    names = {e.name for e in kubedir_server._source_registry.entries()}
    # Exactly one default 'kubernetes' entry
    k8s_entries = [e for e in kubedir_server._source_registry.entries() if e.name == "kubernetes"]
    assert len(k8s_entries) == 1, (
        f"Expected exactly 1 'kubernetes' entry; found {len(k8s_entries)}: {k8s_entries}"
    )
    assert k8s_entries[0].default is True, (
        "Original 'kubernetes' entry must remain default=True after scan"
    )
    # Rename landed: c#kubernetes registered exactly once
    assert "c#kubernetes" in names, (
        f"Expected 'c#kubernetes' (rename for c.kubeconfig/kubernetes); got: {sorted(names)}"
    )
    # Full-skip verified: c#kubernetes appears exactly once (c.yaml was skipped)
    c_k8s_entries = [e for e in kubedir_server._source_registry.entries() if e.name == "c#kubernetes"]
    assert len(c_k8s_entries) == 1, (
        f"'c#kubernetes' should appear exactly once (c.yaml skip guard); "
        f"found {len(c_k8s_entries)}"
    )


# ─── (d) Option absent → no scan ─────────────────────────────────────────────

def test_kubedir_option_absent_no_scan(server, monkeypatch):
    """(d) If kubeconfig_dir is absent, _scan_kubeconfig_dir returns without reading any file.

    Spy on list_kube_config_contexts: it must NOT be called when kubeconfig_dir is absent.
    Mutation kill: removing 'if not kube_dir: return' + using '.' as fallback causes
    config.example.yaml (present in project root) to be read → spy fires → assertion fails.
    """
    from core.config_types import ResolvedConfig as _RC5, SourceConfig as _SC5

    lkcc_calls = []

    def spy_lkcc(config_file=None):
        lkcc_calls.append(config_file)
        # Raise so the except-block skips the file — keeps session registry clean
        raise Exception(f"spy: scan ran with config_file={config_file!r}")

    monkeypatch.setattr(server.config, "list_kube_config_contexts", spy_lkcc)

    no_dir_cfg = _RC5(
        profile="test",
        sources={"kubernetes": _SC5(adapter="kubernetes", options={})},  # no kubeconfig_dir
    )
    before_names = {e.name for e in server._source_registry.entries()}
    server._scan_kubeconfig_dir(cfg=no_dir_cfg)
    after_names = {e.name for e in server._source_registry.entries()}

    assert not lkcc_calls, (
        f"list_kube_config_contexts was called despite kubeconfig_dir being absent; "
        f"calls: {lkcc_calls}. Feature must be OFF when kubeconfig_dir option is not set."
    )
    assert before_names == after_names, (
        f"Registry changed despite kubeconfig_dir absent: "
        f"before={sorted(before_names)}, after={sorted(after_names)}"
    )


# ─── (e) Malformed file → skipped, scan continues ────────────────────────────

def test_kubedir_malformed_file_skipped(kubedir_server):
    """(e) malformed.yaml is skipped (parse error); a.yaml and b.kubeconfig still loaded."""
    names = {e.name for e in kubedir_server._source_registry.entries()}
    # Good files still produced their contexts
    assert "ctx-alpha" in names, (
        f"ctx-alpha missing — malformed.yaml may have aborted the scan; got {sorted(names)}"
    )
    assert "ctx-beta" in names, (
        f"ctx-beta missing — malformed.yaml may have aborted the scan; got {sorted(names)}"
    )
    # No ctx from malformed.yaml (it has no valid contexts anyway — also parse fails)


# ─── (f) Dispatch wiring: _resolve_k8s consults _kubeconfig_dir_paths ────────

def test_kubedir_resolve_dispatches_with_path(kubedir_server, monkeypatch):
    """(f) _resolve_k8s('ctx-alpha') calls _build_k8s_client_set with the recorded path.

    _kubeconfig_dir_paths['ctx-alpha'] = (original_ctx, path_to_a.yaml).
    The builder must receive BOTH the original context name and the kubeconfig path.
    Mutation: ignoring _kubeconfig_dir_paths → builder gets (source, None) → assert fails.
    """
    builder_calls = []
    _fake_cs = kubedir_server.K8sClientSet(
        core_api=None, apps_api=None, custom_api=None,
        batch_api=None, storage_api=None, networking_api=None,
        autoscaling_api=None, apis_api=None,
    )

    def fake_build(context, kubeconfig_path=None):
        builder_calls.append({"context": context, "path": kubeconfig_path})
        return _fake_cs

    monkeypatch.setattr(kubedir_server, "_build_k8s_client_set", fake_build)
    kubedir_server._k8s_instances.pop("ctx-alpha", None)  # clear cache

    orig_ctx, orig_path = kubedir_server._kubeconfig_dir_paths["ctx-alpha"]

    try:
        view, err = kubedir_server._resolve_k8s("ctx-alpha")
    finally:
        kubedir_server._k8s_instances.pop("ctx-alpha", None)  # module-scoped cleanup

    assert err is None, f"Expected no error from _resolve_k8s; got {err!r}"
    assert len(builder_calls) == 1, (
        f"Expected exactly 1 builder call; got {len(builder_calls)}"
    )
    assert builder_calls[0]["context"] == orig_ctx, (
        f"builder context={builder_calls[0]['context']!r}, expected {orig_ctx!r}"
    )
    assert builder_calls[0]["path"] == orig_path, (
        f"builder path={builder_calls[0]['path']!r}, expected {orig_path!r}. "
        "_resolve_k8s must consult _kubeconfig_dir_paths, not _lumino_config.sources."
    )


# ─── Task-5-kill: renamed-instance original-context storage + dispatch ────────
#
# THE SURVIVOR: tests (b) and (f) only ever touch the NON-renamed 'ctx-alpha'
# entry where instance_name == ctx, so the assertion orig_ctx == "ctx-alpha"
# is trivially satisfied whether ctx or instance_name is stored.
# A mutant that stores (instance_name, path) instead of (ctx, path) at
# src/server-mcp.py:13231 leaves all 7 prior kubedir tests green.
# These two tests close that gap by targeting the RENAMED entry 'b#ctx-alpha'.

def test_kubedir_renamed_instance_stores_original_context(kubedir_server):
    """Task-5 pin: 'b#ctx-alpha' must store the ORIGINAL context name 'ctx-alpha', not the key.

    _kubeconfig_dir_paths["b#ctx-alpha"][0] must equal "ctx-alpha".
    Mutation: store (instance_name, path) instead of (ctx, path) at line 13231
    → stored context becomes "b#ctx-alpha" → this assertion fails.
    """
    assert "b#ctx-alpha" in kubedir_server._kubeconfig_dir_paths, (
        "_kubeconfig_dir_paths missing 'b#ctx-alpha' (collision-renamed entry)"
    )
    stored_ctx, stored_path = kubedir_server._kubeconfig_dir_paths["b#ctx-alpha"]
    assert stored_ctx == "ctx-alpha", (
        f"_kubeconfig_dir_paths['b#ctx-alpha'][0] must be 'ctx-alpha' (original context), "
        f"not {stored_ctx!r}. "
        "Storing the renamed instance key breaks _resolve_k8s context dispatch."
    )
    assert "b.kubeconfig" in stored_path, (
        f"_kubeconfig_dir_paths['b#ctx-alpha'][1] must point to b.kubeconfig; "
        f"got {stored_path!r}"
    )


def test_kubedir_renamed_instance_resolve_dispatches_original_context(kubedir_server, monkeypatch):
    """Task-5 pin: _resolve_k8s('b#ctx-alpha') builds with context='ctx-alpha', not 'b#ctx-alpha'.

    Mutation: store (instance_name, path) instead of (ctx, path) in _kubeconfig_dir_paths
    → builder receives context='b#ctx-alpha' → assertion fails.
    """
    builder_calls = []
    _fake_cs = kubedir_server.K8sClientSet(
        core_api=None, apps_api=None, custom_api=None,
        batch_api=None, storage_api=None, networking_api=None,
        autoscaling_api=None, apis_api=None,
    )

    def fake_build(context, kubeconfig_path=None):
        builder_calls.append({"context": context, "path": kubeconfig_path})
        return _fake_cs

    monkeypatch.setattr(kubedir_server, "_build_k8s_client_set", fake_build)
    kubedir_server._k8s_instances.pop("b#ctx-alpha", None)  # clear cache

    orig_ctx, orig_path = kubedir_server._kubeconfig_dir_paths["b#ctx-alpha"]

    try:
        view, err = kubedir_server._resolve_k8s("b#ctx-alpha")
    finally:
        kubedir_server._k8s_instances.pop("b#ctx-alpha", None)  # module-scoped cleanup

    assert err is None, f"Expected no error from _resolve_k8s; got {err!r}"
    assert len(builder_calls) == 1, (
        f"Expected exactly 1 builder call; got {len(builder_calls)}"
    )
    assert builder_calls[0]["context"] == "ctx-alpha", (
        f"builder context={builder_calls[0]['context']!r}, expected 'ctx-alpha' (original context). "
        "_resolve_k8s must use the ORIGINAL context from _kubeconfig_dir_paths, "
        "not the renamed instance key 'b#ctx-alpha'."
    )
    assert builder_calls[0]["path"] == orig_path, (
        f"builder path={builder_calls[0]['path']!r}, expected {orig_path!r} (b.kubeconfig). "
        "_resolve_k8s must consult _kubeconfig_dir_paths for the file path."
    )
    assert "b.kubeconfig" in builder_calls[0]["path"], (
        f"builder must receive path to b.kubeconfig; got {builder_calls[0]['path']!r}"
    )


# ─── Task 6: list_sources per-instance extension_instances rendering ──────────
#
# (a) multi-instance unit: synthetic _extension_states + _k8s_conn_state →
#     exact grouped dict, name-sorted; instance with no detection entries → {}
# (b) regression: top-level "extensions" list is byte-identical to pre-change value


@pytest.mark.asyncio
async def test_t6_extension_instances_multi_instance(server, monkeypatch):
    """extension_instances groups _extension_states by instance, name-sorted.

    Synthetic state:
      _extension_states: {("tekton", "kubernetes"): "active",
                          ("tekton", "ctx-b"): "not-detected: absent"}
      _k8s_conn_state:   {"ctx-b": "unconnected", "kubernetes": "connected"}

    Expected extension_instances:
      {
        "ctx-b":      {"tekton": "not-detected: absent"},
        "kubernetes": {"tekton": "active"},
      }
    All keys are name-sorted; instances with entries are fully represented.
    """
    synth_states = {
        ("tekton", "kubernetes"): "active",
        ("tekton", "ctx-b"): "not-detected: absent",
    }
    synth_conn = {"kubernetes": "connected", "ctx-b": "unconnected"}

    monkeypatch.setattr(server, "_extension_states", synth_states)
    monkeypatch.setattr(server, "_k8s_conn_state", synth_conn)

    result = await server.list_sources()

    assert "extension_instances" in result, (
        f"list_sources must include 'extension_instances' key; got keys: {sorted(result)}"
    )
    ei = result["extension_instances"]
    expected = {
        "ctx-b": {"tekton": "not-detected: absent"},
        "kubernetes": {"tekton": "active"},
    }
    assert ei == expected, (
        f"extension_instances mismatch.\n  expected: {expected}\n  got:      {ei}"
    )
    # Keys must be name-sorted
    assert list(ei) == sorted(ei), (
        f"extension_instances keys must be name-sorted; got {list(ei)}"
    )


@pytest.mark.asyncio
async def test_t6_extension_instances_empty_for_no_entries(server, monkeypatch):
    """Instance present in _k8s_conn_state but absent from _extension_states renders {}.

    _k8s_conn_state has "empty-inst" but _extension_states has no key for it.
    extension_instances["empty-inst"] must be {}.
    """
    synth_states = {("tekton", "kubernetes"): "active"}
    synth_conn = {"kubernetes": "connected", "empty-inst": "unconnected"}

    monkeypatch.setattr(server, "_extension_states", synth_states)
    monkeypatch.setattr(server, "_k8s_conn_state", synth_conn)

    result = await server.list_sources()

    assert "extension_instances" in result, (
        f"list_sources must include 'extension_instances' key; got keys: {sorted(result)}"
    )
    ei = result["extension_instances"]
    assert "empty-inst" in ei, (
        f"Expected 'empty-inst' in extension_instances; got {list(ei)}"
    )
    assert ei["empty-inst"] == {}, (
        f"Instance with no detection entries must render {{}}; got {ei['empty-inst']!r}"
    )


@pytest.mark.asyncio
async def test_t6_extensions_list_unchanged(server):
    """Regression: the top-level 'extensions' list renders identically after Task 6.

    Captures the expected value from the CURRENT module state (pre-change baseline
    to be computed from the same data sources as the implementation) and asserts
    deep-equality.  This test must be GREEN before and after the implementation.
    """
    result = await server.list_sources()

    # extensions key must still be present
    assert "extensions" in result, (
        f"'extensions' key must be present; got keys: {sorted(result)}"
    )
    exts = result["extensions"]
    assert isinstance(exts, list), (
        f"'extensions' must be a list; got {type(exts).__name__}"
    )

    # Rebuild expected from the same sources as the implementation
    default_inst = server._source_registry.default_kubernetes_instance()
    expected = [
        {
            "name": name,
            "configured": mode,
            "state": server._extension_states.get((name, default_inst), "off"),
        }
        for name, mode in sorted(server._lumino_config.extensions.items())
    ]
    assert exts == expected, (
        f"'extensions' list must be byte-identical to pre-change rendering.\n"
        f"  expected: {expected}\n"
        f"  got:      {exts}"
    )


# ─── Cache isolation by kubernetes instance (live-found cross-cluster bug) ────
#
# _namespace_cache must be keyed by resolved instance name, not a single global
# slot.  The four tests below are RED on the pre-fix code (single-slot cache)
# and GREEN after the fix (per-instance keying).
#
# apply_determinism is a plain function (not an autouse fixture) and is not
# applied to this module; each test here resets _namespace_cache explicitly.

@pytest.mark.asyncio
async def test_namespace_cache_warm_then_switch_returns_correct_instance(
        server, monkeypatch):
    """Warm default cache (set A), then call source=ctx-b → must return B, not A.

    Fails on pre-fix code: the single cache slot warmed by the default call is
    returned verbatim for every source within TTL.
    """
    # Explicit reset: multicluster tests are not covered by the golden autouse
    # deterministic fixture, so cache must be reset manually.
    monkeypatch.setattr(server, "_namespace_cache", {})

    # Step 1: warm default cache with A's namespaces
    default_core = FakeApi(list_namespace=items_list([NS("ns-cluster-a")]))
    monkeypatch.setattr(server, "k8s_core_api", default_core)

    result_a = await server.list_namespaces()
    assert result_a == ["ns-cluster-a"], (
        f"Setup: default must return A; got {result_a!r}"
    )

    # Step 2: register ctx-b with a DISTINCT namespace set
    b_core = FakeApi(list_namespace=items_list([NS("ns-cluster-b")]))
    b_cs = _make_cs(server, core_api=b_core)
    _register_fake_instance(server, monkeypatch, "cb-warm-switch", b_cs)

    # Step 3: call ctx-b WITHOUT resetting cache — must reach B's API, not slot A
    result_b = await server.list_namespaces(source="cb-warm-switch")
    assert result_b == ["ns-cluster-b"], (
        f"Cross-cluster poisoning: source=cb-warm-switch must return B's namespaces "
        f"(['ns-cluster-b']); got {result_b!r}. "
        f"If this is ['ns-cluster-a'] the single-slot cache is serving cluster A data "
        f"for a cluster B request."
    )


@pytest.mark.asyncio
async def test_namespace_cache_reverse_poisoning(server, monkeypatch):
    """Warm cache with source=ctx-b (set B), default call → must return A, not B.

    Fails on pre-fix code: a named-instance call poisons the single cache slot;
    the subsequent default call returns the wrong cluster's namespaces for a day.
    """
    monkeypatch.setattr(server, "_namespace_cache", {})

    # Step 1: register ctx-b and warm ITS slot
    b_core = FakeApi(list_namespace=items_list([NS("ns-cluster-b")]))
    b_cs = _make_cs(server, core_api=b_core)
    _register_fake_instance(server, monkeypatch, "cb-rev-poison", b_cs)
    monkeypatch.setattr(server, "k8s_core_api", FakeApi())  # default not called yet

    result_b = await server.list_namespaces(source="cb-rev-poison")
    assert result_b == ["ns-cluster-b"], (
        f"Setup: ctx-b must return B; got {result_b!r}"
    )

    # Step 2: default call — must NOT return B's namespaces
    a_core = FakeApi(list_namespace=items_list([NS("ns-cluster-a")]))
    monkeypatch.setattr(server, "k8s_core_api", a_core)

    result_a = await server.list_namespaces()
    assert result_a == ["ns-cluster-a"], (
        f"Reverse poisoning: default must return A's namespaces (['ns-cluster-a']); "
        f"got {result_a!r}. "
        f"If this is ['ns-cluster-b'] the single-slot cache is serving cluster B data "
        f"to the default cluster's callers."
    )


@pytest.mark.asyncio
async def test_namespace_cache_per_key_ttl_hit(server, monkeypatch):
    """Two consecutive default calls: fake's list_namespace called ONCE (second is a hit).

    Passes on BOTH pre-fix and post-fix code: preserves existing caching behaviour
    for the default path.
    """
    monkeypatch.setattr(server, "_namespace_cache", {})

    call_count = []

    def counting_list_namespace(*args, **kwargs):
        call_count.append(1)
        return items_list([NS("ns-ttl-test")])

    default_core = FakeApi(list_namespace=counting_list_namespace)
    monkeypatch.setattr(server, "k8s_core_api", default_core)

    result1 = await server.list_namespaces()
    result2 = await server.list_namespaces()

    assert call_count == [1], (
        f"list_namespace must be called exactly ONCE across two default calls "
        f"(second must be a cache hit); called {len(call_count)} time(s)"
    )
    assert result1 == result2 == ["ns-ttl-test"], (
        f"Both calls must return the same namespaces; "
        f"result1={result1!r}, result2={result2!r}"
    )


@pytest.mark.asyncio
async def test_detect_tekton_propagation_uses_correct_instance_cache(
        server, monkeypatch):
    """detect_tekton_namespaces(source=ctx-b) must see B's namespaces, not A's.

    Fails on pre-fix code: detect_tekton_namespaces delegates to list_namespaces
    with source=source, but the single-slot cache populated by an earlier default
    call is returned regardless of source, so B's tekton namespace never appears.
    """
    monkeypatch.setattr(server, "_namespace_cache", {})

    # Step 1: warm default cache with A's non-tekton namespaces
    a_core = FakeApi(list_namespace=items_list([NS("ns-cluster-a")]))
    monkeypatch.setattr(server, "k8s_core_api", a_core)

    result_a = await server.list_namespaces()
    assert result_a == ["ns-cluster-a"], (
        f"Setup: default must return A; got {result_a!r}"
    )

    # Step 2: register ctx-b with a distinctly tekton-named namespace
    b_core = FakeApi(list_namespace=items_list([NS("tekton-pipelines-b")]))
    b_cs = _make_cs(server, core_api=b_core)
    _register_fake_instance(server, monkeypatch, "cb-tekton-prop", b_cs)

    # Step 3: detect_tekton must use B's slot, not A's poisoned slot
    tekton_result = await server.detect_tekton_namespaces(source="cb-tekton-prop")
    core_tekton = tekton_result.get("core_tekton", [])
    assert "tekton-pipelines-b" in core_tekton, (
        f"detect_tekton_namespaces(source=cb-tekton-prop) must discover B's tekton "
        f"namespace; core_tekton={core_tekton!r}. "
        f"If this is empty the cache propagation path is still using A's poisoned slot."
    )


@pytest.mark.asyncio
async def test_namespace_cache_empty_and_default_name_share_one_slot(
        server, monkeypatch):
    """source="" and source=<default-name> must map to ONE cache slot, not two.

    Fails on a mutant that drops the "" → default-name normalisation so that
    each spelling writes its own slot, causing two fetches instead of one.
    """
    monkeypatch.setattr(server, "_namespace_cache", {})

    default_name = server._source_registry.default_kubernetes_instance()

    call_count = []

    def counting_list_namespace(*args, **kwargs):
        call_count.append(1)
        return items_list([NS("ns-merge-test")])

    monkeypatch.setattr(server, "k8s_core_api",
                        FakeApi(list_namespace=counting_list_namespace))

    # Warm via source="" (the default spelling)
    await server.list_namespaces()
    # Second call via source=<explicit default name> — must be a cache hit
    await server.list_namespaces(source=default_name)

    assert len(call_count) == 1, (
        f"list_namespace must be called exactly ONCE across source='' and "
        f"source={default_name!r} (they are the same cluster); "
        f"called {len(call_count)} time(s). "
        f"If called twice, the cache key merge is broken."
    )
    assert set(server._namespace_cache.keys()) == {default_name}, (
        f"_namespace_cache must have exactly one key ({default_name!r}); "
        f"got keys {set(server._namespace_cache.keys())!r}"
    )


@pytest.mark.asyncio
async def test_connect_cluster_rollback_purges_namespace_cache(
        server, monkeypatch, tmp_path):
    """Dial failure rolls back the namespace cache slot for the failed name.

    Without the pop, a rolled-back name re-connected to a different cluster
    would inherit the old cluster's namespace data for up to 24 h.
    """
    from core.config_types import ResolvedConfig as _RCd, SourceConfig as _SCd

    cfg = _RCd(
        profile="test",
        sources={"kubernetes": _SCd(adapter="kubernetes",
                                   options={"credential_ref_roots": ["/"]})},
        extensions={},
    )
    monkeypatch.setattr(server, "_lumino_config", cfg)

    unique_name = "t-rollback-cache-purge"
    server._source_registry._entries.pop(unique_name, None)
    server._k8s_conn_state.pop(unique_name, None)
    server._k8s_instances.pop(unique_name, None)

    # Pre-seed a stale cache slot for this name (simulates a previous connection)
    stale_slot = {"namespaces": ["stale-ns"], "timestamp": 9_999_999_999.0}
    monkeypatch.setattr(server, "_namespace_cache",
                        {unique_name: stale_slot})

    def fake_build_fail(context, kubeconfig_path=None):
        raise ConnectionError("connection refused (test-injected)")

    monkeypatch.setattr(server, "_build_k8s_client_set", fake_build_fail)

    result = await server.connect_cluster(
        name=unique_name, credential_ref="kubeconfig:/any/path#ctx"
    )
    assert result.get("code") == "dial_failed", (
        f"Expected dial_failed; got {result}"
    )

    assert unique_name not in server._namespace_cache, (
        f"_rollback_instance must purge the namespace cache slot for {unique_name!r}; "
        f"key still present: {server._namespace_cache.get(unique_name)!r}"
    )
