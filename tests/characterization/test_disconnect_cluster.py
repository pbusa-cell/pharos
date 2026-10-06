"""disconnect_cluster: dynamic removal of runtime kubernetes instances.

2026-08-21: removing prd-rh02/prd-es01 from the fleet required a container
restart (wiping ALL registrations) because connect_cluster had no inverse.
The internal machinery existed (_rollback_instance, server-mcp.py:1119) but
no MCP tool exposed it. These tests pin the disconnect_cluster contract:

  - empty / unknown name -> code "unknown_source"
  - default instance     -> code "cannot_remove_default"
  - non-kubernetes       -> code "not_kubernetes_instance"
  - startup-discovered   -> code "not_runtime_instance" (removal would be
                            irreversible on a stock deployment: re-adding
                            needs connect_cluster, which needs
                            credential_ref_roots, whose default is [])
  - success              -> {"disconnected": True, "name": ...} and EVERY
                            per-instance runtime store purged — registry
                            entry, client set, conn state, namespace cache,
                            bearer token, extension states, API-group
                            discovery cache, kubearchive client + discovery
                            caches — so the name is cleanly re-connectable
                            without serving the old cluster's data.

Review round 1 (Opus): the original purge missed three caches
(server _discovery_cache, kubearchive _ka_client_cache and _discovery_cache)
and had a purge-then-write-back race for in-flight coroutines; the race
tests below pin the tombstone guards.
"""
import asyncio
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import helpers.kubearchive_integration as ka  # noqa: E402


def _seed_runtime_instance(server, name):
    """Register `name` the way a successful connect_cluster would."""
    default_caps = server._source_registry.get(
        server._source_registry.default_kubernetes_instance()).capabilities
    server._source_registry.add_instance(server.SourceEntry(
        name=name, adapter="kubernetes",
        capabilities=default_caps, state="configured", default=False,
    ))
    server._runtime_instances.add(name)
    server._k8s_instances[name] = object()
    server._k8s_conn_state[name] = "connected"
    server._namespace_cache[name] = {"namespaces": ["ns1"], "timestamp": 0.0}
    server._instance_tokens[name] = "seed-token"
    server._extension_states[("tekton", name)] = "active"
    server._extension_states[("konflux", name)] = "not-detected: absent"
    server._discovery_cache[name] = frozenset({"apps.example.io"})
    ka._ka_client_cache[name] = object()
    ka._discovery_cache[name] = object()


@pytest.mark.asyncio
async def test_disconnect_unknown_name(server):
    result = await server.disconnect_cluster(name="no-such-instance")
    assert result.get("code") == "unknown_source", f"got {result}"


@pytest.mark.asyncio
async def test_disconnect_empty_name(server):
    result = await server.disconnect_cluster(name="")
    assert result.get("code") == "unknown_source", f"got {result}"
    # the default instance's name must not leak into the error message
    default_name = server._source_registry.default_kubernetes_instance()
    if default_name:
        assert default_name not in result.get("error", "")


@pytest.mark.asyncio
async def test_disconnect_default_instance_refused(server):
    default_name = server._source_registry.default_kubernetes_instance()
    result = await server.disconnect_cluster(name=default_name)
    assert result.get("code") == "cannot_remove_default", f"got {result}"
    # and the entry must still be there
    assert server._source_registry.get(default_name) is not None


@pytest.mark.asyncio
async def test_disconnect_non_kubernetes_instance_refused(server):
    name = "disc-fake-prom"
    server._source_registry.add_instance(server.SourceEntry(
        name=name, adapter="prometheus",
        capabilities=("Metric",), state="configured", default=False,
    ))
    try:
        result = await server.disconnect_cluster(name=name)
        assert result.get("code") == "not_kubernetes_instance", f"got {result}"
        assert server._source_registry.get(name) is not None
    finally:
        server._source_registry.remove_instance(name)


@pytest.mark.asyncio
async def test_disconnect_refuses_startup_discovered_instance(server):
    """A kubernetes instance present in the registry but never added via
    connect_cluster (startup discovery) is refused: removal would be
    irreversible for the process lifetime on a stock deployment."""
    name = "disc-discovered"
    default_caps = server._source_registry.get(
        server._source_registry.default_kubernetes_instance()).capabilities
    server._source_registry.add_instance(server.SourceEntry(
        name=name, adapter="kubernetes",
        capabilities=default_caps, state="configured", default=False,
    ))
    try:
        result = await server.disconnect_cluster(name=name)
        assert result.get("code") == "not_runtime_instance", f"got {result}"
        assert server._source_registry.get(name) is not None
    finally:
        server._source_registry.remove_instance(name)


@pytest.mark.asyncio
async def test_disconnect_purges_every_runtime_store(server):
    name = "disc-target-a"
    _seed_runtime_instance(server, name)

    result = await server.disconnect_cluster(name=name)

    assert result.get("disconnected") is True, f"got {result}"
    assert result.get("name") == name
    with pytest.raises(KeyError):
        server._source_registry.get(name)
    assert name not in server._runtime_instances
    assert name not in server._k8s_instances
    assert name not in server._k8s_conn_state
    assert name not in server._namespace_cache
    assert name not in server._instance_tokens
    leftover = [k for k in server._extension_states if k[1] == name]
    assert not leftover, f"extension states not purged: {leftover}"
    # review round 1 BLOCKER: these three survived the original purge and
    # would serve cluster A's data after a reconnect to cluster B
    assert name not in server._discovery_cache
    assert name not in ka._ka_client_cache
    assert name not in ka._discovery_cache


@pytest.mark.asyncio
async def test_disconnect_frees_the_name_for_reconnection(server, monkeypatch):
    """Before disconnect, connect_cluster(name) hits duplicate_name; after
    disconnect the same name proceeds past registration (to the dial step),
    proving the registry slot is genuinely freed."""
    from core.config_types import ResolvedConfig as _RC, SourceConfig as _SC

    cfg = _RC(
        profile="test",
        sources={"kubernetes": _SC(adapter="kubernetes",
                                   options={"credential_ref_roots": ["/"]})},
        extensions={},
    )
    monkeypatch.setattr(server, "_lumino_config", cfg)

    name = "disc-target-b"
    _seed_runtime_instance(server, name)

    dup = await server.connect_cluster(
        name=name, credential_ref="kubeconfig:/any/path#ctx")
    assert dup.get("code") == "duplicate_name", f"got {dup}"

    result = await server.disconnect_cluster(name=name)
    assert result.get("disconnected") is True, f"got {result}"

    def fake_build_fail(context, kubeconfig_path=None):
        raise ConnectionError("connection refused (test-injected)")

    monkeypatch.setattr(server, "_build_k8s_client_set", fake_build_fail)
    retry = await server.connect_cluster(
        name=name, credential_ref="kubeconfig:/any/path#ctx")
    assert retry.get("code") == "dial_failed", (
        f"expected the freed name to reach the dial step, got {retry}"
    )


@pytest.mark.asyncio
async def test_discovery_write_back_after_disconnect_is_discarded(server, monkeypatch):
    """Review round 1 MAJOR: a coroutine that resolved the instance before
    disconnect must not resurrect cache state by writing back after it.
    Pin for _discover_api_groups -> _discovery_cache."""
    name = "disc-race-a"
    _seed_runtime_instance(server, name)
    server._discovery_cache.pop(name, None)  # force the discovery path

    gate = asyncio.Event()

    class _SlowApis:
        def get_api_versions(self, **kwargs):
            # runs in a worker thread; block until the disconnect happened
            import time
            while not gate.is_set():
                time.sleep(0.01)
            from types import SimpleNamespace
            return SimpleNamespace(groups=[SimpleNamespace(name="apps")])

    class _View:
        apis_api = _SlowApis()

    monkeypatch.setattr(server, "_resolve_k8s", lambda inst: (_View(), None))
    # restore the import-inertness spy counter on teardown — the session-scoped
    # server module is shared and test_extension_activation pins it at 0
    monkeypatch.setattr(server, "_discovery_call_count",
                        server._discovery_call_count)

    task = asyncio.ensure_future(server._discover_api_groups(name))
    await asyncio.sleep(0.05)  # let the worker start and block
    result = await server.disconnect_cluster(name=name)
    assert result.get("disconnected") is True, f"got {result}"
    gate.set()
    await task
    assert name not in server._discovery_cache, (
        "in-flight discovery wrote back into _discovery_cache after disconnect"
    )


@pytest.mark.asyncio
async def test_connect_interrupted_by_disconnect_leaves_no_zombie(server, monkeypatch):
    """Re-review MAJOR-1: a disconnect landing during connect_cluster's
    extension-detection window (after the dial, before 'connected') must not
    let the resuming connect write conn-state/extension-state back on top of
    the purge — that zombie reports as connected, is unreachable, and cannot
    be removed without a restart."""
    from types import SimpleNamespace
    from core.config_types import ResolvedConfig as _RC, SourceConfig as _SC

    cfg = _RC(
        profile="test",
        sources={"kubernetes": _SC(adapter="kubernetes",
                                   options={"credential_ref_roots": ["/"]})},
        extensions={"tekton": "on"},
    )
    monkeypatch.setattr(server, "_lumino_config", cfg)

    class _FakeApis:
        def get_api_versions(self, **kwargs):
            return SimpleNamespace(groups=[])

    def fake_build(context, kubeconfig_path=None):
        return SimpleNamespace(apis_api=_FakeApis())

    monkeypatch.setattr(server, "_build_k8s_client_set", fake_build)
    monkeypatch.setattr(server, "_extract_kubeconfig_token",
                        lambda path, context: None)

    detect_entered = asyncio.Event()
    release_detect = asyncio.Event()

    async def slow_detect(ext, facade, ctx, timeout_s=2.0):
        detect_entered.set()
        await release_detect.wait()
        return "active", []

    monkeypatch.setattr(server, "detect_and_register", slow_detect)

    name = "zz-race-connect"
    task = asyncio.ensure_future(server.connect_cluster(
        name=name, credential_ref="kubeconfig:/any/path#ctx"))
    await asyncio.wait_for(detect_entered.wait(), timeout=10)

    result = await server.disconnect_cluster(name=name)
    assert result.get("disconnected") is True, f"got {result}"

    release_detect.set()
    connect_result = await task

    assert connect_result.get("code") == "disconnected_during_connect", (
        f"resumed connect must abort, got {connect_result}"
    )
    # no zombie state anywhere
    assert name not in server._k8s_conn_state
    assert name not in server._k8s_instances
    assert not [k for k in server._extension_states if k[1] == name]
    with pytest.raises(KeyError):
        server._source_registry.get(name)
    assert name not in server._runtime_instances


@pytest.mark.asyncio
async def test_kubearchive_revive_clears_caches_and_get_discovery_respects_tombstone():
    """Re-review MAJOR-2: get_discovery re-cached after evict_source, and
    revive_source left both caches intact — a name reused for a different
    cluster then served the OLD cluster's KubeArchive endpoint."""
    name = "disc-race-kb"
    ka._ka_client_cache[name] = object()
    ka._discovery_cache[name] = object()

    ka.evict_source(name)
    assert name not in ka._ka_client_cache
    assert name not in ka._discovery_cache

    # tombstoned: get_discovery must not write the cache back (pass both
    # required clients so the construction path is genuinely reached)
    result = ka.get_discovery(name, k8s_core_api=object(),
                              k8s_custom_api=object())
    assert result is None, "tombstoned source must not receive a discovery"
    assert name not in ka._discovery_cache, (
        "get_discovery re-cached a tombstoned source"
    )

    # simulate stale objects sneaking in anyway; revive must clear them
    ka._ka_client_cache[name] = object()
    ka._discovery_cache[name] = object()
    ka.revive_source(name)
    assert name not in ka._ka_client_cache, "revive_source must clear the client cache"
    assert name not in ka._discovery_cache, "revive_source must clear the discovery cache"
    assert name not in ka._evicted_sources


@pytest.mark.asyncio
async def test_kubearchive_client_write_back_after_evict_is_discarded():
    """Same race, kubearchive side: setup_kubearchive_client awaiting
    endpoint discovery when the source is evicted must not cache a client
    for the evicted source."""
    name = "disc-race-ka"
    ka._ka_client_cache.pop(name, None)
    ka._evicted_sources.discard(name)

    release = asyncio.Event()

    class _SlowDiscovery:
        async def discover_endpoint(self):
            await release.wait()
            return "https://ka.example:443"

    task = asyncio.ensure_future(ka.setup_kubearchive_client(
        _SlowDiscovery(), k8s_core_api=object(), k8s_auth_token="tok",
        source=name))
    await asyncio.sleep(0.02)
    ka.evict_source(name)
    release.set()
    client = await task
    assert client is None, "evicted source must not receive a cached client"
    assert name not in ka._ka_client_cache
    # a later reconnect revives the source for fresh setup
    ka.revive_source(name)
    assert name not in ka._evicted_sources
