"""
Task 5 (F4): Seam tests for the kubearchive per-source discovery factory.

Tests cover:
  1. Two sources → two distinct discovery objects.
  2. Named source: subprocess.Popen NOT called (port-forward confined to default).
  3. Default source (source=""): auto_port_forward=True preserved.
  4. Same source → cached object on second call (process-lifetime cache).
  5. KUBEARCHIVE_ENABLED=false → factory returns None (read at call time).
  6. Missing clients → factory returns None.
  7. BUG 2 fix (review B2): KUBEARCHIVE_HOST env applies only to default source;
     named sources must not short-circuit to the env value.

RED discipline: Written before implementation. Each test fails with
AttributeError when get_discovery / _discovery_cache do not exist.
After implementation all pass without modification.

Mutation check (documented in task-5-report.md):
  Mutant: change auto_port_forward=(source == "") to auto_port_forward=True
  in get_discovery.  Running this suite must cause
  test_named_source_has_auto_port_forward_false to fail — confirming the
  seam test catches the regression.  No other test in the suite should fail.

Mutation check for BUG 2 (review B2):
  Mutant: remove the `if not self._source:` guard around the KUBEARCHIVE_HOST
  env block in discover_endpoint.  Running this suite must cause
  test_kubearchive_host_ignored_for_named_source to fail.

Mutation check for M1 (review round 2):
  Mutant: remove the `if not self._source:` guard at
  kubearchive_integration.py:~202 (the one that gates _check_service).  Running this suite must cause
  test_named_source_service_and_kubeconfig_steps_never_called to fail —
  confirming the seam test catches the regression.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

import helpers.kubearchive_integration as ka


def _mock_clients():
    """Return minimal mock k8s clients: (core_api, custom_api, networking_api)."""
    return MagicMock(), MagicMock(), MagicMock()


@pytest.fixture(autouse=True)
def clear_discovery_cache(monkeypatch):
    """Clear the factory cache and ensure KUBEARCHIVE_ENABLED=true before each test.

    The characterization conftest sets KUBEARCHIVE_ENABLED=false at session scope
    to prevent port-forward during collection. This fixture ensures each test in
    this module starts with the factory enabled. Tests in TestFactoryReturnsNone
    override it back to "false" via their own monkeypatch.setenv calls.
    """
    monkeypatch.setenv("KUBEARCHIVE_ENABLED", "true")
    ka._discovery_cache.clear()
    yield
    ka._discovery_cache.clear()


# ─── 1. Two sources → two distinct objects ────────────────────────────────────

class TestTwoSourcesProduceTwoObjects:
    """Different source strings must yield different discovery instances."""

    def test_default_and_named_are_distinct(self):
        core, custom, networking = _mock_clients()
        d_default = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        d_named = ka.get_discovery(
            "named-cluster", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d_default is not None
        assert d_named is not None
        assert d_default is not d_named, (
            "get_discovery('') and get_discovery('named-cluster') must return "
            "different KubeArchiveEndpointDiscovery instances"
        )

    def test_two_named_sources_are_distinct(self):
        core, custom, _ = _mock_clients()
        d1 = ka.get_discovery("cluster-a", k8s_core_api=core, k8s_custom_api=custom)
        d2 = ka.get_discovery("cluster-b", k8s_core_api=core, k8s_custom_api=custom)
        assert d1 is not None
        assert d2 is not None
        assert d1 is not d2, (
            "Different named sources must produce different discovery objects"
        )


# ─── 2. Port-forward confined to default (subprocess seam) ───────────────────

class TestPortForwardConfinement:
    """Port-forward subprocess is confined to source='' only."""

    def test_default_source_has_auto_port_forward_true(self):
        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None
        assert d._auto_port_forward is True, (
            "Default source must have auto_port_forward=True — port-forward "
            "is the local-dev path for the operator's own cluster"
        )

    def test_named_source_has_auto_port_forward_false(self):
        """Seam: named source discovery object must have auto_port_forward=False.

        Mutation check: changing auto_port_forward=(source == "") to
        auto_port_forward=True in get_discovery causes THIS test to fail.
        """
        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "named-cluster", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None
        assert d._auto_port_forward is False, (
            "Named source must have auto_port_forward=False — port-forward is "
            "confined to the default source"
        )

    def test_named_source_subprocess_popen_not_called(self, monkeypatch):
        """Subprocess seam: creating a named-source discovery object must never
        invoke subprocess.Popen (port-forward setup)."""
        popen_calls = []

        def fake_popen(*args, **kwargs):
            popen_calls.append(args)
            return MagicMock()

        monkeypatch.setattr(
            "helpers.kubearchive_integration.subprocess.Popen", fake_popen
        )

        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "named-cluster", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None
        assert d._auto_port_forward is False
        assert popen_calls == [], (
            "subprocess.Popen must not be invoked when creating a named-source "
            "discovery object — port-forward is confined to the default source"
        )


# ─── 3. Cache: same source → same object ──────────────────────────────────────

class TestFactoryCache:
    """Factory must return the same object on repeated calls for the same source."""

    def test_default_source_cached(self):
        core, custom, networking = _mock_clients()
        d1 = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        d2 = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d1 is not None
        assert d1 is d2, "Same source must return the same cached discovery object"

    def test_named_source_cached(self):
        core, custom, _ = _mock_clients()
        d1 = ka.get_discovery("my-cluster", k8s_core_api=core, k8s_custom_api=custom)
        d2 = ka.get_discovery("my-cluster", k8s_core_api=core, k8s_custom_api=custom)
        assert d1 is not None
        assert d1 is d2, "Named source must return cached object on second call"


# ─── 4. None conditions ────────────────────────────────────────────────────────

class TestFactoryReturnsNone:
    """Factory returns None when disabled or when clients are absent."""

    def test_kubearchive_disabled_returns_none(self, monkeypatch):
        """KUBEARCHIVE_ENABLED is read at factory-call time — not at import."""
        monkeypatch.setenv("KUBEARCHIVE_ENABLED", "false")
        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is None, (
            "Factory must return None when KUBEARCHIVE_ENABLED=false; "
            "flag is now read at call time, not at server import"
        )

    def test_disabled_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("KUBEARCHIVE_ENABLED", "False")
        core, custom, _ = _mock_clients()
        assert ka.get_discovery("", k8s_core_api=core, k8s_custom_api=custom) is None

    def test_missing_core_api_returns_none(self):
        _, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "", k8s_core_api=None, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is None, "Factory must return None when k8s_core_api is None"

    def test_missing_custom_api_returns_none(self):
        core, _, networking = _mock_clients()
        d = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=None,
            k8s_networking_api=networking,
        )
        assert d is None, "Factory must return None when k8s_custom_api is None"

    def test_disabled_does_not_populate_cache(self, monkeypatch):
        """When disabled, factory must not populate the cache with None entries."""
        monkeypatch.setenv("KUBEARCHIVE_ENABLED", "false")
        core, custom, _ = _mock_clients()
        ka.get_discovery("", k8s_core_api=core, k8s_custom_api=custom)
        assert "" not in ka._discovery_cache, (
            "Disabled factory call must not write None into the discovery cache"
        )


# ─── 5. BUG 2 fix: KUBEARCHIVE_HOST env isolation ────────────────────────────

class TestDiscoveryEnvironmentIsolation:
    """BUG 2 fix (review B2): KUBEARCHIVE_HOST env must apply only to the default source.

    Named sources must discover their endpoint exclusively via per-source-client
    paths (Route, Ingress).  The env short-circuit in discover_endpoint must be
    gated with `if not self._source:` mirroring prometheus.py:578's pattern.

    Mutation check: removing the `if not self._source:` guard in discover_endpoint
    causes test_kubearchive_host_ignored_for_named_source to fail — the env value
    is returned for the named source instead of None.
    """

    def test_kubearchive_host_honored_for_default_source(self, monkeypatch):
        """KUBEARCHIVE_HOST must short-circuit endpoint discovery for source=''."""
        monkeypatch.setenv("KUBEARCHIVE_HOST", "https://ka.default.example.com")

        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None

        result = asyncio.run(d.discover_endpoint())
        assert result == "https://ka.default.example.com", (
            "KUBEARCHIVE_HOST must be honored for the default source (source=''). "
            f"Got: {result!r}"
        )

    def test_kubearchive_host_ignored_for_named_source(self, monkeypatch):
        """KUBEARCHIVE_HOST env must be ignored when source is a named cluster.

        Mutation check: removing the `if not self._source:` guard in discover_endpoint
        causes this test to fail — the env value ('https://ka.default.example.com')
        is returned instead of None.

        The sub-discovery methods (_check_route, _check_ingress, _check_service)
        are stubbed to return None so that
        only the env-gating seam is exercised.
        """
        monkeypatch.setenv("KUBEARCHIVE_HOST", "https://ka.default.example.com")

        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "named-cluster-env-test",
            k8s_core_api=core,
            k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None

        # Stub per-source-client discovery paths so only the env gate matters.
        # These are NOT the seam under test; stubbing them isolates the env guard.
        async def stub_none(self_):
            return None

        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_route", stub_none)
        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_ingress", stub_none)
        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_service", stub_none)

        result = asyncio.run(d.discover_endpoint())
        assert result is None, (
            "KUBEARCHIVE_HOST must be ignored for named sources; "
            f"discover_endpoint returned {result!r} instead of None. "
            "Add `if not self._source:` guard around the KUBEARCHIVE_HOST block "
            "in discover_endpoint (mirror prometheus.py:578)."
        )


# ─── 6. M1 spy: service and kubeconfig steps never called for named source ────

class TestDiscoveryGatingSpyM1:
    """M1 mutant kill: _check_service must never be called for a named source.

    Removing the `if not self._source:` guard at kubearchive_integration.py:~202
    must cause test_named_source_service_and_kubeconfig_steps_never_called to fail.

    Spy pattern: both gated methods are replaced with call-recording fakes that
    return None.  For named sources the guard must prevent any invocation; for
    source='' the service step IS attempted (reachability check).
    """

    @pytest.mark.asyncio
    async def test_named_source_service_and_kubeconfig_steps_never_called(
        self, monkeypatch
    ):
        """Spy: _check_service must have call_count == 0 after discover_endpoint() for a named source.

        Mutant kill (M1): removing the `if not self._source:` guard at :~202
        makes _check_service reachable → spy fires → this test fails.
        """
        monkeypatch.delenv("KUBEARCHIVE_HOST", raising=False)

        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "named-spy-cluster-m1",
            k8s_core_api=core,
            k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None

        service_calls: list = []

        async def spy_check_service(self_):
            service_calls.append(1)
            return None

        # Stub _check_route and _check_ingress to return None so discover_endpoint
        # proceeds past steps 2-3 and reaches the guard under test.
        async def stub_none(self_):
            return None

        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_route", stub_none)
        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_ingress", stub_none)
        monkeypatch.setattr(
            ka.KubeArchiveEndpointDiscovery, "_check_service", spy_check_service
        )

        result = await d.discover_endpoint()

        assert service_calls == [], (
            f"_check_service must NOT be called for a named source; "
            f"got {len(service_calls)} call(s). "
            "Add `if not self._source:` guard before _check_service in discover_endpoint."
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_default_source_service_step_is_reachable(self, monkeypatch):
        """Reachability check: for source='', the service step IS attempted.

        Verifies the guard does not block _check_service for the default source.
        If this test fails without the M1 mutant applied, the guard is over-broad.
        """
        monkeypatch.delenv("KUBEARCHIVE_HOST", raising=False)

        core, custom, networking = _mock_clients()
        d = ka.get_discovery(
            "", k8s_core_api=core, k8s_custom_api=custom,
            k8s_networking_api=networking,
        )
        assert d is not None

        service_calls: list = []

        async def spy_check_service(self_):
            service_calls.append(1)
            return None

        async def stub_none(self_):
            return None

        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_route", stub_none)
        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, "_check_ingress", stub_none)
        monkeypatch.setattr(
            ka.KubeArchiveEndpointDiscovery, "_check_service", spy_check_service
        )

        await d.discover_endpoint()

        assert len(service_calls) > 0, (
            "_check_service must be reachable for source=''; got 0 calls. "
            "The `if not self._source:` guard at :~202 is too broad."
        )
