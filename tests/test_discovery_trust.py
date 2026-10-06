"""
tests/test_discovery_trust.py

Endpoint discovery must not let an arbitrary namespace choose the endpoint.

Prometheus/Thanos: the cluster-wide label-selector searches and the Prometheus
Operator CR search accept only services/CRs in TRUSTED_MONITORING_NAMESPACES.
A tenant who creates a Service labelled app=prometheus (or a Prometheus CR)
in its own namespace must not become the metrics source.

KubeArchive: discovery never guesses route hostnames from the cluster domain.
"""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import helpers.kubearchive_integration as ka  # noqa: E402
from helpers import prometheus as prom  # noqa: E402


def _svc(name, namespace, port=9090):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        spec=SimpleNamespace(ports=[SimpleNamespace(port=port, name="web")]),
    )


def _core_api(cluster_wide):
    """Known-namespace searches find nothing; the cluster-wide search returns cluster_wide."""
    core = MagicMock()
    core.list_namespaced_service.return_value = SimpleNamespace(items=[])
    core.list_service_for_all_namespaces.return_value = SimpleNamespace(items=cluster_wide)
    return core


@pytest.mark.asyncio
@pytest.mark.parametrize("discover", [prom._discover_prometheus_via_services, prom._discover_thanos_via_services])
async def test_label_search_ignores_untrusted_namespace(discover):
    core = _core_api([_svc("evil-prometheus", "tenant-a")])

    assert await discover(core) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("discover", [prom._discover_prometheus_via_services, prom._discover_thanos_via_services])
async def test_label_search_picks_trusted_namespace_over_tenant(discover):
    core = _core_api([_svc("evil-prometheus", "aaa-tenant"), _svc("prometheus-x", "monitoring")])

    endpoint = await discover(core)

    assert endpoint == "http://prometheus-x.monitoring.svc.cluster.local:9090"


def _custom_api(crs):
    custom = MagicMock()
    custom.list_cluster_custom_object.return_value = {
        "items": [{"metadata": {"name": n, "namespace": ns}} for n, ns in crs]
    }
    return custom


@pytest.mark.asyncio
async def test_operator_cr_in_untrusted_namespace_is_skipped():
    core = MagicMock()
    core.read_namespaced_service.side_effect = lambda name, namespace: _svc(name, namespace)

    endpoint = await prom._discover_prometheus_via_operator_crd(
        _custom_api([("evil", "aaa-tenant"), ("k8s", "openshift-monitoring")]), core
    )

    assert endpoint == "http://prometheus-k8s.openshift-monitoring.svc.cluster.local:9090"
    namespaces_read = [c.kwargs["namespace"] for c in core.read_namespaced_service.call_args_list]
    assert "aaa-tenant" not in namespaces_read


@pytest.mark.asyncio
async def test_label_search_accepts_user_workload_monitoring():
    core = _core_api([_svc("prometheus-user-workload", "openshift-user-workload-monitoring")])

    endpoint = await prom._discover_prometheus_via_services(core)

    assert endpoint == "http://prometheus-user-workload.openshift-user-workload-monitoring.svc.cluster.local:9090"


@pytest.mark.asyncio
async def test_operator_cr_only_untrusted_returns_none():
    core = MagicMock()
    core.read_namespaced_service.side_effect = lambda name, namespace: _svc(name, namespace)

    assert await prom._discover_prometheus_via_operator_crd(_custom_api([("evil", "tenant-a")]), core) is None


# ── KubeArchive: no hostname guessing ────────────────────────────────────────


@pytest.mark.asyncio
async def test_discovery_does_not_guess_route_hostnames(monkeypatch):
    """With no route/ingress/service found, discovery returns None and sends no request.

    A guessed host (kubearchive-api-server-<ns>.apps.<domain>) can be claimed by
    any project admin with a custom-host route, and the wildcard ingress
    certificate would pass TLS verification.
    """
    monkeypatch.delenv("KUBEARCHIVE_HOST", raising=False)

    def _no_http(*a, **kw):
        raise AssertionError("discovery sent an HTTP request")

    monkeypatch.setattr(ka.aiohttp, "ClientSession", _no_http)
    discovery = ka.KubeArchiveEndpointDiscovery(MagicMock(), MagicMock(), auto_port_forward=False)

    async def _none(self_):
        return None

    for step in ("_check_route", "_check_ingress", "_check_service"):
        monkeypatch.setattr(ka.KubeArchiveEndpointDiscovery, step, _none)

    assert await discovery.discover_endpoint(force_refresh=True) is None
    assert not hasattr(discovery, "_check_kubeconfig_route_inference")
