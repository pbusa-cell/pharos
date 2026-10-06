"""
tests/test_namespace_trust.py

Discovery must not trust a namespace that any user could have created.

On OpenShift a user can self-provision a project with a name such as
"kubearchive" or "monitoring" when it does not exist yet. Such projects carry
the openshift.io/requester annotation. A route, service, ingress, Prometheus CR
or CA secret in such a namespace must not become the KubeArchive or
Prometheus/Thanos endpoint (KubeArchive requests carry the caller's token).

Contract (core.namespace_trust.namespace_is_trusted):
  * openshift-*, kube-* and default are trusted without an API call;
  * other namespaces are trusted only when the Namespace can be read and has
    no openshift.io/requester annotation.
"""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes.client.rest import ApiException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import helpers.kubearchive_integration as ka  # noqa: E402
from core.namespace_trust import namespace_is_trusted  # noqa: E402
from helpers import prometheus as prom  # noqa: E402

REQUESTER = "openshift.io/requester"


def _ns(annotations=None):
    return SimpleNamespace(metadata=SimpleNamespace(annotations=annotations))


def _core(owned=(), missing=(), forbidden=()):
    """Core API whose read_namespace reports self-provisioned/missing/forbidden namespaces."""
    core = MagicMock()

    def read_namespace(name, **kw):
        if name in missing:
            raise ApiException(status=404)
        if name in forbidden:
            raise ApiException(status=403)
        if name in owned:
            return _ns({REQUESTER: "mallory"})
        return _ns({"openshift.io/sa.scc.uid-range": "1000/10000"})

    core.read_namespace.side_effect = read_namespace
    return core


# ── namespace_is_trusted ─────────────────────────────────────────────────────


@pytest.mark.parametrize("ns", ["openshift-monitoring", "openshift-user-workload-monitoring", "kube-system", "default"])
def test_platform_namespaces_trusted_without_read(ns):
    core = MagicMock()

    assert namespace_is_trusted(core, ns) is True
    core.read_namespace.assert_not_called()


def test_admin_created_namespace_trusted():
    assert namespace_is_trusted(_core(), "product-kubearchive") is True


def test_self_provisioned_namespace_untrusted():
    assert namespace_is_trusted(_core(owned={"kubearchive"}), "kubearchive") is False


@pytest.mark.parametrize("kind", ["missing", "forbidden"])
def test_unreadable_namespace_untrusted(kind):
    core = _core(**{kind: {"monitoring"}})

    assert namespace_is_trusted(core, "monitoring") is False


def test_no_core_api_untrusted():
    assert namespace_is_trusted(None, "monitoring") is False


# ── Prometheus / Thanos discovery ────────────────────────────────────────────


def _svc(name, namespace, port=9090):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        spec=SimpleNamespace(ports=[SimpleNamespace(port=port, name="web")]),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "discover,svc_name",
    [(prom._discover_prometheus_via_services, "prometheus"), (prom._discover_thanos_via_services, "thanos-query")],
)
async def test_named_search_skips_self_provisioned_namespace(discover, svc_name):
    core = _core(owned={"monitoring"})
    core.list_namespaced_service.side_effect = lambda namespace, **kw: SimpleNamespace(
        items=[_svc(svc_name, namespace)] if namespace == "monitoring" else []
    )
    core.list_service_for_all_namespaces.return_value = SimpleNamespace(items=[])

    assert await discover(core) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("discover", [prom._discover_prometheus_via_services, prom._discover_thanos_via_services])
async def test_label_search_skips_self_provisioned_namespace(discover):
    core = _core(owned={"monitoring"})
    core.list_namespaced_service.return_value = SimpleNamespace(items=[])
    core.list_service_for_all_namespaces.return_value = SimpleNamespace(items=[_svc("p", "monitoring")])

    assert await discover(core) is None


@pytest.mark.asyncio
async def test_named_search_uses_admin_created_namespace():
    core = _core()
    core.list_namespaced_service.side_effect = lambda namespace, **kw: SimpleNamespace(
        items=[_svc("prometheus", namespace)] if namespace == "monitoring" else []
    )

    assert await prom._discover_prometheus_via_services(core) == (
        "http://prometheus.monitoring.svc.cluster.local:9090"
    )


@pytest.mark.asyncio
async def test_operator_cr_uses_admin_created_namespace():
    core = _core()
    core.read_namespaced_service.side_effect = lambda name, namespace: _svc(name, namespace)
    custom = MagicMock()
    custom.list_cluster_custom_object.return_value = {"items": [{"metadata": {"name": "x", "namespace": "monitoring"}}]}

    assert await prom._discover_prometheus_via_operator_crd(custom, core) == (
        "http://prometheus-x.monitoring.svc.cluster.local:9090"
    )


@pytest.mark.asyncio
async def test_operator_cr_skips_self_provisioned_namespace():
    core = _core(owned={"monitoring"})
    core.read_namespaced_service.side_effect = lambda name, namespace: _svc(name, namespace)
    custom = MagicMock()
    custom.list_cluster_custom_object.return_value = {"items": [{"metadata": {"name": "x", "namespace": "monitoring"}}]}

    assert await prom._discover_prometheus_via_operator_crd(custom, core) is None


# ── KubeArchive discovery ────────────────────────────────────────────────────


def _discovery(core, custom=None, networking=None):
    return ka.KubeArchiveEndpointDiscovery(core, custom or MagicMock(), networking, auto_port_forward=False)


def _custom_with_routes(routes):
    """routes: {namespace: host}"""
    custom = MagicMock()

    def get(group, version, namespace, plural, name):
        if namespace in routes:
            return {"spec": {"host": routes[namespace], "tls": {"termination": "edge"}}}
        raise ApiException(status=404)

    custom.get_namespaced_custom_object.side_effect = get
    return custom


@pytest.mark.asyncio
async def test_route_in_self_provisioned_kubearchive_namespace_ignored():
    core = _core(owned={"kubearchive"})
    d = _discovery(core, _custom_with_routes({"kubearchive": "evil.apps.example.com"}))

    assert await d._check_route() is None


@pytest.mark.asyncio
async def test_trusted_product_kubearchive_used_when_kubearchive_self_provisioned():
    core = _core(owned={"kubearchive"})
    d = _discovery(core, _custom_with_routes({
        "kubearchive": "evil.apps.example.com",
        "product-kubearchive": "ka.apps.example.com",
    }))

    assert await d._check_route() == "https://ka.apps.example.com"


@pytest.mark.asyncio
async def test_product_kubearchive_route_wins_over_kubearchive():
    core = _core()
    d = _discovery(core, _custom_with_routes({
        "kubearchive": "other.apps.example.com",
        "product-kubearchive": "ka.apps.example.com",
    }))

    assert await d._check_route() == "https://ka.apps.example.com"


@pytest.mark.asyncio
async def test_service_in_self_provisioned_namespace_ignored():
    core = _core(owned={"kubearchive"})

    def read_service(name, namespace, **kw):
        if namespace == "kubearchive":
            return SimpleNamespace(
                metadata=SimpleNamespace(name=name),
                spec=SimpleNamespace(ports=[SimpleNamespace(port=8081, name="https")]),
            )
        raise ApiException(status=404)

    core.read_namespaced_service.side_effect = read_service

    assert await _discovery(core)._check_service() is None


@pytest.mark.asyncio
async def test_ingress_in_self_provisioned_namespace_ignored():
    core = _core(owned={"kubearchive"})
    networking = MagicMock()

    def read_ingress(name, namespace, **kw):
        if namespace == "kubearchive":
            rule = SimpleNamespace(host="evil.example.com")
            return SimpleNamespace(spec=SimpleNamespace(rules=[rule], tls=None), status=None)
        raise ApiException(status=404)

    networking.read_namespaced_ingress.side_effect = read_ingress

    assert await _discovery(core, networking=networking)._check_ingress() is None


def test_ca_secret_in_self_provisioned_namespace_ignored():
    core = _core(owned={"kubearchive"})
    secret = SimpleNamespace(data={"ca.crt": "Zm9v"})
    core.read_namespaced_secret.side_effect = lambda name, namespace: (
        secret if namespace == "kubearchive" else (_ for _ in ()).throw(ApiException(status=404))
    )
    disco = MagicMock()
    disco._discovered_namespace = None
    c = ka.KubeArchiveClient(endpoint_discovery=disco, k8s_core_api=core)

    assert c._read_kubearchive_ca() is None
