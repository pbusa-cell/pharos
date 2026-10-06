"""Bug 6 (memory: pharos-tool-bugs-live-testing) — check_resource_constraints
must tolerate a pod vanishing between the list and the per-pod read.

Live repro 2026-08-21 (prd-i01, internal-services): a short-lived
affinity-assistant pod was deleted between list_pods and read_namespaced_pod;
the 404 propagated as a hard error and killed the whole namespace scan.
Vanished pods are normal (completed TaskRun pods, ephemeral assistants) —
skip them, count them, keep scanning.
"""
import asyncio
from types import SimpleNamespace

import pytest
from kubernetes.client.rest import ApiException


def _minimal_pod(name):
    return SimpleNamespace(
        status=SimpleNamespace(conditions=None, container_statuses=None,
                               init_container_statuses=None),
        spec=SimpleNamespace(containers=[]),
        metadata=SimpleNamespace(name=name),
    )


def _fake_clients():
    def read_namespaced_pod(name, namespace, **kwargs):
        if name == "ghost":
            raise ApiException(status=404, reason="Not Found")
        return _minimal_pod(name)

    core = SimpleNamespace(
        read_namespace=lambda ns, **kw: SimpleNamespace(),
        read_namespaced_pod=read_namespaced_pod,
        list_namespaced_resource_quota=lambda ns, **kw: SimpleNamespace(items=[]),
    )
    return SimpleNamespace(core_api=core)


@pytest.fixture()
def constraints_result(server, monkeypatch):
    monkeypatch.setattr(server, "_resolve_k8s",
                        lambda source: (_fake_clients(), None))
    monkeypatch.setattr(server.ReadOnlyK8sClient, "wrap",
                        staticmethod(lambda c: c))

    async def fake_list_pods(namespace, core_api, log, **kw):
        return [{"name": "alive", "status": "Running"},
                {"name": "ghost", "status": "Pending"}]
    monkeypatch.setattr(server, "list_pods", fake_list_pods)

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            server.check_resource_constraints(namespace="ns-x"))
    finally:
        loop.close()


def test_vanished_pod_does_not_kill_the_scan(constraints_result):
    assert "error" not in constraints_result, (
        f"a 404 on one short-lived pod must not fail the whole scan; "
        f"got {constraints_result.get('summary')}"
    )
    assert constraints_result.get("status") in ("Healthy", "Warning", "Critical")


def test_vanished_pod_is_counted(constraints_result):
    assert constraints_result.get("pods_vanished_during_scan") == 1, (
        f"the skipped pod must be surfaced, not silent; got "
        f"{constraints_result.get('pods_vanished_during_scan')}"
    )
