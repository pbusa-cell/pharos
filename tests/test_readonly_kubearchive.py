"""Behavioral proof + must-stay-raw guards for kubearchive_integration
(spec SS4.7, phase 1e).  KubeArchiveClient.k8s_core_api is AUTH-CRITICAL raw
(api_client at :696/:721); only EndpointDiscovery wraps at assignment and
_get_ssl_context wraps locally."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Insert order is load-bearing: src/ MUST end up at sys.path[0] (tests/core/
# would otherwise shadow src/core for the guarded core imports).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import helpers.kubearchive_integration as ka
from _readonly_spy import make_spy
from core.readonly_client import ReadOnlyK8sClient, WriteOperationError


def test_endpoint_discovery_wraps_clients(monkeypatch):
    record = []
    monkeypatch.setattr(ka, "ReadOnlyK8sClient", make_spy(record))

    disco = ka.KubeArchiveEndpointDiscovery(
        k8s_core_api=MagicMock(), k8s_custom_api=MagicMock(),
        k8s_networking_api=MagicMock())
    disco.k8s_core_api.read_namespaced_service
    disco.k8s_custom_api.get_namespaced_custom_object

    assert "read_namespaced_service" in record and \
        "get_namespaced_custom_object" in record, (
        f"discovery clients not wrapped at assignment; record={record}")
    with pytest.raises(WriteOperationError):
        disco.k8s_core_api.delete_namespaced_pod


def test_kubearchive_client_core_api_stays_raw():
    """AUTH GUARD: KubeArchiveClient must keep the raw client — its token
    extraction (:696) and OpenShift detection (:721) read api_client, which
    the proxy denies.  Wrapping here would break authentication."""
    src = (Path(__file__).resolve().parents[1]
           / "src" / "helpers" / "kubearchive_integration.py").read_text()
    assert "self.k8s_core_api = k8s_core_api" in src, (
        "KubeArchiveClient.__init__ no longer assigns the RAW client — "
        "api_client access at :696/:721 would break")
    assert "self.k8s_core_api = ReadOnlyK8sClient.wrap" not in src, (
        "KubeArchiveClient.k8s_core_api was wrapped — this BREAKS AUTH "
        "(api_client.configuration token extraction)")


@pytest.mark.asyncio
async def test_ssl_context_read_routes_readonly(monkeypatch):
    """_get_ssl_context is ASYNC — the await is mandatory (an un-awaited call
    never executes the body).  Instance built via __new__ needs the attrs the
    method touches before the read (Step 1 confirms; adjust attrs only, never
    the assertion)."""
    record = []
    monkeypatch.setattr(ka, "ReadOnlyK8sClient", make_spy(record))
    client = ka.KubeArchiveClient.__new__(ka.KubeArchiveClient)
    client.k8s_core_api = MagicMock()
    client.k8s_core_api.read_namespaced_secret.side_effect = Exception("no secret")
    client._ssl_context = None
    client._ssl_context_key = None
    client._ca_namespaces = ["kubearchive"]
    client._ca_secret_names = ["kubearchive-ca"]
    disco = MagicMock()
    disco._port_forward_process = None
    disco._discovered_namespace = None
    async def _no_endpoint(*a, **k):
        return None
    disco.discover_endpoint = _no_endpoint
    client.endpoint_discovery = disco

    try:
        await client._get_ssl_context()
    except Exception:
        pass  # any downstream failure is fine — the read attempt is the proof

    assert "read_namespaced_secret" in record, (
        f"_get_ssl_context read not routed through local wrap; record={record}")
