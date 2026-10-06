"""
tests/test_kubearchive_tls.py

KubeArchive requests carry a bearer token, so KubeArchiveClient._get_ssl_context
must fail closed:
  * verification is off only for loopback hosts and a live port-forward,
    or when LUMINO_TLS_INSECURE_SKIP_VERIFY is set;
  * no core API, a missing/forbidden CA secret, or any read error gives the
    shared verifying context, never ssl=False;
  * a CA read from the cluster goes into a client-scoped context only;
  * the decision follows the current endpoint, not the first one seen.

Token-bearing requests never follow redirects and never go to a plain http,
non-loopback endpoint.
"""
import base64
import ssl
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from kubernetes.client.rest import ApiException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import helpers.kubearchive_integration as ka
from core import tls
from tests._tls_fixtures import make_ca_and_server_cert


@pytest.fixture(autouse=True)
def _clean_tls_env(monkeypatch):
    monkeypatch.delenv(tls.INSECURE_ENV, raising=False)
    monkeypatch.delenv(tls.CA_BUNDLE_ENV, raising=False)
    tls.clear_cache()
    yield
    tls.clear_cache()


def _client(endpoint, core_api=None, port_forward=None):
    discovery = MagicMock()
    discovery.discover_endpoint = AsyncMock(return_value=endpoint)
    discovery._port_forward_process = port_forward
    discovery._discovered_namespace = None
    return ka.KubeArchiveClient(endpoint_discovery=discovery, k8s_auth_token="tok", k8s_core_api=core_api)


def _assert_verifying(ctx):
    assert isinstance(ctx, ssl.SSLContext), f"got {ctx!r}: TLS verification disabled"
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def _core_api_raising(exc):
    core = MagicMock()
    core.read_namespaced_secret.side_effect = exc
    return core


def _ca_names(ctx):
    return [dict(x[0] for x in c["subject"]).get("commonName") for c in ctx.get_ca_certs()]


@pytest.mark.asyncio
async def test_no_core_api_fails_closed():
    c = _client("https://kubearchive-api-server.product-kubearchive.svc.cluster.local:8081")

    _assert_verifying(await c._get_ssl_context())


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [ApiException(status=403), ApiException(status=404), RuntimeError("boom")])
async def test_ca_secret_unavailable_fails_closed(exc):
    c = _client(
        "https://kubearchive-api-server.product-kubearchive.svc.cluster.local:8081",
        core_api=_core_api_raising(exc),
    )

    _assert_verifying(await c._get_ssl_context())


@pytest.mark.asyncio
async def test_apps_route_verifies():
    c = _client("https://kubearchive-api-server-kubearchive.apps.example.com")

    _assert_verifying(await c._get_ssl_context())


@pytest.mark.asyncio
async def test_ca_from_secret_is_client_scoped(tmp_path):
    _, _, _, ca_pem = make_ca_and_server_cert(tmp_path)
    secret = MagicMock()
    secret.data = {"ca.crt": base64.b64encode(ca_pem.encode()).decode()}
    core = MagicMock()
    core.read_namespaced_secret.return_value = secret
    c = _client("https://kubearchive-api-server.kubearchive.svc.cluster.local:8081", core_api=core)

    ctx = await c._get_ssl_context()

    _assert_verifying(ctx)
    assert "pharos-test-ca" in _ca_names(ctx)
    assert "pharos-test-ca" not in _ca_names(tls.client_ssl_context())


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["https://localhost:8081", "https://127.0.0.1:8081", "https://[::1]:8081"])
async def test_loopback_skips_verification(endpoint):
    assert await _client(endpoint)._get_ssl_context() is False


@pytest.mark.asyncio
async def test_live_port_forward_skips_verification():
    c = _client("https://localhost:8081", port_forward=MagicMock())

    assert await c._get_ssl_context() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "https://kubearchive-api-server.kubearchive.svc.cluster.local:8081",
    "https://kubearchive-api-server-kubearchive.apps.example.com",
])
async def test_port_forward_flag_alone_does_not_skip_verification(endpoint):
    """_port_forward_process stays set when kubectl exits at once; only a loopback endpoint may skip."""
    c = _client(endpoint, port_forward=MagicMock())

    _assert_verifying(await c._get_ssl_context())


@pytest.mark.asyncio
async def test_invalid_ca_in_secret_falls_back_to_verifying_context():
    secret = MagicMock()
    secret.data = {"ca.crt": base64.b64encode(b"not a pem").decode()}
    core = MagicMock()
    core.read_namespaced_secret.return_value = secret
    c = _client("https://kubearchive-api-server.kubearchive.svc.cluster.local:8081", core_api=core)

    _assert_verifying(await c._get_ssl_context())


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query", "logs"])
async def test_unreadable_ca_bundle_returns_error(monkeypatch, tmp_path, method):
    monkeypatch.setenv(tls.CA_BUNDLE_ENV, str(tmp_path / "missing.pem"))
    c = _client("https://kubearchive-api-server-kubearchive.apps.example.com")

    if method == "query":
        result = await c.query_resources(resource_type="pod", namespace="team-a")
    else:
        result = await c.get_resource_logs(resource_type="pod", namespace="team-a", name="p")

    assert result["status"] == "error"
    assert tls.CA_BUNDLE_ENV in result["message"]


@pytest.mark.asyncio
async def test_decision_follows_current_endpoint():
    """A cached False for a port-forward must not apply to a later remote endpoint."""
    c = _client("https://localhost:8081", port_forward=MagicMock())
    assert await c._get_ssl_context() is False

    c.endpoint_discovery._port_forward_process = None
    c.endpoint_discovery.discover_endpoint = AsyncMock(
        return_value="https://kubearchive-api-server-kubearchive.apps.example.com"
    )

    _assert_verifying(await c._get_ssl_context())


@pytest.mark.asyncio
async def test_insecure_opt_out(monkeypatch):
    monkeypatch.setenv(tls.INSECURE_ENV, "true")
    c = _client("https://kubearchive.example.com")

    assert await c._get_ssl_context() is False


# ── token-bearing requests ───────────────────────────────────────────────────


class _Resp:
    status = 200
    headers = {"Content-Type": "application/json"}

    async def json(self):
        return {"kind": "List", "items": []}

    async def text(self):
        return "log line"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class _Session:
    def __init__(self, *a, **kw):
        self.calls = []
        _Session.last = self

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Resp()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query", "logs"])
async def test_requests_do_not_follow_redirects(monkeypatch, method):
    monkeypatch.setattr(ka.aiohttp, "ClientSession", _Session)
    c = _client("https://kubearchive-api-server-kubearchive.apps.example.com")

    if method == "query":
        await c.query_resources(resource_type="pod", namespace="team-a")
    else:
        await c.get_resource_logs(resource_type="pod", namespace="team-a", name="p")

    (_, kwargs), = _Session.last.calls
    assert kwargs.get("allow_redirects") is False
    _assert_verifying(kwargs["ssl"])


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query", "logs"])
async def test_plain_http_remote_endpoint_refused(monkeypatch, method):
    def _no_http(*a, **kw):
        raise AssertionError("token-bearing request sent over plain http")

    monkeypatch.setattr(ka.aiohttp, "ClientSession", _no_http)
    c = _client("http://kubearchive-api-server.kubearchive.svc.cluster.local:8081")

    if method == "query":
        result = await c.query_resources(resource_type="pod", namespace="team-a")
    else:
        result = await c.get_resource_logs(resource_type="pod", namespace="team-a", name="p")

    assert result["status"] == "error"
    assert result["message"].startswith("Refusing to send the bearer token over plain http")
