"""
tests/test_prometheus_tls.py

Prometheus/Thanos requests carry a bearer token, so they must:
  * verify the server certificate (no ssl=False unless explicitly opted out),
  * never follow redirects,
  * never send the token over plain http to a non-loopback host.

Covers helpers.prometheus._execute_prometheus_query_internal and the
prometheus_query tool in server-mcp.py, with call-site fakes and a real local
HTTPS server signed by a test CA.
"""
import importlib.util
import os
import ssl
import sys
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(SRC))

from core import tls  # noqa: E402
from helpers import prometheus as prom  # noqa: E402
from tests._tls_fixtures import make_ca_and_server_cert  # noqa: E402

TOKEN = "sha256~sre-token"

FAKE_KUBECONFIG = """\
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


@pytest.fixture(autouse=True)
def _clean_tls_env(monkeypatch):
    monkeypatch.delenv(tls.INSECURE_ENV, raising=False)
    monkeypatch.delenv(tls.CA_BUNDLE_ENV, raising=False)
    tls.clear_cache()
    yield
    tls.clear_cache()


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """Import server-mcp.py once per module against a fake kubeconfig."""
    saved = {k: os.environ.get(k) for k in ("KUBECONFIG", "KUBEARCHIVE_ENABLED")}
    kubeconfig = tmp_path_factory.mktemp("kube_prom_tls") / "config"
    kubeconfig.write_text(FAKE_KUBECONFIG)
    os.environ["KUBECONFIG"] = str(kubeconfig)
    os.environ["KUBEARCHIVE_ENABLED"] = "false"
    os.environ.pop("LUMINO_CONFIG", None)
    os.environ.pop("LUMINO_PROFILE", None)

    spec = importlib.util.spec_from_file_location("server_mcp_prom_tls", SRC / "server-mcp.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_prom_tls"] = mod
    spec.loader.exec_module(mod)

    yield mod

    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    sys.modules.pop("server_mcp_prom_tls", None)


# ── call-site fakes ──────────────────────────────────────────────────────────


class _FakeResp:
    status = 200

    async def json(self):
        return {"status": "success", "data": {"resultType": "vector", "result": []}}

    async def text(self):
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class _CaptureSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResp()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


def _patch_endpoint(monkeypatch, target, url):
    async def _discover(*args, **kwargs):
        return (url, "thanos")

    monkeypatch.setattr(target, "_discover_prometheus_endpoint", _discover)


def _patch_session(monkeypatch):
    session = _CaptureSession()
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **kw: session)
    return session


async def _run_internal(monkeypatch, url):
    _patch_endpoint(monkeypatch, prom, url)
    session = _patch_session(monkeypatch)
    result = await prom._execute_prometheus_query_internal("up", bearer_token=TOKEN)
    return session, result


async def _run_tool(server, monkeypatch, url):
    _patch_endpoint(monkeypatch, server, url)

    async def _token():
        return TOKEN

    monkeypatch.setattr(server, "_get_k8s_bearer_token", _token)
    session = _patch_session(monkeypatch)
    result = await server.prometheus_query("up")
    return session, result


def _assert_verified_no_redirects(kwargs):
    ctx = kwargs.get("ssl")
    assert isinstance(ctx, ssl.SSLContext), f"ssl={ctx!r}; certificate verification is off"
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert kwargs.get("allow_redirects") is False


@pytest.mark.asyncio
async def test_internal_https_verifies_and_sends_token(monkeypatch):
    session, _ = await _run_internal(monkeypatch, "https://thanos.apps.example.com")

    (_, kwargs), = session.calls
    _assert_verified_no_redirects(kwargs)
    assert kwargs["headers"]["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.asyncio
async def test_internal_plain_http_never_sends_token(monkeypatch):
    session, _ = await _run_internal(
        monkeypatch, "http://prometheus.tenant-ns.svc.cluster.local:9090"
    )

    (_, kwargs), = session.calls
    assert "Authorization" not in kwargs["headers"]


@pytest.mark.asyncio
async def test_internal_insecure_opt_out(monkeypatch):
    monkeypatch.setenv(tls.INSECURE_ENV, "true")

    session, _ = await _run_internal(monkeypatch, "https://thanos.apps.example.com")

    (_, kwargs), = session.calls
    assert kwargs["ssl"] is False


@pytest.mark.asyncio
async def test_tool_https_verifies_and_sends_token(server, monkeypatch):
    session, _ = await _run_tool(server, monkeypatch, "https://thanos.apps.example.com")

    (_, kwargs), = session.calls
    _assert_verified_no_redirects(kwargs)
    assert kwargs["headers"]["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.asyncio
async def test_tool_plain_http_never_sends_token(server, monkeypatch):
    session, _ = await _run_tool(
        server, monkeypatch, "http://prometheus.tenant-ns.svc.cluster.local:9090"
    )

    (_, kwargs), = session.calls
    assert "Authorization" not in kwargs["headers"]


class _UnauthorizedResp(_FakeResp):
    status = 401


@pytest.mark.asyncio
async def test_tool_401_on_plain_http_explains_withheld_token(server, monkeypatch):
    session, result = await _run_tool(
        server, monkeypatch, "http://thanos.example.com:9090"
    )
    assert session.calls  # sanity: request went out

    session.get = lambda url, **kw: _UnauthorizedResp()
    result = await server.prometheus_query("up")

    assert result["error_type"] == "authentication_failed"
    assert result["suggestions"][0] == tls.PLAIN_HTTP_TOKEN_HINT


@pytest.mark.asyncio
async def test_internal_401_on_plain_http_explains_withheld_token(monkeypatch):
    _patch_endpoint(monkeypatch, prom, "http://thanos.example.com:9090")
    session = _patch_session(monkeypatch)
    session.get = lambda url, **kw: _UnauthorizedResp()

    result = await prom._execute_prometheus_query_internal("up", bearer_token=TOKEN)

    assert tls.PLAIN_HTTP_TOKEN_HINT in result["error"]


# ── real local HTTPS server ──────────────────────────────────────────────────


async def _start(app, ssl_ctx=None):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_ctx)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


def _server_ctx(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def _recording_app(received, response):
    async def handler(request):
        received.append(request.headers.get("Authorization"))
        return response()

    app = web.Application()
    app.router.add_get("/{tail:.*}", handler)
    return app


def _ok():
    return web.json_response({"status": "success", "data": {"resultType": "vector", "result": []}})


@pytest.mark.asyncio
async def test_real_https_untrusted_cert_fails_before_token_is_sent(monkeypatch, tmp_path):
    _, cert, key, _ = make_ca_and_server_cert(tmp_path)
    received = []
    runner, port = await _start(_recording_app(received, _ok), _server_ctx(cert, key))
    try:
        _patch_endpoint(monkeypatch, prom, f"https://127.0.0.1:{port}")
        result = await prom._execute_prometheus_query_internal("up", bearer_token=TOKEN)
    finally:
        await runner.cleanup()

    assert result["success"] is False
    assert tls.TLS_HINT in result["error"], result["error"]
    assert received == [], "server received a request although the certificate is untrusted"


@pytest.mark.asyncio
async def test_real_https_with_ca_bundle_succeeds(monkeypatch, tmp_path):
    ca_path, cert, key, _ = make_ca_and_server_cert(tmp_path)
    monkeypatch.setenv(tls.CA_BUNDLE_ENV, str(ca_path))
    received = []
    runner, port = await _start(_recording_app(received, _ok), _server_ctx(cert, key))
    try:
        _patch_endpoint(monkeypatch, prom, f"https://127.0.0.1:{port}")
        result = await prom._execute_prometheus_query_internal("up", bearer_token=TOKEN)
    finally:
        await runner.cleanup()

    assert result["success"] is True, result
    assert received == [f"Bearer {TOKEN}"]


@pytest.mark.asyncio
async def test_real_https_redirect_is_not_followed(monkeypatch, tmp_path):
    ca_path, cert, key, _ = make_ca_and_server_cert(tmp_path)
    monkeypatch.setenv(tls.CA_BUNDLE_ENV, str(ca_path))
    sink = []
    sink_runner, sink_port = await _start(_recording_app(sink, _ok))
    received = []

    def _redirect():
        raise web.HTTPFound(f"http://127.0.0.1:{sink_port}/api/v1/query")

    runner, port = await _start(_recording_app(received, _redirect), _server_ctx(cert, key))
    try:
        _patch_endpoint(monkeypatch, prom, f"https://127.0.0.1:{port}")
        result = await prom._execute_prometheus_query_internal("up", bearer_token=TOKEN)
    finally:
        await runner.cleanup()
        await sink_runner.cleanup()

    assert result["success"] is False
    assert sink == [], "redirect was followed"
