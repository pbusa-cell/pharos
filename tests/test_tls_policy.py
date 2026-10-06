"""
tests/test_tls_policy.py

Outbound TLS policy for requests that carry a bearer token (core/tls.py).

Contract:
  * client_ssl_context() verifies certificates and hostnames by default.
  * LUMINO_TLS_INSECURE_SKIP_VERIFY=true is the only way to turn verification off.
  * LUMINO_TLS_CA_BUNDLE adds a PEM bundle; an unreadable path is an error.
  * extra_ca_pem gives a fresh context and never changes the shared one.
  * bearer_token_allowed(url) is True only for https URLs and loopback hosts.
"""
import ssl
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from core import tls
from tests._tls_fixtures import make_ca_and_server_cert


@pytest.fixture(autouse=True)
def _clean_tls_env(monkeypatch):
    monkeypatch.delenv(tls.INSECURE_ENV, raising=False)
    monkeypatch.delenv(tls.CA_BUNDLE_ENV, raising=False)
    tls.clear_cache()
    yield
    tls.clear_cache()


def _ca_subjects(ctx: ssl.SSLContext):
    return [dict(x[0] for x in c["subject"]).get("commonName") for c in ctx.get_ca_certs()]


def test_default_context_verifies():
    ctx = tls.client_ssl_context()

    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


@pytest.mark.parametrize("value", ["true", "1", "yes", "TRUE"])
def test_insecure_opt_out(monkeypatch, value):
    monkeypatch.setenv(tls.INSECURE_ENV, value)

    assert tls.client_ssl_context() is False


@pytest.mark.parametrize("value", ["", "false", "0", "no"])
def test_insecure_env_falsy_keeps_verification(monkeypatch, value):
    monkeypatch.setenv(tls.INSECURE_ENV, value)

    assert isinstance(tls.client_ssl_context(), ssl.SSLContext)


def test_ca_bundle_env_is_loaded(monkeypatch, tmp_path):
    ca_path, _, _, _ = make_ca_and_server_cert(tmp_path)
    monkeypatch.setenv(tls.CA_BUNDLE_ENV, str(ca_path))

    assert "pharos-test-ca" in _ca_subjects(tls.client_ssl_context())


def test_unreadable_ca_bundle_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv(tls.CA_BUNDLE_ENV, str(tmp_path / "missing.pem"))

    with pytest.raises(ValueError, match=tls.CA_BUNDLE_ENV):
        tls.client_ssl_context()


def test_extra_ca_pem_does_not_touch_shared_context(tmp_path):
    _, _, _, ca_pem = make_ca_and_server_cert(tmp_path)

    shared = tls.client_ssl_context()
    scoped = tls.client_ssl_context(extra_ca_pem=ca_pem)

    assert scoped is not shared
    assert "pharos-test-ca" in _ca_subjects(scoped)
    assert "pharos-test-ca" not in _ca_subjects(shared)
    assert "pharos-test-ca" not in _ca_subjects(tls.client_ssl_context())


@pytest.mark.parametrize(
    "url,allowed",
    [
        ("https://thanos.apps.example.com", True),
        ("HTTPS://thanos.apps.example.com", True),
        ("http://prometheus.tenant.svc.cluster.local:9090", False),
        ("http://thanos.apps.example.com", False),
        ("http://localhost:9090", True),
        ("http://127.0.0.1:9090", True),
        ("http://[::1]:9090", True),
        ("http://localhost.attacker.example:9090", False),
        ("ftp://example.com", False),
        ("", False),
    ],
)
def test_bearer_token_allowed(url, allowed):
    assert tls.bearer_token_allowed(url) is allowed
