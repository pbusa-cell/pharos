"""Outbound TLS policy for HTTP requests that carry a bearer token.

Prometheus/Thanos and KubeArchive requests send the caller's Kubernetes token,
often the SRE's own `oc whoami -t` token, so certificate verification is on by
default and can only be turned off explicitly:

  LUMINO_TLS_CA_BUNDLE             PEM file with extra trusted CAs (e.g. a
                                   cluster's self-signed ingress CA).
  LUMINO_TLS_INSECURE_SKIP_VERIFY  "true" disables verification for every
                                   such request. Last resort; logged per use.

Trust store: system CAs (honours SSL_CERT_FILE), the certifi bundle, the
OpenShift service CA when running in a pod, and LUMINO_TLS_CA_BUNDLE.
"""
from __future__ import annotations

import functools
import logging
import os
import ssl
from typing import Optional, Union
from urllib.parse import urlparse

logger = logging.getLogger("lumino-mcp.tls")

INSECURE_ENV = "LUMINO_TLS_INSECURE_SKIP_VERIFY"
CA_BUNDLE_ENV = "LUMINO_TLS_CA_BUNDLE"
SERVICE_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

PLAIN_HTTP_TOKEN_HINT = (
    "The bearer token was not sent because the endpoint uses plain http; "
    "use an https endpoint (or a loopback port-forward) if it needs authentication."
)

TLS_HINT = (
    f"TLS verification failed. Add the server's CA to a PEM file and set {CA_BUNDLE_ENV}=<path>; "
    f"as a last resort set {INSECURE_ENV}=true."
)


def is_loopback(url: str) -> bool:
    """True when the URL's host is localhost, 127.0.0.1 or ::1."""
    return (urlparse(url).hostname or "").lower() in LOOPBACK_HOSTS


def bearer_token_allowed(url: str) -> bool:
    """True when a bearer token may be sent to url: https, or any loopback host."""
    if not url:
        return False
    return urlparse(url).scheme.lower() == "https" or is_loopback(url)


def insecure_skip_verify() -> bool:
    return os.getenv(INSECURE_ENV, "").strip().lower() in ("1", "true", "yes")


def client_ssl_context(
    extra_ca_pem: Optional[str] = None, host: str = ""
) -> Union[ssl.SSLContext, bool]:
    """SSL context for a token-bearing request, or False when explicitly opted out.

    extra_ca_pem (a CA read from one cluster) goes into a fresh context, never
    the shared one, so one cluster's CA is not trusted for another's endpoints.
    Raises ValueError when LUMINO_TLS_CA_BUNDLE is set but cannot be loaded.
    """
    if insecure_skip_verify():
        logger.warning("TLS verification disabled by %s for %s", INSECURE_ENV, host or "request")
        return False
    if extra_ca_pem:
        ctx = _new_context()
        ctx.load_verify_locations(cadata=extra_ca_pem)
        return ctx
    return _shared_context()


def clear_cache() -> None:
    """Drop the shared context so the next call re-reads the environment."""
    _shared_context.cache_clear()


@functools.lru_cache(maxsize=1)
def _shared_context() -> ssl.SSLContext:
    return _new_context()


def _new_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # Trust a configured CA even when it is an intermediate or a server leaf
    # (KubeArchive TLS secrets often hold only tls.crt). Python 3.13+ sets
    # this by default; set it explicitly so 3.10-3.12 behave the same. Cost:
    # such an anchor is trusted as-is (no check up to a root, no revocation).
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    try:
        import certifi

        ctx.load_verify_locations(cafile=certifi.where())
    except ImportError:
        pass
    if os.path.isfile(SERVICE_CA_PATH):
        ctx.load_verify_locations(cafile=SERVICE_CA_PATH)
    bundle = os.getenv(CA_BUNDLE_ENV)
    if bundle:
        try:
            ctx.load_verify_locations(cafile=bundle)
        except (OSError, ssl.SSLError) as e:
            raise ValueError(f"{CA_BUNDLE_ENV}={bundle!r} cannot be loaded: {e}") from e
    return ctx
