"""Task 4 seam tests — per-source Prometheus routing + source-scoped bearer tokens.

These tests are RED before the implementation lands.  Each covers one
spec-mandated invariant; together they pin the atomic constraint: Prometheus
routing and source-scoped tokens land together or not at all.

Invariants tested:
  1. _extract_kubeconfig_token extracts the right token for a named context.
  2. bearer_token=None (explicit) → structured token_unavailable error, no HTTP call.
  3. Named-instance query with explicit token never calls subprocess.run (default chain).
  4. Source A and source B occupy distinct cache slots.
  5. PROMETHEUS_URL / THANOS_URL env vars are ignored for named sources.
  6. bearer_token=_BEARER_SENTINEL (default path) still consults the default chain.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from helpers.prometheus import (
    _BEARER_SENTINEL,
    _execute_prometheus_query_internal,
    _discover_prometheus_endpoint,
    _prometheus_endpoint_cache,
    _extract_kubeconfig_token,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_kubeconfig(path: Path, contexts: dict) -> None:
    """Write a minimal kubeconfig with one user entry per context.

    contexts: {ctx_name: token_or_None}  (None → cert-auth user, no token field)
    """
    ctx_entries = []
    user_entries = []
    for i, (ctx_name, token) in enumerate(contexts.items()):
        user_name = f"user-{i}"
        ctx_entries.append(
            f"- context:\n    cluster: c\n    user: {user_name}\n  name: {ctx_name}"
        )
        if token is not None:
            user_entries.append(
                f"- name: {user_name}\n  user:\n    token: \"{token}\""
            )
        else:
            user_entries.append(
                f"- name: {user_name}\n  user:\n    client-certificate: /dev/null\n    client-key: /dev/null"
            )

    first_ctx = next(iter(contexts))
    path.write_text(
        "apiVersion: v1\nkind: Config\n"
        f"current-context: {first_ctx}\n"
        "clusters:\n- cluster: {server: 'https://127.0.0.1:1'}\n  name: c\n"
        + "contexts:\n" + "\n".join(ctx_entries) + "\n"
        + "users:\n" + "\n".join(user_entries) + "\n"
    )


class _FakeResp:
    status = 200

    async def json(self):
        return {"status": "success", "data": {"result": []}}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class _FakeSession:
    """Minimal aiohttp.ClientSession stub that captures Authorization headers."""

    def __init__(self):
        self.captured_auth: Optional[str] = None

    def get(self, *args, headers=None, **kwargs):
        if headers:
            self.captured_auth = headers.get("Authorization")
        return _FakeResp()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


# ── 1. _extract_kubeconfig_token ─────────────────────────────────────────────

class TestExtractKubeconfigToken:
    def test_extracts_token_for_named_context(self, tmp_path):
        """Reads correct token for each named context."""
        kc = tmp_path / "config"
        _write_kubeconfig(kc, {"ctx1": "sha256~token-1", "ctx2": "sha256~token-2"})
        assert _extract_kubeconfig_token(str(kc), "ctx1") == "sha256~token-1"
        assert _extract_kubeconfig_token(str(kc), "ctx2") == "sha256~token-2"

    def test_returns_none_for_cert_auth_context(self, tmp_path):
        """cert-auth contexts have no token field → None, not raised."""
        kc = tmp_path / "config"
        _write_kubeconfig(kc, {"cert-ctx": None})
        assert _extract_kubeconfig_token(str(kc), "cert-ctx") is None

    def test_returns_none_for_missing_context(self, tmp_path):
        """Requested context absent from file → None, not raised."""
        kc = tmp_path / "config"
        kc.write_text("apiVersion: v1\nkind: Config\n")
        assert _extract_kubeconfig_token(str(kc), "nonexistent-ctx") is None

    def test_returns_none_for_nonexistent_file(self, tmp_path):
        """Nonexistent file path → None, not raised."""
        result = _extract_kubeconfig_token(str(tmp_path / "does-not-exist"), "ctx")
        assert result is None


# ── 2. token_unavailable structured error ─────────────────────────────────────

class TestTokenUnavailableError:
    @pytest.mark.asyncio
    async def test_explicit_none_bearer_token_returns_token_unavailable(self, monkeypatch):
        """bearer_token=None (explicit) → success=False, error='token_unavailable'.

        No HTTP call must be made — the error short-circuits before aiohttp.
        """
        # Patch discovery to return a fake URL so we reach the token-selection branch
        async def _fake_discover(*args, **kwargs):
            return ("http://fake.example.com:9090", "prometheus")
        monkeypatch.setattr("helpers.prometheus._discover_prometheus_endpoint", _fake_discover)

        result = await _execute_prometheus_query_internal("up", bearer_token=None)

        assert result.get("success") is False, f"Expected success=False, got: {result}"
        assert result.get("error") == "token_unavailable", (
            f"Expected error='token_unavailable', got: {result.get('error')!r}"
        )


# ── 3. named-instance never consults default chain ────────────────────────────

class TestNamedSourceNeverConsultsDefaultChain:
    @pytest.mark.asyncio
    async def test_explicit_token_skips_subprocess(self, monkeypatch):
        """Explicit bearer_token string must never trigger subprocess.run.

        The oc-whoami step (Method 1 of the default chain) raises AssertionError
        if reached — the test passes iff it is never reached.
        """
        def _explode(*args, **kwargs):
            raise AssertionError(
                "subprocess.run must NOT be called when bearer_token is provided explicitly"
            )
        monkeypatch.setattr(subprocess, "run", _explode)

        # Patch discovery to return a fake URL
        async def _fake_discover(*args, **kwargs):
            return ("http://fake.example.com:9090", "prometheus")
        monkeypatch.setattr("helpers.prometheus._discover_prometheus_endpoint", _fake_discover)

        # Patch aiohttp to avoid network I/O
        import aiohttp
        session = _FakeSession()
        monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **kw: session)

        result = await _execute_prometheus_query_internal(
            "up",
            bearer_token="sha256~stored-instance-token",
            source="my-cluster",
        )
        # Completed without AssertionError → subprocess.run was never called
        assert "success" in result or "error" in result

    @pytest.mark.asyncio
    async def test_explicit_token_used_in_auth_header(self, monkeypatch):
        """The explicit bearer_token string appears in the Authorization header."""
        async def _fake_discover(*args, **kwargs):
            return ("https://fake.example.com:9090", "prometheus")
        monkeypatch.setattr("helpers.prometheus._discover_prometheus_endpoint", _fake_discover)

        import aiohttp
        session = _FakeSession()
        monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **kw: session)

        await _execute_prometheus_query_internal(
            "up",
            bearer_token="sha256~my-explicit-token",
            source="my-cluster",
        )
        assert session.captured_auth == "Bearer sha256~my-explicit-token", (
            f"Expected 'Bearer sha256~my-explicit-token', got {session.captured_auth!r}"
        )


# ── 4. cache isolation ────────────────────────────────────────────────────────

class TestCacheIsolation:
    def test_two_sources_occupy_distinct_cache_slots(self):
        """Source A and source B must not share a cache entry."""
        key_a = ("source-a", "")
        key_b = ("source-b", "")

        _prometheus_endpoint_cache.invalidate(key_a)
        _prometheus_endpoint_cache.invalidate(key_b)

        _prometheus_endpoint_cache.set(
            "http://cluster-a.example.com", key_a, endpoint_type="prometheus"
        )

        # Source B must not see source A's entry
        assert _prometheus_endpoint_cache.get(key_b) is None, (
            "Source B should not see Source A's cached endpoint (cache isolation violated)"
        )
        # Source A sees its own entry
        hit = _prometheus_endpoint_cache.get(key_a)
        assert hit is not None
        assert hit[0] == "http://cluster-a.example.com"

        _prometheus_endpoint_cache.invalidate(key_a)

    def test_default_instance_uses_tuple_key(self):
        """The default instance uses (source or 'default', cluster_override or '') as key."""
        key_default = ("default", "")
        _prometheus_endpoint_cache.invalidate(key_default)

        _prometheus_endpoint_cache.set(
            "http://default-cluster.example.com", key_default, endpoint_type="thanos"
        )

        hit = _prometheus_endpoint_cache.get(key_default)
        assert hit is not None
        assert hit[0] == "http://default-cluster.example.com"
        assert hit[1] == "thanos"

        _prometheus_endpoint_cache.invalidate(key_default)


# ── 5. env overrides ignored for named sources ────────────────────────────────

class TestEnvOverrideIgnoredForNamedSource:
    @pytest.mark.asyncio
    async def test_prometheus_url_env_ignored_for_named_source(self, monkeypatch):
        """PROMETHEUS_URL env var must NOT be returned for named sources.

        Named sources use discovery (routes / services); env vars apply only to
        the default instance.  Cross-cluster endpoint bleed via env is the bug
        this prevents.
        """
        monkeypatch.setenv("PROMETHEUS_URL", "http://env-override.should.not.appear")
        # No custom_api / core_api → discovery fails → (None, None)
        result = await _discover_prometheus_endpoint(source="named-instance")
        assert result[0] != "http://env-override.should.not.appear", (
            "PROMETHEUS_URL env var was returned for a named source — spec violation (cross-cluster bleed)"
        )

    @pytest.mark.asyncio
    async def test_thanos_url_env_ignored_for_named_source(self, monkeypatch):
        """THANOS_URL env var must NOT be returned for named sources."""
        monkeypatch.setenv("THANOS_URL", "http://thanos-env-override.should.not.appear")
        result = await _discover_prometheus_endpoint(source="named-instance")
        assert result[0] != "http://thanos-env-override.should.not.appear", (
            "THANOS_URL env var was returned for a named source — spec violation (cross-cluster bleed)"
        )

    @pytest.mark.asyncio
    async def test_prometheus_url_env_honoured_for_default_source(self, monkeypatch):
        """PROMETHEUS_URL env var IS honoured when source is '' (default instance)."""
        monkeypatch.setenv("PROMETHEUS_URL", "http://env-url-for-default.example.com")
        result = await _discover_prometheus_endpoint(source="")
        assert result[0] == "http://env-url-for-default.example.com", (
            "PROMETHEUS_URL env var should be returned for the default instance"
        )


# ── 6. default path (sentinel) preserved ─────────────────────────────────────

class TestDefaultPathPreserved:
    @pytest.mark.asyncio
    async def test_sentinel_uses_kubeconfig_chain(self, monkeypatch, tmp_path):
        """_BEARER_SENTINEL triggers the full fallback chain, reaching kubeconfig Method 2.

        Setup: KUBECONFIG → temp file with known token; oc blocked (FileNotFoundError).
        Expected: Authorization header contains the kubeconfig token.
        """
        kc = tmp_path / "config"
        _write_kubeconfig(kc, {"test-ctx": "sha256~from-kubeconfig-chain"})

        monkeypatch.setenv("KUBECONFIG", str(kc))
        monkeypatch.delenv("PROMETHEUS_TOKEN", raising=False)
        monkeypatch.delenv("OPENSHIFT_TOKEN", raising=False)
        monkeypatch.delenv("OC_TOKEN", raising=False)

        # Block oc so Method 2 (kubeconfig file) is exercised
        def _no_oc(*args, **kwargs):
            raise FileNotFoundError("oc not available")
        monkeypatch.setattr(subprocess, "run", _no_oc)

        # Patch discovery and aiohttp
        async def _fake_discover(*args, **kwargs):
            return ("https://fake.example.com:9090", "prometheus")
        monkeypatch.setattr("helpers.prometheus._discover_prometheus_endpoint", _fake_discover)

        import aiohttp
        session = _FakeSession()
        monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **kw: session)

        # Call WITHOUT bearer_token — uses _BEARER_SENTINEL (the default)
        await _execute_prometheus_query_internal("up")

        assert session.captured_auth == "Bearer sha256~from-kubeconfig-chain", (
            f"Expected kubeconfig token in Authorization header, got: {session.captured_auth!r}. "
            "The default chain must still be consulted when bearer_token is not passed."
        )
