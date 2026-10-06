"""
tests/test_namespace_filter_safety.py

C02: a namespace_filter must never stall the server (ReDoS).
H03: a rejected namespace_filter must be reported, never silently ignored.

The old guard blacklisted a few nested-quantifier shapes and then used
Python's backtracking `re`; "(a+b?)+$", "(\\w+-?)+!" or many ".*" passed it and
froze the event loop for seconds to minutes. A rejected filter was only logged,
so prometheus_query / live_system_topology_mapper returned unfiltered,
cluster-wide data while the metadata still echoed the filter.

Contract:
  * _safe_compile_namespace_filter returns an RE2 pattern (linear-time
    matching); unsupported syntax (backreferences, lookaround) is a ValueError;
  * prometheus_query and live_system_topology_mapper return an
    invalid_namespace_filter error for a rejected filter, before any query.
"""
import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

# Patterns from the bug report and classic ReDoS shapes, with inputs that make
# a backtracking engine take seconds or more.
SLOW_FOR_BACKTRACKING = [
    (r"(a+b?)+$", "a" * 40 + "!"),
    (r"(\w+-?)+!", "abc-" * 15 + "abc"),
    (".*" * 14 + "!", "a" * 34),
    (r"(a|aa)+$", "a" * 40 + "b"),
    (r"(a+)+$", "a" * 40 + "b"),
]


def _run_isolated(code: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run code in a fresh interpreter so a regression times out instead of hanging pytest."""
    env = dict(os.environ, PYTHONPATH=str(SRC))
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], env=env,
                          capture_output=True, text=True, timeout=timeout)


@pytest.mark.parametrize("pattern,text", SLOW_FOR_BACKTRACKING)
def test_filter_matching_is_linear_time(pattern, text):
    code = f"""
        from helpers.utils import _safe_compile_namespace_filter
        try:
            p = _safe_compile_namespace_filter({pattern!r})
        except ValueError:
            print("rejected")
        else:
            p.search({text!r})
            print("matched-fast")
    """
    try:
        result = _run_isolated(code)
    except subprocess.TimeoutExpired:
        pytest.fail(f"namespace_filter {pattern!r} stalled for > 10 s (ReDoS)")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() in ("rejected", "matched-fast")


def _helper():
    sys.path.insert(0, str(SRC))
    from helpers.utils import _safe_compile_namespace_filter
    return _safe_compile_namespace_filter


@pytest.mark.parametrize("pattern", [r"(a)\1", r"(?=tenant)t", r"(?<=x)y", "tenant-(a"])
def test_unsupported_or_invalid_syntax_is_value_error(pattern):
    with pytest.raises(ValueError):
        _helper()(pattern)


def test_overly_complex_filter_rejected():
    with pytest.raises(ValueError, match="too complex"):
        _helper()(".{1000}" * 12)


def test_normal_filters_still_work():
    compile_filter = _helper()

    p = compile_filter(r"^tenant-(a|b)$")
    assert p.search("tenant-a") and not p.search("tenant-c")
    assert compile_filter("openshift-").search("openshift-monitoring")
    assert compile_filter(r"^team-\d+-prod$").search("team-42-prod")


# ── H03: tools report a rejected filter ──────────────────────────────────────

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

REJECTED = ["tenant-(a", "x" * 201, r"(a|aa)+", r"(?=a)b"]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    saved = {k: os.environ.get(k) for k in ("KUBECONFIG", "KUBEARCHIVE_ENABLED")}
    kubeconfig = tmp_path_factory.mktemp("kube_nsf") / "config"
    kubeconfig.write_text(FAKE_KUBECONFIG)
    os.environ["KUBECONFIG"] = str(kubeconfig)
    os.environ["KUBEARCHIVE_ENABLED"] = "false"
    os.environ.pop("LUMINO_CONFIG", None)
    os.environ.pop("LUMINO_PROFILE", None)
    sys.path.insert(0, str(SRC))
    spec = importlib.util.spec_from_file_location("server_mcp_nsf", SRC / "server-mcp.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_nsf"] = mod
    spec.loader.exec_module(mod)
    yield mod
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    sys.modules.pop("server_mcp_nsf", None)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", REJECTED)
async def test_prometheus_query_reports_rejected_filter(server, monkeypatch, bad):
    discovered = []

    async def _discover(*a, **kw):
        discovered.append(1)
        return ("https://thanos.example.com", "thanos")

    monkeypatch.setattr(server, "_discover_prometheus_endpoint", _discover)

    result = await server.prometheus_query("up", namespace_filter=bad)

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_namespace_filter"
    assert result["result_count"] == 0 and result["data"] == []
    assert discovered == [], "query ran although the filter was rejected"


@pytest.mark.asyncio
async def test_process_results_never_drops_filter_silently():
    sys.path.insert(0, str(SRC))
    from helpers import prometheus as prom

    data = {"data": {"resultType": "vector", "result": [{"metric": {"namespace": "ns-a"}, "value": [0, "1"]}]}}
    with pytest.raises(ValueError):
        await prom._process_prometheus_results(data, "json", "tenant-(a", None, "up", "instant")


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", REJECTED)
async def test_topology_mapper_reports_rejected_filter(server, monkeypatch, bad):
    core = MagicMock()

    async def _clients(*a, **kw):
        return {"c1": {"core_api": core, "apps_api": MagicMock(), "custom_api": MagicMock(),
                       "storage_api": MagicMock()}}

    monkeypatch.setattr(server, "get_multi_cluster_topology_clients", _clients)

    result = await server.live_system_topology_mapper(namespace_filter=bad)

    assert result.get("error_type") == "invalid_namespace_filter", result
    assert result["topology"] == {"nodes": [], "edges": []}
    core.list_namespace.assert_not_called()


# ── valid filters actually filter (end to end) ───────────────────────────────


class _Resp:
    status = 200

    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload

    async def text(self):
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class _Session:
    def __init__(self, payload):
        self._payload = payload

    def get(self, url, **kwargs):
        return _Resp(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


@pytest.mark.asyncio
async def test_prometheus_query_valid_filter_filters_results(server, monkeypatch):
    import aiohttp

    payload = {"status": "success", "data": {"resultType": "vector", "result": [
        {"metric": {"namespace": "tenant-a"}, "value": [0, "1"]},
        {"metric": {"namespace": "tenant-b"}, "value": [0, "2"]},
        {"metric": {"namespace": "openshift-etcd"}, "value": [0, "3"]},
    ]}}

    async def _discover(*a, **kw):
        return ("https://thanos.example.com", "thanos")

    async def _token():
        return "t"

    monkeypatch.setattr(server, "_discover_prometheus_endpoint", _discover)
    monkeypatch.setattr(server, "_get_k8s_bearer_token", _token)
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **kw: _Session(payload))

    result = await server.prometheus_query("up", namespace_filter=r"^tenant-(a|c)$")

    assert result["status"] == "success"
    assert result["result_count"] == 1
    assert "tenant-a" in str(result["data"]) and "tenant-b" not in str(result["data"])


@pytest.mark.asyncio
async def test_topology_mapper_valid_filter_maps_only_matching(server, monkeypatch):
    core = MagicMock()
    core.list_namespace.return_value = MagicMock(items=[
        MagicMock(metadata=MagicMock(name=n)) for n in ("tenant-a", "tenant-b", "kube-system")
    ])
    for item, n in zip(core.list_namespace.return_value.items, ("tenant-a", "tenant-b", "kube-system")):
        item.metadata.name = n
    mapped = []

    async def _clients(*a, **kw):
        return {"c1": {"core_api": core, "apps_api": MagicMock(), "custom_api": MagicMock(),
                       "storage_api": MagicMock()}}

    async def _process(namespace, **kw):
        mapped.append(namespace)
        return {"nodes": [], "edges": [], "permissions": {"accessible": [], "denied": [], "errors": []}}

    monkeypatch.setattr(server, "get_multi_cluster_topology_clients", _clients)
    monkeypatch.setattr(server, "_process_namespace_topology", _process)

    await server.live_system_topology_mapper(namespace_filter=r"^tenant-")

    assert sorted(mapped) == ["tenant-a", "tenant-b"]
