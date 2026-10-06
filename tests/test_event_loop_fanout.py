"""
tests/test_event_loop_fanout.py

C06: get_etcd_logs(follow=True) streamed forever (read_namespaced_pod_log with
     follow=True and no request timeout), pinning a worker thread per call.
C09: live_system_topology_mapper fanned out over every namespace with ~10
     thread calls each and no limit, exhausting the default thread pool.

Contract:
  * pod log reads never follow and always carry a request timeout;
  * topology maps at most MAX_TOPOLOGY_NAMESPACES namespaces per cluster and
    reports the truncation; Kubernetes calls run at most
    k8s_async.MAX_CONCURRENT_CALLS at a time, so unrelated worker-thread work
    is not starved.
"""
import asyncio
import importlib.util
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(SRC))

from core import k8s_async  # noqa: E402
from helpers.log_analysis import _get_logs_with_k8s_client  # noqa: E402


# ── C06 ──────────────────────────────────────────────────────────────────────


class _LogApi:
    def __init__(self):
        self.calls = []

    def read_namespaced_pod_log(self, **kwargs):
        self.calls.append(kwargs)
        return "line 1\nline 2\n"


def test_pod_log_read_never_follows_and_has_timeout():
    api = _LogApi()
    out = {}

    ok = _get_logs_with_k8s_client(api, ["etcd-0"], "openshift-etcd", "etcd", out,
                                   {"follow": True, "tail_lines": 10})

    assert ok
    (kwargs,) = api.calls
    assert kwargs.get("follow", False) is False
    assert kwargs.get("_request_timeout") == k8s_async.LOG_TIMEOUT


# ── C09 ──────────────────────────────────────────────────────────────────────

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


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    saved = {k: os.environ.get(k) for k in ("KUBECONFIG", "KUBEARCHIVE_ENABLED")}
    kubeconfig = tmp_path_factory.mktemp("kube_fanout") / "config"
    kubeconfig.write_text(FAKE_KUBECONFIG)
    os.environ["KUBECONFIG"] = str(kubeconfig)
    os.environ["KUBEARCHIVE_ENABLED"] = "false"
    os.environ.pop("LUMINO_CONFIG", None)
    os.environ.pop("LUMINO_PROFILE", None)
    spec = importlib.util.spec_from_file_location("server_mcp_fanout", SRC / "server-mcp.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_fanout"] = mod
    spec.loader.exec_module(mod)
    yield mod
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    sys.modules.pop("server_mcp_fanout", None)


class _SlowApi:
    """Every list_* call sleeps a little in its worker thread and records concurrency."""

    def __init__(self, namespaces, state):
        self._namespaces = namespaces
        self._state = state

    def list_namespace(self, **kw):
        return SimpleNamespace(items=[SimpleNamespace(metadata=SimpleNamespace(name=n)) for n in self._namespaces])

    def __getattr__(self, name):
        if not name.startswith("list_"):
            raise AttributeError(name)

        def call(*args, **kwargs):
            st = self._state
            with st["lock"]:
                st["now"] += 1
                st["max"] = max(st["max"], st["now"])
                st["timeouts"].add(kwargs.get("_request_timeout"))
            time.sleep(0.005)
            with st["lock"]:
                st["now"] -= 1
            if "custom_object" in name:
                return {"items": []}
            return SimpleNamespace(items=[])

        return call


@pytest.mark.asyncio
async def test_topology_fanout_is_bounded(server, monkeypatch):
    state = {"lock": threading.Lock(), "now": 0, "max": 0, "timeouts": set()}
    namespaces = [f"ns-{i:03d}" for i in range(300)]
    api = _SlowApi(namespaces, state)

    async def _clients(*a, **kw):
        return {"c1": {"core_api": api, "apps_api": api, "custom_api": api, "storage_api": api}}

    monkeypatch.setattr(server, "get_multi_cluster_topology_clients", _clients)

    async def unrelated_thread_work():
        await asyncio.sleep(0.05)
        t = time.monotonic()
        await asyncio.to_thread(lambda: None)
        return time.monotonic() - t

    result, waited = await asyncio.gather(
        server.live_system_topology_mapper(), unrelated_thread_work()
    )

    assert state["max"] <= k8s_async.MAX_CONCURRENT_CALLS
    assert None not in state["timeouts"], "a topology call had no _request_timeout"
    assert waited < 0.5, f"unrelated to_thread work waited {waited:.2f}s"
    trunc = result["namespace_truncation"]["c1"]
    assert trunc == {"total": 300, "mapped": server.MAX_TOPOLOGY_NAMESPACES}


@pytest.mark.asyncio
async def test_topology_small_cluster_not_truncated(server, monkeypatch):
    state = {"lock": threading.Lock(), "now": 0, "max": 0, "timeouts": set()}
    api = _SlowApi(["a", "b"], state)

    async def _clients(*a, **kw):
        return {"c1": {"core_api": api, "apps_api": api, "custom_api": api, "storage_api": api}}

    monkeypatch.setattr(server, "get_multi_cluster_topology_clients", _clients)

    result = await server.live_system_topology_mapper()

    assert "namespace_truncation" not in result
