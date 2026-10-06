"""
tests/test_no_blocking_k8s_calls.py

C07/C08/H26: no synchronous Kubernetes client call may run on the event loop.

The kubernetes client is blocking. A direct ``api.list_...()`` inside an
``async def`` freezes every MCP request (and /health) for the duration of the
HTTP call, and without ``_request_timeout`` a hung apiserver freezes the
server forever. Calls go through ``core.k8s_async.k8s_call`` instead (worker
thread + request timeout + bounded concurrency).

Ratchet: the AST scan below must find zero direct Kubernetes calls in any
``async def`` under src/ (calls inside nested sync functions are allowed; those
run wherever their caller runs them, normally asyncio.to_thread).
"""
import ast
import asyncio
import sys
import threading
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from core import k8s_async  # noqa: E402
from core.k8s_async import k8s_call  # noqa: E402

_K8S_PREFIXES = ("list_", "read_", "get_namespaced_custom_object", "get_cluster_custom_object")
_NOT_K8S = {"list_models", "list_sources", "read_text", "read_bytes", "list_kube_config_contexts"}


def _direct_k8s_calls(fn: ast.AsyncFunctionDef):
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(_K8S_PREFIXES) and node.func.attr not in _NOT_K8S:
                yield node
        stack.extend(ast.iter_child_nodes(node))


def test_no_direct_k8s_calls_in_async_functions():
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if isinstance(fn, ast.AsyncFunctionDef):
                for call in _direct_k8s_calls(fn):
                    hits.append(f"{path.relative_to(SRC.parent)}:{call.lineno} {fn.name}() -> .{call.func.attr}(...)")
    assert not hits, (
        "blocking Kubernetes calls on the event loop; use `await k8s_call(api.method, ...)`:\n"
        + "\n".join(hits)
    )


def test_scanner_detects_a_direct_call():
    tree = ast.parse("async def f(api):\n    return api.list_namespaced_pod('ns')\n")
    assert len(list(_direct_k8s_calls(tree.body[0]))) == 1


def test_scanner_ignores_nested_sync_function_and_k8s_call():
    src = (
        "async def f(api):\n"
        "    def inner():\n"
        "        return api.list_namespaced_pod('ns')\n"
        "    await k8s_call(api.read_namespace, 'ns')\n"
        "    return await asyncio.to_thread(inner)\n"
    )
    assert list(_direct_k8s_calls(ast.parse(src).body[0])) == []


# ── k8s_call behaviour ───────────────────────────────────────────────────────


def test_k8s_call_passes_request_timeout_and_args():
    seen = {}

    def api_method(name, namespace=None, _request_timeout=None):
        seen.update(name=name, namespace=namespace, timeout=_request_timeout,
                    thread=threading.current_thread().name)
        return "ok"

    result = asyncio.run(k8s_call(api_method, "p1", namespace="ns", timeout=7))

    assert result == "ok"
    assert seen["name"] == "p1" and seen["namespace"] == "ns" and seen["timeout"] == 7
    assert seen["thread"] != threading.main_thread().name


def test_k8s_call_default_timeout():
    seen = {}
    asyncio.run(k8s_call(lambda _request_timeout=None: seen.setdefault("t", _request_timeout)))
    assert seen["t"] == k8s_async.DEFAULT_TIMEOUT


def test_k8s_call_keeps_event_loop_responsive():
    def slow(_request_timeout=None):
        time.sleep(0.3)

    async def main():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        t = asyncio.create_task(ticker())
        await k8s_call(slow)
        t.cancel()
        return ticks

    assert asyncio.run(main()) >= 10


def test_k8s_call_bounds_concurrency():
    lock = threading.Lock()
    state = {"now": 0, "max": 0}

    def call(_request_timeout=None):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1

    async def main():
        await asyncio.gather(*(k8s_call(call) for _ in range(40)))

    asyncio.run(main())
    assert state["max"] <= k8s_async.MAX_CONCURRENT_CALLS


def test_k8s_call_works_across_event_loops():
    """The semaphore is per loop; a second asyncio.run must not reuse the first loop's."""
    for _ in range(2):
        assert asyncio.run(k8s_call(lambda _request_timeout=None: 1)) == 1


def test_k8s_call_propagates_errors():
    def boom(_request_timeout=None):
        raise ValueError("x")

    with pytest.raises(ValueError):
        asyncio.run(k8s_call(boom))
