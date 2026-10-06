"""
tests/test_no_blocking_k8s_calls.py

C07/C08/H26: no synchronous Kubernetes client call may run on the event loop.

The kubernetes client is blocking. A direct ``api.list_...()`` inside an
``async def`` freezes every MCP request (and /health) for the duration of the
HTTP call, and without ``_request_timeout`` a hung apiserver freezes the
server forever. Calls go through ``core.k8s_async.k8s_call`` instead (worker
thread + request timeout + bounded concurrency).

Ratchet: the AST scan below must find, in any ``async def`` under src/:
  1. no direct Kubernetes call (``api.list_...()``);
  2. no call of a method taken with ``getattr(<api object>, ...)``;
  3. no ``asyncio.to_thread`` / ``run_in_executor`` of a Kubernetes method
     (or a lambda / getattr-method wrapping one) — that runs off the loop but
     with no request timeout and outside k8s_call's thread bound;
  4. no direct call of a sync function or method anywhere in src/ that makes
     Kubernetes calls (it blocks just like rule 1); run it with
     ``k8s_offload``. Helpers are matched by name across modules.
Calls inside nested sync functions are judged where those functions run.
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

_K8S_PREFIXES = ("list_", "read_", "get_namespaced_custom_object", "get_cluster_custom_object", "get_code",
                 "get_api_versions", "call_api")
_NOT_K8S = {"list_models", "list_sources", "read_text", "read_bytes", "list_kube_config_contexts"}
_OFFLOAD = {"to_thread", "run_in_executor"}


def _is_k8s_attr(node) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr.startswith(_K8S_PREFIXES)
            and node.attr not in _NOT_K8S)


def _own_nodes(fn):
    """Nodes of fn's body, not descending into nested defs, lambdas or classes."""
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _direct_k8s_calls(fn: ast.AsyncFunctionDef):
    for node in _own_nodes(fn):
        if isinstance(node, ast.Call) and _is_k8s_attr(node.func):
            yield node


def _has_timeout(call: ast.Call) -> bool:
    return any(k.arg == "_request_timeout" for k in call.keywords)


def _api_getattr_names(fn) -> set:
    """Names assigned from getattr(<obj whose name mentions api / _ro>, ...)."""
    names = set()
    for node in _own_nodes(fn):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name) and node.value.func.id == "getattr"
                and node.value.args):
            target = ast.unparse(node.value.args[0])
            if "api" in target.lower() or target.startswith("_ro"):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _sync_k8s_functions(tree) -> dict:
    """Sync defs in a module that call Kubernetes directly -> first method called."""
    found = {}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for node in _own_nodes(fn):
                if isinstance(node, ast.Call) and _is_k8s_attr(node.func):
                    found[fn.name] = node.func.attr
                    break
    return found


def _blocking_or_unbounded(fn: ast.AsyncFunctionDef, sync_k8s: dict):
    """Yield (lineno, description) for every rule violation in fn."""
    api_methods = _api_getattr_names(fn)
    for node in _own_nodes(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if _is_k8s_attr(f):
            yield node.lineno, f"direct .{f.attr}(...)"
        elif isinstance(f, ast.Name) and f.id in api_methods:
            yield node.lineno, f"getattr method {f.id}(...)"
        elif isinstance(f, ast.Name) and f.id in sync_k8s:
            yield node.lineno, f"sync helper {f.id}() calls .{sync_k8s[f.id]}"
        elif (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
              and f.value.id == "self" and f.attr in sync_k8s):
            yield node.lineno, f"sync method self.{f.attr}() calls .{sync_k8s[f.attr]}"
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        if name in _OFFLOAD:
            args = node.args[1:] if name == "run_in_executor" else node.args
            if not args or _has_timeout(node):
                continue
            target = args[0]
            if _is_k8s_attr(target) or (isinstance(target, ast.Name) and target.id in api_methods):
                yield node.lineno, f"{name}({ast.unparse(target)}) without timeout/bound"
            elif isinstance(target, ast.Lambda):
                for inner in ast.walk(target.body):
                    if isinstance(inner, ast.Call) and _is_k8s_attr(inner.func) and not _has_timeout(inner):
                        yield node.lineno, f"{name}(lambda: .{inner.func.attr}(...)) without timeout/bound"


def test_no_direct_k8s_calls_in_async_functions():
    trees = {path: ast.parse(path.read_text()) for path in sorted(SRC.rglob("*.py"))}
    sync_k8s = {}
    for tree in trees.values():
        sync_k8s.update(_sync_k8s_functions(tree))
    hits = []
    for path, tree in trees.items():
        for fn in ast.walk(tree):
            if isinstance(fn, ast.AsyncFunctionDef):
                for lineno, what in _blocking_or_unbounded(fn, sync_k8s):
                    hits.append(f"{path.relative_to(SRC.parent)}:{lineno} {fn.name}(): {what}")
    assert not hits, (
        "Kubernetes calls that block the event loop or run without a timeout/bound; "
        "use `await k8s_call(api.method, ...)` (or `await k8s_offload(sync_fn, ...)` "
        "for a sync helper that sets its own timeouts):\n" + "\n".join(sorted(hits))
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


def test_cancelled_calls_do_not_exceed_thread_bound():
    """A deadline cancels the await, not the thread: threads must still be bounded."""
    lock = threading.Lock()
    state = {"now": 0, "max": 0}

    def slow(_request_timeout=None):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.2)
        with lock:
            state["now"] -= 1

    async def main():
        for _ in range(4):  # repeated timed-out fan-outs, as under a slow apiserver
            try:
                await asyncio.wait_for(asyncio.gather(*(k8s_call(slow) for _ in range(20))), 0.05)
            except asyncio.TimeoutError:
                pass
        await asyncio.gather(*(k8s_call(slow) for _ in range(20)))

    asyncio.run(main())
    assert state["max"] <= k8s_async.MAX_CONCURRENT_CALLS


def test_k8s_offload_runs_sync_helper_off_loop():
    seen = {}

    def helper(a, b=None):
        seen.update(a=a, b=b, thread=threading.current_thread().name)
        return "done"

    assert asyncio.run(k8s_async.k8s_offload(helper, 1, b=2)) == "done"
    assert seen["a"] == 1 and seen["b"] == 2 and seen["thread"].startswith("k8s-call")


def test_k8s_call_works_across_event_loops():
    """The pool is process-wide; calls from a second event loop still work."""
    for _ in range(2):
        assert asyncio.run(k8s_call(lambda _request_timeout=None: 1)) == 1


def test_k8s_call_propagates_errors():
    def boom(_request_timeout=None):
        raise ValueError("x")

    with pytest.raises(ValueError):
        asyncio.run(k8s_call(boom))


def _hits(src):
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef))
    return list(_blocking_or_unbounded(fn, _sync_k8s_functions(tree)))


def test_sync_helper_rule_is_cross_module():
    """Helpers are collected from all of src/, so a direct call from another module is caught."""
    helper = ast.parse("def is_trusted(api, ns):\n    return api.read_namespace(ns)\n")
    caller = ast.parse("async def discover(api):\n    if is_trusted(api, 'x'):\n        return 1\n")
    fn = caller.body[0]
    assert list(_blocking_or_unbounded(fn, _sync_k8s_functions(helper)))
    assert not list(_blocking_or_unbounded(fn, _sync_k8s_functions(caller)))


def test_scanner_rules():
    assert _hits("async def f(core_api):\n    m = getattr(core_api, 'list_x')\n    m(namespace='a')\n")
    assert _hits("async def f(api):\n    await asyncio.to_thread(api.list_namespaced_pod, 'a')\n")
    assert _hits("async def f(api, loop):\n    await loop.run_in_executor(None, lambda: api.list_x())\n")
    assert _hits("def helper(api):\n    return api.read_namespace('x')\n"
                 "async def f(api):\n    helper(api)\n")
    assert not _hits("async def f(api):\n    await asyncio.to_thread(api.list_x, 'a', _request_timeout=5)\n")
    assert not _hits("async def f(reg):\n    fn = getattr(reg, 'query')\n    fn()\n")
