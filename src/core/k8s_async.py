"""Run blocking Kubernetes client calls off the event loop, with a timeout.

The kubernetes Python client is synchronous. Calling it inside ``async def``
blocks the whole MCP server (every client, /health) for the duration of the
HTTP request, and with no ``_request_timeout`` a hung apiserver blocks it
forever. ``k8s_call`` runs the call in a worker thread with a request timeout,
and a per-event-loop semaphore bounds how many such calls run at once so a
fan-out over many namespaces cannot exhaust the default thread pool.

    pods = await k8s_call(core_api.list_namespaced_pod, namespace="team-a")

tests/test_no_blocking_k8s_calls.py fails if a direct (blocking) Kubernetes
call appears in an ``async def`` again.
"""
from __future__ import annotations

import asyncio
import functools
import weakref
from typing import Any, Callable, TypeVar

T = TypeVar("T")

# Seconds for one Kubernetes API request (urllib3 total timeout).
DEFAULT_TIMEOUT: float = 30.0
# Pod logs can be large and slow to stream.
LOG_TIMEOUT: float = 120.0
# Kubernetes calls allowed in worker threads at once, per event loop. The
# default executor has min(32, cpu + 4) workers; this leaves room for others.
MAX_CONCURRENT_CALLS: int = 8

_semaphores: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = (
    weakref.WeakKeyDictionary()
)


def _semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    sem = _semaphores.get(loop)
    if sem is None:
        sem = _semaphores[loop] = asyncio.Semaphore(MAX_CONCURRENT_CALLS)
    return sem


async def k8s_call(fn: Callable[..., T], /, *args: Any, timeout: float = DEFAULT_TIMEOUT, **kwargs: Any) -> T:
    """Await ``fn(*args, **kwargs, _request_timeout=timeout)`` in a worker thread."""
    async with _semaphore():
        return await asyncio.to_thread(functools.partial(fn, *args, _request_timeout=timeout, **kwargs))
