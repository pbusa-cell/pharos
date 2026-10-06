"""Run blocking Kubernetes client calls off the event loop, with a timeout.

The kubernetes Python client is synchronous. Calling it inside ``async def``
blocks the whole MCP server (every client, /health) for the duration of the
HTTP request, and with no ``_request_timeout`` a hung apiserver blocks it
forever. ``k8s_call`` runs the call with a request timeout on a dedicated
thread pool of MAX_CONCURRENT_CALLS workers, so a fan-out over many
namespaces queues instead of exhausting the default executor — also when a
deadline cancels the await while the worker thread is still running.

    pods = await k8s_call(core_api.list_namespaced_pod, namespace="team-a")
    ok = await k8s_offload(sync_helper_that_sets_its_own_timeouts, arg)

tests/test_no_blocking_k8s_calls.py fails if a Kubernetes call in an
``async def`` bypasses these helpers again.
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

T = TypeVar("T")

# Seconds for one Kubernetes API request (urllib3 total timeout).
DEFAULT_TIMEOUT: float = 30.0
# Pod logs can be large and slow to stream.
LOG_TIMEOUT: float = 120.0
# Kubernetes calls running at once, process-wide. A dedicated pool (not the
# default executor) bounds the threads themselves: a cancelled await cannot
# free a slot while its thread is still blocked in a request.
MAX_CONCURRENT_CALLS: int = 8

_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CALLS, thread_name_prefix="k8s-call")


async def k8s_offload(fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """Await ``fn(*args, **kwargs)`` on the Kubernetes thread pool.

    For sync helpers that make Kubernetes calls and set their own
    ``_request_timeout``; plain API methods go through :func:`k8s_call`.
    """
    loop = asyncio.get_running_loop()
    call = functools.partial(contextvars.copy_context().run, fn, *args, **kwargs)
    return await loop.run_in_executor(_EXECUTOR, call)


async def k8s_call(fn: Callable[..., T], /, *args: Any, timeout: float = DEFAULT_TIMEOUT, **kwargs: Any) -> T:
    """Await ``fn(*args, **kwargs, _request_timeout=timeout)`` on the Kubernetes thread pool."""
    return await k8s_offload(fn, *args, _request_timeout=timeout, **kwargs)
