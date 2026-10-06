"""C07: pipeline_tracer has an overall deadline for each fan-out stage.

Correlation fans out over up to max_namespaces namespaces and the lifecycle
chain follows snapshots/releases; a slow or hung apiserver must not keep one
tool call running indefinitely. When a stage exceeds its limit the trace still
returns, with the stage empty (or its error) and a "warnings" entry.
"""
import asyncio
import json
import sys
import time

import pytest


def _tools_module():
    return next(m for name, m in sys.modules.items()
                if name.endswith("extensions.konflux.tools") and hasattr(m, "TRACE_CORRELATE_TIMEOUT"))


def _as_dict(result):
    if isinstance(result, dict):
        return result
    if isinstance(result, (list, tuple)) and len(result) == 2 and isinstance(result[1], dict):
        return result[1].get("result", result[1])
    text = "".join(getattr(c, "text", "") for c in result)
    return json.loads(text)


@pytest.mark.asyncio
async def test_correlation_stage_times_out(server, monkeypatch):
    tools = _tools_module()

    async def never_finishes(**kwargs):
        await asyncio.sleep(10)  # a broken deadline fails the < 5 s check, not hangs

    monkeypatch.setattr(tools, "correlate_pipeline_events", never_finishes)
    monkeypatch.setattr(tools, "TRACE_CORRELATE_TIMEOUT", 0.2)

    started = time.monotonic()
    result = _as_dict(await server.mcp.call_tool(
        "pipeline_tracer",
        {"trace_identifier": "build-run-2", "trace_type": "custom", "namespaces": ["team-a"]},
    ))

    assert time.monotonic() - started < 5
    assert result["pipeline_flow"] == []
    assert any("timed out" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_lifecycle_stage_times_out(server, monkeypatch):
    tools = _tools_module()

    async def one_run(**kwargs):
        return [{"name": "build-run-2", "namespace": "team-a", "cluster": "default",
                 "status": "Succeeded", "start_time": "2026-01-01T00:00:00Z",
                 "completion_time": "2026-01-01T00:05:00Z", "labels": {}}]

    async def never_finishes(**kwargs):
        await asyncio.sleep(10)  # a broken deadline fails the < 5 s check, not hangs

    monkeypatch.setattr(tools, "correlate_pipeline_events", one_run)
    monkeypatch.setattr(tools, "follow_lifecycle_chain", never_finishes)
    monkeypatch.setattr(tools, "TRACE_LIFECYCLE_TIMEOUT", 0.2)

    started = time.monotonic()
    result = _as_dict(await server.mcp.call_tool(
        "pipeline_tracer",
        {"trace_identifier": "build-run-2", "trace_type": "custom", "namespaces": ["team-a"]},
    ))

    assert time.monotonic() - started < 5
    assert "timed out" in result["lifecycle"]["error"]
    assert any("timed out" in w for w in result["warnings"])
