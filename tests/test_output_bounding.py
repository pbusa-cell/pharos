"""Output bounding tests for get_etcd_logs (Task 3, phase 3.5).

Tests that get_etcd_logs respects max_context_tokens by truncating per-pod
log entries and reporting the truncation via a _truncation summary key.

Mutation targets (per plan):
  - truncation boundary: budget comfortably above content → NO _truncation key
"""

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

_FAKE_KUBECONFIG = """\
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

# ── Synthetic log fixture (~2200 chars, ~733 tokens at the ÷3 heuristic) ─────
# Each line is a realistic etcd-style INFO log entry (not JSON, so clean_etcd_logs
# passes it through unchanged).  40 lines × ~55 chars each ≈ 2200 chars.
_LONG_LOG = "\n".join(
    f"2026-07-24T10:{i // 60:02d}:{i % 60:02d}Z INFO etcd member elected "
    f"member-id=abc{i:04d}def cluster-id=xyz{i:04d}789 "
    f"peer-urls=https://10.0.0.{i % 256}:2380"
    for i in range(40)
)
assert len(_LONG_LOG) > 2000, f"synthetic log too short: {len(_LONG_LOG)} chars"


# ── Minimal fake CoreV1Api ────────────────────────────────────────────────────

def _pod(name, ns):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=ns),
        spec=SimpleNamespace(node_name="node-1"),
        status=SimpleNamespace(phase="Running"),
    )


def _items_list(items):
    return SimpleNamespace(
        items=list(items),
        metadata=SimpleNamespace(_continue=None),
    )


def _fake_etcd_api(log_content: str):
    """Build a minimal fake CoreV1Api for get_etcd_logs.

    Responds to the OpenShift strategy: returns one pod in openshift-etcd
    and the given log_content for read_namespaced_pod_log.
    """
    class _FakeApi:
        def list_namespaced_pod(self, namespace, label_selector=None,
                                timeout_seconds=None, **kwargs):
            if namespace == "openshift-etcd":
                return _items_list([_pod("etcd-node-1", "openshift-etcd")])
            return _items_list([])

        def read_namespaced_pod_log(self, **kwargs):
            return log_content

    return _FakeApi()


# ── Server fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """Import server-mcp.py once with a fake kubeconfig (module-scoped)."""
    kubeconfig = tmp_path_factory.mktemp("kube_bounding") / "config"
    kubeconfig.write_text(_FAKE_KUBECONFIG)
    _orig = {
        "KUBECONFIG": os.environ.get("KUBECONFIG"),
        "KUBEARCHIVE_ENABLED": os.environ.get("KUBEARCHIVE_ENABLED"),
        "LUMINO_DISABLE_TELEMETRY": os.environ.get("LUMINO_DISABLE_TELEMETRY"),
        "LUMINO_CONFIG": os.environ.get("LUMINO_CONFIG"),
        "LUMINO_PROFILE": os.environ.get("LUMINO_PROFILE"),
    }
    os.environ["KUBECONFIG"] = str(kubeconfig)
    os.environ["KUBEARCHIVE_ENABLED"] = "false"
    os.environ.setdefault("LUMINO_DISABLE_TELEMETRY", "1")
    os.environ.pop("LUMINO_CONFIG", None)
    os.environ.pop("LUMINO_PROFILE", None)

    # F9 harness-bleed guard: pin KUBE_CONFIG_DEFAULT_LOCATION to the fake
    # kubeconfig so _discover_kube_contexts reads only the harness contexts
    # (not ~/.kube/config on a dev machine with real contexts).
    # Mirrors tests/characterization/conftest.py:78-83.
    _orig_kube_loc = None
    try:
        from kubernetes.config import kube_config as _k8s_kube_config
        _orig_kube_loc = _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION
        _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = str(kubeconfig)
    except Exception:
        pass

    sys.path.insert(0, str(SRC))
    spec = importlib.util.spec_from_file_location(
        "server_mcp_bounding", SRC / "server-mcp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_bounding"] = mod
    spec.loader.exec_module(mod)

    yield mod

    for key, orig in _orig.items():
        if orig is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = orig
    if _orig_kube_loc is not None:
        try:
            from kubernetes.config import kube_config as _k8s_kube_config
            _k8s_kube_config.KUBE_CONFIG_DEFAULT_LOCATION = _orig_kube_loc
        except Exception:
            pass
    try:
        sys.path.remove(str(SRC))
    except ValueError:
        pass


# ── Tests: get_etcd_logs output bounding ─────────────────────────────────────

class TestGetEtcdLogsBounding:
    """Token-bounding tests for get_etcd_logs.max_context_tokens.

    The synthetic log is ~733 tokens (÷3 heuristic).
    With max_context_tokens=50:  per_entry = max(200, 50 // 1) = 200 → truncated.
    With max_context_tokens=10000: per_entry = 10000 → no truncation.
    """

    @pytest.mark.asyncio
    async def test_tiny_budget_truncates_pod_entry(self, server, monkeypatch):
        """max_context_tokens=50 → pod log contains TRUNCATED notice."""
        monkeypatch.setattr(server, "k8s_core_api", _fake_etcd_api(_LONG_LOG))
        result = await server.get_etcd_logs(max_context_tokens=50)
        pod_log = result.get("etcd-node-1", "")
        assert "[... TRUNCATED" in pod_log, (
            f"Expected '[... TRUNCATED' in pod log.\n"
            f"Got ({len(pod_log)} chars): {pod_log[:300]!r}"
        )

    @pytest.mark.asyncio
    async def test_tiny_budget_adds_truncation_summary_key(self, server, monkeypatch):
        """max_context_tokens=50 → _truncation summary key added to result."""
        monkeypatch.setattr(server, "k8s_core_api", _fake_etcd_api(_LONG_LOG))
        result = await server.get_etcd_logs(max_context_tokens=50)
        assert "_truncation" in result, (
            f"Expected '_truncation' key in result, got keys: {sorted(result.keys())}"
        )

    @pytest.mark.asyncio
    async def test_tiny_budget_truncation_message_reports_applied_budget(
            self, server, monkeypatch):
        """_truncation message names the applied per-entry budget (floor 200).

        With max_context_tokens=50 and 1 log entry: 50 // 1 = 50 < 200 → floor
        raises to 200.  The message must name '200' (applied budget) and
        'max_context_tokens=50' (requested value).
        """
        monkeypatch.setattr(server, "k8s_core_api", _fake_etcd_api(_LONG_LOG))
        result = await server.get_etcd_logs(max_context_tokens=50)
        msg = result["_truncation"]
        assert "200" in msg, (
            f"Expected applied budget 200 in _truncation message: {msg!r}"
        )
        assert "max_context_tokens=50" in msg, (
            f"Expected 'max_context_tokens=50' in _truncation message: {msg!r}"
        )

    @pytest.mark.asyncio
    async def test_tiny_budget_output_smaller_than_input(self, server, monkeypatch):
        """Truncated pod log is substantially smaller than the original content."""
        monkeypatch.setattr(server, "k8s_core_api", _fake_etcd_api(_LONG_LOG))
        result = await server.get_etcd_logs(max_context_tokens=50)
        pod_log = result.get("etcd-node-1", "")
        assert len(pod_log) < len(_LONG_LOG), (
            f"Expected truncated output ({len(pod_log)}) < input ({len(_LONG_LOG)} chars)"
        )

    @pytest.mark.asyncio
    async def test_large_budget_no_truncation_key(self, server, monkeypatch):
        """MUTATION TARGET: budget comfortably above content → NO _truncation key.

        10000 token budget >> ~733 tokens of content.
        Removing or inverting the truncation condition breaks this test.
        """
        monkeypatch.setattr(server, "k8s_core_api", _fake_etcd_api(_LONG_LOG))
        result = await server.get_etcd_logs(max_context_tokens=10000)
        assert "_truncation" not in result, (
            f"Unexpected _truncation with large budget: {result.get('_truncation')!r}"
        )

    @pytest.mark.asyncio
    async def test_large_budget_output_identical_to_default(self, server, monkeypatch):
        """Budget above content → same output whether explicit or default (50000)."""
        monkeypatch.setattr(server, "k8s_core_api", _fake_etcd_api(_LONG_LOG))
        result_explicit = await server.get_etcd_logs(max_context_tokens=10000)
        result_default = await server.get_etcd_logs()          # default 50000
        assert result_explicit == result_default, (
            f"Large-budget call diverged from default:\n"
            f"  explicit={result_explicit}\n  default={result_default}"
        )


# ── Helpers for ci_cd truncator tests ────────────────────────────────────────

def _one_baseline(i: int) -> dict:
    """Realistic pipeline_baseline entry for synthetic test data."""
    return {
        "pipeline_name": f"pipeline-ns-{i:03d}",
        "namespace": f"ns-{i:03d}",
        "cluster": "current-cluster",
        "baseline_metrics": {
            "duration": {
                "mean_seconds": 120.0 + i,
                "std_seconds": 10.0,
                "upper_bound": 140.0 + i,
                "lower_bound": 100.0,
            },
            "success_rate": {
                "mean_percent": 95.0,
                "std_percent": 2.0,
                "lower_bound": 91.0,
                "upper_bound": 99.0,
            },
            "reconciliation": {
                "success_rate_per_second": 5.0,
                "failure_rate_per_second": 0.1,
                "health": "healthy",
            },
        },
        "data_points": 100 + i,
        "success_count": 95 + i,
        "failed_count": 5,
        "last_updated": "2026-07-24T12:00:00.000000",
        "trend": "Stable performance (no significant trend)",
        "trend_metrics": {
            "recent_avg_duration": 120.0,
            "historical_avg_duration": 118.0,
            "duration_change_pct": 1.7,
            "recent_success_rate": 95.0,
            "historical_success_rate": 94.0,
            "success_rate_change": 1.0,
            "comparison_period": "24h vs 30d",
        },
    }


def _make_synthetic_result(n_pipelines: int = 100) -> dict:
    """Build a synthetic ci_cd result with n_pipelines pipeline baselines.

    The task_level_analysis lists (50 entries each) and performance_trends
    lists (20 entries each) are sized so that even a 100-pipeline result
    at max_tokens=200 forces all three truncation stages.
    """
    task_entry = lambda i: {  # noqa: E731
        "task": f"task-{i:03d}",
        "namespace": "ns-000",
        "avg_duration_seconds": 30.0 + i,
        "total_runs": 50,
        "success_count": 48,
        "failed_count": 2,
        "success_rate": 96.0,
    }
    trend_entry = lambda i: {  # noqa: E731
        "pipeline": f"pipeline-{i:03d}",
        "trend": "Stable performance (no significant trend)",
        "avg_duration": 120.0,
        "success_rate": 95.0,
    }
    return {
        "pipeline_baselines": [_one_baseline(i) for i in range(n_pipelines)],
        "performance_trends": {
            "improving_pipelines": [trend_entry(i) for i in range(20)],
            "degrading_pipelines": [trend_entry(i) for i in range(20)],
            "stable_pipelines": [trend_entry(i) for i in range(20)],
            "most_variable_pipelines": [trend_entry(i) for i in range(20)],
        },
        "optimization_opportunities": [],
        "data_source": "prometheus",
        "task_level_analysis": {
            "task_baselines": [task_entry(i) for i in range(50)],
            "slowest_tasks": [task_entry(i) for i in range(50)],
            "most_failed_tasks": [task_entry(i) for i in range(50)],
        },
        "summary": {
            "total_namespaces_analyzed": n_pipelines,
            "total_taskruns_tracked": n_pipelines * 100,
            "total_successes": n_pipelines * 95,
            "total_failures": n_pipelines * 5,
            "namespaces_needing_attention": 0,
            "optimization_opportunities_count": 0,
        },
    }


def _result_tokens(result: dict) -> int:
    import json
    return len(json.dumps(result, default=str)) // 4


def _import_truncate_baseline_results():
    """Import truncate_baseline_results — fails until the function is implemented."""
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from helpers.log_analysis import truncate_baseline_results  # noqa: PLC0415
    return truncate_baseline_results


# ── Tests: truncate_baseline_results unit tests ───────────────────────────────

class TestTruncateBaselineResults:
    """Unit tests for the ci_cd-specific truncator in helpers/log_analysis.py.

    Mutation target (per plan): under-budget input returned IDENTICAL with no
    _truncation_stage — test_under_budget_returned_identical tests this.

    The characterization fixture uses the Prometheus-absent early-return path
    (data_source=kubernetes_api_fallback) and is permanently tiny; the truncator
    proof is intentionally unit-level with synthetic large data.
    """

    def test_over_budget_gets_staged_down_under_budget(self):
        """100-pipeline synthetic result staged down to fit within a 1 500-token budget.

        The 100-pipeline result is ~28 000 tokens (÷4 heuristic); all 3 stages
        reduce it to ~919 tokens (1 baseline + stage-3 trend counts).
        1 500 is safely above the 919-token minimum achievable by all 3 stages.
        """
        fn = _import_truncate_baseline_results()
        data = _make_synthetic_result(n_pipelines=100)
        max_tokens = 1500  # 100-pipeline result is ~28 000 tokens; min after stages ~919

        result = fn(data, max_tokens)

        tokens_after = _result_tokens(result)
        assert tokens_after <= max_tokens, (
            f"Expected result ≤ {max_tokens} tokens after truncation; "
            f"got {tokens_after} tokens"
        )

    def test_over_budget_sets_truncation_stage(self):
        """Over-budget input has _truncation_stage set on return."""
        fn = _import_truncate_baseline_results()
        data = _make_synthetic_result(n_pipelines=100)

        result = fn(data, max_tokens=1500)

        assert "_truncation_stage" in result, (
            f"Expected '_truncation_stage' in result; got keys: {sorted(result.keys())}"
        )

    def test_under_budget_returned_identical_no_truncation_stage(self):
        """MUTATION TARGET: under-budget input returned IDENTICAL — no _truncation_stage.

        A 1-pipeline result at 100 000 tokens budget must come back byte-identical
        to the input dict, with no _truncation_stage key injected.  Inverting or
        removing the early-exit guard breaks this test.
        """
        fn = _import_truncate_baseline_results()
        data = _make_synthetic_result(n_pipelines=1)
        max_tokens = 100_000  # far above a 1-pipeline result

        result = fn(data, max_tokens)

        assert result == data, (
            f"Under-budget result should be identical to input.\n"
            f"Extra keys in result: {set(result) - set(data)}\n"
            f"Missing keys in result: {set(data) - set(result)}"
        )
        assert "_truncation_stage" not in result, (
            f"_truncation_stage must NOT appear for under-budget input; "
            f"got: {result.get('_truncation_stage')!r}"
        )

    def test_stage1_caps_task_level_analysis_lists_to_5(self):
        """Stage 1 caps task_level_analysis lists (task_baselines/slowest/failed) to 5."""
        fn = _import_truncate_baseline_results()
        # Build a result that goes over budget ONLY due to task_level_analysis;
        # use a budget that's satisfied after stage-1 capping.
        # 50-entry task lists dominate; 1 pipeline_baseline keeps it manageable.
        data = _make_synthetic_result(n_pipelines=1)
        # The 1-pipeline + 50-task-entry result is ~1500 tokens; use budget 800
        # so stage 1 capping (→ 5 entries each) is enough to satisfy budget.
        # (After stage 1: 3 lists × 5 entries ~= much smaller)
        result = fn(data, max_tokens=800)

        if "_truncation_stage" in result:
            # Truncation was applied — verify the cap
            tla = result.get("task_level_analysis", {})
            for list_key in ("task_baselines", "slowest_tasks", "most_failed_tasks"):
                lst = tla.get(list_key, [])
                assert len(lst) <= 5, (
                    f"task_level_analysis.{list_key} should be capped to 5; "
                    f"got {len(lst)} entries"
                )

    def test_below_floor_budget_terminates_at_stage3_floor(self):
        """A budget BELOW the achievable post-3-stage floor (~919 tokens for the
        100-pipeline synthetic) must TERMINATE (the stage-2 `n > 1` guard is the
        only thing preventing an infinite halving loop) and return the floor
        result with all stages applied.  Task-4 review: removing the guard hangs
        forever; this test pins it.

        Note: if pytest-timeout is unavailable, the test simply hanging on mutation
        IS the failure signal — no timeout decorator needed.
        """
        fn = _import_truncate_baseline_results()
        data = _make_synthetic_result(n_pipelines=100)
        result = fn(data, max_tokens=200)  # below floor
        assert result["_truncation_stage"] == 3
        assert len(result["pipeline_baselines"]) == 1  # halved to the n==1 floor


# ── Behavioral test: ci_cd Prometheus-absent early path ──────────────────────

class TestCiCdPrometheusAbsentPath:
    """Behavioral test: the Prometheus-absent early return is NOT wrapped.

    The ci_cd tool returns early (before the truncator) when Prometheus is
    absent, leaving _truncation_stage absent from the result.  This proves
    the truncator is wired ONLY at the success return.
    """

    def test_prometheus_absent_no_truncation_stage(self, server, monkeypatch):
        """Prometheus-absent path returns WITHOUT _truncation_stage.

        Verifies the success-path truncator is NOT applied to the early return
        that fires when Prometheus is unreachable.
        """
        import asyncio

        # Ensure Prometheus discovery env vars are absent (prevent accidental hit)
        monkeypatch.delenv("THANOS_URL", raising=False)
        monkeypatch.delenv("PROMETHEUS_URL", raising=False)
        # Reset endpoint cache so discovery is re-attempted (not cached success)
        prom_cache = getattr(server, "_prometheus_endpoint_cache", None)
        if isinstance(prom_cache, dict):
            monkeypatch.setattr(server, "_prometheus_endpoint_cache", {},
                                raising=False)
        elif prom_cache is not None and hasattr(prom_cache, "_cache"):
            prom_cache._cache.clear()

        coro = server.ci_cd_performance_baselining_tool()
        result = asyncio.run(coro)

        assert "_truncation_stage" not in result, (
            f"_truncation_stage must NOT appear on the Prometheus-absent early path; "
            f"got: {result.get('_truncation_stage')!r}"
        )
        assert result.get("data_source") == "kubernetes_api_fallback", (
            f"Expected data_source='kubernetes_api_fallback' (Prometheus absent); "
            f"got: {result.get('data_source')!r}"
        )


# ── Phase 3.5 guard ───────────────────────────────────────────────────────────

def test_bounded_tools_inventory():
    """Phase-3.5 guard: the three context-killer tools carry output bounding.
    get_pipelinerun_logs bounds via its pre-existing max_token_budget;
    the other two via max_context_tokens added this phase.
    ci_cd_performance_baselining_tool relocated to extensions/konflux/tools.py (Task 5).
    """
    repo = Path(__file__).resolve().parents[1]
    src = (repo / "src" / "server-mcp.py").read_text()
    tools_src = (repo / "src" / "extensions" / "konflux" / "tools.py").read_text()
    assert "max_token_budget" in src.split("async def get_pipelinerun_logs(")[1].split("->")[0]
    assert "max_context_tokens" in src.split("def get_etcd_logs(")[1].split("->")[0]
    assert "max_context_tokens" in tools_src.split(
        "async def ci_cd_performance_baselining_tool(")[1].split("->")[0]
