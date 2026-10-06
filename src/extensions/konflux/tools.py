"""Konflux MCP tools (phase 2d Task 5).

Relocated from server-mcp.py.  Each make_*() factory closes over `reg`
(ToolRegistry) so that late-bound properties (k8s_custom_api, query_prometheus,
etc.) are resolved per-call, enabling per-case monkeypatching in the golden
harness.

Bodies are verbatim copies of the server-mcp.py originals with the following
minimal edits:
  k8s_core_api    → reg.k8s_core_api
  k8s_custom_api  → reg.k8s_custom_api
  k8s_apps_api    → reg.k8s_apps_api
  _execute_prometheus_query_internal(  → reg.query_prometheus(
  detect_tekton_namespaces(            → reg.detect_tekton_namespaces(
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

from helpers import truncate_baseline_results
from helpers.resource_topology import analyze_bottlenecks, get_multi_cluster_clients, track_artifacts
from .lineage import (
    TRACE_COMMIT_LABEL_KEYS,
    TRACE_PR_LABEL_KEYS,
    correlate_pipeline_events,
    derive_overall_status,
    follow_lifecycle_chain,
    merge_archived_plrs,
    partition_release_plrs,
    summarize_stages,
)

logger = logging.getLogger("lumino-mcp")

# Overall time limits (seconds) for the two fan-out stages of one
# pipeline_tracer call (C07), so a slow or hung apiserver cannot keep a trace
# running indefinitely; each Kubernetes request also has its own timeout.
TRACE_CORRELATE_TIMEOUT = 120.0
TRACE_LIFECYCLE_TIMEOUT = 120.0


def make_ci_cd_performance_baselining_tool(reg):
    async def ci_cd_performance_baselining_tool(
        pipeline_names: Optional[List[str]] = None,
        baseline_period: str = "30d",
        deviation_threshold: float = 2.0,
        include_task_level: bool = True,
        max_context_tokens: int = 50000,
        source: str = ""
    ) -> Dict[str, Any]:
        """
    Establish performance baselines for pipelines and flag runs deviating from historical norms.

    Uses Prometheus metrics from Tekton controller for accurate historical performance data.

    Args:
        pipeline_names: Pipelines to analyze (default: all).
        baseline_period: "7d", "30d" (default), or "90d".
        deviation_threshold: Std deviations to trigger alerts (default: 2.0).
        include_task_level: Include task-level analysis (default: True).
        max_context_tokens: Output token budget (default 50000). Staged truncation caps task_level_analysis lists, then pipeline_baselines count, then drops performance_trends details.
        source: Kubernetes instance name (default "" = the default configured instance).
                Discovered/connected instances accepted; see list_sources.
                Kubeconfig-dir-discovered instances require a prior connect_cluster
                call before the konflux extension can be active on them.

    Returns:
        Dict: Baselines, recent runs analysis, trends, and optimization opportunities.
    """
        from core.extension import InstanceResolutionError
        ireg = reg.for_instance(source) if source else reg
        if source and not ireg.extension_active("konflux"):
            return {
                "error": f"extension 'konflux' is not active on kubernetes instance {source!r}",
                "tool": "ci_cd_performance_baselining_tool",
                "requested_source": source,
                "extension": "konflux",
                "instance": source,
                "extension_state": "unknown",
                "hint": "connect_cluster(<name>, <credential_ref>) runs per-instance detection",
            }
        logger.info(f"Starting CI/CD performance baselining analysis with period: {baseline_period} using Prometheus metrics")

        try:
            # Initialize result structure
            result = {
                "pipeline_baselines": [],
                "performance_trends": {
                    "improving_pipelines": [],
                    "degrading_pipelines": [],
                    "stable_pipelines": [],
                    "most_variable_pipelines": []
                },
                "optimization_opportunities": [],
                "data_source": "prometheus"
            }

            # Define all Prometheus queries upfront
            duration_count_query = "sum by (namespace, status) (tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count)"
            duration_sum_query = "sum by (namespace, status) (tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_sum)"
            avg_duration_query = "sum by (namespace) (tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_sum) / sum by (namespace) (tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count)"
            p16_query = "histogram_quantile(0.16, sum by (namespace, le) (rate(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_bucket[1h])))"
            p84_query = "histogram_quantile(0.84, sum by (namespace, le) (rate(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_bucket[1h])))"
            recent_avg_query = "sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_sum[24h])) / sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count[24h]))"
            historical_avg_query = f"sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_sum[{baseline_period}])) / sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count[{baseline_period}]))"
            recent_success_query = "sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count{status='success'}[24h])) / sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count[24h])) * 100"
            historical_success_query = f"sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count{{status='success'}}[{baseline_period}])) / sum by (namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count[{baseline_period}])) * 100"
            reconcile_query = "sum by (namespace_name, success) (rate(tekton_pipelines_controller_reconcile_count[1h]))"

            logger.info("Querying Prometheus for Tekton pipeline metrics (10 queries in parallel)...")

            # Execute ALL queries in parallel for maximum performance
            (
                count_result,
                sum_result,
                avg_result,
                p16_result,
                p84_result,
                recent_avg_result,
                historical_avg_result,
                recent_success_result,
                historical_success_result,
                reconcile_result
            ) = await asyncio.gather(
                ireg.query_prometheus(duration_count_query),
                ireg.query_prometheus(duration_sum_query),
                ireg.query_prometheus(avg_duration_query),
                ireg.query_prometheus(p16_query),
                ireg.query_prometheus(p84_query),
                ireg.query_prometheus(recent_avg_query),
                ireg.query_prometheus(historical_avg_query),
                ireg.query_prometheus(recent_success_query),
                ireg.query_prometheus(historical_success_query),
                ireg.query_prometheus(reconcile_query)
            )

            logger.info("All Prometheus queries completed")

            if not count_result.get("success") or not sum_result.get("success"):
                logger.warning("Prometheus queries failed, falling back to Kubernetes API")
                result["data_source"] = "kubernetes_api_fallback"
                result["prometheus_error"] = count_result.get("error") or sum_result.get("error")
                # Return early with empty results if Prometheus fails
                return result

            # Parse Prometheus results into namespace-level statistics
            namespace_stats = {}

            # Process count data
            for item in count_result.get("data", []):
                metric = item.get("metric", {})
                namespace = metric.get("namespace", "unknown")
                status = metric.get("status", "unknown")
                count = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0

                if namespace not in namespace_stats:
                    namespace_stats[namespace] = {
                        "success_count": 0,
                        "failed_count": 0,
                        "total_duration_sum": 0,
                        "total_count": 0
                    }

                if status == "success":
                    namespace_stats[namespace]["success_count"] = count
                elif status == "failed":
                    namespace_stats[namespace]["failed_count"] = count
                namespace_stats[namespace]["total_count"] += count

            # Process duration sum data
            for item in sum_result.get("data", []):
                metric = item.get("metric", {})
                namespace = metric.get("namespace", "unknown")
                duration_sum = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0

                if namespace in namespace_stats:
                    namespace_stats[namespace]["total_duration_sum"] += duration_sum

            # Process average duration data
            if avg_result.get("success"):
                for item in avg_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    avg_duration = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0

                    if namespace in namespace_stats and not np.isnan(avg_duration):
                        namespace_stats[namespace]["avg_duration"] = avg_duration

            # Store percentile data for std deviation calculation (std ≈ (P84 - P16) / 2)
            percentile_data = {}
            if p16_result.get("success"):
                for item in p16_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    p16_val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0
                    if namespace not in percentile_data:
                        percentile_data[namespace] = {"p16": 0, "p84": 0}
                    if not np.isnan(p16_val) and not np.isinf(p16_val):
                        percentile_data[namespace]["p16"] = p16_val

            if p84_result.get("success"):
                for item in p84_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    p84_val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0
                    if namespace not in percentile_data:
                        percentile_data[namespace] = {"p16": 0, "p84": 0}
                    if not np.isnan(p84_val) and not np.isinf(p84_val):
                        percentile_data[namespace]["p84"] = p84_val

            # Store trend data for each namespace (recent vs historical comparison)
            trend_data = {}

            # Process recent average duration
            if recent_avg_result.get("success"):
                for item in recent_avg_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0
                    if namespace not in trend_data:
                        trend_data[namespace] = {"recent_avg": 0, "historical_avg": 0, "recent_success": 0, "historical_success": 0}
                    if not np.isnan(val) and not np.isinf(val):
                        trend_data[namespace]["recent_avg"] = val

            # Process historical average duration
            if historical_avg_result.get("success"):
                for item in historical_avg_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0
                    if namespace not in trend_data:
                        trend_data[namespace] = {"recent_avg": 0, "historical_avg": 0, "recent_success": 0, "historical_success": 0}
                    if not np.isnan(val) and not np.isinf(val):
                        trend_data[namespace]["historical_avg"] = val

            # Process recent success rate
            if recent_success_result.get("success"):
                for item in recent_success_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0
                    if namespace not in trend_data:
                        trend_data[namespace] = {"recent_avg": 0, "historical_avg": 0, "recent_success": 0, "historical_success": 0}
                    if not np.isnan(val) and not np.isinf(val):
                        trend_data[namespace]["recent_success"] = val

            # Process historical success rate
            if historical_success_result.get("success"):
                for item in historical_success_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace", "unknown")
                    val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0
                    if namespace not in trend_data:
                        trend_data[namespace] = {"recent_avg": 0, "historical_avg": 0, "recent_success": 0, "historical_success": 0}
                    if not np.isnan(val) and not np.isinf(val):
                        trend_data[namespace]["historical_success"] = val

            reconcile_stats = {}
            if reconcile_result.get("success"):
                for item in reconcile_result.get("data", []):
                    metric = item.get("metric", {})
                    namespace = metric.get("namespace_name", "unknown")
                    success = metric.get("success", "false")
                    rate_val = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0

                    if namespace not in reconcile_stats:
                        reconcile_stats[namespace] = {"success_rate": 0, "failure_rate": 0}

                    if success == "true":
                        reconcile_stats[namespace]["success_rate"] = rate_val
                    else:
                        reconcile_stats[namespace]["failure_rate"] = rate_val

            # Filter namespaces by pipeline_names if specified
            filtered_namespaces = namespace_stats.keys()
            if pipeline_names:
                filtered_namespaces = [ns for ns in filtered_namespaces if any(pn in ns for pn in pipeline_names)]

            # Build baseline entries for each namespace
            for namespace in filtered_namespaces:
                stats = namespace_stats[namespace]

                # Skip namespaces with no data
                if stats["total_count"] == 0:
                    continue

                # Calculate metrics
                total_count = stats["total_count"]
                success_count = stats["success_count"]
                failed_count = stats["failed_count"]
                avg_duration = stats.get("avg_duration", 0)

                # Calculate success rate
                success_rate = (success_count / total_count * 100) if total_count > 0 else 0

                # Calculate std deviation from histogram percentiles (P84 - P16) / 2
                # This provides actual statistical std deviation instead of an estimate
                pdata = percentile_data.get(namespace, {"p16": 0, "p84": 0})
                if pdata["p84"] > pdata["p16"] and pdata["p84"] > 0:
                    # Calculate actual std deviation from percentile spread
                    estimated_std = (pdata["p84"] - pdata["p16"]) / 2.0
                else:
                    # Fallback: use coefficient of variation heuristic if percentile data unavailable
                    estimated_std = avg_duration * 0.4

                # Get reconciliation health
                recon = reconcile_stats.get(namespace, {"success_rate": 0, "failure_rate": 0})
                reconcile_health = "healthy"
                if recon["failure_rate"] > recon["success_rate"]:
                    reconcile_health = "degraded"
                elif recon["failure_rate"] > 0.5:
                    reconcile_health = "warning"

                # Calculate success rate confidence interval using binomial standard error
                # SE = sqrt(p * (1-p) / n) where p is success rate as decimal
                p = success_rate / 100.0
                if total_count > 0 and 0 < p < 1:
                    success_rate_se = np.sqrt(p * (1 - p) / total_count) * 100  # Convert to percentage
                else:
                    success_rate_se = 0  # No variance for 0% or 100% success rate

                # Create baseline entry
                baseline_metrics = {
                    "duration": {
                        "mean_seconds": avg_duration,
                        "std_seconds": estimated_std,
                        "upper_bound": avg_duration + (deviation_threshold * estimated_std),
                        "lower_bound": max(0, avg_duration - (deviation_threshold * estimated_std))
                    },
                    "success_rate": {
                        "mean_percent": success_rate,
                        "std_percent": success_rate_se,
                        "lower_bound": max(0, success_rate - (deviation_threshold * success_rate_se)),
                        "upper_bound": min(100, success_rate + (deviation_threshold * success_rate_se))
                    },
                    "reconciliation": {
                        "success_rate_per_second": recon["success_rate"],
                        "failure_rate_per_second": recon["failure_rate"],
                        "health": reconcile_health
                    }
                }

                # Determine trend using actual time-series comparison (recent vs historical)
                ns_trend = trend_data.get(namespace, {"recent_avg": 0, "historical_avg": 0, "recent_success": 0, "historical_success": 0})
                recent_avg = ns_trend["recent_avg"]
                historical_avg = ns_trend["historical_avg"]
                recent_success = ns_trend["recent_success"]
                historical_success = ns_trend["historical_success"]

                # Calculate duration change percentage (positive = slower = degradation)
                if historical_avg > 0 and recent_avg > 0:
                    duration_change_pct = ((recent_avg - historical_avg) / historical_avg) * 100
                else:
                    duration_change_pct = 0

                # Calculate success rate change (positive = improvement)
                success_change = recent_success - historical_success if (recent_success > 0 or historical_success > 0) else 0

                # Determine trend based on actual metrics comparison
                # Use deviation_threshold to determine significance (default 2.0 = ~5% significance)
                significance_threshold = 10.0 / deviation_threshold  # ~5% change with default threshold

                # Check if there is any recent activity before classifying trends
                has_recent_data = (recent_avg > 0 or recent_success > 0)

                if not has_recent_data:
                    trend = "No recent activity (inactive in last 24h)"
                    trend_direction = "inactive"
                elif abs(duration_change_pct) < significance_threshold and abs(success_change) < significance_threshold:
                    trend = "Stable performance (no significant trend)"
                    trend_direction = "stable"
                elif duration_change_pct < -significance_threshold or success_change > significance_threshold:
                    trend = f"Performance improving: duration {duration_change_pct:+.1f}%, success rate {success_change:+.1f}%"
                    trend_direction = "improving"
                elif duration_change_pct > significance_threshold or success_change < -significance_threshold:
                    trend = f"Performance degrading: duration {duration_change_pct:+.1f}%, success rate {success_change:+.1f}%"
                    trend_direction = "degrading"
                else:
                    trend = f"Slight variation: duration {duration_change_pct:+.1f}%, success rate {success_change:+.1f}%"
                    trend_direction = "variable"

                pipeline_baseline = {
                    "pipeline_name": namespace,  # Using namespace as pipeline identifier for Prometheus data
                    "namespace": namespace,
                    "cluster": "current-cluster",
                    "baseline_metrics": baseline_metrics,
                    "data_points": int(total_count),
                    "success_count": int(success_count),
                    "failed_count": int(failed_count),
                    "last_updated": datetime.now().isoformat(),
                    "trend": trend,
                    "trend_metrics": {
                        "recent_avg_duration": recent_avg,
                        "historical_avg_duration": historical_avg,
                        "duration_change_pct": duration_change_pct,
                        "recent_success_rate": recent_success,
                        "historical_success_rate": historical_success,
                        "success_rate_change": success_change,
                        "comparison_period": f"24h vs {baseline_period}"
                    }
                }

                result["pipeline_baselines"].append(pipeline_baseline)

                # Categorize pipeline trends using trend_direction
                if trend_direction == "improving":
                    result["performance_trends"]["improving_pipelines"].append({
                        "pipeline": namespace,
                        "trend": trend,
                        "avg_duration": avg_duration,
                        "success_rate": success_rate,
                        "duration_change_pct": duration_change_pct,
                        "success_rate_change": success_change
                    })
                elif trend_direction == "degrading":
                    result["performance_trends"]["degrading_pipelines"].append({
                        "pipeline": namespace,
                        "trend": trend,
                        "avg_duration": avg_duration,
                        "success_rate": success_rate,
                        "duration_change_pct": duration_change_pct,
                        "success_rate_change": success_change
                    })
                elif trend_direction in ("stable", "inactive"):
                    result["performance_trends"]["stable_pipelines"].append({
                        "pipeline": namespace,
                        "trend": trend,
                        "avg_duration": avg_duration,
                        "success_rate": success_rate
                    })

                # Check for high variability (using reconciliation failure rate as proxy)
                if recon["failure_rate"] > 1.0:  # More than 1 failure per second
                    result["performance_trends"]["most_variable_pipelines"].append({
                        "pipeline": namespace,
                        "failure_rate": recon["failure_rate"],
                        "avg_duration": avg_duration
                    })

                # Generate optimization opportunities
                if avg_duration > 600:  # Pipelines taking more than 10 minutes
                    result["optimization_opportunities"].append({
                        "pipeline": namespace,
                        "opportunity": "Long execution time optimization",
                        "potential_improvement": f"Pipeline averages {avg_duration/60:.1f} minutes - consider task parallelization or caching",
                        "complexity": "medium",
                        "avg_duration_seconds": avg_duration
                    })

                if success_rate < 80:
                    result["optimization_opportunities"].append({
                        "pipeline": namespace,
                        "opportunity": "Reliability improvement",
                        "potential_improvement": f"Success rate is {success_rate:.1f}% - investigate common failure patterns",
                        "complexity": "high",
                        "current_success_rate": success_rate
                    })

                if reconcile_health == "degraded":
                    result["optimization_opportunities"].append({
                        "pipeline": namespace,
                        "opportunity": "Reconciliation health improvement",
                        "potential_improvement": f"High reconciliation failure rate ({recon['failure_rate']:.2f}/s) - check controller logs and resource limits",
                        "complexity": "high",
                        "failure_rate": recon["failure_rate"]
                    })

            # Task-level analysis if requested
            if include_task_level:
                logger.info("Performing task-level analysis...")
                result["task_level_analysis"] = {
                    "task_baselines": [],
                    "slowest_tasks": [],
                    "most_failed_tasks": []
                }

                # Query task-level duration metrics by task name
                task_duration_query = f"sum by (task, namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_sum[{baseline_period}])) / sum by (task, namespace) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count[{baseline_period}]))"
                task_count_query = f"sum by (task, namespace, status) (increase(tekton_pipelines_controller_pipelinerun_taskrun_duration_seconds_count[{baseline_period}]))"

                task_duration_result = await ireg.query_prometheus(task_duration_query)
                task_count_result = await ireg.query_prometheus(task_count_query)

                task_stats = {}

                # Process task duration data
                if task_duration_result.get("success"):
                    for item in task_duration_result.get("data", []):
                        metric = item.get("metric", {})
                        task_name = metric.get("task", "unknown")
                        namespace = metric.get("namespace", "unknown")
                        avg_duration = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0

                        if np.isnan(avg_duration) or np.isinf(avg_duration):
                            continue

                        key = f"{namespace}/{task_name}"
                        if key not in task_stats:
                            task_stats[key] = {"task": task_name, "namespace": namespace, "avg_duration": 0, "success_count": 0, "failed_count": 0, "total_count": 0}
                        task_stats[key]["avg_duration"] = avg_duration

                # Process task count data
                if task_count_result.get("success"):
                    for item in task_count_result.get("data", []):
                        metric = item.get("metric", {})
                        task_name = metric.get("task", "unknown")
                        namespace = metric.get("namespace", "unknown")
                        status = metric.get("status", "unknown")
                        count = float(item.get("value", [0, 0])[1]) if isinstance(item.get("value"), list) else 0

                        if np.isnan(count) or np.isinf(count):
                            continue

                        key = f"{namespace}/{task_name}"
                        if key not in task_stats:
                            task_stats[key] = {"task": task_name, "namespace": namespace, "avg_duration": 0, "success_count": 0, "failed_count": 0, "total_count": 0}

                        if status == "success":
                            task_stats[key]["success_count"] = count
                        elif status == "failed":
                            task_stats[key]["failed_count"] = count
                        task_stats[key]["total_count"] += count

                # Build task baselines and identify problem tasks
                # Filter out "unknown" tasks - these indicate missing 'task' label in Prometheus metrics
                unknown_task_count = 0
                for key, stats in task_stats.items():
                    if stats["total_count"] < 1:
                        continue

                    # Skip entries where task name is "unknown" - this means the Prometheus metric
                    # doesn't have a 'task' label, so the data is aggregated at namespace level only
                    if stats["task"] == "unknown":
                        unknown_task_count += 1
                        continue

                    task_success_rate = (stats["success_count"] / stats["total_count"] * 100) if stats["total_count"] > 0 else 0

                    task_baseline = {
                        "task": stats["task"],
                        "namespace": stats["namespace"],
                        "avg_duration_seconds": stats["avg_duration"],
                        "total_runs": int(stats["total_count"]),
                        "success_count": int(stats["success_count"]),
                        "failed_count": int(stats["failed_count"]),
                        "success_rate": task_success_rate
                    }
                    result["task_level_analysis"]["task_baselines"].append(task_baseline)

                # Add note if task-level data is limited
                if unknown_task_count > 0 and len(result["task_level_analysis"]["task_baselines"]) == 0:
                    result["task_level_analysis"]["note"] = (
                        f"Task-level analysis unavailable: Prometheus metrics do not include 'task' labels. "
                        f"Found {unknown_task_count} namespace-level aggregations. "
                        "For task-level details, query TaskRun resources directly via Kubernetes API."
                    )
                    logger.info(f"Task-level analysis: No task labels in Prometheus metrics ({unknown_task_count} namespaces without task granularity)")

                # Sort and get top slowest tasks
                result["task_level_analysis"]["task_baselines"].sort(key=lambda x: x.get("avg_duration_seconds", 0) or 0, reverse=True)
                result["task_level_analysis"]["slowest_tasks"] = result["task_level_analysis"]["task_baselines"][:10]

                # Get most failed tasks (by failure count)
                failed_tasks = [t for t in result["task_level_analysis"]["task_baselines"] if t["failed_count"] > 0]
                failed_tasks.sort(key=lambda x: x["failed_count"], reverse=True)
                result["task_level_analysis"]["most_failed_tasks"] = failed_tasks[:10]

                logger.info(f"Task-level analysis completed: {len(result['task_level_analysis']['task_baselines'])} tasks analyzed (filtered {unknown_task_count} 'unknown' entries)")

            # Sort results for better presentation
            result["pipeline_baselines"].sort(key=lambda x: x.get("data_points", 0), reverse=True)
            result["performance_trends"]["improving_pipelines"].sort(key=lambda x: x.get("avg_duration", 0))
            result["performance_trends"]["degrading_pipelines"].sort(key=lambda x: x.get("avg_duration", 0), reverse=True)
            result["performance_trends"]["most_variable_pipelines"].sort(key=lambda x: x.get("failure_rate", 0), reverse=True)

            # Add summary statistics
            result["summary"] = {
                "total_namespaces_analyzed": len(result["pipeline_baselines"]),
                "total_taskruns_tracked": sum(b.get("data_points", 0) for b in result["pipeline_baselines"]),
                "total_successes": sum(b.get("success_count", 0) for b in result["pipeline_baselines"]),
                "total_failures": sum(b.get("failed_count", 0) for b in result["pipeline_baselines"]),
                "namespaces_needing_attention": len([b for b in result["pipeline_baselines"]
                                                      if b.get("baseline_metrics", {}).get("success_rate", {}).get("mean_percent", 100) < 80]),
                "optimization_opportunities_count": len(result["optimization_opportunities"])
            }

            logger.info(f"Performance baselining completed. Analyzed {len(result['pipeline_baselines'])} namespaces, "
                       f"tracking {result['summary']['total_taskruns_tracked']} total TaskRuns")

            result = truncate_baseline_results(result, max_context_tokens)
            return result

        except InstanceResolutionError as exc:
            return exc.error_dict
        except Exception as e:
            logger.error(f"Error in CI/CD performance baselining: {str(e)}", exc_info=True)
            return {
                "pipeline_baselines": [],
                "performance_trends": {
                    "improving_pipelines": [],
                    "degrading_pipelines": [],
                    "stable_pipelines": [],
                    "most_variable_pipelines": []
                },
                "optimization_opportunities": [],
                "error": str(e)
            }

    return ci_cd_performance_baselining_tool


def make_pipeline_tracer(reg):
    async def pipeline_tracer(
        trace_identifier: str,
        trace_type: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        include_artifacts: bool = True,
        trace_depth: str = "deep",
        namespaces: Optional[List[str]] = None,
        max_namespaces: int = 50,
        source: str = ""
    ) -> Dict[str, Any]:
        """
    Trace a logical operation (commit, PR, image) as it flows through pipelines.

    Correlates pipeline runs using labels, annotations, and artifact references.

    Args:
        trace_identifier: Commit SHA, PR number, image tag, or custom trace ID.
        trace_type: "commit", "pr", "image", or "custom".
        start_time: ISO 8601 start timestamp.
        end_time: ISO 8601 end timestamp.
        include_artifacts: Include artifact details (default: True).
        trace_depth: "shallow" or "deep" (default: "deep").
        namespaces: Specific namespaces to search (skips auto-detection).
        max_namespaces: Maximum namespaces to search when auto-detecting (default: 50).
        source: Kubernetes instance name (default "" = the default configured instance).
                Discovered/connected instances accepted; see list_sources.
                Kubeconfig-dir-discovered instances require a prior connect_cluster
                call before the konflux extension can be active on them.

    Returns:
        Dict: Pipeline flow, artifacts, bottlenecks, and summary.
    """
        from core.extension import InstanceResolutionError
        ireg = reg.for_instance(source) if source else reg
        if source and not ireg.extension_active("konflux"):
            return {
                "error": f"extension 'konflux' is not active on kubernetes instance {source!r}",
                "tool": "pipeline_tracer",
                "requested_source": source,
                "extension": "konflux",
                "instance": source,
                "extension_state": "unknown",
                "hint": "connect_cluster(<name>, <credential_ref>) runs per-instance detection",
            }
        try:
            logger.info(f"Starting pipeline trace for {trace_type}: {trace_identifier}")

            # Validate inputs
            valid_trace_types = ["commit", "pr", "image", "custom"]
            if trace_type not in valid_trace_types:
                return {
                    "error": f"Invalid trace_type '{trace_type}'. Must be one of: {', '.join(valid_trace_types)}"
                }

            valid_depths = ["shallow", "deep"]
            if trace_depth not in valid_depths:
                return {
                    "error": f"Invalid trace_depth '{trace_depth}'. Must be one of: {', '.join(valid_depths)}"
                }

            # Get multi-cluster clients
            cluster_clients = await get_multi_cluster_clients(ireg.k8s_core_api, ireg.k8s_custom_api, ireg.k8s_apps_api)

            if not cluster_clients:
                return {
                    "error": "No cluster clients available for tracing"
                }

            # Detect tekton-active namespaces for prioritization (if not user-specified)
            tekton_ns_list = None
            if not namespaces:
                try:
                    tekton_ns = await ireg.detect_tekton_namespaces(source=source)
                    tekton_ns_list = []
                    for category in tekton_ns.values():
                        tekton_ns_list.extend(category)
                    tekton_ns_list = list(set(tekton_ns_list))
                    logger.info(f"Detected {len(tekton_ns_list)} tekton-active namespaces for prioritization")
                except Exception as e:
                    logger.debug(f"Failed to detect tekton namespaces: {e}")

            # Correlate pipeline events across clusters (parallelized)
            trace_warnings: List[str] = []
            correlation_timed_out = False
            try:
                pipeline_flow = await asyncio.wait_for(correlate_pipeline_events(
                    trace_identifier=trace_identifier,
                    trace_type=trace_type,
                    cluster_clients=cluster_clients,
                    start_time=start_time,
                    end_time=end_time,
                    namespaces=namespaces,
                    max_namespaces=max_namespaces,
                    tekton_namespaces=tekton_ns_list,
                    logger=logger
                ), timeout=TRACE_CORRELATE_TIMEOUT)
            except asyncio.TimeoutError:
                pipeline_flow = []
                correlation_timed_out = True
                trace_warnings.append(
                    f"Pipeline correlation timed out after {TRACE_CORRELATE_TIMEOUT:.0f}s; "
                    "pass namespaces= or a lower max_namespaces to narrow the search"
                )
                logger.warning(trace_warnings[-1])

            # KubeArchive fallback (live finding 2026-08-20): prod Tekton GC
            # prunes PLRs within ~2h, so live-only correlation misses runs that
            # provably happened.  Search the archive for the explicitly given
            # namespaces; when auto-detecting, only if the live pass found
            # nothing (cost control: one archive HTTP query per namespace).
            # Best-effort: an unreachable archive never breaks the live trace.
            try:
                # After a correlation timeout the apiserver is slow; do not
                # start the archive dredge on top of it.
                archive_namespaces = [] if correlation_timed_out else (
                    list(namespaces) if namespaces else (
                        (tekton_ns_list or [])[:max_namespaces] if not pipeline_flow else []
                    )
                )
                if archive_namespaces:
                    # Exact label-selector queries whenever the trace type maps to
                    # known label keys — live measurement 2026-08-20: 1.4s per
                    # selector query vs ~13min (and newest-first truncation) for
                    # the bare window dredge on a busy namespace.  The dredge
                    # still runs alongside (capped in the server helper) because
                    # release-side PLRs carry the identifier in annotation VALUES
                    # rather than under a known label key.
                    if trace_type == "commit" and len(trace_identifier) >= 40:
                        _sel_keys = TRACE_COMMIT_LABEL_KEYS
                    elif trace_type == "pr":
                        _sel_keys = TRACE_PR_LABEL_KEYS
                    else:
                        _sel_keys = []
                    _archive_queries = [
                        ireg.query_archived_plrs(
                            namespace=ns, since_time=start_time, until_time=end_time,
                            label_selector=f"{key}={trace_identifier}",
                        )
                        for ns in archive_namespaces for key in _sel_keys
                    ] + [
                        ireg.query_archived_plrs(
                            namespace=ns, since_time=start_time, until_time=end_time
                        )
                        for ns in archive_namespaces
                    ]
                    archived_lists = await asyncio.gather(
                        *_archive_queries,
                        return_exceptions=True,
                    )
                    archived_items = [
                        item for sub in archived_lists if isinstance(sub, list) for item in sub
                    ]
                    if archived_items:
                        before = len(pipeline_flow)
                        pipeline_flow = merge_archived_plrs(
                            pipeline_flow, archived_items, trace_identifier, trace_type,
                            start_time=start_time, end_time=end_time, logger=logger,
                        )
                        logger.info(
                            f"KubeArchive fallback merged {len(pipeline_flow) - before} "
                            f"archived PLR(s) into trace (live: {before})"
                        )
            except Exception as e:
                logger.debug(f"KubeArchive trace fallback skipped: {e}")

            # Track artifacts if requested
            artifacts = await track_artifacts(pipeline_flow, include_artifacts, logger)

            # Analyze for bottlenecks
            bottlenecks = analyze_bottlenecks(pipeline_flow, logger)

            # Calculate summary metrics
            summary = {
                "total_duration": 0,
                "clusters_traversed": len(set(p["cluster"] for p in pipeline_flow)),
                "pipelines_executed": len(pipeline_flow)
            }

            # Calculate total duration if we have start and end times
            if pipeline_flow:
                first_start = pipeline_flow[0].get("start_time")
                last_completion = None

                for pipeline in reversed(pipeline_flow):
                    if pipeline.get("completion_time"):
                        last_completion = pipeline["completion_time"]
                        break

                if first_start and last_completion:
                    try:
                        start_dt = datetime.fromisoformat(first_start.replace('Z', '+00:00'))
                        end_dt = datetime.fromisoformat(last_completion.replace('Z', '+00:00'))
                        summary["total_duration"] = (end_dt - start_dt).total_seconds()
                    except Exception as e:
                        logger.debug(f"Failed to calculate total duration: {e}")

            # Follow lifecycle chain (snapshots → tests → releases → release pipelines)
            lifecycle = {}
            if pipeline_flow:
                try:
                    lifecycle = await asyncio.wait_for(follow_lifecycle_chain(
                        pipeline_flow=pipeline_flow,
                        custom_api=ireg.k8s_custom_api,
                        core_api=ireg.k8s_core_api,
                        trace_depth=trace_depth,
                        logger=logger
                    ), timeout=TRACE_LIFECYCLE_TIMEOUT)
                    logger.info(
                        f"Lifecycle chain: {len(lifecycle.get('snapshots', []))} snapshots, "
                        f"{len(lifecycle.get('integration_tests', []))} tests, "
                        f"{len(lifecycle.get('releases', []))} releases, "
                        f"{len(lifecycle.get('release_pipelines', []))} release PLRs, "
                        f"{len(lifecycle.get('nudge_cascade', []))} nudge cascades"
                    )
                except asyncio.TimeoutError:
                    lifecycle = {"error": f"lifecycle chain timed out after {TRACE_LIFECYCLE_TIMEOUT:.0f}s"}
                    trace_warnings.append(lifecycle["error"])
                    logger.warning(lifecycle["error"])
                except Exception as e:
                    logger.warning(f"Failed to follow lifecycle chain: {e}")
                    lifecycle = {"error": str(e)[:200]}

            # Determine overall status + stage summary (live-p02 finding,
            # 2026-07-24): managed/tenant/final release PLRs are NOT builds.
            # Logic lives in pure, unit-tested helpers in lineage.py.
            build_flow, release_plr_flow = partition_release_plrs(pipeline_flow)
            overall_status = derive_overall_status(
                build_flow, release_plr_flow, lifecycle.get("releases", [])
            )
            summary["stages"] = summarize_stages(build_flow, release_plr_flow, lifecycle)

            result = {
                "trace_id": f"{trace_type}:{trace_identifier}",
                "trace_type": trace_type,
                "start_time": start_time or (pipeline_flow[0].get("start_time") if pipeline_flow else None),
                "end_time": end_time or (pipeline_flow[-1].get("completion_time") if pipeline_flow else None),
                "overall_status": overall_status,
                "pipeline_flow": pipeline_flow,
                "lifecycle": lifecycle,
                "artifacts": artifacts,
                "bottlenecks": bottlenecks,
                "summary": summary
            }
            if trace_warnings:
                result["warnings"] = trace_warnings

            logger.info(f"Trace completed: found {len(pipeline_flow)} pipelines across {summary['clusters_traversed']} clusters")

            return result

        except InstanceResolutionError as exc:
            return exc.error_dict
        except Exception as e:
            logger.error(f"Error in pipeline_tracer: {str(e)}", exc_info=True)
            return {
                "error": f"Failed to trace pipeline: {str(e)}",
                "trace_id": f"{trace_type}:{trace_identifier}",
                "trace_type": trace_type,
                "overall_status": "error",
                "pipeline_flow": [],
                "artifacts": [],
                "bottlenecks": [],
                "summary": {"total_duration": 0, "clusters_traversed": 0, "pipelines_executed": 0}
            }

    return pipeline_tracer
