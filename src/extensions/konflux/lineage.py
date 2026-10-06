"""Konflux lifecycle-lineage helpers (phase 2d Task 5).

Relocated from helpers/resource_topology.py.  This module owns all
Konflux-specific topology resolution: trace-identifier matching, pipeline
event correlation, and the full snapshot→test→release→nudge chain.

Import discipline: this module imports FROM helpers (helpers→extensions
direction is forbidden; extensions→helpers is correct).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

# Guarded import mirrors the pattern in helpers/resource_topology.py.
try:
    from core.k8s_async import k8s_call
    from core.readonly_client import ReadOnlyK8sClient
except ImportError:
    from src.core.k8s_async import k8s_call
    from src.core.readonly_client import ReadOnlyK8sClient

from helpers.resource_topology import (
    extract_task_info,
    get_pipeline_status,
    in_time_range,
)

logger = logging.getLogger("lumino-mcp")

# ── PAC/AppStudio label-key lists ────────────────────────────────────────────
# Extracted from matches_trace_identifier() as module constants so that
# packs/konflux.yaml labels section can be validated for faithfulness (Task 5
# Step 3 faithfulness test in tests/core/test_packs.py).

TRACE_COMMIT_LABEL_KEYS: List[str] = [
    "pipelinesascode.tekton.dev/sha",  # Standard PAC
    "pac.test.appstudio.openshift.io/sha",  # Konflux/AppStudio PAC
    "tekton.dev/git-commit",  # Tekton standard
    "git.commit",  # Generic
    "build.appstudio.redhat.com/commit_sha",  # Red Hat AppStudio
]

TRACE_PR_LABEL_KEYS: List[str] = [
    "pac.test.appstudio.openshift.io/pull-request",  # Konflux/AppStudio PAC
    "pipelinesascode.tekton.dev/pull-request",  # Standard PAC
    "pull-request",
    "pr",
]

TRACE_PR_FALLBACK_KEYS: List[str] = [
    "pipelinesascode.tekton.dev/pull-request",
    "build.appstudio.openshift.io/pull_request_number",
]


# ============================================================================
# PIPELINE CORRELATION AND TRACKING
# ============================================================================


async def correlate_pipeline_events(
    trace_identifier: str,
    trace_type: str,
    cluster_clients: Dict[str, Dict[str, Any]],
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    namespaces: Optional[List[str]] = None,
    max_namespaces: int = 50,
    tekton_namespaces: Optional[List[str]] = None,
    logger=None,
) -> List[Dict[str, Any]]:
    """
    Correlate pipeline runs across clusters using labels, annotations, and artifact references.

    Args:
        trace_identifier: The identifier to trace (commit SHA, PR number, image tag, etc.)
        trace_type: Type of trace ("commit", "pr", "image", "custom")
        cluster_clients: Dict of cluster clients with core_api, custom_api, apps_api
        start_time: Optional start time filter (ISO 8601)
        end_time: Optional end time filter (ISO 8601)
        namespaces: Optional list of specific namespaces to search (skips auto-detection)
        max_namespaces: Maximum namespaces to search when auto-detecting (default: 50)
        tekton_namespaces: Optional list of known tekton-active namespaces for prioritization
        logger: Optional logger instance

    Returns:
        List of pipeline info dicts with cluster, namespace, status, and metadata
    """
    pipeline_flow = []

    async def query_namespace(
        cluster_name: str, namespace: str, custom_api
    ) -> List[Dict[str, Any]]:
        """Query PipelineRuns in a single namespace - designed for parallel execution."""
        results = []
        try:
            pipeline_runs = await k8s_call(custom_api.list_namespaced_custom_object,
                group="tekton.dev",
                version="v1",
                namespace=namespace,
                plural="pipelineruns",
                limit=200,
            )

            for pr in pipeline_runs.get("items", []):
                if matches_trace_identifier(pr, trace_identifier, trace_type):
                    pipeline_info = {
                        "cluster": cluster_name,
                        "namespace": namespace,
                        "pipeline_name": pr.get("metadata", {}).get("name", "unknown"),
                        "pipeline_run_name": pr.get("metadata", {}).get("name", "unknown"),
                        "status": get_pipeline_status(pr),
                        "start_time": pr.get("status", {}).get("startTime"),
                        "completion_time": pr.get("status", {}).get("completionTime"),
                        "tasks": extract_task_info(pr),
                        "labels": pr.get("metadata", {}).get("labels", {}),
                        "annotations": pr.get("metadata", {}).get("annotations", {}),
                    }

                    # Filter by time range if specified
                    if in_time_range(pipeline_info, start_time, end_time):
                        results.append(pipeline_info)

        except Exception as e:
            if logger:
                logger.debug(f"Failed to query PipelineRuns in {cluster_name}/{namespace}: {e}")

        return results

    for cluster_name, clients in cluster_clients.items():
        try:
            custom_api = clients["custom_api"]

            # Determine which namespaces to search
            target_namespaces = []

            if namespaces:
                # User specified exact namespaces - use them directly
                target_namespaces = namespaces
            else:
                # Auto-detect namespaces with tekton prioritization
                try:
                    ns_list = await k8s_call(clients["core_api"].list_namespace)
                    all_namespaces = [ns.metadata.name for ns in ns_list.items]

                    if tekton_namespaces:
                        # Prioritize tekton-active namespaces first
                        tekton_set = set(tekton_namespaces)
                        prioritized = [ns for ns in all_namespaces if ns in tekton_set]
                        others = [ns for ns in all_namespaces if ns not in tekton_set]
                        target_namespaces = (prioritized + others)[:max_namespaces]
                    else:
                        # No tekton hints - use heuristic prioritization
                        # Prioritize namespaces likely to have pipelines
                        pipeline_keywords = [
                            "tenant",
                            "pipeline",
                            "tekton",
                            "cicd",
                            "ci-cd",
                            "build",
                            "konflux",
                        ]
                        prioritized = []
                        others = []
                        for ns in all_namespaces:
                            if any(kw in ns.lower() for kw in pipeline_keywords):
                                prioritized.append(ns)
                            else:
                                others.append(ns)
                        target_namespaces = (prioritized + others)[:max_namespaces]

                except Exception as e:
                    if logger:
                        logger.warning(f"Failed to list namespaces in cluster {cluster_name}: {e}")
                    continue

            if not target_namespaces:
                continue

            if logger:
                logger.info(
                    f"Searching {len(target_namespaces)} namespaces in cluster {cluster_name}"
                )

            # Parallelize namespace queries using asyncio.gather
            tasks = [
                asyncio.ensure_future(query_namespace(cluster_name, ns, custom_api))
                for ns in target_namespaces
            ]

            # Execute all namespace queries in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect results, handling any exceptions
            for result in results:
                if isinstance(result, Exception):
                    if logger:
                        logger.debug(f"Namespace query failed: {result}")
                elif isinstance(result, list):
                    pipeline_flow.extend(result)

        except Exception as e:
            if logger:
                logger.error(f"Failed to query cluster {cluster_name}: {e}")
            continue

    return pipeline_flow


def matches_trace_identifier(
    pipeline_run: Dict[str, Any], trace_identifier: str, trace_type: str
) -> bool:
    """Check if a pipeline run matches the trace identifier."""
    metadata = pipeline_run.get("metadata", {})
    labels = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})

    if trace_type == "commit":
        # Look for commit SHA in labels and annotations
        # Support multiple PAC/Konflux label formats
        for key in TRACE_COMMIT_LABEL_KEYS:
            if labels.get(key, "").startswith(trace_identifier) or annotations.get(
                key, ""
            ).startswith(trace_identifier):
                return True
        # Also check in all values (catches non-standard label placements)
        return any(trace_identifier in str(v) for v in labels.values()) or any(
            trace_identifier in str(v) for v in annotations.values()
        )

    elif trace_type == "pr":
        # Look for PR number in labels and annotations
        # Support multiple PAC label formats used by different Konflux/Tekton installations
        for key in TRACE_PR_LABEL_KEYS:
            if labels.get(key) == trace_identifier or annotations.get(key) == trace_identifier:
                return True
        # Also check annotation keys that might store PR info
        for key in TRACE_PR_FALLBACK_KEYS:
            if annotations.get(key) == trace_identifier:
                return True
        return False

    elif trace_type == "image":
        # Look for image reference in labels, annotations, or results
        return any(trace_identifier in str(v) for v in labels.values()) or any(
            trace_identifier in str(v) for v in annotations.values()
        )

    elif trace_type == "custom":
        # Search across all labels and annotations
        name = metadata.get("name", "")
        return (
            trace_identifier in name
            or any(trace_identifier in str(v) for v in labels.values())
            or any(trace_identifier in str(v) for v in annotations.values())
        )

    return False


def merge_archived_plrs(
    pipeline_flow: List[Dict[str, Any]],
    archived_items: List[Dict[str, Any]],
    trace_identifier: str,
    trace_type: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    logger=None,
) -> List[Dict[str, Any]]:
    """Merge archived (KubeArchive) PipelineRun objects into a live pipeline_flow.

    Live finding 2026-08-20: prod-cluster Tekton GC prunes PLRs within ~2 hours,
    so live-only correlation misses builds that provably happened.  Archived raw
    PLR objects go through the SAME matcher and time filter as live ones, are
    marked cluster="kubearchive" / archived=True, and are deduped against live
    entries by (namespace, name) — a PLR present both live and archived keeps
    its live entry.  The merged list is sorted by start_time so downstream
    summary math (first start / last completion) stays correct.
    """
    seen = {(p.get("namespace"), p.get("pipeline_run_name")) for p in pipeline_flow}
    merged = list(pipeline_flow)

    for pr in archived_items or []:
        try:
            if not matches_trace_identifier(pr, trace_identifier, trace_type):
                continue
            md = pr.get("metadata", {})
            key = (md.get("namespace"), md.get("name"))
            if key in seen:
                continue
            entry = {
                "cluster": "kubearchive",
                "archived": True,
                "namespace": md.get("namespace", "unknown"),
                "pipeline_name": md.get("name", "unknown"),
                "pipeline_run_name": md.get("name", "unknown"),
                "status": get_pipeline_status(pr),
                "start_time": pr.get("status", {}).get("startTime"),
                "completion_time": pr.get("status", {}).get("completionTime"),
                "tasks": extract_task_info(pr),
                "labels": md.get("labels", {}),
                "annotations": md.get("annotations", {}),
            }
            if not in_time_range(entry, start_time, end_time):
                continue
            seen.add(key)
            merged.append(entry)
        except Exception as e:  # one bad archived object must not kill the trace
            if logger:
                logger.debug(f"Skipping malformed archived PLR: {e}")

    # ISO-8601 strings sort chronologically; None sorts last.
    merged.sort(key=lambda p: (p.get("start_time") is None, p.get("start_time") or ""))
    return merged


# ============================================================================
# FULL LIFECYCLE CHAIN FOLLOWING
# ============================================================================


async def follow_lifecycle_chain(
    pipeline_flow: List[Dict[str, Any]],
    custom_api,
    core_api,
    trace_depth: str = "deep",
    logger=None,
) -> Dict[str, Any]:
    """
    Follow the Konflux lifecycle chain from build PLRs through snapshots,
    integration tests, releases, and release pipelines.

    Chain: Build PLR -> Snapshot -> Integration Tests ->
           Release -> Managed/Tenant/Final PLR -> Nudge Cascade

    Args:
        pipeline_flow: Initial matched PipelineRuns from correlate_pipeline_events()
        custom_api: Kubernetes CustomObjectsApi for CRD queries
        core_api: Kubernetes CoreV1Api
        trace_depth: "shallow" (snapshots only) or "deep" (full chain)
        logger: Optional logger

    Returns:
        Dict with snapshots, integration_tests, releases, release_pipelines, nudge_cascade
    """

    custom_api = ReadOnlyK8sClient.wrap(custom_api)

    lifecycle = {
        "application": None,
        "component": None,
        "snapshots": [],
        "integration_tests": [],
        "releases": [],
        "release_pipelines": [],
        "nudge_cascade": [],
    }

    seen_snapshots = set()
    seen_releases = set()
    seen_plrs = set()

    for plr in pipeline_flow:
        annotations = plr.get("annotations", {})
        labels = plr.get("labels", {})
        # Managed/tenant/final release PLRs run in the releng namespace; their
        # Snapshot/Application/Component/Release objects live in the ORIGIN
        # tenant named by this label.  Resolve there when present.
        namespace = labels.get("release.appstudio.openshift.io/namespace") or plr.get(
            "namespace", ""
        )

        # ── Step 2: Build PLR → Snapshot ──
        # Check both annotations (build PLRs) and labels (test PLRs) for snapshot reference
        snapshot_name = annotations.get("appstudio.openshift.io/snapshot") or labels.get(
            "appstudio.openshift.io/snapshot"
        )
        if not snapshot_name or snapshot_name in seen_snapshots:
            continue
        seen_snapshots.add(snapshot_name)

        snapshot_data = await _resolve_snapshot(custom_api, namespace, snapshot_name, plr, logger)
        if not snapshot_data:
            continue
        lifecycle["snapshots"].append(snapshot_data)

        # ── Step 2b: Resolve Application and Component context ──
        if not lifecycle["application"]:
            app_name = snapshot_data.get("application")
            if app_name:
                lifecycle["application"] = await _resolve_application(
                    custom_api, namespace, app_name, logger
                )

        if not lifecycle["component"]:
            comp_name = labels.get("appstudio.openshift.io/component")
            if comp_name:
                lifecycle["component"] = await _resolve_component(
                    custom_api, namespace, comp_name, logger
                )

        # ── Step 3: Snapshot → Integration Tests ──
        test_entries = _extract_test_info_from_snapshot(snapshot_data)
        for test_entry in test_entries:
            lifecycle["integration_tests"].append(test_entry)
            # Optionally fetch the test PLR for task-level details
            if trace_depth == "deep" and test_entry.get("plr_name"):
                test_plr_detail = await _resolve_plr(
                    custom_api, namespace, test_entry["plr_name"], logger
                )
                if test_plr_detail:
                    test_entry["tasks"] = extract_task_info_from_status(test_plr_detail)
                    test_entry["pipeline"] = (
                        test_plr_detail.get("metadata", {})
                        .get("labels", {})
                        .get("tekton.dev/pipeline", "")
                    )

        # ── Step 4: Snapshot → Releases ──
        releases = await _resolve_releases_for_snapshot(
            custom_api, namespace, snapshot_name, logger
        )
        for release in releases:
            release_key = release.get("name", "")
            if release_key in seen_releases:
                continue
            seen_releases.add(release_key)
            lifecycle["releases"].append(release)

            # ── Step 5: Release → Managed/Tenant/Final PLRs ──
            if trace_depth == "deep":
                release_plrs = await _resolve_release_pipelines(custom_api, release, logger)
                for rp in release_plrs:
                    plr_key = f"{rp.get('namespace')}/{rp.get('name')}"
                    if plr_key not in seen_plrs:
                        seen_plrs.add(plr_key)
                        lifecycle["release_pipelines"].append(rp)

        # ── Step 6: Nudge Cascade (deep only) ──
        if trace_depth == "deep" and snapshot_data.get("nudge_processed"):
            nudge_entries = await _resolve_nudge_cascade(
                custom_api, namespace, snapshot_data, lifecycle["releases"], logger
            )
            lifecycle["nudge_cascade"].extend(nudge_entries)

    return lifecycle


#: PLR types executed BY the release service — not build pipelines.
#: "release" covers InternalRequest PLRs on the internal-services cluster
#: (kflux-c-prd-i01), which label themselves type=release (live finding 2026-08-20).
RELEASE_PLR_TYPES = frozenset({"managed", "tenant", "final", "release"})


def partition_release_plrs(
    pipeline_flow: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split matched PLRs into (build_flow, release_flow) by the
    pipelines.appstudio.openshift.io/type label — managed/tenant/final PLRs
    belong to the release stage, everything else counts as build."""
    build_flow: List[Dict[str, Any]] = []
    release_flow: List[Dict[str, Any]] = []
    for plr in pipeline_flow:
        plr_type = plr.get("labels", {}).get("pipelines.appstudio.openshift.io/type")
        (release_flow if plr_type in RELEASE_PLR_TYPES else build_flow).append(plr)
    return build_flow, release_flow


_TERMINAL_OK = ("Succeeded", "Completed")
_IN_FLIGHT = frozenset({"Running", "Started", "PipelineRunPending"})
# Tekton-vocabulary extension point (OQ-10): this closed set is the deliberate
# trade-off — a false positive (reporting a cancelled run as "failed") beats a
# false negative (reporting it as "in_progress") in triage. If Tekton introduces
# new in-flight statuses (e.g. "Queued"), add them to _IN_FLIGHT here.
# Sharp edge: get_pipeline_status() (src/helpers/resource_topology.py:54) returns
# "Unknown" for a PipelineRun with no conditions yet (brand-new run) — under this
# closed set, that run reports "failed" until its first condition lands.


def _is_terminal_failure(status: str) -> bool:
    """Return True when the status is a terminal failure — not successful, not in-flight."""
    return status not in _TERMINAL_OK and status not in _IN_FLIGHT


def derive_release_status(condition_map: Dict[str, Any]) -> str:
    """Release-CR status from its Released condition (Konflux release contract):
    True -> Succeeded; False + reason Progressing -> still in flight (the old
    mapping mislabeled this Failed); False otherwise -> Failed; absent ->
    InProgress (controller hasn't reported yet)."""
    released = condition_map.get("Released", {})
    if released.get("status") == "True":
        return "Succeeded"
    if released.get("status") == "False":
        if released.get("reason") == "Progressing":
            return "Progressing"
        return "Failed"
    return "InProgress"


def derive_overall_status(
    build_flow: List[Dict[str, Any]],
    release_plr_flow: List[Dict[str, Any]],
    releases: List[Dict[str, Any]],
) -> str:
    """Overall trace status from partitioned PLRs + resolved Release objects.

    Build failures win over release failures; a non-terminal release PLR is
    in_progress, never succeeded (a Release CR may be unresolvable cross-tenant
    while its PLR is still running)."""
    if not build_flow and not release_plr_flow:
        return "not_found"
    builds_ok = all(p["status"] in _TERMINAL_OK for p in build_flow)
    builds_failed = any(_is_terminal_failure(p["status"]) for p in build_flow)
    release_failed = any(r.get("status") == "Failed" for r in releases) or any(
        _is_terminal_failure(p["status"]) for p in release_plr_flow
    )
    release_succeeded = (
        all(r.get("status") == "Succeeded" for r in releases) if releases else True
    )
    release_plrs_ok = all(p["status"] in _TERMINAL_OK for p in release_plr_flow)

    if builds_failed:
        return "failed"
    if release_failed:
        return "release_failed"
    if builds_ok and release_succeeded and release_plrs_ok:
        return "succeeded"
    return "in_progress"


def summarize_stages(
    build_flow: List[Dict[str, Any]],
    release_plr_flow: List[Dict[str, Any]],
    lifecycle: Dict[str, Any],
) -> Dict[str, Any]:
    """Stage-level summary buckets; release-service PLRs are their own stage."""
    # F-38 fixed: terminal-failure reasons use _is_terminal_failure() via the
    # closed _IN_FLIGHT set. Both functions (derive_overall_status and this one)
    # use the same helper so their verdicts agree atomically.
    stage_summary: Dict[str, Any] = {}
    if build_flow:
        stage_summary["build"] = {
            "count": len(build_flow),
            "status": (
                "failed" if any(_is_terminal_failure(p["status"]) for p in build_flow)
                else "succeeded" if all(p["status"] in _TERMINAL_OK for p in build_flow)
                else "in_progress"
            ),
        }
    if release_plr_flow:
        stage_summary["release_pipelines"] = {
            "count": len(release_plr_flow),
            "status": (
                "failed" if any(_is_terminal_failure(p["status"]) for p in release_plr_flow)
                else "succeeded" if all(p["status"] in _TERMINAL_OK for p in release_plr_flow)
                else "in_progress"
            ),
        }
    if lifecycle.get("integration_tests"):
        tests = lifecycle["integration_tests"]
        stage_summary["integration_tests"] = {
            "count": len(tests),
            "passed": sum(1 for t in tests if t.get("status") == "TestPassed"),
            "failed": sum(1 for t in tests if t.get("status") == "TestFail"),
        }
    if lifecycle.get("releases"):
        rels = lifecycle["releases"]
        stage_summary["releases"] = {
            "count": len(rels),
            "succeeded": sum(1 for r in rels if r.get("status") == "Succeeded"),
            "failed": sum(1 for r in rels if r.get("status") == "Failed"),
        }
    if lifecycle.get("nudge_cascade"):
        stage_summary["nudge_cascade"] = {
            "count": len(lifecycle["nudge_cascade"]),
        }
    return stage_summary


async def _resolve_plr(custom_api, namespace: str, plr_name: str, logger=None) -> Optional[Dict]:
    """Fetch a single PipelineRun resource."""
    try:
        return await k8s_call(custom_api.get_namespaced_custom_object,
            group="tekton.dev",
            version="v1",
            namespace=namespace,
            plural="pipelineruns",
            name=plr_name,
        )
    except Exception as e:
        if logger:
            logger.debug(f"Failed to resolve PLR {plr_name} in {namespace}: {e}")
        return None


async def _resolve_application(
    custom_api, namespace: str, app_name: str, logger=None
) -> Optional[Dict]:
    """Fetch an Application resource and extract key fields."""
    try:
        app = await k8s_call(custom_api.get_namespaced_custom_object,
            group="appstudio.redhat.com",
            version="v1alpha1",
            namespace=namespace,
            plural="applications",
            name=app_name,
        )
        spec = app.get("spec", {})

        # Count components belonging to this application
        component_count = 0
        try:
            comp_list = await k8s_call(custom_api.list_namespaced_custom_object,
                group="appstudio.redhat.com",
                version="v1alpha1",
                namespace=namespace,
                plural="components",
                label_selector=f"appstudio.openshift.io/application={app_name}",
            )
            component_count = len(comp_list.get("items", []))
        except Exception:
            pass

        return {
            "name": app_name,
            "namespace": namespace,
            "display_name": spec.get("displayName", app_name),
            "component_count": component_count,
        }
    except Exception as e:
        if logger:
            logger.debug(f"Failed to resolve application {app_name} in {namespace}: {e}")
        return {"name": app_name, "namespace": namespace, "status": "not_found"}


async def _resolve_component(
    custom_api, namespace: str, comp_name: str, logger=None
) -> Optional[Dict]:
    """Fetch a Component resource and extract key fields."""
    try:
        comp = await k8s_call(custom_api.get_namespaced_custom_object,
            group="appstudio.redhat.com",
            version="v1alpha1",
            namespace=namespace,
            plural="components",
            name=comp_name,
        )
        spec = comp.get("spec", {})
        status = comp.get("status", {})
        annotations = comp.get("metadata", {}).get("annotations", {})

        # Parse build pipeline annotation
        build_pipeline = ""
        try:
            import json

            pipeline_info = json.loads(
                annotations.get("build.appstudio.openshift.io/pipeline", "{}")
            )
            build_pipeline = pipeline_info.get("name", "")
        except Exception:
            pass

        # Parse PaC status
        pac_enabled = False
        try:
            import json

            pac_info = json.loads(annotations.get("build.appstudio.openshift.io/status", "{}"))
            pac_enabled = pac_info.get("pac", {}).get("state") == "enabled"
        except Exception:
            pass

        git_source = spec.get("source", {}).get("git", {})

        return {
            "name": comp_name,
            "namespace": namespace,
            "application": spec.get("application", ""),
            "source_url": git_source.get("url", ""),
            "revision": git_source.get("revision", ""),
            "dockerfile": git_source.get("dockerfileUrl", ""),
            "context": git_source.get("context", ""),
            "build_pipeline": build_pipeline,
            "pac_enabled": pac_enabled,
            "container_image": spec.get("containerImage", "")[:100],
            "last_built_commit": status.get("lastBuiltCommit", "")[:12],
        }
    except Exception as e:
        if logger:
            logger.debug(f"Failed to resolve component {comp_name} in {namespace}: {e}")
        return {"name": comp_name, "namespace": namespace, "status": "not_found"}


async def _resolve_snapshot(
    custom_api, namespace: str, snapshot_name: str, source_plr: Dict, logger=None
) -> Optional[Dict]:
    """Fetch a Snapshot resource and extract key fields."""
    try:
        snapshot = await k8s_call(custom_api.get_namespaced_custom_object,
            group="appstudio.redhat.com",
            version="v1alpha1",
            namespace=namespace,
            plural="snapshots",
            name=snapshot_name,
        )
        metadata = snapshot.get("metadata", {})
        annotations = metadata.get("annotations", {})
        spec = snapshot.get("spec", {})
        status = snapshot.get("status", {})
        conditions = status.get("conditions", [])

        # Parse conditions into a simple dict
        condition_map = {}
        for c in conditions:
            condition_map[c.get("type", "")] = {
                "status": c.get("status"),
                "reason": c.get("reason"),
                "message": c.get("message", "")[:200],
            }

        # Extract components
        components = []
        for comp in spec.get("components", []):
            components.append(
                {
                    "name": comp.get("name", ""),
                    "containerImage": comp.get("containerImage", "")[:100],
                    "git_url": comp.get("source", {}).get("git", {}).get("url", ""),
                    "revision": comp.get("source", {}).get("git", {}).get("revision", "")[:12],
                }
            )

        return {
            "name": snapshot_name,
            "namespace": namespace,
            "application": spec.get("application", ""),
            "components": components,
            "component_count": len(components),
            "conditions": condition_map,
            "tests_passed": condition_map.get("AppStudioTestSucceeded", {}).get("status") == "True",
            "auto_released": condition_map.get("AutoReleased", {}).get("status") == "True",
            "nudge_processed": annotations.get(
                "build.appstudio.openshift.io/component-nudge-processed"
            )
            == "true",
            "triggered_by_plr": source_plr.get("pipeline_run_name", ""),
            "created_at": metadata.get("creationTimestamp", ""),
            "_raw_annotations": annotations,  # Kept for test extraction
        }
    except Exception as e:
        if logger:
            logger.debug(f"Failed to resolve snapshot {snapshot_name} in {namespace}: {e}")
        status_msg = (
            "not_found" if "404" in str(e) else "rbac_denied" if "403" in str(e) else str(e)[:80]
        )
        return {
            "name": snapshot_name,
            "namespace": namespace,
            "status": status_msg,
            "components": [],
            "component_count": 0,
            "conditions": {},
            "tests_passed": None,
            "auto_released": None,
            "nudge_processed": False,
            "triggered_by_plr": source_plr.get("pipeline_run_name", ""),
        }


def _extract_test_info_from_snapshot(snapshot_data: Dict) -> List[Dict]:
    """Extract integration test results from snapshot annotations."""
    import json

    tests = []
    raw_annotations = snapshot_data.get("_raw_annotations", {})
    test_status_str = raw_annotations.get("test.appstudio.openshift.io/status", "[]")

    try:
        test_statuses = json.loads(test_status_str)
    except (json.JSONDecodeError, TypeError):
        return tests

    for test in test_statuses:
        duration_seconds = None
        start_time = test.get("startTime")
        completion_time = test.get("completionTime")
        if start_time and completion_time:
            try:
                from datetime import datetime

                s = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                e = datetime.fromisoformat(completion_time.replace("Z", "+00:00"))
                duration_seconds = int((e - s).total_seconds())
            except Exception:
                pass

        tests.append(
            {
                "scenario": test.get("scenario", ""),
                "status": test.get("status", ""),
                "plr_name": test.get("testPipelineRunName", ""),
                "start_time": start_time,
                "completion_time": completion_time,
                "duration_seconds": duration_seconds,
                "snapshot": snapshot_data.get("name", ""),
            }
        )

    return tests


async def _resolve_releases_for_snapshot(
    custom_api, namespace: str, snapshot_name: str, logger=None
) -> List[Dict]:
    """Find Release resources linked to a snapshot via label."""
    releases = []
    try:
        release_list = await k8s_call(custom_api.list_namespaced_custom_object,
            group="appstudio.redhat.com",
            version="v1alpha1",
            namespace=namespace,
            plural="releases",
            label_selector=f"release.appstudio.openshift.io/snapshot={snapshot_name}",
        )

        for release in release_list.get("items", []):
            metadata = release.get("metadata", {})
            metadata.get("labels", {})
            spec = release.get("spec", {})
            status = release.get("status", {})
            conditions = status.get("conditions", [])

            condition_map = {}
            for c in conditions:
                condition_map[c.get("type", "")] = {
                    "status": c.get("status"),
                    "reason": c.get("reason"),
                    "message": c.get("message", "")[:200],
                }

            releases.append(
                {
                    "name": metadata.get("name", ""),
                    "namespace": namespace,
                    "snapshot": snapshot_name,
                    "release_plan": spec.get("releasePlan", ""),
                    "grace_period_days": spec.get("gracePeriodDays"),
                    "status": derive_release_status(condition_map),
                    "conditions": condition_map,
                    "automated": status.get("automated", False),
                    "author": status.get("attribution", {}).get("author", ""),
                    "start_time": status.get("startTime"),
                    "completion_time": status.get("completionTime"),
                    "target": status.get("target", ""),
                    "artifacts": status.get("artifacts", {}),
                    # Pipeline references for step 5
                    "_managed_plr_ref": status.get("managedProcessing", {}).get("pipelineRun"),
                    "_tenant_plr_ref": status.get("tenantProcessing", {}).get("pipelineRun"),
                    "_final_plr_ref": status.get("finalProcessing", {}).get("pipelineRun"),
                }
            )

    except Exception as e:
        if logger:
            logger.debug(f"Failed to find releases for snapshot {snapshot_name}: {e}")

    return releases


async def _resolve_release_pipelines(custom_api, release: Dict, logger=None) -> List[Dict]:
    """Resolve managed, tenant, and final PLRs from a Release resource."""
    plrs = []
    refs = [
        ("managed", release.get("_managed_plr_ref")),
        ("tenant", release.get("_tenant_plr_ref")),
        ("final", release.get("_final_plr_ref")),
    ]

    for stage, ref in refs:
        if not ref or "/" not in ref:
            continue
        ns, name = ref.split("/", 1)

        try:
            plr = await k8s_call(custom_api.get_namespaced_custom_object,
                group="tekton.dev", version="v1", namespace=ns, plural="pipelineruns", name=name
            )
            status = plr.get("status", {})
            conditions = status.get("conditions", [])
            plr_status = "Unknown"
            plr_message = ""
            for c in conditions:
                if c.get("type") == "Succeeded":
                    plr_status = c.get("reason", "Unknown")
                    plr_message = c.get("message", "")
                    break

            # Extract tasks
            tasks = extract_task_info_from_status(plr)

            # Calculate duration
            duration_seconds = None
            start = status.get("startTime")
            end = status.get("completionTime")
            if start and end:
                try:
                    from datetime import datetime

                    s = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    e = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    duration_seconds = int((e - s).total_seconds())
                except Exception:
                    pass

            plrs.append(
                {
                    "name": name,
                    "namespace": ns,
                    "stage": stage,
                    "pipeline": plr.get("metadata", {})
                    .get("labels", {})
                    .get("tekton.dev/pipeline", ""),
                    "status": plr_status,
                    "message": plr_message[:150],
                    "start_time": start,
                    "completion_time": end,
                    "duration_seconds": duration_seconds,
                    "tasks": tasks,
                    "task_count": len(tasks),
                    "release": release.get("name", ""),
                }
            )

        except Exception as e:
            if logger:
                logger.debug(f"Failed to resolve {stage} PLR {ns}/{name}: {e}")
            status_msg = (
                "not_found"
                if "404" in str(e)
                else "rbac_denied"
                if "403" in str(e)
                else str(e)[:60]
            )
            plrs.append(
                {
                    "name": name,
                    "namespace": ns,
                    "stage": stage,
                    "status": status_msg,
                    "release": release.get("name", ""),
                }
            )

    return plrs


def extract_task_info_from_status(plr: Dict) -> List[Dict]:
    """Extract task info from a PipelineRun, using childReferences (v1) or taskRuns (v1beta1)."""
    tasks = []

    # Try childReferences first (Tekton v1 format)
    child_refs = plr.get("status", {}).get("childReferences", [])
    if child_refs:
        for ref in child_refs:
            tasks.append(
                {
                    "name": ref.get("pipelineTaskName", ref.get("name", "")),
                    "taskrun_name": ref.get("name", ""),
                }
            )
        return tasks

    # Fall back to inline taskRuns (v1beta1 format)
    task_runs = plr.get("status", {}).get("taskRuns", {})
    for task_run_name, task_run_status in task_runs.items():
        task_status = task_run_status.get("status", {})
        conds = task_status.get("conditions", [])
        result = conds[-1].get("reason", "Unknown") if conds else "Unknown"

        start = task_status.get("startTime")
        end = task_status.get("completionTime")
        duration = None
        if start and end:
            try:
                from datetime import datetime

                s = datetime.fromisoformat(start.replace("Z", "+00:00"))
                e = datetime.fromisoformat(end.replace("Z", "+00:00"))
                duration = int((e - s).total_seconds())
            except Exception:
                pass

        tasks.append(
            {
                "name": task_run_name,
                "status": result,
                "start_time": start,
                "completion_time": end,
                "duration_seconds": duration,
            }
        )

    return tasks


async def _resolve_nudge_cascade(
    custom_api, namespace: str, snapshot_data: Dict, releases: List[Dict], logger=None
) -> List[Dict]:
    """Find downstream build PLRs triggered by component nudge after a release."""
    nudge_entries = []

    # Find the latest release completion time as the nudge start point
    latest_completion = None
    for release in releases:
        comp_time = release.get("completion_time")
        if comp_time:
            try:
                from datetime import datetime

                dt = datetime.fromisoformat(comp_time.replace("Z", "+00:00"))
                if latest_completion is None or dt > latest_completion:
                    latest_completion = dt
            except Exception:
                pass

    if not latest_completion:
        return nudge_entries

    try:
        # List recent PLRs in the same namespace
        plr_list = await k8s_call(custom_api.list_namespaced_custom_object,
            group="tekton.dev", version="v1", namespace=namespace, plural="pipelineruns", limit=50
        )

        for plr in plr_list.get("items", []):
            metadata = plr.get("metadata", {})
            annotations = metadata.get("annotations", {})
            labels = metadata.get("labels", {})
            created = metadata.get("creationTimestamp", "")

            # Check if this PLR was created after the release and is a nudge-triggered build
            sender = annotations.get("pipelinesascode.tekton.dev/sender", "")
            title = annotations.get("pipelinesascode.tekton.dev/sha-title", "")
            is_nudge = ("konflux" in sender.lower() or "red-hat-konflux" in sender.lower()) and (
                "chore(deps)" in title.lower() or "update" in title.lower()
            )

            if not is_nudge:
                continue

            # Check creation time is after the release
            try:
                from datetime import datetime

                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if created_dt <= latest_completion:
                    continue
            except Exception:
                continue

            component = labels.get("appstudio.openshift.io/component", "")
            status_conds = plr.get("status", {}).get("conditions", [])
            plr_status = status_conds[0].get("reason", "Unknown") if status_conds else "Unknown"

            nudge_entries.append(
                {
                    "plr_name": metadata.get("name", ""),
                    "component": component,
                    "status": plr_status,
                    "triggered_at": created,
                    "title": title[:100],
                    "sender": sender[:40],
                }
            )

    except Exception as e:
        if logger:
            logger.debug(f"Failed to resolve nudge cascade in {namespace}: {e}")

    return nudge_entries
