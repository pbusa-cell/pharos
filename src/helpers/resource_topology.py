# ============================================================================
# RESOURCE TOPOLOGY HELPER MODULE
# ============================================================================
#
# This module contains all resource topology related classes, functions, and utilities
# used by the MCP server for dependency analysis, topology mapping, multi-cluster
# coordination, and artifact tracking.
# ============================================================================

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from helpers.utils import calculate_context_tokens

# Guarded import so helpers.resource_topology is importable both at runtime
# (src/ on path) and in tooling contexts (repo root on path).
try:
    from core.readonly_client import ReadOnlyK8sClient
    from core.k8s_async import k8s_call
except ImportError:
    from src.core.readonly_client import ReadOnlyK8sClient
    from src.core.k8s_async import k8s_call

logger = logging.getLogger("lumino-mcp")


def _effective_replicas(deployment) -> int:
    """status.replicas, else spec.replicas, else the k8s default of 1."""
    status = getattr(deployment.status, "replicas", None)
    if status is not None:
        return status
    spec = getattr(deployment.spec, "replicas", None)
    return spec if spec is not None else 1


# ============================================================================
# MULTI-CLUSTER CLIENT MANAGEMENT
# ============================================================================


async def get_multi_cluster_clients(
    k8s_core_api, k8s_custom_api, k8s_apps_api
) -> Dict[str, Dict[str, Any]]:
    """Get authenticated clients for multiple clusters."""
    # For now, return the current cluster - extend this for actual multi-cluster setups
    # Read-only choke point: every pipeline_tracer consumer receives wrapped clients.
    return {
        "current": {
            "core_api": ReadOnlyK8sClient.wrap(k8s_core_api),
            "custom_api": ReadOnlyK8sClient.wrap(k8s_custom_api),
            "apps_api": ReadOnlyK8sClient.wrap(k8s_apps_api),
        }
    }


def get_pipeline_status(pipeline_run: Dict[str, Any]) -> str:
    """Extract pipeline status from PipelineRun."""
    conditions = pipeline_run.get("status", {}).get("conditions", [])
    if conditions:
        latest_condition = conditions[-1]
        if latest_condition.get("status") == "True":
            return latest_condition.get("reason", "Unknown")
        else:
            return latest_condition.get("reason", "Failed")
    return "Unknown"


def extract_task_info(pipeline_run: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract task information from PipelineRun status."""
    tasks = []
    task_runs = pipeline_run.get("status", {}).get("taskRuns", {})

    for task_run_name, task_run_status in task_runs.items():
        task_info = {
            "name": task_run_name,
            "status": task_run_status.get("status", {})
            .get("conditions", [{}])[-1]
            .get("reason", "Unknown"),
            "start_time": task_run_status.get("status", {}).get("startTime"),
            "completion_time": task_run_status.get("status", {}).get("completionTime"),
        }
        tasks.append(task_info)

    return tasks


def in_time_range(
    pipeline_info: Dict[str, Any], start_time: Optional[str], end_time: Optional[str]
) -> bool:
    """Check if pipeline execution falls within the specified time range."""
    if not start_time and not end_time:
        return True

    pipeline_start = pipeline_info.get("start_time")
    if not pipeline_start:
        return True

    try:
        pipeline_dt = datetime.fromisoformat(pipeline_start.replace("Z", "+00:00"))

        if start_time:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            if pipeline_dt < start_dt:
                return False

        if end_time:
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            if pipeline_dt > end_dt:
                return False

        return True
    except Exception:
        return True


# ============================================================================
# ARTIFACT TRACKING AND ANALYSIS
# ============================================================================


async def track_artifacts(
    pipeline_flow: List[Dict[str, Any]], include_artifacts: bool = True, logger=None
) -> List[Dict[str, Any]]:
    """Track artifacts through container registries and pipeline results."""
    if not include_artifacts:
        return []

    artifacts = []
    seen_artifacts = set()

    for pipeline in pipeline_flow:
        try:
            # Extract artifacts from pipeline results and parameters
            pipeline_artifacts = extract_pipeline_artifacts(pipeline)

            for artifact in pipeline_artifacts:
                artifact_id = artifact.get("artifact_id", "")
                if artifact_id and artifact_id not in seen_artifacts:
                    artifacts.append(artifact)
                    seen_artifacts.add(artifact_id)

        except Exception as e:
            if logger:
                logger.debug(
                    f"Failed to track artifacts for pipeline "
                    f"{pipeline.get('pipeline_name', '')}: {e}"
                )
            continue

    return artifacts


def extract_pipeline_artifacts(pipeline: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract artifact information from pipeline metadata."""
    artifacts = []

    # Look for image references in labels and annotations
    labels = pipeline.get("labels", {})
    annotations = pipeline.get("annotations", {})

    # Common patterns for artifact IDs
    potential_images = []

    # Check for common image label patterns
    for key, value in labels.items():
        if any(keyword in key.lower() for keyword in ["image", "container", "artifact"]):
            potential_images.append(value)

    for key, value in annotations.items():
        if any(keyword in key.lower() for keyword in ["image", "container", "artifact"]):
            potential_images.append(value)

    for image in potential_images:
        if image and ":" in image:  # Basic image validation
            artifacts.append(
                {
                    "artifact_id": image,
                    "type": "container_image",
                    "registry": image.split("/")[0] if "/" in image else "unknown",
                    "propagation_path": [
                        {
                            "cluster": pipeline["cluster"],
                            "namespace": pipeline["namespace"],
                            "pipeline": pipeline["pipeline_name"],
                            "timestamp": pipeline.get("start_time", ""),
                        }
                    ],
                }
            )

    return artifacts


# ============================================================================
# PERFORMANCE ANALYSIS AND BOTTLENECK DETECTION
# ============================================================================


def analyze_bottlenecks(pipeline_flow: List[Dict[str, Any]], logger=None) -> List[Dict[str, Any]]:
    """Analyze pipeline flow for bottlenecks and performance issues."""
    bottlenecks = []

    try:
        for i, pipeline in enumerate(pipeline_flow):
            start_time = pipeline.get("start_time")
            completion_time = pipeline.get("completion_time")

            if start_time and completion_time:
                try:
                    start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(completion_time.replace("Z", "+00:00"))
                    duration = (end_dt - start_dt).total_seconds()

                    # Flag pipelines that take unusually long (> 30 minutes)
                    if duration > 1800:
                        cluster = pipeline["cluster"]
                        ns = pipeline["namespace"]
                        pname = pipeline["pipeline_name"]
                        loc = f"{cluster}/{ns}/{pname}"
                        dur_min = duration / 60
                        bottlenecks.append(
                            {
                                "location": loc,
                                "type": "long_duration",
                                "duration": duration,
                                "description": (
                                    f"Pipeline execution took "
                                    f"{dur_min:.1f} minutes"
                                ),
                            }
                        )

                    # Check task-level bottlenecks
                    for task in pipeline.get("tasks", []):
                        task_start = task.get("start_time")
                        task_end = task.get("completion_time")

                        if task_start and task_end:
                            try:
                                task_start_dt = datetime.fromisoformat(
                                    task_start.replace("Z", "+00:00")
                                )
                                task_end_dt = datetime.fromisoformat(
                                    task_end.replace("Z", "+00:00")
                                )
                                task_duration = (task_end_dt - task_start_dt).total_seconds()

                                # Flag tasks that take more than 15 minutes
                                if task_duration > 900:
                                    cluster = pipeline["cluster"]
                                    ns = pipeline["namespace"]
                                    tname = task["name"]
                                    loc = f"{cluster}/{ns}/{tname}"
                                    td_min = task_duration / 60
                                    bottlenecks.append(
                                        {
                                            "location": loc,
                                            "type": "slow_task",
                                            "duration": task_duration,
                                            "description": (
                                                f"Task '{tname}' took "
                                                f"{td_min:.1f} minutes"
                                            ),
                                        }
                                    )
                            except Exception:
                                continue

                except Exception:
                    continue

        # Look for patterns across the flow
        if len(pipeline_flow) > 1:
            # Check for frequent failures
            failed_pipelines = [
                p for p in pipeline_flow if p.get("status", "").lower() in ["failed", "error"]
            ]
            if len(failed_pipelines) / len(pipeline_flow) > 0.3:
                bottlenecks.append(
                    {
                        "location": "cross_cluster",
                        "type": "high_failure_rate",
                        "description": (
                            f"High failure rate: "
                            f"{len(failed_pipelines)}/"
                            f"{len(pipeline_flow)} "
                            "pipelines failed"
                        ),
                    }
                )

    except Exception as e:
        if logger:
            logger.error(f"Error analyzing bottlenecks: {e}")

    return bottlenecks


# ============================================================================
# MACHINE CONFIG POOL ANALYSIS
# ============================================================================


def analyze_machine_config_pool_status(pool: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze machine config pool status and extract key information."""
    try:
        metadata = pool.get("metadata", {})
        spec = pool.get("spec", {})
        status = pool.get("status", {})

        # Extract basic information
        name = metadata.get("name", "unknown")
        machine_count = status.get("machineCount", 0)
        ready_machine_count = status.get("readyMachineCount", 0)
        updated_machine_count = status.get("updatedMachineCount", 0)
        degraded_machine_count = status.get("degradedMachineCount", 0)

        # Determine overall status
        if degraded_machine_count > 0:
            overall_status = "degraded"
        elif machine_count != ready_machine_count:
            overall_status = "updating"
        elif machine_count == ready_machine_count and ready_machine_count == updated_machine_count:
            overall_status = "ready"
        else:
            overall_status = "unknown"

        # Extract configuration information
        configuration = {
            "machine_config_selector": spec.get("machineConfigSelector", {}),
            "node_selector": spec.get("nodeSelector", {}),
            "paused": spec.get("paused", False),
            "max_unavailable": spec.get("maxUnavailable", "1"),
        }

        # Extract conditions
        conditions = status.get("conditions", [])

        # Calculate update progress
        if machine_count > 0:
            update_progress = {
                "total_machines": machine_count,
                "ready_machines": ready_machine_count,
                "updated_machines": updated_machine_count,
                "degraded_machines": degraded_machine_count,
                "progress_percentage": round((updated_machine_count / machine_count) * 100, 2)
                if machine_count > 0
                else 0,
                "is_updating": machine_count != updated_machine_count,
            }
        else:
            update_progress = {
                "total_machines": 0,
                "ready_machines": 0,
                "updated_machines": 0,
                "degraded_machines": 0,
                "progress_percentage": 0,
                "is_updating": False,
            }

        return {
            "name": name,
            "machine_count": machine_count,
            "ready_machine_count": ready_machine_count,
            "status": overall_status,
            "configuration": configuration,
            "conditions": conditions,
            "update_progress": update_progress,
            "node_status": [],  # Will be populated later if requested
        }

    except Exception as e:
        return {
            "name": pool.get("metadata", {}).get("name", "unknown"),
            "machine_count": 0,
            "ready_machine_count": 0,
            "status": "error",
            "configuration": {},
            "conditions": [],
            "update_progress": {},
            "node_status": [],
            "error": str(e),
        }


def detect_pool_issues(pool_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect issues in machine config pool analysis."""
    issues = []
    name = pool_analysis.get("name", "unknown")
    status = pool_analysis.get("status", "unknown")
    update_progress = pool_analysis.get("update_progress", {})
    conditions = pool_analysis.get("conditions", [])

    # Check for degraded status
    if status == "degraded":
        degraded_count = update_progress.get("degraded_machines", 0)
        issues.append(
            {
                "pool": name,
                "issue_type": "degraded_machines",
                "description": f"Pool has {degraded_count} degraded machine(s)",
                "affected_nodes": [],  # Would need node details to populate
                "severity": "high" if degraded_count > 1 else "medium",
                "remediation": "Check individual node status and machine config application logs",
            }
        )

    # Check for stuck updates
    if update_progress.get("is_updating", False):
        progress_pct = update_progress.get("progress_percentage", 0)
        if progress_pct < 100:
            issues.append(
                {
                    "pool": name,
                    "issue_type": "update_in_progress",
                    "description": f"Update in progress: {progress_pct}% complete",
                    "affected_nodes": [],
                    "severity": "low",
                    "remediation": "Monitor update progress and check for any stuck nodes",
                }
            )

    # Check conditions for specific issues
    for condition in conditions:
        condition_type = condition.get("type", "")
        condition_status = condition.get("status", "")
        condition_reason = condition.get("reason", "")
        condition_message = condition.get("message", "")

        if condition_type == "NodeDegraded" and condition_status == "True":
            issues.append(
                {
                    "pool": name,
                    "issue_type": "node_degraded",
                    "description": f"Node degraded: {condition_message}",
                    "affected_nodes": [],
                    "severity": "high",
                    "remediation": f"Investigate degraded condition: {condition_reason}",
                }
            )
        elif condition_type == "RenderDegraded" and condition_status == "True":
            issues.append(
                {
                    "pool": name,
                    "issue_type": "render_degraded",
                    "description": f"Configuration rendering failed: {condition_message}",
                    "affected_nodes": [],
                    "severity": "high",
                    "remediation": "Check machine config rendering and template validation",
                }
            )

    return issues


def generate_update_recommendations(pools_analysis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate update recommendations based on pool analysis."""
    recommendations = []

    for pool in pools_analysis:
        name = pool.get("name", "unknown")
        status = pool.get("status", "unknown")
        update_progress = pool.get("update_progress", {})
        configuration = pool.get("configuration", {})

        # Recommendation for degraded pools
        if status == "degraded":
            recommendations.append(
                {
                    "pool": name,
                    "recommendation": "Investigate and resolve degraded machines immediately",
                    "reasoning": (
                        "Degraded machines can impact cluster "
                        "stability and workload scheduling"
                    ),
                    "urgency": "high",
                }
            )

        # Recommendation for paused pools
        if configuration.get("paused", False):
            recommendations.append(
                {
                    "pool": name,
                    "recommendation": "Review paused pool status and resume updates if appropriate",
                    "reasoning": "Paused pools may miss critical security and stability updates",
                    "urgency": "medium",
                }
            )

        # Recommendation for stuck updates
        if update_progress.get("is_updating", False):
            progress_pct = update_progress.get("progress_percentage", 0)
            if progress_pct > 0 and progress_pct < 100:
                recommendations.append(
                    {
                        "pool": name,
                        "recommendation": "Monitor update progress and check for stuck nodes",
                        "reasoning": (
                            f"Update is {progress_pct}% complete "
                            "but may require intervention"
                        ),
                        "urgency": "low",
                    }
                )

    return recommendations


# ============================================================================
# OPERATOR ANALYSIS
# ============================================================================


def analyze_operator_dependencies(operators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze operator dependencies and relationships."""
    dependencies = []

    # Common OpenShift operator dependency mappings
    operator_deps = {
        "authentication": ["oauth-openshift", "openshift-apiserver"],
        "console": ["authentication", "oauth-openshift"],
        "monitoring": ["prometheus-operator"],
        "ingress": ["dns"],
        "image-registry": ["storage"],
        "openshift-apiserver": ["etcd", "kube-apiserver-operator"],
        "openshift-controller-manager": ["openshift-apiserver"],
        "machine-api": ["cluster-autoscaler-operator"],
        "cluster-autoscaler-operator": ["machine-api"],
    }

    operator_names = {op.get("name", "") for op in operators}

    for operator in operators:
        op_name = operator.get("name", "")
        deps_list = operator_deps.get(op_name, [])

        # Filter dependencies to only include those present in cluster
        existing_deps = [dep for dep in deps_list if dep in operator_names]

        if existing_deps:
            # Check dependency status
            dep_status = "healthy"
            for dep in existing_deps:
                dep_operator = next((op for op in operators if op.get("name") == dep), None)
                if dep_operator:
                    conditions = dep_operator.get("conditions", [])
                    for condition in conditions:
                        if (
                            condition.get("type") in ["Degraded", "Available"]
                            and condition.get("status") != "True"
                        ):
                            dep_status = "unhealthy"
                            break

            dependencies.append(
                {"operator": op_name, "depends_on": existing_deps, "dependency_status": dep_status}
            )

    return dependencies


def identify_critical_issues(operators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify critical issues requiring immediate attention."""
    critical_issues = []

    for operator in operators:
        op_name = operator.get("name", "")
        # Simple health assessment based on conditions
        conditions_analysis = operator.get("conditions_analysis", {})
        critical_conditions = conditions_analysis.get("critical_conditions", [])
        warning_conditions = conditions_analysis.get("warning_conditions", [])

        # Determine health status
        if critical_conditions:
            health = "critical"
        elif warning_conditions:
            health = "warning"
        else:
            health = "healthy"

        if health == "critical":
            for cond in critical_conditions:
                critical_issues.append(
                    {
                        "operator": op_name,
                        "severity": "critical",
                        "issue": cond.get("message", "Operator is degraded"),
                        "impact": (
                            f"Operator {op_name} failure may "
                            "affect cluster functionality"
                        ),
                        "recommended_action": (
                            f"Investigate and resolve {op_name} "
                            "operator issues immediately"
                        ),
                    }
                )
        elif health == "warning":
            for cond in warning_conditions:
                critical_issues.append(
                    {
                        "operator": op_name,
                        "severity": "warning",
                        "issue": cond.get("message", "Operator is not available"),
                        "impact": (
                            f"Operator {op_name} availability "
                            "issues may affect functionality"
                        ),
                        "recommended_action": (
                            f"Monitor and investigate {op_name} "
                            "operator availability"
                        ),
                    }
                )

    return critical_issues


def analyze_operator_conditions(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze operator conditions to determine health status."""
    condition_summary = {
        "available": False,
        "progressing": False,
        "degraded": False,
        "critical_conditions": [],
        "warning_conditions": [],
        "healthy_conditions": [],
    }

    for condition in conditions:
        condition_type = condition.get("type", "")
        status = condition.get("status", "Unknown")
        message = condition.get("message", "")
        reason = condition.get("reason", "")

        if condition_type == "Available":
            condition_summary["available"] = status == "True"
        elif condition_type == "Progressing":
            condition_summary["progressing"] = status == "True"
        elif condition_type == "Degraded":
            condition_summary["degraded"] = status == "True"

        # Categorize conditions by severity
        if status == "True" and condition_type in ["Degraded", "Failed"]:
            condition_summary["critical_conditions"].append(
                {"type": condition_type, "message": message, "reason": reason}
            )
        elif status == "Unknown" or (status == "False" and condition_type in ["Available"]):
            condition_summary["warning_conditions"].append(
                {"type": condition_type, "message": message, "reason": reason}
            )
        else:
            condition_summary["healthy_conditions"].append(
                {"type": condition_type, "status": status}
            )

    return condition_summary


# ============================================================================
# TOPOLOGY MAPPING UTILITIES
# ============================================================================


async def get_multi_cluster_topology_clients(
    k8s_core_api, k8s_custom_api, k8s_apps_api, k8s_storage_api, k8s_batch_api
) -> Dict[str, Dict[str, Any]]:
    """Get authenticated clients for multiple clusters for topology mapping."""
    # For now, return the current cluster - extend this for actual multi-cluster setups
    # Read-only choke point: every topology consumer receives wrapped clients.
    return {
        "current": {
            "core_api": ReadOnlyK8sClient.wrap(k8s_core_api),
            "custom_api": ReadOnlyK8sClient.wrap(k8s_custom_api),
            "apps_api": ReadOnlyK8sClient.wrap(k8s_apps_api),
            "storage_api": ReadOnlyK8sClient.wrap(k8s_storage_api),
            "batch_api": ReadOnlyK8sClient.wrap(k8s_batch_api),
        }
    }


def generate_node_id(cluster: str, namespace: str, resource_type: str, name: str) -> str:
    """Generate a unique node ID for the topology graph."""
    return f"{cluster}:{namespace}:{resource_type}:{name}"


def calculate_dependency_weight(source_type: str, target_type: str, relationship: str) -> float:
    """Calculate dependency weight based on relationship criticality."""
    weight_matrix = {
        ("deployment", "service"): 0.9,
        ("deployment", "configmap"): 0.7,
        ("deployment", "secret"): 0.8,
        ("deployment", "persistentvolumeclaim"): 0.6,
        ("service", "pod"): 0.9,
        ("pipelinerun", "pipeline"): 0.9,
        ("taskrun", "task"): 0.8,
        ("pod", "node"): 0.5,
        ("pod", "persistentvolumeclaim"): 0.6,
    }

    key = (source_type.lower(), target_type.lower())
    return weight_matrix.get(key, 0.5)


async def get_resource_metrics(
    cluster_name: str, resource_type: str, namespace: str, name: str, logger
) -> Dict[str, Any]:
    """Return a placeholder metrics shape for a resource.

    No metrics backend is wired; this function queries nothing and cannot determine
    actual CPU usage, memory usage, or running status. All three measurement fields
    are set to None. Consumers must check ``data_source`` before treating any value
    as live data — when ``data_source == "unavailable"`` the numeric fields carry no
    information and must not be compared against thresholds.

    Note: ``logger`` is accepted for API compatibility with call sites but is unused
    here (the dead try/except that logged errors was removed with F-28). It is a
    follow-up candidate for removal once call sites are updated.
    """
    return {
        "cpu_usage": None,
        "memory_usage": None,
        "status": None,
        "last_updated": datetime.now().isoformat(),
        "data_source": "unavailable",
    }


async def analyze_owner_references(
    resource: Dict[str, Any], cluster: str, resource_type: str
) -> List[Dict[str, str]]:
    """Analyze Kubernetes OwnerReferences to find parent-child relationships.

    Args:
        resource: Resource dict from Kubernetes API
        cluster: Cluster name
        resource_type: The type of the resource (e.g., 'pod', 'deployment', 'replicaset')
                      Required because .to_dict() doesn't include 'kind' field.
    """
    edges = []
    owner_refs = resource.get("metadata", {}).get("owner_references", [])

    # Also check camelCase version (raw API response vs client model)
    if not owner_refs:
        owner_refs = resource.get("metadata", {}).get("ownerReferences", [])

    for owner in owner_refs:
        owner_kind = owner.get("kind", "").lower()
        owner_name = owner.get("name", "")

        # Skip if owner info is missing
        if not owner_kind or not owner_name:
            continue

        source_id = generate_node_id(
            cluster,
            resource.get("metadata", {}).get("namespace", "default"),
            owner_kind,
            owner_name,
        )
        target_id = generate_node_id(
            cluster,
            resource.get("metadata", {}).get("namespace", "default"),
            resource_type,
            resource.get("metadata", {}).get("name", ""),
        )

        edges.append(
            {
                "source": source_id,
                "target": target_id,
                "relationship": "owns",
                "weight": calculate_dependency_weight(owner_kind, resource_type, "owns"),
            }
        )

    return edges


async def analyze_service_dependencies(
    service: Dict[str, Any], cluster: str, core_api, logger, pods_list=None
) -> List[Dict[str, str]]:
    """Analyze service selector relationships to pods.

    Args:
        service: Service resource dict
        cluster: Cluster name
        core_api: Kubernetes CoreV1Api client
        logger: Logger instance
        pods_list: Optional pre-fetched list of pods to avoid N+1 queries.
                   If None, will fetch pods from API (legacy behavior).
    """
    edges = []
    try:
        selector = service.get("spec", {}).get("selector", {})
        namespace = service.get("metadata", {}).get("namespace", "default")

        if not selector:
            return edges

        # Use pre-fetched pods if available, otherwise fetch (legacy fallback)
        if pods_list is not None:
            pods_items = pods_list
        else:
            pods = await k8s_call(core_api.list_namespaced_pod, namespace=namespace)
            pods_items = pods.items

        for pod in pods_items:
            pod_labels = pod.metadata.labels or {}

            # Check if all selector labels match pod labels
            if all(pod_labels.get(key) == value for key, value in selector.items()):
                service_id = generate_node_id(
                    cluster, namespace, "service", service.get("metadata", {}).get("name", "")
                )
                pod_id = generate_node_id(cluster, namespace, "pod", pod.metadata.name)

                edges.append(
                    {
                        "source": service_id,
                        "target": pod_id,
                        "relationship": "routes_to",
                        "weight": calculate_dependency_weight("service", "pod", "routes_to"),
                    }
                )

    except Exception as e:
        logger.debug(f"Error analyzing service dependencies: {e}")

    return edges


async def analyze_volume_dependencies(
    resource: Dict[str, Any], cluster: str, resource_type: str, logger
) -> List[Dict[str, str]]:
    """Analyze volume mount dependencies.

    Args:
        resource: Resource dict from Kubernetes API
        cluster: Cluster name
        resource_type: The type of the resource (e.g., 'pod', 'deployment')
                      Required because .to_dict() doesn't include 'kind' field.
        logger: Logger instance
    """
    edges = []
    try:
        spec = resource.get("spec", {})
        namespace = resource.get("metadata", {}).get("namespace", "default")
        resource_name = resource.get("metadata", {}).get("name", "")

        # Get volumes - handle different resource types
        # For Pods: spec.volumes
        # For Deployments/StatefulSets/etc: spec.template.spec.volumes
        volumes = spec.get("volumes", [])
        if not volumes and "template" in spec:
            template_spec = spec.get("template", {}).get("spec", {})
            volumes = template_spec.get("volumes", [])

        for volume in volumes:
            source_id = generate_node_id(cluster, namespace, resource_type, resource_name)
            volume.get("name", "")

            # Check for PVC references (handle both camelCase and snake_case)
            pvc_ref = volume.get("persistentVolumeClaim") or volume.get("persistent_volume_claim")
            if pvc_ref:
                pvc_name = pvc_ref.get("claimName") or pvc_ref.get("claim_name", "")
                if pvc_name:
                    target_id = generate_node_id(
                        cluster, namespace, "persistentvolumeclaim", pvc_name
                    )
                    edges.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "relationship": "mounts",
                            "weight": calculate_dependency_weight(
                                resource_type, "persistentvolumeclaim", "mounts"
                            ),
                        }
                    )

            # Check for ConfigMap references (handle both camelCase and snake_case)
            cm_ref = volume.get("configMap") or volume.get("config_map")
            if cm_ref:
                cm_name = cm_ref.get("name", "")
                if cm_name:
                    target_id = generate_node_id(cluster, namespace, "configmap", cm_name)
                    edges.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "relationship": "mounts",
                            "weight": calculate_dependency_weight(
                                resource_type, "configmap", "mounts"
                            ),
                        }
                    )

            # Check for Secret references
            secret_ref = volume.get("secret")
            if secret_ref:
                secret_name = secret_ref.get("secretName") or secret_ref.get("secret_name", "")
                if secret_name:
                    target_id = generate_node_id(cluster, namespace, "secret", secret_name)
                    edges.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "relationship": "mounts",
                            "weight": calculate_dependency_weight(
                                resource_type, "secret", "mounts"
                            ),
                        }
                    )

            # Check for projected volumes (can include ConfigMaps and Secrets)
            projected = volume.get("projected")
            if projected:
                for source in projected.get("sources", []):
                    if "configMap" in source or "config_map" in source:
                        cm_src = source.get("configMap") or source.get("config_map", {})
                        cm_name = cm_src.get("name", "")
                        if cm_name:
                            target_id = generate_node_id(cluster, namespace, "configmap", cm_name)
                            edges.append(
                                {
                                    "source": source_id,
                                    "target": target_id,
                                    "relationship": "mounts",
                                    "weight": calculate_dependency_weight(
                                        resource_type, "configmap", "mounts"
                                    ),
                                }
                            )
                    if "secret" in source:
                        secret_src = source.get("secret", {})
                        secret_name = secret_src.get("name", "")
                        if secret_name:
                            target_id = generate_node_id(cluster, namespace, "secret", secret_name)
                            edges.append(
                                {
                                    "source": source_id,
                                    "target": target_id,
                                    "relationship": "mounts",
                                    "weight": calculate_dependency_weight(
                                        resource_type, "secret", "mounts"
                                    ),
                                }
                            )

    except Exception as e:
        logger.debug(f"Error analyzing volume dependencies: {e}")

    return edges


# ============================================================================
# SIMULATION AFFECTED COMPONENTS ANALYSIS
# ============================================================================


# ============================================================================
# PERMISSION-AWARE RESOURCE FETCHING
# ============================================================================


def handle_resource_fetch_error(
    e: Exception, resource_type: str, namespace: str, skip_on_permission_denied: bool, logger
) -> Dict[str, Any]:
    """
    Handle errors during resource fetching with permission-aware logic.

    Returns:
        Dict with 'success', 'permission_denied', 'error_message' keys
    """
    from kubernetes.client.rest import ApiException

    result = {"success": False, "permission_denied": False, "error_message": str(e)}

    if isinstance(e, ApiException):
        if e.status == 403:
            # Permission denied
            result["permission_denied"] = True
            logger.info(
                f"Permission denied for {resource_type} in namespace {namespace} (403 Forbidden)"
            )

            if skip_on_permission_denied:
                logger.debug(
                    f"Skipping {resource_type} due to "
                    "permission denied "
                    "(skip_on_permission_denied=True)"
                )
            else:
                logger.warning(f"Permission denied for {resource_type} in namespace {namespace}")
        elif e.status == 404:
            # Resource type not found (e.g., Tekton not installed)
            logger.debug(f"Resource type {resource_type} not found in namespace {namespace} (404)")
        else:
            # Other API error
            logger.warning(
                f"API error fetching {resource_type} in "
                f"namespace {namespace}: {e.status} - {e.reason}"
            )
    else:
        # Non-API exception
        logger.error(f"Unexpected error fetching {resource_type} in namespace {namespace}: {e}")

    return result


async def identify_affected_components(
    changes: Dict[str, Any],
    scope: Dict[str, Any],
    scenario_type: str,
    k8s_core_api,
    k8s_apps_api,
    list_pods,
    list_namespaces,
) -> List[Dict[str, Any]]:
    """Identify components that will be affected by the proposed changes."""
    from kubernetes.client.rest import ApiException

    try:
        k8s_core_api = ReadOnlyK8sClient.wrap(k8s_core_api)
        k8s_apps_api = ReadOnlyK8sClient.wrap(k8s_apps_api)
        affected_components = []

        # Get namespaces in scope
        if scope.get("namespaces") == ["all"]:
            namespaces = await list_namespaces()
        else:
            namespaces = scope.get("namespaces", [])

        # Analyze components in each namespace
        for namespace in namespaces[:5]:  # Limit to prevent timeout
            try:
                if scenario_type == "scaling":
                    # Identify deployments that could be affected by scaling changes
                    # Off-loop + bounded (final fix wave, I-1): this call was
                    # synchronous and unbounded, blocking the event loop on a
                    # degraded API path with no cap on payload size.
                    deployments = await k8s_call(
                        k8s_apps_api.list_namespaced_deployment, namespace,
                        limit=200, timeout=30)
                    for deployment in deployments.items:
                        component_info = {
                            "component": f"deployment/{deployment.metadata.name}",
                            "namespace": namespace,
                            "impact_type": "scaling",
                            "severity": "medium",
                            "details": f"Deployment with {_effective_replicas(deployment)} replicas",
                        }

                        # Check if this deployment matches any change criteria
                        for change_key, change_value in changes.items():
                            if change_key.lower() in deployment.metadata.name.lower():
                                component_info["severity"] = "high"
                                component_info["details"] += (
                                    f" - directly affected by {change_key} changes"
                                )
                                break

                        affected_components.append(component_info)

                elif scenario_type == "resource_limits":
                    # Identify pods/containers that could be affected by resource limit changes
                    # list_pods requires (namespace, k8s_core_api, logger)
                    # field_selector="status.phase=Running": only running pods can be
                    # affected by a resource limit change going forward, and this
                    # collapses the payload on namespaces with many completed pods
                    # (live finding 2026-08-20, rhtap-releng-tenant).
                    pods = await list_pods(
                        namespace, k8s_core_api, logger,
                        field_selector="status.phase=Running")
                    if any("_truncation" in p for p in pods):
                        logger.warning(
                            f"pod list for {namespace} truncated at limit; analysis covers a sample")
                    pods = [p for p in pods if "_truncation" not in p]
                    for pod in pods[:10]:  # Limit pods to prevent timeout
                        if not pod.get("error"):
                            component_info = {
                                "component": f"pod/{pod['name']}",
                                "namespace": namespace,
                                "impact_type": "resource_limits",
                                "severity": "medium",
                                "details": f"Pod with {len(pod.get('containers', []))} containers",
                            }

                            # Check for resource-constrained containers
                            containers = pod.get("containers", [])
                            constrained_containers = 0
                            for container in containers:
                                if container.get("state") in ["Waiting", "Terminated"]:
                                    constrained_containers += 1

                            if constrained_containers > 0:
                                component_info["severity"] = "high"
                                component_info["details"] += (
                                    f" - {constrained_containers} "
                                    "containers show resource "
                                    "constraints"
                                )

                            affected_components.append(component_info)

                elif scenario_type in ["configuration", "deployment"]:
                    # Identify services and deployments that could be affected
                    # Off-loop + bounded (final fix wave, I-1): same treatment
                    # as the scaling branch above — synchronous, unbounded,
                    # on-loop call had no cap and no client-side timeout.
                    services = await k8s_call(
                        k8s_core_api.list_namespaced_service, namespace,
                        limit=200, timeout=30)
                    for service in services.items:
                        component_info = {
                            "component": f"service/{service.metadata.name}",
                            "namespace": namespace,
                            "impact_type": scenario_type,
                            "severity": "low",
                            "details": f"Service with {len(service.spec.ports or [])} ports",
                        }

                        # Higher severity for services with many endpoints
                        if service.spec.ports and len(service.spec.ports) > 3:
                            component_info["severity"] = "medium"

                        affected_components.append(component_info)

            except Exception as e:
                # Broadened from ApiException (final fix wave, I-3): a
                # urllib3 ReadTimeoutError/MaxRetryError on a degraded link
                # is not an ApiException and used to escape this handler,
                # hitting the outer except below and replacing results for
                # ALL namespaces with a single opaque error stub. Catching
                # broadly here contains the failure to this namespace and
                # keeps processing the rest, while still surfacing the
                # failure in the returned components list.
                logger.warning(f"Error analyzing components in namespace {namespace}: {e}")
                affected_components.append(
                    {
                        "component": f"namespace/{namespace}",
                        "impact_type": "collection_error",
                        "severity": "unknown",
                        "details": str(e),
                    }
                )
                continue

        # Limit the number of components returned
        return affected_components[:20]

    except Exception as e:
        logger.error(f"Error identifying affected components: {e}")
        return [
            {
                "component": "unknown",
                "impact_type": "error",
                "severity": "unknown",
                "details": str(e),
            }
        ]


# ============================================================================
# TOPOLOGY OUTPUT FORMAT CONVERTERS
# ============================================================================


def convert_to_graphviz(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Convert topology to Graphviz DOT format."""
    dot = ["digraph topology {"]
    dot.append("  rankdir=LR;")
    dot.append("  node [shape=box];")

    # Add nodes with labels
    for node in nodes:
        node_type = node.get("type", "unknown")
        name = node.get("name", "unknown")
        namespace = node.get("namespace", "default")
        label = f"{namespace}\\n{name}\\n({node_type})"
        dot.append(f'  "{node["id"]}" [label="{label}"];')

    # Add edges
    for edge in edges:
        relationship = edge.get("relationship", "")
        dot.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{relationship}"];')

    dot.append("}")
    return "\n".join(dot)


def convert_to_mermaid(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Convert topology to Mermaid diagram format."""
    mermaid = ["graph LR"]

    # Add nodes
    for node in nodes:
        node_type = node.get("type", "unknown")
        name = node.get("name", "unknown")
        label = f"{name}<br/>({node_type})"
        # Sanitize node ID for mermaid
        node_id = node["id"].replace(":", "_").replace("/", "_")
        mermaid.append(f'  {node_id}["{label}"]')

    # Add edges
    for edge in edges:
        source_id = edge["source"].replace(":", "_").replace("/", "_")
        target_id = edge["target"].replace(":", "_").replace("/", "_")
        relationship = edge.get("relationship", "")
        mermaid.append(f"  {source_id} -->|{relationship}| {target_id}")

    return "\n".join(mermaid)


async def _process_namespace_topology(
    namespace: str,
    cluster_name: str,
    component_types: List[str],
    core_api,
    apps_api,
    custom_api,
    include_metrics: bool,
    skip_on_permission_denied: bool,
    logger
) -> Dict[str, Any]:
    """Process a single namespace and return its topology data."""
    nodes = []
    edges = []
    permissions = {"accessible": [], "denied": [], "errors": []}
    stats = {"nodes": 0, "edges": 0}

    # Pre-fetch pods once to avoid N+1 queries in analyze_service_dependencies
    pods_list = None
    if "pods" in component_types or "services" in component_types:
        try:
            pods_result = await k8s_call(core_api.list_namespaced_pod, namespace=namespace)
            pods_list = pods_result.items
        except Exception as e:
            logger.debug(f"Could not pre-fetch pods for {namespace}: {e}")

    try:
        # Process Deployments
        if "deployments" in component_types:
            try:
                deployments = await k8s_call(apps_api.list_namespaced_deployment, namespace=namespace)
                permissions["accessible"].append(f"{cluster_name}/{namespace}/deployments")

                for deployment in deployments.items:
                    node_id = generate_node_id(cluster_name, namespace, "deployment", deployment.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "deployment",
                        "name": deployment.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": deployment.status.conditions[-1].type if deployment.status.conditions else "Unknown",
                        "metadata": {
                            "replicas": deployment.spec.replicas or 0,
                            "ready_replicas": deployment.status.ready_replicas or 0,
                            "labels": deployment.metadata.labels or {}
                        }
                    }

                    if include_metrics:
                        node["metrics"] = await get_resource_metrics(cluster_name, "deployment", namespace, deployment.metadata.name, logger)

                    nodes.append(node)
                    stats["nodes"] += 1

                    # Analyze dependencies
                    deployment_dict = deployment.to_dict()
                    owner_edges = await analyze_owner_references(deployment_dict, cluster_name, "deployment")
                    volume_edges = await analyze_volume_dependencies(deployment_dict, cluster_name, "deployment", logger)
                    edges.extend(owner_edges + volume_edges)
                    stats["edges"] += len(owner_edges + volume_edges)

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "deployments", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/deployments")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/deployments",
                        "error": error_info["error_message"]
                    })

        # Process ReplicaSets (needed for complete Deployment→ReplicaSet→Pod ownership chain)
        if "replicasets" in component_types:
            try:
                replicasets = await k8s_call(apps_api.list_namespaced_replica_set, namespace=namespace)
                permissions["accessible"].append(f"{cluster_name}/{namespace}/replicasets")

                for replicaset in replicasets.items:
                    node_id = generate_node_id(cluster_name, namespace, "replicaset", replicaset.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "replicaset",
                        "name": replicaset.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": "Active" if (replicaset.status.ready_replicas or 0) > 0 else "Inactive",
                        "metadata": {
                            "replicas": replicaset.spec.replicas or 0,
                            "ready_replicas": replicaset.status.ready_replicas or 0,
                            "labels": replicaset.metadata.labels or {}
                        }
                    }

                    if include_metrics:
                        node["metrics"] = await get_resource_metrics(cluster_name, "replicaset", namespace, replicaset.metadata.name, logger)

                    nodes.append(node)
                    stats["nodes"] += 1

                    # Analyze dependencies (ReplicaSet→Deployment ownership)
                    replicaset_dict = replicaset.to_dict()
                    owner_edges = await analyze_owner_references(replicaset_dict, cluster_name, "replicaset")
                    edges.extend(owner_edges)
                    stats["edges"] += len(owner_edges)

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "replicasets", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/replicasets")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/replicasets",
                        "error": error_info["error_message"]
                    })

        # Process Services
        if "services" in component_types:
            try:
                services = await k8s_call(core_api.list_namespaced_service, namespace=namespace)
                permissions["accessible"].append(f"{cluster_name}/{namespace}/services")

                for service in services.items:
                    node_id = generate_node_id(cluster_name, namespace, "service", service.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "service",
                        "name": service.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": "Active",
                        "metadata": {
                            "type": service.spec.type,
                            "cluster_ip": service.spec.cluster_ip,
                            "ports": [{"port": p.port, "target_port": p.target_port} for p in (service.spec.ports or [])],
                            "selector": service.spec.selector or {}
                        }
                    }

                    if include_metrics:
                        node["metrics"] = await get_resource_metrics(cluster_name, "service", namespace, service.metadata.name, logger)

                    nodes.append(node)
                    stats["nodes"] += 1

                    # Analyze service dependencies (pass pre-fetched pods to avoid N+1 queries)
                    service_dict = service.to_dict()
                    service_edges = await analyze_service_dependencies(service_dict, cluster_name, core_api, logger, pods_list=pods_list)
                    edges.extend(service_edges)
                    stats["edges"] += len(service_edges)

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "services", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/services")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/services",
                        "error": error_info["error_message"]
                    })

        # Process Pods (use pre-fetched pods_list if available)
        if "pods" in component_types:
            try:
                # Use pre-fetched pods if available, otherwise fetch
                if pods_list is not None:
                    pods_items = pods_list
                else:
                    pods_result = await k8s_call(core_api.list_namespaced_pod, namespace=namespace)
                    pods_items = pods_result.items
                for pod in pods_items:
                    node_id = generate_node_id(cluster_name, namespace, "pod", pod.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "pod",
                        "name": pod.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": pod.status.phase or "Unknown",
                        "metadata": {
                            "node_name": pod.spec.node_name,
                            "labels": pod.metadata.labels or {},
                            "containers": len(pod.spec.containers or [])
                        }
                    }

                    if include_metrics:
                        node["metrics"] = await get_resource_metrics(cluster_name, "pod", namespace, pod.metadata.name, logger)

                    nodes.append(node)
                    stats["nodes"] += 1

                    # Analyze pod dependencies
                    pod_dict = pod.to_dict()
                    owner_edges = await analyze_owner_references(pod_dict, cluster_name, "pod")
                    volume_edges = await analyze_volume_dependencies(pod_dict, cluster_name, "pod", logger)
                    edges.extend(owner_edges + volume_edges)
                    stats["edges"] += len(owner_edges + volume_edges)

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "pods", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/pods")
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/pods",
                        "error": error_info["error_message"]
                    })

        # Process PVCs
        if "persistentvolumeclaims" in component_types:
            try:
                pvcs = await k8s_call(core_api.list_namespaced_persistent_volume_claim, namespace=namespace)
                for pvc in pvcs.items:
                    node_id = generate_node_id(cluster_name, namespace, "persistentvolumeclaim", pvc.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "persistentvolumeclaim",
                        "name": pvc.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": pvc.status.phase or "Unknown",
                        "metadata": {
                            "capacity": pvc.status.capacity.get("storage") if pvc.status.capacity else None,
                            "access_modes": pvc.spec.access_modes or [],
                            "storage_class": pvc.spec.storage_class_name
                        }
                    }

                    if include_metrics:
                        node["metrics"] = await get_resource_metrics(cluster_name, "persistentvolumeclaim", namespace, pvc.metadata.name, logger)

                    nodes.append(node)
                    stats["nodes"] += 1

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "persistentvolumeclaims", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/persistentvolumeclaims")
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/persistentvolumeclaims",
                        "error": error_info["error_message"]
                    })

        # Process ConfigMaps
        if "configmaps" in component_types:
            try:
                configmaps = await k8s_call(core_api.list_namespaced_config_map, namespace=namespace)
                permissions["accessible"].append(f"{cluster_name}/{namespace}/configmaps")

                for cm in configmaps.items:
                    node_id = generate_node_id(cluster_name, namespace, "configmap", cm.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "configmap",
                        "name": cm.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": "Active",
                        "metadata": {
                            "data_keys": list(cm.data.keys()) if cm.data else []
                        }
                    }

                    nodes.append(node)
                    stats["nodes"] += 1

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "configmaps", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/configmaps")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/configmaps",
                        "error": error_info["error_message"]
                    })

        # Process Secrets (NOT included in defaults due to common RBAC restrictions)
        if "secrets" in component_types:
            try:
                secrets = await k8s_call(core_api.list_namespaced_secret, namespace=namespace)
                permissions["accessible"].append(f"{cluster_name}/{namespace}/secrets")

                for secret in secrets.items:
                    node_id = generate_node_id(cluster_name, namespace, "secret", secret.metadata.name)

                    node = {
                        "id": node_id,
                        "type": "secret",
                        "name": secret.metadata.name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": "Active",
                        "metadata": {
                            "type": secret.type,
                            "data_keys": list(secret.data.keys()) if secret.data else []
                        }
                    }

                    nodes.append(node)
                    stats["nodes"] += 1

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "secrets", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/secrets")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/secrets",
                        "error": error_info["error_message"]
                    })

        # Process Tekton PipelineRuns
        if "pipelineruns" in component_types:
            try:
                pipeline_runs = await k8s_call(
                    custom_api.list_namespaced_custom_object,
                    group="tekton.dev",
                    version="v1",
                    namespace=namespace,
                    plural="pipelineruns",
                    limit=200
                )

                for pr in pipeline_runs.get("items", []):
                    node_id = generate_node_id(cluster_name, namespace, "pipelinerun", pr.get("metadata", {}).get("name", ""))

                    node = {
                        "id": node_id,
                        "type": "pipelinerun",
                        "name": pr.get("metadata", {}).get("name", ""),
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": pr.get("status", {}).get("conditions", [{}])[-1].get("type", "Unknown"),
                        "metadata": {
                            "pipeline_ref": pr.get("spec", {}).get("pipelineRef", {}).get("name", ""),
                            "labels": pr.get("metadata", {}).get("labels", {})
                        }
                    }

                    if include_metrics:
                        node["metrics"] = await get_resource_metrics(cluster_name, "pipelinerun", namespace, node["name"], logger)

                    nodes.append(node)
                    stats["nodes"] += 1

                    # Create edge to pipeline if referenced
                    pipeline_ref = pr.get("spec", {}).get("pipelineRef", {}).get("name")
                    if pipeline_ref:
                        pipeline_id = generate_node_id(cluster_name, namespace, "pipeline", pipeline_ref)
                        edges.append({
                            "source": node_id,
                            "target": pipeline_id,
                            "relationship": "runs",
                            "weight": calculate_dependency_weight("pipelinerun", "pipeline", "runs")
                        })
                        stats["edges"] += 1

            except Exception as e:
                logger.debug(f"Could not fetch PipelineRuns in {namespace}: {e}")

        # Process Tekton Pipelines
        if "pipelines" in component_types:
            try:
                pipelines = await k8s_call(
                    custom_api.list_namespaced_custom_object,
                    group="tekton.dev",
                    version="v1",
                    namespace=namespace,
                    plural="pipelines"
                )

                for pipeline in pipelines.get("items", []):
                    node_id = generate_node_id(cluster_name, namespace, "pipeline", pipeline.get("metadata", {}).get("name", ""))

                    node = {
                        "id": node_id,
                        "type": "pipeline",
                        "name": pipeline.get("metadata", {}).get("name", ""),
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": "Active",
                        "metadata": {
                            "tasks": len(pipeline.get("spec", {}).get("tasks", [])),
                            "labels": pipeline.get("metadata", {}).get("labels", {})
                        }
                    }

                    nodes.append(node)
                    stats["nodes"] += 1

            except Exception as e:
                logger.debug(f"Could not fetch Pipelines in {namespace}: {e}")

        # Process Tekton TaskRuns
        if "taskruns" in component_types:
            try:
                task_runs = await k8s_call(
                    custom_api.list_namespaced_custom_object,
                    group="tekton.dev",
                    version="v1",
                    namespace=namespace,
                    plural="taskruns",
                    limit=500
                )
                permissions["accessible"].append(f"{cluster_name}/{namespace}/taskruns")

                for tr in task_runs.get("items", []):
                    tr_name = tr.get("metadata", {}).get("name", "")
                    node_id = generate_node_id(cluster_name, namespace, "taskrun", tr_name)

                    # Get status from conditions
                    conditions = tr.get("status", {}).get("conditions", [])
                    status = conditions[-1].get("reason", "Unknown") if conditions else "Unknown"

                    node = {
                        "id": node_id,
                        "type": "taskrun",
                        "name": tr_name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": status,
                        "metadata": {
                            "task_ref": tr.get("spec", {}).get("taskRef", {}).get("name", ""),
                            "pipeline_run": tr.get("metadata", {}).get("labels", {}).get("tekton.dev/pipelineRun", ""),
                            "labels": tr.get("metadata", {}).get("labels", {}),
                            "start_time": tr.get("status", {}).get("startTime")
                        }
                    }

                    nodes.append(node)
                    stats["nodes"] += 1

                    # Create edge to PipelineRun if part of one
                    pipeline_run_name = tr.get("metadata", {}).get("labels", {}).get("tekton.dev/pipelineRun")
                    if pipeline_run_name:
                        pr_id = generate_node_id(cluster_name, namespace, "pipelinerun", pipeline_run_name)
                        edges.append({
                            "source": pr_id,
                            "target": node_id,
                            "relationship": "runs_task",
                            "weight": 0.85
                        })
                        stats["edges"] += 1

                    # Create edge to Task if referenced
                    task_ref = tr.get("spec", {}).get("taskRef", {}).get("name")
                    if task_ref:
                        task_id = generate_node_id(cluster_name, namespace, "task", task_ref)
                        edges.append({
                            "source": node_id,
                            "target": task_id,
                            "relationship": "uses",
                            "weight": calculate_dependency_weight("taskrun", "task", "uses")
                        })
                        stats["edges"] += 1

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "taskruns", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/taskruns")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/taskruns",
                        "error": error_info["error_message"]
                    })

        # Process Tekton Tasks
        if "tasks" in component_types:
            try:
                tasks = await k8s_call(
                    custom_api.list_namespaced_custom_object,
                    group="tekton.dev",
                    version="v1",
                    namespace=namespace,
                    plural="tasks"
                )
                permissions["accessible"].append(f"{cluster_name}/{namespace}/tasks")

                for task in tasks.get("items", []):
                    task_name = task.get("metadata", {}).get("name", "")
                    node_id = generate_node_id(cluster_name, namespace, "task", task_name)

                    node = {
                        "id": node_id,
                        "type": "task",
                        "name": task_name,
                        "namespace": namespace,
                        "cluster": cluster_name,
                        "status": "Active",
                        "metadata": {
                            "steps": len(task.get("spec", {}).get("steps", [])),
                            "labels": task.get("metadata", {}).get("labels", {})
                        }
                    }

                    nodes.append(node)
                    stats["nodes"] += 1

            except Exception as e:
                error_info = handle_resource_fetch_error(e, "tasks", namespace, skip_on_permission_denied, logger)
                if error_info["permission_denied"]:
                    permissions["denied"].append(f"{cluster_name}/{namespace}/tasks")
                    if not skip_on_permission_denied:
                        raise
                else:
                    permissions["errors"].append({
                        "resource": f"{cluster_name}/{namespace}/tasks",
                        "error": error_info["error_message"]
                    })

    except Exception as e:
        logger.warning(f"Error processing namespace {namespace} in cluster {cluster_name}: {e}")

    return {
        "nodes": nodes,
        "edges": edges,
        "permissions": permissions,
        "stats": stats
    }


def _bound_topology_result(result: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
    """Stage-truncate a topology result to fit the token budget (phase-3.5 style).

    Drops edges first (halving, keep-first order), then nodes, until the
    serialized result fits or both lists reach a floor of 10; records what was
    dropped under _truncation. Mutates-and-returns the SAME dict (not pure —
    deliberate: the caller owns the freshly-built result and identity keeps
    the under-budget path golden-stable). Under-budget results are returned
    UNCHANGED (no _truncation key) — the no-op boundary. At the 10/10 floor
    the budget is best-effort (summary/permissions are separately self-bounded)."""
    text = json.dumps(result, default=str)
    if calculate_context_tokens(text) <= max_tokens:
        return result

    topo = result.get("topology", {})
    nodes = list(topo.get("nodes", []))
    edges = list(topo.get("edges", []))
    orig_nodes, orig_edges = len(nodes), len(edges)

    while (len(edges) > 10 or len(nodes) > 10):
        if len(edges) > 10:
            edges = edges[: max(10, len(edges) // 2)]
        else:
            nodes = nodes[: max(10, len(nodes) // 2)]
        topo["nodes"], topo["edges"] = nodes, edges
        if calculate_context_tokens(json.dumps(result, default=str)) <= max_tokens:
            break

    result["_truncation"] = {
        "truncated": True,
        "nodes_kept": len(nodes),
        "nodes_total": orig_nodes,
        "edges_kept": len(edges),
        "edges_total": orig_edges,
        "note": f"topology bounded to ~{max_tokens} max_context_tokens; raise it "
                f"or narrow namespace_filter/component_types for the full graph",
    }
    return result
