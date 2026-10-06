"""
LUMINO MCP Server - FastMCP Server Module

This module provides the core MCP (Model Context Protocol) server implementation
for Kubernetes, OpenShift, and Tekton monitoring and analysis.
"""

import re
import os
import sys
import json
import yaml
import time
import base64
import asyncio
import functools
import logging
import requests
import aiohttp
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from mcp.server.fastmcp import FastMCP, Context
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from collections import defaultdict

# For metrics and analysis
import pandas as pd
import numpy as np
import networkx as nx
from sklearn.ensemble import IsolationForest

from prometheus_client.parser import text_string_to_metric_families

# Helper imports
from helpers import (
    calculate_duration,
    calculate_duration_seconds,
    parse_time_parameters,
    format_yaml_output,
    format_detailed_output,
    format_summary_output,
    redact_secret,
    calculate_context_tokens,
    get_all_pod_logs,
    normalize_pod_log_text,
    clean_pipeline_logs,
    calculate_utilization,
    list_pods,
    detect_anomalies_in_data,
    SMART_EVENTS_CONFIG,
    LOG_ANALYSIS_CONFIG,
    TERMINAL_FAILURE_PR_STATUSES,
    EventSeverity,
    EventCategory,
    MLPatternDetector,
    LogMetricsIntegrator,
    RunbookSuggestionEngine,
    assess_overall_risk,
    generate_strategic_recommendations,
    generate_comprehensive_insights,
    smart_sample_string_events,
    generate_string_events_summary,
    generate_string_events_insights,
    generate_string_events_recommendations,
    # Log analysis helpers
    extract_error_patterns,
    categorize_errors,
    generate_log_summary,
    # Advanced log analysis helpers
    extract_log_patterns,
    sample_logs_by_time,
    generate_focused_summary,
    LogStreamProcessor,
    generate_streaming_summary,
    analyze_trending_patterns,
    generate_streaming_recommendations,
    combine_analysis_results,
    generate_supplementary_insights,
    generate_hybrid_recommendations,
    LogAnalysisStrategy,
    LogAnalysisContext,
    StrategySelector,
    get_strategy_selection_reason,
    analysis_cache,
    # ML/Data processing helpers for predictive analysis
    preprocess_log_data,
    extract_log_features,
    train_anomaly_model,
    train_or_load_model,
    analyze_log_patterns_for_failure_prediction,
    generate_failure_predictions,
    # Token limit truncation helpers
    truncate_to_token_limit,
    truncate_baseline_results,
    # Pipeline analysis helpers
    determine_root_cause,
    recommend_actions,
    get_pipeline_details,
    get_task_details,
    build_coverage,
    # Resource search helpers
    build_advanced_label_selector,
    get_resource_api_info,
    extract_resource_info,
    analyze_labels,
    calculate_namespace_distribution,
    sort_resources,
    # Certificate parsing helpers
    parse_certificate,
    categorize_certificate_status,
    # Performance analysis helpers
    detect_performance_trend,
    # Failure analysis helpers
    identify_failure_context,
    analyze_pipeline_failure,
    analyze_pod_failure,
    analyze_generic_failure,
    build_failure_timeline,
    find_related_failures,
    perform_advanced_rca,
    analyze_resource_constraints,
    analyze_configuration_issues,
    analyze_pipeline_dependencies,
    analyze_pipeline_performance,
    generate_remediation_plan,
    calculate_confidence_score,
    assess_failure_severity,
    # Resource topology helpers
    get_multi_cluster_clients,
    track_artifacts,
    analyze_bottlenecks,
    # Machine config pool helpers
    analyze_machine_config_pool_status,
    detect_pool_issues,
    generate_update_recommendations,
    # Operator analysis helpers
    analyze_operator_dependencies,
    identify_critical_issues,
    analyze_operator_conditions,
    # Topology mapping helpers
    get_multi_cluster_topology_clients,
    convert_to_graphviz,
    convert_to_mermaid,
    # Semantic search helpers
    interpret_semantic_query,
    determine_search_strategy,
    extract_k8s_entities,
    find_semantic_matches,
    calculate_semantic_relevance,
    identify_match_reasons,
    extract_log_metadata,
    rank_results_by_semantic_relevance,
    identify_common_patterns,
    analyze_severity_distribution,
    generate_semantic_suggestions,
    _build_log_params,
    _get_target_namespaces,
    _search_pod_logs_semantically,
    _search_events_semantically,
    _search_tekton_resources_semantically,
    # Simulation helpers
    convert_duration_to_seconds,
    calibrate_simulation_models,
    run_monte_carlo_simulation,
    collect_baseline_system_data,
    build_system_behavior_models,
    load_historical_performance_data,
    # Simulation impact analysis
    analyze_system_impact,
    perform_risk_assessment,
    calculate_simulation_quality,
    generate_simulation_recommendations,
    # Simulation affected components
    identify_affected_components,
)

from core.readonly_client import ReadOnlyCoreV1, ReadOnlyK8sClient
from core.tls import PLAIN_HTTP_TOKEN_HINT, TLS_HINT, bearer_token_allowed, client_ssl_context
from core.config import load_config
from core.registry import build_registry, SourceEntry, ADAPTER_CAPABILITIES as _ADAPTER_CAPABILITIES
from core.selector import make_capability_error, Entity, TimeWindow, Limit
from core.timewindow import make_time_window
from core.errors import AdapterError
from core.k8s_async import k8s_call, LOG_TIMEOUT
from core.credentials import _parse_credential_ref
from engines.pattern_scan import scan as _scan_logs
from engines.log_anomaly import detect as _detect_log_anomalies

# Configure logging with custom format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("lumino-mcp")


# Suppress the default MCP server logging to replace with our enhanced version
mcp_server_logger = logging.getLogger("mcp.server.lowlevel.server")
mcp_server_logger.setLevel(logging.WARNING)  # Only show warnings and errors

# Phase 2f (D2): HTTP bind settings are read from env at import. With no env set
# these equal the SDK constructor defaults (host 127.0.0.1, port 8000,
# stateless_http False) so the Settings object is byte-identical to the previous
# hardcoded construction. The values are consumed ONLY on the http serving path
# (uvicorn/session-manager) which stdio and the test harness never build.
mcp = FastMCP(
    name="pharos",
    instructions="""\
Pharos is a Kubernetes/OpenShift SRE MCP server with 48 tools for cluster diagnostics, \
pipeline analysis, log investigation, and multi-cluster fleet operations.

## Multi-Cluster Support

Every tool accepts an optional `source` parameter to target a specific cluster. \
Without `source`, tools query the default cluster (the kubeconfig context active at startup).

### Connecting additional clusters

1. Call `list_sources` to see all discovered kubeconfig contexts.
2. Call `connect_cluster` to register a named cluster:
   connect_cluster(name="prod-rh01", credential_ref="kubeconfig:/opt/app-root/.kube/config#<context-name>")
   The credential_ref path must be the CONTAINER path (usually /opt/app-root/.kube/config), \
not the host path. The context name after # must match exactly what appears in list_sources.
3. After connecting, pass source="prod-rh01" to any tool to target that cluster.

Extension tools (Tekton, OpenShift, Konflux) only activate for a named source AFTER \
connect_cluster succeeds. If a tool returns "extension not active", connect that cluster first.

## Tool Categories

- Kubernetes Core (5): list_namespaces, list_pods_in_namespace, get_kubernetes_resource, \
search_resources_by_labels, check_resource_constraints
- Log Analysis (10): smart_summarize_logs, stream_analyze_logs, analyze_logs_hybrid, \
analyze_pod_logs_hybrid, semantic_log_search, analyze_logs, detect_log_anomalies, get_etcd_logs
- Tekton Pipelines (8): list_pipelineruns, list_taskruns, list_recent_pipeline_runs, \
get_pipelinerun_logs, get_tekton_pipeline_runs_status, find_pipeline, analyze_failed_pipeline, \
pipeline_tracer
- Events & Analysis (5): get_events_smart, progressive_event_analysis, advanced_event_analytics, \
detect_anomalies, adaptive_namespace_investigation
- Prometheus & Metrics (3): prometheus_query / query_metrics, resource_bottleneck_forecaster
- OpenShift (3): get_openshift_cluster_operator_status, get_machine_config_pool_status, get_etcd_logs
- Security (2): check_cluster_certificate_health, investigate_tls_certificate_issues
- Topology (3): topology_mapper / live_system_topology_mapper, what_if_scenario_simulator
- Predictive (2): predictive_log_analyzer, manage_prediction_training_data
- KubeArchive (1): query_kubearchive (archived resources — garbage-collected PipelineRuns, pods)
- Incident (1): automated_triage_rca_report_generator
- Cluster Management (3): connect_cluster, list_sources, refresh_capabilities

## Log Retrieval Chain

When investigating pod or pipeline failures, follow this order:
1. get_pipelinerun_logs or smart_summarize_logs — live pod logs
2. If "No pods found" (garbage collected) -> query_kubearchive with include_logs=true
3. Only conclude "logs unavailable" after trying both

## Adapter Sources

Log tools support multiple data sources via the source parameter: Kubernetes pod logs (default), \
Loki, Elasticsearch, local files, and OTLP push ingest (port 4318). Configure adapters in \
lumino.yaml and pass source="my-loki" to any log tool.
""",
    host=os.getenv("LUMINO_BIND_HOST", "127.0.0.1"),
    port=int(os.getenv("LUMINO_BIND_PORT", "8000")),
    stateless_http=os.getenv("LUMINO_STATELESS_HTTP", "").lower() in ("1", "true", "yes"),
)


@mcp.custom_route("/health", methods=["GET"])
async def _health(request):  # HTTP route, NOT a tool (custom routes mount only in the http app)
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok"})


# Phase 2a: resolved profile + declarative source registry (spec SS4.2/SS4.6).
# load_config() is import-time inert - absent config -> built-in konflux profile.
_lumino_config = load_config()
_source_registry = build_registry(_lumino_config)
_extension_states: dict = {}  # populated at module end by activate_extensions (§4.6.1)


def _gate_source(tool_name: str, source: str, required_caps: tuple,
                 legacy_adapter: str = "kubernetes") -> Optional[Dict[str, Any]]:
    """Phase 2b source gating (spec SS4.4), shared by every generic tool.

    "" (default) -> the tool's legacy in-process path; no gating.  Non-empty:
    unknown -> error with known names; required_caps=() (provenance-only mode)
    -> any registered source accepted silently as declared provenance (no
    capability or routing check — there is nothing to dispatch; the tool
    operates on caller-supplied data and source= is audit metadata only);
    otherwise missing a required capability -> canonical capability error
    (capable_sources = sources holding ALL required caps); capable but NOT the
    default instance of the TOOL'S legacy adapter family -> structured phase-3
    routing error.  The default is anchored to legacy_adapter (the backend the
    legacy body actually reads), NEVER to the requested source's own adapter --
    otherwise a config-enabled cross-adapter source (e.g. kubearchive,
    Log+Event-capable) would pass the gate and be silently served kubernetes
    data (round-1 review Major).
    """
    if not source:
        return None
    try:
        entry = _source_registry.get(source)
    except KeyError as exc:
        return {"error": str(exc), "tool": tool_name, "requested_source": source}
    # Provenance-only mode: source is declared provenance, nothing to route.
    # Any registered source passes; skip capability and routing checks.
    if not required_caps:
        return None
    capable = sorted(
        set.intersection(*[set(_source_registry.capable_of(c)) for c in required_caps])
    )
    if any(c not in entry.capabilities for c in required_caps):
        return make_capability_error(tool_name, source, capable)
    if (entry.adapter != legacy_adapter or
            source != _source_registry.default_instance_of(legacy_adapter)):
        return {
            "error": (f"source {source!r} is configured and capable, but "
                      f"per-source routing lands in phase 3; only the default "
                      f"instance is currently served"),
            "tool": tool_name, "requested_source": source, "routable": False,
        }
    return None


def _make_tool_extension_map() -> Dict[str, str]:
    """Build _TOOL_EXTENSION once at module level (no circular import — extensions
    import server only under TYPE_CHECKING per their __init__.py).
    Konflux tools are intentionally excluded: D9 defers their dispatch, and
    including them without dispatch would violate R7 atomicity."""
    import importlib
    _t = importlib.import_module("extensions.tekton")
    _o = importlib.import_module("extensions.openshift")
    return {n: "tekton" for n in _t.TOOLS} | {n: "openshift" for n in _o.TOOLS}


_TOOL_EXTENSION: Dict[str, str] = _make_tool_extension_map()
del _make_tool_extension_map


def _gate_extension(tool_name: str, source: str) -> Optional[Dict[str, Any]]:
    """Per-call per-instance extension gate (D3/D4). Returns None when the tool's
    extension is 'active' on the instance `source` resolves to, else a structured
    error dict. Never touches the network (D4).

    Resolution: ext = _TOOL_EXTENSION[tool_name]  (KeyError = programmer error,
    let it raise); instance = _source_registry.default_kubernetes_instance() if
    source == "" else source. Reads _extension_states.get((ext, instance)) —
    'active' passes; anything else (or missing key → 'unknown') FAILS CLOSED."""
    ext = _TOOL_EXTENSION[tool_name]  # programmer error if tool_name absent; let raise
    instance = _source_registry.default_kubernetes_instance() if source == "" else source
    state = _extension_states.get((ext, instance))
    if state == "active":
        return None
    return {
        "error": f"extension {ext!r} is not active on kubernetes instance {instance!r}",
        "tool": tool_name,
        "requested_source": source,
        "extension": ext,
        "instance": instance,
        "extension_state": state if state is not None else "unknown",
        "hint": "connect_cluster(<name>, <credential_ref>) runs per-instance detection",
    }


# Phase 3/4: dispatch plumbing — adapter factories, instance cache, router,
# and envelope converter.

_adapter_instances: Dict[str, Any] = {}

# Phase 5: OTLP ring registry and listener state.
# _otlp_rings maps source name → LogRing; set here so the harness can import
# server-mcp.py without running main.py and still find these names (V5).
# _otlp_listening tracks whether the receiver thread is running (F9 flag).
_otlp_rings: Dict[str, Any] = {}
_otlp_listening: bool = False


def _build_file_source(source_name: str, source_config):
    """Build a FileLogSource from config (the file-adapter factory).

    Verbatim body of the former _get_file_source, now accepting an explicit
    source_config so ADAPTER_FACTORIES can call it generically.
    """
    from adapters.file.logs import FileLogSource
    sc = source_config
    roots = tuple(sc.options.get("roots") or ())
    if not roots:
        raise ValueError(
            f"file source {source_name!r} has no roots configured "
            f"(sources.{source_name}.roots; no default per spec SS4.7)")
    return FileLogSource(roots)


def _build_loki_source(source_name: str, source_config):
    """Build a LokiLogSource from config (the loki-adapter factory).

    Required option: ``url`` — the base URL of the Loki instance.
    Optional: ``entity_label`` (default "pod"), ``tenant``, ``timeout_s``,
    ``bearer_env`` / ``basic_user_env`` + ``basic_pass_env`` for auth.
    """
    from adapters.loki.logs import LokiLogSource
    sc = source_config
    url = sc.options.get("url")
    if not url:
        raise AdapterError(
            f"loki source {source_name!r} requires options.url "
            f"(sources.{source_name}.url is missing or empty)"
        )
    return LokiLogSource(url=url, options=dict(sc.options))


def _build_es_source(source_name: str, source_config):
    """Build an ESLogSource from config (the elasticsearch-adapter factory).

    Required options: ``url`` (base URL) and ``index_pattern`` (e.g.
    ``k8s-logs-*``).
    Optional: ``entity_field`` (default "kubernetes.pod_name"),
    ``timestamp_field`` (default "@timestamp"), ``message_field`` (default
    "message"), ``level_field`` (default "level"), ``entity_query``
    (default "term"), ``timeout_s``, ``bearer_env`` / ``basic_user_env`` +
    ``basic_pass_env`` for auth.
    """
    from adapters.elasticsearch.logs import ESLogSource
    sc = source_config
    url = sc.options.get("url")
    if not url:
        raise AdapterError(
            f"elasticsearch source {source_name!r} requires options.url "
            f"(sources.{source_name}.url is missing or empty)"
        )
    return ESLogSource(url=url, options=dict(sc.options))


def _build_otlp_source(source_name: str, source_config):
    """Build an OtlpLogSource from config (the OTLP-adapter factory, phase 5).

    Required options: ``ring_capacity`` (int > 0), ``max_body_bytes`` (int > 0).
    Optional: ``max_record_bytes`` (default 65 536), ``signals`` (default
    ``["logs"]``).  Validated by :func:`~adapters.otlp.config.validate_otlp_options`.

    The ring is created via ``setdefault`` so that a listener-less fetch
    (e.g. harness/import paths) honestly serves an empty ring and never
    raises a KeyError (F9).
    """
    from adapters.otlp.rings import LogRing
    from adapters.otlp.config import validate_otlp_options
    from adapters.otlp.logs import OtlpLogSource
    opts = validate_otlp_options(source_name, dict(source_config.options))
    ring = _otlp_rings.setdefault(
        source_name, LogRing(capacity=opts["ring_capacity"])
    )
    return OtlpLogSource(ring, opts)


def _otlp_ingest_stats(source_name: str) -> dict:
    """Return ingest statistics for an OTLP source (V5 ring-absent rendering).

    Safe to call before the receiver thread starts or when no ring has been
    created yet (e.g. harness import paths, config-declared-but-never-served).
    Absent ring → all-zero stats, ``covered_window: null``, ``listening: false``.
    """
    ring = _otlp_rings.get(source_name)
    if ring is None:
        return {
            "buffered": 0,
            "dropped_oldest": 0,
            "truncated_records": 0,
            "covered_window": None,
            "listening": False,
            "signals": ["logs"],
        }
    s = ring.stats()
    return {
        "buffered": s["buffered"],
        "dropped_oldest": s["dropped_oldest"],
        "truncated_records": s["truncated_records"],
        "covered_window": list(s["covered_window"]),
        "listening": _otlp_listening,
        "signals": ["logs"],
    }


# Type-keyed registry of adapter builder functions.  Each factory is called as
# factory(source_name, source_config) -> adapter instance.
ADAPTER_FACTORIES: Dict[str, Any] = {
    "file": _build_file_source,
    "loki": _build_loki_source,
    "elasticsearch": _build_es_source,
    "otlp": _build_otlp_source,
}


# ── Phase 2e: k8s instance registry — late-bound default view + lazy frozen ClientSets ──
#
# The DEFAULT kubernetes instance (the one _source_registry marks default=True)
# ALWAYS uses the module-level k8s_xxx_api globals.  Those globals are what the
# characterization harness monkeypatches; routing the default through _THIS_MODULE
# ensures test patches reach every consumer without any per-test plumbing.
#
# Non-default instances each get a freshly-dialed K8sClientSet (construct-once,
# cached in _k8s_instances).  _build_k8s_client_set is THE only dial site.

from dataclasses import dataclass as _dataclass

_THIS_MODULE = sys.modules[__name__]  # captured at import time; works under any module name


@_dataclass(frozen=True)
class K8sClientSet:
    """Frozen set of RO-wrapped API clients for one non-default kubernetes instance."""
    core_api: Any
    apps_api: Any
    custom_api: Any
    batch_api: Any
    storage_api: Any
    networking_api: Any
    autoscaling_api: Any
    apis_api: Any  # 8th field: ApisApi for GET /apis detection (no module global backing)


class _DefaultClientView:
    """Late-bound view over the module-level k8s_xxx_api globals.

    Each of the 7 typed-client properties resolves getattr(_THIS_MODULE, name)
    at ACCESS time so per-test monkeypatches always reach through.

    apis_api is the ONE exception: it has no module global, so it is
    constructed fresh on access as ReadOnlyK8sClient.wrap(client.ApisApi()),
    matching the _discover_api_groups path exactly (server-mcp.py ~line 12386).
    """

    @property
    def core_api(self):
        return getattr(_THIS_MODULE, "k8s_core_api")

    @property
    def apps_api(self):
        return getattr(_THIS_MODULE, "k8s_apps_api")

    @property
    def custom_api(self):
        return getattr(_THIS_MODULE, "k8s_custom_api")

    @property
    def batch_api(self):
        return getattr(_THIS_MODULE, "k8s_batch_api")

    @property
    def storage_api(self):
        return getattr(_THIS_MODULE, "k8s_storage_api")

    @property
    def networking_api(self):
        return getattr(_THIS_MODULE, "k8s_networking_api")

    @property
    def autoscaling_api(self):
        return getattr(_THIS_MODULE, "k8s_autoscaling_api")

    @property
    def apis_api(self):
        # No module global for ApisApi; construct fresh on each access.
        return ReadOnlyK8sClient.wrap(client.ApisApi())


_k8s_instances: Dict[str, K8sClientSet] = {}  # name -> K8sClientSet; default NOT stored here
_dial_call_count: int = 0                      # incremented ONLY inside _build_k8s_client_set
_k8s_conn_state: Dict[str, str] = {}          # name -> "connected" | "unconnected"; populated at activation
_kubeconfig_dir_paths: Dict[str, tuple] = {}  # instance_name -> (original_context_name, kubeconfig_path); phase 2e-b T5
_instance_tokens: Dict[str, Optional[str]] = {}  # instance_name -> bearer token (None = cert-auth or unregistered)
_runtime_instances: set = set()  # names added via connect_cluster; only these are disconnect_cluster-removable
_disconnected_instances: set = set()  # tombstones: block cache write-backs from coroutines in flight at disconnect; cleared on reconnect


def _build_k8s_client_set(context: str, kubeconfig_path: Optional[str] = None) -> K8sClientSet:
    """Dial a kubernetes context and return a frozen, RO-wrapped K8sClientSet.

    new_client_from_config(context=..., config_file=...) -> one ApiClient shared
    across all per-API client objects, each wrapped ReadOnlyK8sClient.wrap(…).

    This is THE only construction seam — tests monkeypatch it to avoid network I/O.
    Increments _dial_call_count so tests can assert the default path never dials.
    """
    global _dial_call_count
    _dial_call_count += 1
    api_client = config.new_client_from_config(
        context=context, config_file=kubeconfig_path
    )
    return K8sClientSet(
        core_api=ReadOnlyK8sClient.wrap(client.CoreV1Api(api_client=api_client)),
        apps_api=ReadOnlyK8sClient.wrap(client.AppsV1Api(api_client=api_client)),
        custom_api=ReadOnlyK8sClient.wrap(client.CustomObjectsApi(api_client=api_client)),
        batch_api=ReadOnlyK8sClient.wrap(client.BatchV1Api(api_client=api_client)),
        storage_api=ReadOnlyK8sClient.wrap(client.StorageV1Api(api_client=api_client)),
        networking_api=ReadOnlyK8sClient.wrap(client.NetworkingV1Api(api_client=api_client)),
        autoscaling_api=ReadOnlyK8sClient.wrap(client.AutoscalingV2Api(api_client=api_client)),
        apis_api=ReadOnlyK8sClient.wrap(client.ApisApi(api_client=api_client)),
    )


def _build_k8s_client_set_from_token(
    server_url: str, token: str, ca_file: Optional[str] = None
) -> "K8sClientSet":
    """Build a K8sClientSet authenticated with a bearer token (secret:/env: refs).

    Increments _dial_call_count — this IS a dial.
    ca_file: path to CA certificate file (optional).

    SECURITY: verify_ssl is NEVER set to False.  If ca_file is absent the
    default verify_ssl=True stays in place; a missing-CA dial will fail
    naturally (surfaces as dial_failed) rather than silently accepting an
    untrusted server and exposing the bearer token to MITM.
    """
    global _dial_call_count
    _dial_call_count += 1
    configuration = client.Configuration()
    configuration.host = server_url
    configuration.api_key_prefix["authorization"] = "Bearer"
    configuration.api_key["authorization"] = token
    if ca_file:
        configuration.ssl_ca_cert = ca_file
    # Deliberately omit `else: configuration.verify_ssl = False` — fail closed.
    api_client = client.ApiClient(configuration=configuration)
    return K8sClientSet(
        core_api=ReadOnlyK8sClient.wrap(client.CoreV1Api(api_client=api_client)),
        apps_api=ReadOnlyK8sClient.wrap(client.AppsV1Api(api_client=api_client)),
        custom_api=ReadOnlyK8sClient.wrap(client.CustomObjectsApi(api_client=api_client)),
        batch_api=ReadOnlyK8sClient.wrap(client.BatchV1Api(api_client=api_client)),
        storage_api=ReadOnlyK8sClient.wrap(client.StorageV1Api(api_client=api_client)),
        networking_api=ReadOnlyK8sClient.wrap(client.NetworkingV1Api(api_client=api_client)),
        autoscaling_api=ReadOnlyK8sClient.wrap(client.AutoscalingV2Api(api_client=api_client)),
        apis_api=ReadOnlyK8sClient.wrap(client.ApisApi(api_client=api_client)),
    )


def _resolve_k8s(source: str):
    """Resolve a kubernetes source name to (view_or_clientset, error_or_None).

    ''  or the default instance name  -> (_DefaultClientView(), None)
    Known non-default kubernetes name  -> lazy-built cached K8sClientSet
    Unknown or non-kubernetes name     -> (None, structured error dict)
    """
    default_name = _source_registry.default_kubernetes_instance()
    if source == "" or source == default_name:
        return _DefaultClientView(), None

    # NOTE(F-01): the known-instance list is deliberately NOT computed here.
    # An earlier build returned it to callers as `known_kubernetes_instances`,
    # which disclosed every configured cluster endpoint (with usernames) on a
    # single typo. The key is retained but always empty; use `list_sources`.

    # Check if it's a known kubernetes-adapter source
    try:
        entry = _source_registry.get(source)
    except KeyError:
        entry = None

    if entry is not None and entry.adapter == "kubernetes":
        # Non-default kubernetes instance — construct once, cache
        if source not in _k8s_instances:
            if source in _kubeconfig_dir_paths:
                # Dir-discovered instance: use stored (original_ctx, kubeconfig_path)
                context, kubeconfig = _kubeconfig_dir_paths[source]
            else:
                sc = _lumino_config.sources.get(source)
                context = sc.options.get("context", source) if sc else source
                kubeconfig = sc.options.get("kubeconfig") if sc else None
            _k8s_instances[source] = _build_k8s_client_set(context, kubeconfig)
        return _k8s_instances[source], None

    # Unknown or non-kubernetes source
    return None, {
        "error": (
            f"unknown kubernetes instance {source!r}; "
            f"known instances available via list_sources"
        ),
        "requested_source": source,
        "known_kubernetes_instances": [],  # Empty: invalid source must not enumerate the inventory
    }


# ── End phase 2e k8s instance registry ───────────────────────────────────────


def _get_adapter_instance(source_name: str):
    """Construct-once cache: return (or build) the adapter for source_name.

    Raises AdapterError for source types with no registered factory.
    """
    if source_name not in _adapter_instances:
        sc = _lumino_config.sources[source_name]
        factory = ADAPTER_FACTORIES.get(sc.adapter)
        if factory is None:
            raise AdapterError(
                f"no factory registered for adapter type {sc.adapter!r} "
                f"(source {source_name!r}); registered types: "
                f"{sorted(ADAPTER_FACTORIES)}")
        _adapter_instances[source_name] = factory(source_name, sc)
    return _adapter_instances[source_name]


def _route_log_source(tool_name: str, source: str):
    """Phase-3/4 routing for WIRED log tools only: returns (adapter, error).

    (None, None)  -> run the legacy kubernetes path (source empty/default).
    (adapter, None) -> fetch via the adapter (registered adapter types).
    (None, error) -> return the error dict (unknown/incapable, or a capable
                     non-registered source whose routing is still unimplemented).
    Unwired tools keep calling _gate_source directly and are unaffected.
    """
    err = _gate_source(tool_name, source, ("Log",))
    if err is None:
        return None, None
    entry = _source_registry._entries.get(source) if source else None
    if entry is not None and entry.adapter == "kubernetes":
        return None, None
    if err.get("routable") is False:
        if entry is not None and entry.adapter in ADAPTER_FACTORIES:
            return _get_adapter_instance(source), None
    return None, err


def _otlp_retention_or_none(batch, window, source_name) -> Optional[Dict[str, Any]]:
    """Return an outside-retention dict when the empty batch falls outside the
    OTLP ring's covered window; return None otherwise.

    Single pinned site for all five retention contracts:
      V1  – evicted>0 conjunct (predicate: unbounded window fires ONLY when ring has drops;
             unbounded + evicted==0 must fall through to No-logs-found — the honest-empty-
             buffer rule; deleting the conjunct reintroduces the dishonesty)
      F4  – unbounded disjunct (window.start is None + evicted>0 triggers outside-retention)
      F12 – both message variants (evicted>0 and evicted==0 exact strings)
      V6  – window rendering / injected clock (requested_window from batch.provenance,
             not wall time — the two diverge under a fixed clock by design; R6 caveat)
      M8  – conditionality (result dict returned only for OTLP adapters with covered_window)
    No-op for non-OTLP adapters whose Provenance.covered_window is None.
    """
    _prov = batch.provenance
    _covered = _prov.covered_window  # None for non-OTLP adapters
    if _covered is not None and not batch.records:
        _ring = _otlp_rings.get(source_name)
        _evicted = _ring.stats()["dropped_oldest"] if _ring is not None else 0
        try:
            _covered_start_dt = datetime.fromisoformat(
                _covered[0].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            _covered_start_dt = None
        _is_outside = (
            (window.start is None and _evicted > 0)
            or (
                window.start is not None
                and _covered_start_dt is not None
                and window.start < _covered_start_dt
            )
        )
        if _is_outside:
            # IMPORTANT: use _prov.requested_window (injected clock) NOT
            # time.time() — the two diverge under a fixed clock by design.
            if _evicted > 0:
                _msg = (
                    f"outside retention: {_evicted} record(s) evicted; "
                    f"buffer covers from {_covered[0]}"
                )
            else:
                _msg = (
                    f"outside retention: the receiver started at "
                    f"{_covered[0]}; nothing was being buffered before that"
                )
            return {
                "outside_retention": True,
                "requested_window": list(_prov.requested_window),
                "covered_window": list(_covered),
                "evicted": _evicted,
                "message": _msg,
            }
    return None


# Health check functionality will be handled by the MCP server itself
# The FastMCP framework provides its own health endpoints

from helpers.kubearchive_integration import (
    KubeArchiveClient,
    check_kubearchive_availability,
    query_kubearchive_resources,
    normalize_to_rfc3339,
    setup_kubearchive_client,
    get_discovery,
    evict_source as _ka_evict_source,
    revive_source as _ka_revive_source,
)
from helpers.decorators import log_tool_execution
# Names marked noqa: F401 below are not called by this module; they are
# re-exported here so tests can monkeypatch them on the server module object.
from helpers.prometheus import (
    _prometheus_endpoint_cache,  # noqa: F401 - re-exported for test monkeypatch surface
    _BEARER_SENTINEL,
    _get_k8s_bearer_token,
    _discover_prometheus_endpoint,
    _execute_prometheus_query_internal,
    _extract_kubeconfig_token,
    _process_prometheus_results,
    _generate_query_suggestions,
)
from helpers.utils import _safe_compile_namespace_filter, _parse_time_parameter, _handle_api_exception, _get_fallback_cluster_health
from helpers.utils import list_nodes_bounded
from helpers.utils import _get_active_node_names  # noqa: F401 - re-exported for test monkeypatch surface
from helpers.event_analysis import (  # noqa: F401 - re-exported for test monkeypatch surface
    _compress_events_for_synthesis,
    _extract_events_from_progressive,
    _get_namespace_events_internal,
    _get_namespace_events_as_dicts,
    _progressive_event_analysis_core,
)
from helpers.resource_topology import _bound_topology_result, _process_namespace_topology
from helpers.resource_forecasting import _analyze_node_resources_new, _analyze_cluster_capacity_new
from helpers.log_analysis import (
    AdaptiveLogProcessor,
    _estimate_pod_log_tokens,
    _calculate_adaptive_tail_lines,
    _truncate_logs_to_token_limit,
    _prioritize_pipeline_pods,
    _filter_analysis_for_synthesis,
    _get_logs_with_k8s_client,
    _filter_logs_by_time_range,
    _logbatch_to_legacy_envelope,
    _quick_volume_estimate,
)
# Wire the server-side _DefaultClientView into the helper so _estimate_pod_log_tokens
# can late-bind module globals (k8s_core_api) when clients= is not supplied.
# _DefaultClientView reads server module globals and cannot move to the helper;
# this assignment avoids any helper→server import.
import helpers.log_analysis as _helpers_log_analysis
_helpers_log_analysis._DefaultClientView = _DefaultClientView

# Wire the server-side _DefaultClientView into helpers.event_analysis so
# _get_namespace_events_as_dicts can late-bind module globals (k8s_core_api)
# when clients= is not supplied.
import helpers.event_analysis as _helpers_event_analysis
_helpers_event_analysis._DefaultClientView = _DefaultClientView


# Override the mcp.tool decorator to include our logging
original_tool_decorator = mcp.tool


def enhanced_tool_decorator(*args, **kwargs):
    """Enhanced tool decorator that adds logging."""
    def decorator(func):
        # First apply our logging decorator
        logged_func = log_tool_execution(func)
        # Then apply the original MCP tool decorator
        return original_tool_decorator(*args, **kwargs)(logged_func)

    # Handle both @mcp.tool and @mcp.tool() usage
    if len(args) == 1 and callable(args[0]) and not kwargs:
        # Direct decoration: @mcp.tool
        func = args[0]
        logged_func = log_tool_execution(func)
        return original_tool_decorator(logged_func)
    else:
        # Parameterized decoration: @mcp.tool()
        return decorator


# Replace the tool decorator
mcp.tool = enhanced_tool_decorator


# Configure Kubernetes client
try:
    config.load_incluster_config()
    logger.info("Loaded Kubernetes configuration from cluster")
except config.ConfigException:
    try:
        config.load_kube_config()
        logger.info("Loaded Kubernetes configuration from local kubeconfig")
    except config.ConfigException:
        logger.warning("No Kubernetes configuration found. Some tools may not work.")

# Initialize Kubernetes API clients
try:
    k8s_core_api = client.CoreV1Api()
    k8s_apps_api = client.AppsV1Api()
    k8s_custom_api = client.CustomObjectsApi()
    k8s_batch_api = client.BatchV1Api()
    k8s_storage_api = client.StorageV1Api()
    k8s_autoscaling_api = client.AutoscalingV2Api()
except Exception as e:
    logger.warning(f"Failed to initialize Kubernetes API clients: {e}")
    k8s_core_api = None
    k8s_apps_api = None
    k8s_custom_api = None
    k8s_batch_api = None
    k8s_storage_api = None
    k8s_autoscaling_api = None

# Initialize NetworkingV1Api for Ingress support (for KubeArchive discovery on plain Kubernetes)
try:
    k8s_networking_api = client.NetworkingV1Api()
except Exception as e:
    logger.warning(f"Failed to initialize NetworkingV1Api: {e}")
    k8s_networking_api = None

# KubeArchive discovery is now created lazily via get_discovery() on first
# query_kubearchive call (F4 — per-source factory). The module-level singleton
# is intentionally removed; see src/helpers/kubearchive_integration.py.


# Prometheus endpoints configuration (local Tekton components)
PROMETHEUS_ENDPOINTS = {
    'tekton-operator': 'http://localhost:9092/metrics',
    'tekton-chains-metrics': 'http://localhost:9093/metrics',
    'tekton-events-controller': 'http://localhost:9094/metrics',
    'tekton-pipelines-controller': 'http://localhost:9097/metrics',
    'tekton-pipelines-remote-resolvers': 'http://localhost:9100/metrics',
    'tekton-pipelines-webhook': 'http://localhost:9103/metrics',
    'tekton-results-api-service': 'http://localhost:9108/metrics',
    'tekton-results-watcher': 'http://localhost:9110/metrics'
}

# Namespace cache for avoiding repeated API calls.
# Keyed by resolved kubernetes instance name so that callers targeting
# different clusters never serve each other's cached namespace lists.
# Shape: { instance_name: {"namespaces": List[str], "timestamp": float} }
_namespace_cache: dict = {}
_namespace_cache_lock = asyncio.Lock()
_NAMESPACE_CACHE_TTL = 86400  # 1 day in seconds


# ============================================================================
# MCP TOOLS
# ============================================================================


@mcp.tool()
async def list_sources() -> Dict[str, Any]:
    """
    List configured telemetry sources (adapters), their capabilities, and extension states.

    Returns:
        Dict[str, Any]: Keys: profile, sources (name-sorted; each entry has name, adapter,
            capabilities, state; kubernetes entries additionally include a connection key
            with the dial state; otlp entries additionally include an ingest key with
            live buffer stats), extensions (name-sorted; each with name, configured, state).
    """
    return {
        "profile": _lumino_config.profile,
        "sources": [
            {
                "name": e.name,
                "adapter": e.adapter,
                "capabilities": list(e.capabilities),
                "state": e.state,
                **({"connection": _k8s_conn_state.get(e.name, "unconnected")}
                   if e.adapter == "kubernetes" else {}),
                **({"ingest": _otlp_ingest_stats(e.name)}
                   if e.adapter == "otlp" else {}),
            }
            for e in _source_registry.entries()
        ],
        "extensions": [
            {"name": name, "configured": mode,
             "state": _extension_states.get((name, _source_registry.default_kubernetes_instance()), "off")}
            for name, mode in sorted(_lumino_config.extensions.items())
        ],
        "extension_instances": {
            instance: {
                ext: _extension_states[(ext, inst)]
                for (ext, inst) in sorted(_extension_states) if inst == instance
            }
            for instance in sorted(_k8s_conn_state)
        },
    }


@mcp.tool()
async def refresh_capabilities() -> Dict[str, Any]:
    """Re-run extension detection (auto-mode only) and register newly available tools.

    Returns:
        Dict[str, Any]: Keys: changed (name-sorted list of newly registered tool names),
        extensions (name-sorted list of {name, configured, state}).
    """
    changed = []
    # Iterate connected instances only (R7: never dial unconnected clusters on refresh).
    # _k8s_conn_state is sorted for deterministic ordering.
    for _instance, _conn in sorted(_k8s_conn_state.items()):
        if _conn != "connected":
            continue
        for ext in _load_intree_extensions(_lumino_config):      # name-sorted
            mode = _lumino_config.extensions.get(ext.name, "off")
            key = (ext.name, _instance)
            if mode != "auto" or _extension_states.get(key) == "active":
                continue
            state, newly = await detect_and_register(ext, _extension_facade, _detect_ctx(_instance))  # round-1 F1: AWAIT the shared async core — a nested asyncio.run here would RuntimeError inside the server loop
            if _instance in _disconnected_instances:  # disconnected while detection ran; no write-back
                continue
            _extension_states[key] = state
            changed.extend(newly)  # union: newly==[] when tools already registered
    if changed:
        for _name in changed:
            globals()[_name] = _extension_facade.registered[_name]
        try:
            ctx = mcp.get_context()
            await ctx.session.send_tool_list_changed()
        except (LookupError, ValueError, AttributeError):
            pass  # no active session (direct invocation / harness) — result below still reports states
    return {"changed": sorted(changed),
            "extensions": [{"name": n, "configured": m,
                            "state": _extension_states.get((n, _source_registry.default_kubernetes_instance()), "off")}
                           for n, m in sorted(_lumino_config.extensions.items())]}


# ── Phase 2e Task 5: connect_cluster meta-tool ────────────────────────────────

_CONNECT_CLUSTER_HINT = "kubeconfig:<path>#<context> | secret:<path> | env:<VAR>"


@mcp.tool()
async def connect_cluster(name: str, credential_ref: str) -> Dict[str, Any]:
    """Register a kubernetes cluster instance at runtime from a credential REFERENCE.

    credential_ref accepts EXACTLY: "kubeconfig:<path>#<context>" | "secret:<path>" | "env:<VAR>".
    Raw tokens or kubeconfig bodies are rejected. secret:/env: refs additionally require a
    sources.kubernetes cluster_registry entry for <name> providing the server URL.

    Returns: {connected, name, extensions, tools_added} on success, else
    {error, code, hint} with code ∈ raw_credential_rejected | unknown_ref_scheme |
    bad_ref_grammar | ref_outside_allowlist | missing_cluster_registry_entry |
    context_not_found | dial_failed | duplicate_name.
    """
    _hint = _CONNECT_CLUSTER_HINT

    # ── Step 1: parse the credential ref (scheme-first positive match) ─────────
    ok, parsed = _parse_credential_ref(credential_ref)
    if not ok:
        return {"error": f"credential ref rejected: {parsed['code']}",
                "code": parsed["code"], "hint": _hint}

    # ── Step 2: allowlist check ────────────────────────────────────────────────
    k8s_sc = _lumino_config.sources.get(_source_registry.default_kubernetes_instance())
    opts = k8s_sc.options if k8s_sc is not None else {}

    if parsed["scheme"] in ("kubeconfig", "secret"):
        roots = opts.get("credential_ref_roots", [])
        ref_path = os.path.realpath(parsed["path"])
        # Path-boundary check: a root "/creds" must NOT admit a sibling
        # "/creds-evil/token" — require exact match or a real path-separator
        # boundary (whole-branch review: bare startswith is a prefix hole).
        def _under_root(rp, root):
            r = os.path.realpath(root)
            return rp == r or rp.startswith(r.rstrip(os.sep) + os.sep)
        if not roots or not any(_under_root(ref_path, r) for r in roots):
            return {"error": "path ref outside configured credential_ref_roots",
                    "code": "ref_outside_allowlist", "hint": _hint}
    elif parsed["scheme"] == "env":
        env_allowlist = opts.get("credential_ref_env_allowlist", [])
        if parsed["var"] not in env_allowlist:
            return {"error": (f"env var {parsed['var']!r} not in "
                              f"credential_ref_env_allowlist"),
                    "code": "ref_outside_allowlist", "hint": _hint}

    # ── Step 3: cluster_registry required for secret:/env: ────────────────────
    if parsed["scheme"] in ("secret", "env"):
        cluster_registry = opts.get("cluster_registry", {})
        registry_entry = cluster_registry.get(name)
        if not registry_entry or not registry_entry.get("server"):
            return {"error": (f"no cluster_registry entry with server URL for "
                              f"{name!r}"),
                    "code": "missing_cluster_registry_entry", "hint": _hint}

    # ── Step 4: add_instance (raises ValueError on duplicate name) ─────────────
    _default_name = _source_registry.default_kubernetes_instance()
    _k8s_caps = (
        _source_registry.get(_default_name).capabilities
        # "kubernetes" here is the ADAPTER name (capability-set key), not the
        # instance name (which may be renamed).  Correct to keep the literal.
        if _default_name else _ADAPTER_CAPABILITIES["kubernetes"]
    )
    try:
        _source_registry.add_instance(SourceEntry(
            name=name, adapter="kubernetes",
            capabilities=_k8s_caps, state="configured", default=False,
        ))
    except ValueError:
        return {"error": f"source name {name!r} is already registered",
                "code": "duplicate_name", "hint": _hint}

    # ── Step 5: bounded dial via asyncio.to_thread (round-1 F3) ───────────────
    # Build the client set AND run the /apis probe in the same thread so the
    # wait_for timeout can genuinely cancel a dead apiserver (bare sync I/O
    # inside wait_for cannot be cancelled from the event loop).
    _scheme = parsed["scheme"]
    _parsed_copy = dict(parsed)
    _captured_token: Optional[str] = None  # written by _blocking_build_and_probe; read after success

    def _blocking_build_and_probe():
        nonlocal _captured_token
        if _scheme == "kubeconfig":
            cs = _build_k8s_client_set(_parsed_copy["context"], _parsed_copy["path"])
            # Extract token for per-instance Prometheus auth (None for cert-auth kubeconfigs).
            _captured_token = _extract_kubeconfig_token(_parsed_copy["path"], _parsed_copy["context"])
        elif _scheme == "secret":
            _token = open(
                os.path.join(_parsed_copy["path"], "token")
            ).read().strip()
            _captured_token = _token
            _ca_path = os.path.join(_parsed_copy["path"], "ca.crt")
            _ca = _ca_path if os.path.exists(_ca_path) else None
            _reg = opts["cluster_registry"][name]
            cs = _build_k8s_client_set_from_token(
                _reg["server"], _token, _ca or _reg.get("ca_file")
            )
        else:  # env:
            _token = os.environ[_parsed_copy["var"]]
            _captured_token = _token
            _reg = opts["cluster_registry"][name]
            cs = _build_k8s_client_set_from_token(
                _reg["server"], _token, _reg.get("ca_file")
            )
        # First GET /apis probe — verifies connectivity before marking connected.
        cs.apis_api.get_api_versions()
        return cs

    def _rollback_instance():
        """Roll back add_instance so the name is cleanly retryable.

        Removes the registry entry and any conn_state written so far.
        Idempotent: safe to call even if the entry is already absent.
        """
        try:
            _source_registry.remove_instance(name)
        except ValueError:
            pass  # default=True guard — should never happen for runtime instances
        _k8s_conn_state.pop(name, None)
        _k8s_instances.pop(name, None)
        _namespace_cache.pop(name, None)
        _instance_tokens.pop(name, None)

    try:
        _cs = await asyncio.wait_for(
            asyncio.to_thread(_blocking_build_and_probe), 10.0
        )
    except asyncio.TimeoutError:
        _rollback_instance()
        return {"error": "dial timed out after 10 s",
                "code": "dial_failed", "hint": _hint}
    except Exception as _exc:
        _reason = str(_exc)
        # Distinguish kubeconfig context-not-found (ConfigException) from
        # generic network / auth failures.
        _exc_type = type(_exc).__name__
        _rollback_instance()
        if _exc_type == "ConfigException" and "not found" in _reason.lower():
            return {"error": _reason, "code": "context_not_found", "hint": _hint}
        # §4.7 secret-absence: str(exc) is never echoed for dial failures —
        # urllib3/k8s exceptions may embed URL fragments or header snippets.
        # Report only the exception class name plus a static message so that
        # no credential value can leak through this path.
        logger.warning("connect_cluster: dial failed for instance %r: %s", name, _exc_type)
        return {"error": f"{_exc_type}: dial failed",
                "code": "dial_failed", "hint": _hint}

    _k8s_instances[name] = _cs
    _instance_tokens[name] = _captured_token  # None for cert-auth kubeconfig; token str for secret/env
    _runtime_instances.add(name)             # disconnect_cluster-removable
    _disconnected_instances.discard(name)    # lift any tombstone from a prior disconnect
    _ka_revive_source(name)

    # ── Step 6: per-instance extension detection ───────────────────────────────
    # Iterate all INTREE extensions with configured mode != 'off'.  For 'on'
    # extensions: tools are already registered (union); detect() records honest
    # per-instance state.  For 'auto': detect() may add new tools.
    _ext_states: Dict[str, str] = {}
    _newly_all: List[str] = []

    def _abort_if_disconnected() -> Optional[Dict[str, Any]]:
        """Re-review MAJOR-1: a disconnect_cluster landing during the
        detection awaits purges this name; the resuming connect must not
        write conn-state/extension-state back on top of the purge (the
        resulting zombie reports connected, is unreachable, and cannot be
        removed without a restart)."""
        if name not in _disconnected_instances:
            return None
        for _key in [k for k in _extension_states if k[1] == name]:
            _extension_states.pop(_key, None)
        logger.warning("connect_cluster: instance %r disconnected while "
                       "connect was in flight; aborting without state writes", name)
        return {"error": f"instance {name!r} was disconnected while connect was in flight; retry connect_cluster",
                "code": "disconnected_during_connect", "hint": _hint}

    for _ext in _load_intree_extensions(_lumino_config):
        _mode = _lumino_config.extensions.get(_ext.name, "off")
        if _mode == "off":
            continue
        _state, _newly = await detect_and_register(
            _ext, _extension_facade, _detect_ctx(name), timeout_s=2.0
        )
        _aborted = _abort_if_disconnected()
        if _aborted is not None:
            return _aborted
        _extension_states[(_ext.name, name)] = _state
        _ext_states[_ext.name] = _state
        _newly_all.extend(_newly)

    # ── Step 7: mark connected ────────────────────────────────────────────────
    _aborted = _abort_if_disconnected()
    if _aborted is not None:
        return _aborted
    _k8s_conn_state[name] = "connected"

    # ── Step 8: rebind newly-registered tool names into globals() ─────────────
    for _n in _newly_all:
        globals()[_n] = _extension_facade.registered[_n]

    # ── Step 9: notify MCP client (guarded — no session in harness/tests) ──────
    try:
        _mcp_ctx = mcp.get_context()
        await _mcp_ctx.session.send_tool_list_changed()
    except (LookupError, ValueError, AttributeError):
        pass  # no active session (direct invocation / test harness)

    return {
        "connected": True,
        "name": name,
        "extensions": _ext_states,
        "tools_added": sorted(_newly_all),
    }


@mcp.tool()
async def disconnect_cluster(name: str) -> Dict[str, Any]:
    """Unregister a kubernetes cluster instance previously added at runtime.

    Inverse of connect_cluster. Removes the named instance from the source
    registry and purges every per-instance runtime store — client set,
    connection state, namespace cache, bearer token, extension states,
    API-group discovery cache, and kubearchive client/discovery caches — so
    the name is immediately reusable by a fresh connect_cluster call without
    serving the previous cluster's data.

    Only instances added via connect_cluster are removable: the default
    instance and startup-discovered kubeconfig instances are refused (their
    removal would be irreversible for the process lifetime on deployments
    with the default empty credential_ref_roots). Non-kubernetes sources
    (e.g. prometheus) are refused. The registered tool surface is
    intentionally never narrowed by a disconnect (registration is
    union-only), so no tool-list-changed notification is emitted.

    Returns: {disconnected: true, name} on success, else {error, code, hint}
    with code ∈ unknown_source | cannot_remove_default |
    not_kubernetes_instance | not_runtime_instance.
    """
    _hint = "disconnect_cluster removes runtime kubernetes instances; see list_sources"
    if not name:
        return {"error": "name must be a non-empty instance name",
                "code": "unknown_source", "hint": _hint}
    default_name = _source_registry.default_kubernetes_instance()
    if default_name is not None and name == default_name:
        return {"error": f"cannot remove the default kubernetes instance {default_name!r}",
                "code": "cannot_remove_default", "hint": _hint}
    try:
        entry = _source_registry.get(name)
    except KeyError:
        return {"error": (f"unknown kubernetes instance {name!r}; "
                          f"known instances available via list_sources"),
                "code": "unknown_source", "hint": _hint}
    if entry.adapter != "kubernetes":
        return {"error": f"source {name!r} is a {entry.adapter!r} source, not a kubernetes instance",
                "code": "not_kubernetes_instance", "hint": _hint}
    if name not in _runtime_instances:
        return {"error": (f"instance {name!r} was not added at runtime "
                          f"(startup-discovered or static); it persists until "
                          f"restart or config change"),
                "code": "not_runtime_instance", "hint": _hint}

    try:
        _source_registry.remove_instance(name)
    except ValueError:
        # registry-level default guard — unreachable given the check above,
        # kept as a belt-and-suspenders refusal rather than a crash
        return {"error": f"cannot remove the default kubernetes instance {name!r}",
                "code": "cannot_remove_default", "hint": _hint}

    # Tombstone FIRST: coroutines that resolved this instance before removal
    # and would write back to a cache after an await point check this set.
    _disconnected_instances.add(name)
    _runtime_instances.discard(name)

    # Same purge set as connect_cluster's _rollback_instance, plus the
    # per-instance extension states and discovery/kubearchive caches
    # (rollback runs before detection; a real disconnect runs after, so
    # those keys exist here).
    _k8s_conn_state.pop(name, None)
    # The popped K8sClientSet's ApiClient is deliberately NOT closed: an
    # in-flight tool call may still hold the reference and must complete
    # against the correct cluster. The urllib3 pool is released by GC once
    # the last holder finishes.
    _k8s_instances.pop(name, None)
    _namespace_cache.pop(name, None)
    _instance_tokens.pop(name, None)
    for _key in [k for k in _extension_states if k[1] == name]:
        _extension_states.pop(_key, None)
    _discovery_cache.pop(name, None)
    _ka_evict_source(name)

    logger.info("disconnect_cluster: removed instance %r", name)
    return {"disconnected": True, "name": name}


# ── End phase 2e Task 5 ───────────────────────────────────────────────────────


@mcp.tool()
async def list_namespaces(source: str = "") -> Union[List[str], Dict[str, Any]]:
    """
    List all namespaces in the Kubernetes cluster.

    Args:
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        List[str]: Alphabetically sorted namespace names on success.
            Returns an EMPTY list — indistinguishable from "cluster has no namespaces" —
            when access is denied (403/401) or the cluster is unreachable; callers must
            not interpret an empty list as evidence of a healthy empty cluster.
        Dict[str, Any]: Error dict with ``"error"`` key when the source is invalid.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err

    # Resolve the cache key: "" and the default instance name are the same
    # cluster — key them identically so they share one slot.
    _default_k8s = _source_registry.default_kubernetes_instance()
    _cache_key = _default_k8s if (source == "" or source == _default_k8s) else source

    current_time = time.time()
    _slot = _namespace_cache.get(_cache_key)
    if (_slot is not None and
            current_time - _slot["timestamp"] < _NAMESPACE_CACHE_TTL):
        logger.debug("Returning cached namespace list")
        return _slot["namespaces"]

    async with _namespace_cache_lock:
        current_time = time.time()
        _slot = _namespace_cache.get(_cache_key)
        if (_slot is not None and
                current_time - _slot["timestamp"] < _NAMESPACE_CACHE_TTL):
            return _slot["namespaces"]

        try:
            logger.info("Retrieving all namespaces from Kubernetes cluster")
            _ro = ReadOnlyK8sClient.wrap(_clients.core_api)
            namespaces = await k8s_call(_ro.list_namespace)
            ns_names = sorted([ns.metadata.name for ns in namespaces.items if ns.metadata and ns.metadata.name])

            if _cache_key not in _disconnected_instances:  # no write-back for a name disconnected mid-flight
                _namespace_cache[_cache_key] = {"namespaces": ns_names, "timestamp": current_time}

            logger.info(f"Successfully retrieved {len(ns_names)} namespaces")
            return ns_names

        except ApiException as e:
            if e.status == 403:
                logger.warning(f"Insufficient permissions to list namespaces: {e.reason}. Check RBAC configuration.")
            elif e.status == 401:
                logger.error(f"Authentication failed while listing namespaces: {e.reason}. Check kubeconfig.")
            else:
                logger.error(f"API error while listing namespaces: {e.status} - {e.reason}")
            return []

        except Exception as e:
            logger.error(f"Unexpected error while listing namespaces: {str(e)}", exc_info=True)
            return []


async def detect_tekton_namespaces(source: str = "") -> Dict[str, List[str]]:
    """
    Intelligently identifies and categorizes namespaces related to Tekton/CI-CD ecosystems.

    This tool performs advanced pattern matching to detect and classify namespaces that are part of
    or related to Tekton-based CI/CD systems. It uses a hierarchical classification
    system to organize namespaces by their functional role within the CI/CD pipeline infrastructure.

    The detection algorithm uses pattern matching against namespace names to identify:
    - Core Tekton components and services
    - Tekton pipeline and task execution environments
    - Build and compilation workspaces
    - Integration and deployment namespaces
    - Supporting infrastructure and tooling

    Args:
        source: Kubernetes instance name for per-instance dispatch; "" uses the default instance.

    Returns:
        Dict[str, List[str]]: Categorized namespace collections with the following structure:
            - "core_tekton": Namespaces containing "tekton" (primary system components)
            - "tekton_related": Namespaces containing tekton-related patterns
            - "pipeline_related": Namespaces containing "pipeline" (CI/CD workflows)
            - "build_related": Namespaces containing "build" (compilation and packaging)
            - "other_relevant": Namespaces matching other CI/CD ecosystem patterns
    """
    try:
        logger.info("Starting Tekton/CI-CD namespace detection and classification")
        all_namespaces = await list_namespaces(source=source)

        if not all_namespaces:
            logger.warning("No namespaces retrieved from cluster - returning empty classification")
            return {
                "core_tekton": [],
                "tekton_related": [],
                "pipeline_related": [],
                "build_related": [],
                "other_relevant": []
            }

        # Define comprehensive patterns for CI/CD ecosystem detection
        cicd_patterns = [
            "tekton", "pipeline", "build", "ci", "cd",
            "openshift-pipelines", "build-service", "release-service",
            "image-controller", "integration-service", "namespace-lister",
            "pipelines-as-code", "smee-client", "tekton-operator",
            "user-ns", "tekton-chains", "tekton-results", "tekton-triggers"
        ]

        result = {
            "core_tekton": [],
            "tekton_related": [],
            "pipeline_related": [],
            "build_related": [],
            "other_relevant": []
        }

        # Classification counters for logging
        classification_stats = {category: 0 for category in result.keys()}
        unclassified_count = 0

        logger.info(f"Classifying {len(all_namespaces)} namespaces using {len(cicd_patterns)} patterns")

        for ns in all_namespaces:
            ns_lower = ns.lower()
            classified = False

            # Priority-based classification (order matters)
            if "tekton" in ns_lower:
                result["core_tekton"].append(ns)
                classification_stats["core_tekton"] += 1
                classified = True
            elif "pipeline" in ns_lower:
                result["pipeline_related"].append(ns)
                classification_stats["pipeline_related"] += 1
                classified = True
            elif "build" in ns_lower:
                result["build_related"].append(ns)
                classification_stats["build_related"] += 1
                classified = True
            elif any(pattern in ns_lower for pattern in cicd_patterns):
                result["other_relevant"].append(ns)
                classification_stats["other_relevant"] += 1
                classified = True

            if not classified:
                unclassified_count += 1

        # Sort results within each category for consistent output
        for category in result:
            result[category].sort()

        # Log classification statistics
        total_classified = sum(classification_stats.values())
        logger.info(f"Namespace classification complete: {total_classified} CI/CD-related, "
                   f"{unclassified_count} other namespaces")

        for category, count in classification_stats.items():
            if count > 0:
                logger.info(f"  {category}: {count} namespaces")

        return result

    except Exception as e:
        logger.error(f"Unexpected error during Tekton namespace detection: {str(e)}", exc_info=True)
        # Return empty but consistent structure on error
        return {
            "core_tekton": [],
            "tekton_related": [],
            "pipeline_related": [],
            "build_related": [],
            "other_relevant": []
        }


async def list_pipelineruns(namespace: str, limit: Optional[int] = 200, source: str = "") -> List[Dict[str, Any]]:
    """
    List Tekton PipelineRuns in a namespace with status and timing details.

    Args:
        namespace: Kubernetes namespace to query.
        limit: Maximum number of PipelineRuns to return (default: 200). Set to 0 for no limit.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        List[Dict]: PipelineRuns with keys: name, pipeline, status, started_at, completed_at, duration.
                    Empty list if none found. [{"error": "msg"}] on failure.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return [_err]
    _gerr = _gate_extension("list_pipelineruns", source)
    if _gerr:
        return [_gerr]
    try:
        logger.info(f"Retrieving PipelineRuns from namespace: {namespace}")

        # Validate namespace parameter
        if not namespace or not isinstance(namespace, str):
            error_msg = f"Invalid namespace parameter: {namespace}. Must be a non-empty string."
            logger.error(error_msg)
            return [{"error": error_msg}]

        # Query Tekton PipelineRuns using Kubernetes Custom Resource API
        list_kwargs = {
            "group": "tekton.dev",
            "version": "v1",
            "namespace": namespace,
            "plural": "pipelineruns",
        }
        if limit:
            list_kwargs["limit"] = limit

        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)
        pipeline_runs = await k8s_call(_ro.list_namespaced_custom_object, **list_kwargs)

        pipeline_run_items = pipeline_runs.get("items", [])
        logger.info(f"Found {len(pipeline_run_items)} PipelineRuns in namespace '{namespace}'")

        if not pipeline_run_items:
            logger.info(f"No PipelineRuns found in namespace '{namespace}'")
            return []

        result = []
        processed_count = 0
        error_count = 0

        for pr in pipeline_run_items:
            try:
                # Extract metadata with null safety
                metadata = pr.get("metadata", {})
                spec = pr.get("spec", {})
                status = pr.get("status", {})

                # Get pipeline reference from multiple possible sources
                # Priority: pipelineRef.name > labels > pipelineSpec metadata > unknown
                pipeline_name = "unknown"

                # 1. Check spec.pipelineRef.name (direct reference to named Pipeline)
                pipeline_ref = spec.get("pipelineRef", {})
                if pipeline_ref and pipeline_ref.get("name"):
                    pipeline_name = pipeline_ref.get("name")

                # 2. Check common Tekton labels (used by Konflux and other platforms)
                if pipeline_name == "unknown":
                    labels = metadata.get("labels", {})
                    # Try multiple common label keys
                    pipeline_name = (
                        labels.get("tekton.dev/pipeline") or
                        labels.get("pipelines.tekton.dev/pipeline") or
                        labels.get("pipelines.openshift.io/pipeline") or
                        "unknown"
                    )

                # 3. Check inline pipelineSpec for name/displayName
                if pipeline_name == "unknown":
                    pipeline_spec = spec.get("pipelineSpec", {})
                    if pipeline_spec:
                        # Some inline specs may have displayName or name metadata
                        pipeline_name = (
                            pipeline_spec.get("displayName") or
                            pipeline_spec.get("name") or
                            "inline-pipeline"
                        )

                # Extract status information
                conditions = status.get("conditions", [])
                current_status = "Unknown"
                if conditions:
                    # Get the latest condition (Tekton uses last condition as current status)
                    latest_condition = conditions[-1]
                    current_status = latest_condition.get("reason", "Unknown")

                # Extract timing information
                start_time = status.get("startTime")
                completion_time = status.get("completionTime")

                # Determine if pipeline is still running
                is_running = current_status in ("Running", "Started", "Pending", "PipelineRunPending")

                # Calculate duration using helper function
                # For running pipelines, calculate elapsed time from start
                duration = "unknown"
                duration_seconds = None
                try:
                    duration = calculate_duration(start_time, completion_time, use_current_if_missing=is_running)
                    duration_seconds = calculate_duration_seconds(start_time, completion_time, use_current_if_missing=is_running)
                except Exception as e:
                    logger.debug(f"Duration calculation failed for PipelineRun {metadata.get('name', 'unknown')}: {e}")
                    duration = "calculation_error"

                pipeline_run_info = {
                    "name": metadata.get("name", "unknown"),
                    "pipeline": pipeline_name,
                    "status": current_status,
                    "started_at": start_time,
                    "completed_at": completion_time,
                    "duration": duration,
                    "duration_seconds": duration_seconds,
                }

                result.append(pipeline_run_info)
                processed_count += 1

            except Exception as e:
                error_count += 1
                logger.warning(f"Error processing individual PipelineRun: {e}")
                # Continue processing other PipelineRuns instead of failing completely
                continue

        logger.info(f"Successfully processed {processed_count} PipelineRuns from namespace '{namespace}' "
                   f"({error_count} errors encountered)")
        result.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return result

    except ApiException as e:
        if e.status == 404:
            logger.warning(f"Namespace '{namespace}' not found or no PipelineRuns accessible")
            return []
        elif e.status == 403:
            error_msg = (f"Insufficient permissions to list PipelineRuns in namespace '{namespace}'. "
                        f"Required RBAC: pipelineruns.tekton.dev/list")
            logger.error(error_msg)
            return [{"error": error_msg}]
        elif e.status == 401:
            error_msg = f"Authentication failed while accessing namespace '{namespace}'. Check kubeconfig."
            logger.error(error_msg)
            return [{"error": error_msg}]
        else:
            error_msg = f"API error listing PipelineRuns in namespace '{namespace}': {e.status} - {e.reason}"
            logger.error(error_msg)
            return [{"error": error_msg}]

    except Exception as e:
        error_msg = f"Unexpected error listing PipelineRuns in namespace '{namespace}': {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [{"error": error_msg}]


async def list_taskruns(namespace: str, pipeline_run: Optional[str] = None, source: str = "") -> List[Dict[str, Any]]:
    """
    List Tekton TaskRuns in a namespace, optionally filtered by a specific PipelineRun.

    Args:
        namespace: Kubernetes namespace to query.
        pipeline_run: Optional PipelineRun name to filter by.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        List[Dict]: TaskRuns with keys: name, task, pipeline_run, status, started_at, completed_at, duration.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return [_err]
    _gerr = _gate_extension("list_taskruns", source)
    if _gerr:
        return [_gerr]
    try:
        logger.info(f"Retrieving TaskRuns from namespace: {namespace}" +
                   (f" (filtered by PipelineRun: {pipeline_run})" if pipeline_run else ""))

        label_selector = f"tekton.dev/pipelineRun={pipeline_run}" if pipeline_run else None

        # When filtering by pipeline_run, the label_selector narrows the result set
        # so no limit is needed. Without a filter, limit to prevent fetching all
        # TaskRuns in large namespaces (can be 2000+ objects, ~97MB response).
        list_kwargs = {
            "group": "tekton.dev",
            "version": "v1",
            "namespace": namespace,
            "plural": "taskruns",
        }
        if label_selector:
            list_kwargs["label_selector"] = label_selector
        else:
            list_kwargs["limit"] = 200

        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)
        task_runs = await k8s_call(_ro.list_namespaced_custom_object, **list_kwargs)

        result = []
        for tr in task_runs.get("items", []):
            # Skip if filtering by pipeline_run and this task doesn't match
            if pipeline_run and tr.get("metadata", {}).get("labels", {}).get("tekton.dev/pipelineRun") != pipeline_run:
                continue

            metadata = tr.get("metadata", {})
            spec = tr.get("spec", {})
            status = tr.get("status", {})
            labels = metadata.get("labels", {})

            conditions = status.get("conditions", [])
            current_status = conditions[0].get("reason", "Unknown") if conditions else "Unknown"

            # Determine if task is still running
            is_running = current_status in ("Running", "Started", "Pending", "TaskRunPending")

            start_time = status.get("startTime")
            completion_time = status.get("completionTime")

            # Get task name from multiple possible sources
            # Priority: taskRef.name > labels > pipelineTask label > extract from taskrun name
            task_name = None

            # 1. Check spec.taskRef.name (direct reference to named Task)
            task_ref = spec.get("taskRef", {})
            if task_ref and task_ref.get("name"):
                task_name = task_ref.get("name")

            # 2. Check common Tekton labels
            if not task_name:
                task_name = (
                    labels.get("tekton.dev/task") or
                    labels.get("tekton.dev/pipelineTask") or
                    labels.get("pipelines.tekton.dev/task")
                )

            # 3. Try to extract from TaskRun name (format: pipelinerun-taskname-suffix)
            if not task_name:
                tr_name = metadata.get("name", "")
                pr_name = labels.get("tekton.dev/pipelineRun", "")
                if pr_name and tr_name.startswith(pr_name + "-"):
                    # Remove pipelinerun prefix and random suffix
                    remaining = tr_name[len(pr_name) + 1:]
                    # Task name is everything except the last random suffix (usually 5-6 chars)
                    parts = remaining.rsplit("-", 1)
                    if len(parts) > 1 and len(parts[-1]) <= 6:
                        task_name = parts[0]

            result.append({
                "name": metadata.get("name"),
                "task": task_name,
                "pipeline_run": labels.get("tekton.dev/pipelineRun"),
                "status": current_status,
                "started_at": start_time,
                "completed_at": completion_time,
                "duration": calculate_duration(start_time, completion_time, use_current_if_missing=is_running),
                "duration_seconds": calculate_duration_seconds(start_time, completion_time, use_current_if_missing=is_running),
            })

        logger.info(f"Found {len(result)} TaskRuns in namespace '{namespace}'")
        return result

    except ApiException as e:
        logger.error(f"Error listing TaskRuns in namespace {namespace}: {e}")
        return [{"error": str(e)}]


@mcp.tool()
async def list_pods_in_namespace(namespace: str, limit: Optional[int] = 200, source: str = "") -> List[Dict[str, Any]]:
    """
    List all pods in a Kubernetes namespace with status and placement info.

    Args:
        namespace: Kubernetes namespace to query.
        limit: Max pods to return (default 200; server-side bound — large
               namespaces can exceed 250 pods / multi-MB responses). A trailing
               "_truncation" entry is appended when more pods exist.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        List[Dict]: Pods with keys: name, status, ip, node_name, creation_timestamp,
                    restart_count, container_states (list of waiting/terminated reasons).
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return [_err]

    if not _clients.core_api:
        return [{"error": "Kubernetes client not available."}]

    pods_info = []
    try:
        logger.info(f"Listing pods in namespace: {namespace}")
        _ro = ReadOnlyK8sClient.wrap(_clients.core_api)
        pod_list_resp = await asyncio.to_thread(
            _ro.list_namespaced_pod, namespace=namespace, limit=limit)
        pod_list = pod_list_resp.items
        for pod in pod_list:
            # Extract container status information for better prioritization
            total_restart_count = 0
            container_states = []

            # Guard against pod.status being None (pods in early creation)
            if pod.status and pod.status.container_statuses:
                for cs in pod.status.container_statuses:
                    if cs.restart_count:
                        total_restart_count += cs.restart_count

                    # Capture waiting state reasons (CrashLoopBackOff, ImagePullBackOff, etc.)
                    if cs.state:
                        if cs.state.waiting and cs.state.waiting.reason:
                            container_states.append(cs.state.waiting.reason)
                        elif cs.state.terminated and cs.state.terminated.reason:
                            container_states.append(cs.state.terminated.reason)

            # Check init container statuses (common failure point in Tekton)
            if pod.status and pod.status.init_container_statuses:
                for ics in pod.status.init_container_statuses:
                    if ics.restart_count:
                        total_restart_count += ics.restart_count
                    if ics.state:
                        if ics.state.waiting and ics.state.waiting.reason:
                            container_states.append(f"Init:{ics.state.waiting.reason}")
                        elif ics.state.terminated and ics.state.terminated.reason and ics.state.terminated.reason != "Completed":
                            container_states.append(f"Init:{ics.state.terminated.reason}")

            pods_info.append({
                "name": pod.metadata.name,
                "status": pod.status.phase if pod.status else "Unknown",
                "ip": pod.status.pod_ip if pod.status else None,
                "node_name": pod.spec.node_name if pod.spec else "N/A",
                "creation_timestamp": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else "N/A",
                "restart_count": total_restart_count,
                "container_states": container_states
            })
        _continue = getattr(getattr(pod_list_resp, "metadata", None), "_continue", None)
        if isinstance(_continue, str) and _continue:
            pods_info.append({"_truncation": {
                "truncated": True,
                "returned": len(pods_info),
                "note": f"namespace has more pods than limit={limit}; "
                        f"raise limit or filter to see the rest",
            }})
        logger.info(f"Found {len(pods_info)} pods in namespace '{namespace}'.")
        return pods_info
    except ApiException as e:
        logger.error(f"API error listing pods in namespace '{namespace}': {e}")
        return [{"error": f"API Error: {e.reason}", "namespace": namespace}]
    except Exception as e:
        logger.error(f"Unexpected error listing pods in namespace '{namespace}': {e}", exc_info=True)
        return [{"error": f"Unexpected Error: {str(e)}", "namespace": namespace}]


@mcp.tool()
async def get_kubernetes_resource(
    resource_type: str,
    name: str,
    namespace: str = "default",
    output_format: str = "summary",
    source: str = ""
) -> str:
    """
    Retrieve details about a Kubernetes/Tekton resource.

    Args:
        resource_type: Resource type. Supported: pod, service, configmap, secret, pvc, namespace, node,
                       serviceaccount, endpoints, event, persistentvolume, resourcequota, limitrange,
                       deployment, replicaset, daemonset, statefulset, job, cronjob, ingress,
                       storageclass, hpa (horizontalpodautoscaler),
                       pipelinerun, taskrun, pipeline, task, clustertask,
                       triggertemplate, triggerbinding, eventlistener,
                       podmonitor, servicemonitor, prometheusrule, alertmanager,
                       application, component, snapshot, release, releaseplan,
                       releaseplanadmission, integrationtestscenario.
        name: Resource name.
        namespace: Namespace (default: "default").
        output_format: "summary", "detailed", or "yaml" (default: "summary").
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        str: Formatted resource information.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return f"Error: unknown source {source!r}; known instances are available via list_sources"
    try:
        resource_type = resource_type.lower().strip()

        # Define resource mappings
        core_resources = {
            'pod': ('pods', 'v1'),
            'service': ('services', 'v1'),
            'configmap': ('config_maps', 'v1'),
            'secret': ('secrets', 'v1'),
            'pvc': ('persistent_volume_claims', 'v1'),
            'persistentvolumeclaim': ('persistent_volume_claims', 'v1'),
            'namespace': ('namespaces', 'v1'),
            'node': ('nodes', 'v1'),
            'serviceaccount': ('service_accounts', 'v1'),
            'endpoints': ('endpoints', 'v1'),
            'event': ('events', 'v1'),
            'persistentvolume': ('persistent_volumes', 'v1'),
            'pv': ('persistent_volumes', 'v1'),
            'resourcequota': ('resource_quotas', 'v1'),
            'limitrange': ('limit_ranges', 'v1')
        }

        apps_resources = {
            'deployment': ('deployments', 'apps/v1'),
            'replicaset': ('replica_sets', 'apps/v1'),
            'daemonset': ('daemon_sets', 'apps/v1'),
            'statefulset': ('stateful_sets', 'apps/v1')
        }

        batch_resources = {
            'job': ('jobs', 'batch/v1'),
            'cronjob': ('cron_jobs', 'batch/v1')
        }

        networking_resources = {
            'ingress': ('ingresses', 'networking.k8s.io/v1')
        }

        storage_resources = {
            'storageclass': ('storage_classes', 'storage.k8s.io/v1'),
            'sc': ('storage_classes', 'storage.k8s.io/v1')
        }

        autoscaling_resources = {
            'horizontalpodautoscaler': ('horizontal_pod_autoscalers', 'autoscaling/v2'),
            'hpa': ('horizontal_pod_autoscalers', 'autoscaling/v2')
        }

        tekton_resources = {
            'pipelinerun': ('pipelineruns', 'tekton.dev/v1'),
            'taskrun': ('taskruns', 'tekton.dev/v1'),
            'pipeline': ('pipelines', 'tekton.dev/v1'),
            'task': ('tasks', 'tekton.dev/v1'),
            'clustertask': ('clustertasks', 'tekton.dev/v1beta1')  # ClusterTask deprecated, stays v1beta1
        }

        tekton_triggers_resources = {
            'triggertemplate': ('triggertemplates', 'triggers.tekton.dev/v1beta1'),
            'triggerbinding': ('triggerbindings', 'triggers.tekton.dev/v1beta1'),
            'eventlistener': ('eventlisteners', 'triggers.tekton.dev/v1beta1')
        }

        monitoring_resources = {
            'podmonitor': ('podmonitors', 'monitoring.coreos.com/v1'),
            'servicemonitor': ('servicemonitors', 'monitoring.coreos.com/v1'),
            'prometheusrule': ('prometheusrules', 'monitoring.coreos.com/v1'),
            'alertmanager': ('alertmanagers', 'monitoring.coreos.com/v1')
        }

        admission_resources = {
            'validatingadmissionwebhook': ('validatingwebhookconfigurations', 'admissionregistration.k8s.io/v1'),
            'mutatingadmissionwebhook': ('mutatingwebhookconfigurations', 'admissionregistration.k8s.io/v1')
        }

        konflux_resources = {
            'application': ('applications', 'appstudio.redhat.com/v1alpha1'),
            'component': ('components', 'appstudio.redhat.com/v1alpha1'),
            'snapshot': ('snapshots', 'appstudio.redhat.com/v1alpha1'),
            'release': ('releases', 'appstudio.redhat.com/v1alpha1'),
            'releaseplan': ('releaseplans', 'appstudio.redhat.com/v1alpha1'),
            'releaseplanadmission': ('releaseplanadmissions', 'appstudio.redhat.com/v1alpha1'),
            'integrationtestscenario': ('integrationtestscenarios', 'appstudio.redhat.com/v1beta2'),
        }

        resource_obj = None
        api_version = None

        _ro_core = ReadOnlyK8sClient.wrap(_clients.core_api)
        _ro_apps = ReadOnlyK8sClient.wrap(_clients.apps_api)
        _ro_batch = ReadOnlyK8sClient.wrap(_clients.batch_api)
        _ro_autoscaling = ReadOnlyK8sClient.wrap(_clients.autoscaling_api)
        _ro_storage = ReadOnlyK8sClient.wrap(_clients.storage_api)
        _ro_custom = ReadOnlyK8sClient.wrap(_clients.custom_api)

        # Fetch resource based on type
        if resource_type in core_resources:
            method_name, api_version = core_resources[resource_type]
            if resource_type in ['namespace', 'node', 'persistentvolume', 'pv']:
                # Cluster-scoped resources
                method = getattr(_ro_core, f'read_{method_name[:-1]}')
                resource_obj = await asyncio.to_thread(method, name=name)
            elif resource_type == 'endpoints':
                # Endpoints uses plural form in method name
                resource_obj = await asyncio.to_thread(
                    _ro_core.read_namespaced_endpoints,
                    name=name, namespace=namespace
                )
            else:
                # Namespaced resources
                method = getattr(_ro_core, f'read_namespaced_{method_name[:-1]}')
                resource_obj = await asyncio.to_thread(
                    method, name=name, namespace=namespace
                )

        elif resource_type in storage_resources:
            # Cluster-scoped storage resources
            # StorageV1Api uses read_storage_class (singular) while the dict
            # stores the plural 'storage_classes' for the supported-types list.
            # Dynamic dispatch via method_name[:-1] doesn't work here because
            # 'storage_classes'[:-1] == 'storage_classe', not 'storage_class'.
            resource_obj = await asyncio.to_thread(
                _ro_storage.read_storage_class, name=name
            )

        elif resource_type in autoscaling_resources:
            method_name, api_version = autoscaling_resources[resource_type]
            method = getattr(_ro_autoscaling, f'read_namespaced_{method_name[:-1]}')
            resource_obj = await asyncio.to_thread(
                method, name=name, namespace=namespace
            )

        elif resource_type in apps_resources:
            method_name, api_version = apps_resources[resource_type]
            method = getattr(_ro_apps, f'read_namespaced_{method_name[:-1]}')
            resource_obj = await asyncio.to_thread(
                method, name=name, namespace=namespace
            )

        elif resource_type in batch_resources:
            method_name, api_version = batch_resources[resource_type]
            method = getattr(_ro_batch, f'read_namespaced_{method_name[:-1]}')
            resource_obj = await asyncio.to_thread(
                method, name=name, namespace=namespace
            )

        elif resource_type in networking_resources:
            method_name, api_version = networking_resources[resource_type]
            resource_obj = await asyncio.to_thread(
                _ro_custom.get_namespaced_custom_object,
                group="networking.k8s.io",
                version="v1",
                namespace=namespace,
                plural="ingresses",
                name=name
            )

        elif resource_type in monitoring_resources:
            method_name, api_version = monitoring_resources[resource_type]
            group, version = api_version.split('/')
            resource_obj = await asyncio.to_thread(
                _ro_custom.get_namespaced_custom_object,
                group=group,
                version=version,
                namespace=namespace,
                plural=method_name,
                name=name
            )

        elif resource_type in admission_resources:
            method_name, api_version = admission_resources[resource_type]
            group, version = api_version.split('/')
            resource_obj = await asyncio.to_thread(
                _ro_custom.get_cluster_custom_object,
                group=group,
                version=version,
                plural=method_name,
                name=name
            )

        elif resource_type in tekton_resources:
            method_name, api_version = tekton_resources[resource_type]
            group, version = api_version.split('/')

            if resource_type == 'clustertask':
                # Cluster-scoped Tekton resource
                resource_obj = await asyncio.to_thread(
                    _ro_custom.get_cluster_custom_object,
                    group=group,
                    version=version,
                    plural=method_name,
                    name=name
                )
            else:
                # Namespaced Tekton resource
                resource_obj = await asyncio.to_thread(
                    _ro_custom.get_namespaced_custom_object,
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=method_name,
                    name=name
                )

        elif resource_type in tekton_triggers_resources:
            method_name, api_version = tekton_triggers_resources[resource_type]
            group, version = api_version.split('/')
            resource_obj = await asyncio.to_thread(
                _ro_custom.get_namespaced_custom_object,
                group=group,
                version=version,
                namespace=namespace,
                plural=method_name,
                name=name
            )

        elif resource_type in konflux_resources:
            method_name, api_version = konflux_resources[resource_type]
            group, version = api_version.split('/')
            resource_obj = await asyncio.to_thread(
                _ro_custom.get_namespaced_custom_object,
                group=group,
                version=version,
                namespace=namespace,
                plural=method_name,
                name=name
            )

        else:
            supported_types = (
                list(core_resources.keys()) + list(apps_resources.keys()) +
                list(batch_resources.keys()) + list(networking_resources.keys()) +
                list(storage_resources.keys()) + list(autoscaling_resources.keys()) +
                list(tekton_resources.keys()) + list(tekton_triggers_resources.keys()) +
                list(monitoring_resources.keys()) + list(admission_resources.keys()) +
                list(konflux_resources.keys())
            )
            return f"Error: Unsupported resource type '{resource_type}'. Supported types: {', '.join(sorted(supported_types))}"

        if not resource_obj:
            return f"Error: Resource '{name}' of type '{resource_type}' not found in namespace '{namespace}'"

        # Secret values never leave the server; key names and sizes stay visible.
        if resource_type == 'secret':
            resource_obj = redact_secret(resource_obj)

        # Format output based on requested format
        if output_format.lower() == "yaml":
            return format_yaml_output(resource_obj, resource_type, name, namespace)
        elif output_format.lower() == "detailed":
            return format_detailed_output(resource_obj, resource_type, name, namespace)
        else:  # summary
            return format_summary_output(resource_obj, resource_type, name, namespace)

    except ApiException as e:
        if e.status == 404:
            return f"Error: Resource '{name}' of type '{resource_type}' not found in namespace '{namespace}'"
        else:
            return f"Kubernetes API Error: {e.status} - {e.reason}"
    except Exception as e:
        return f"Error retrieving resource: {str(e)}"


async def get_pipelinerun_logs(
    pipelinerun_name: str,
    namespace: str,
    clean_logs: bool = True,
    tail_lines: Optional[int] = None,
    since_seconds: Optional[int] = None,
    since_time: Optional[str] = None,
    timestamps: bool = True,
    previous: bool = False,
    max_token_budget: int = 18000,
    source: str = ""
) -> Dict[str, Any]:
    """
    Fetch logs from all pods in a Tekton PipelineRun with adaptive volume management.

    Prioritizes failed pods and manages token budgets automatically when no time/line filters specified.

    Args:
        pipelinerun_name: PipelineRun name.
        namespace: Kubernetes namespace.
        clean_logs: Clean and format logs (default: True).
        tail_lines: Lines from end (optional).
        since_seconds: Logs newer than N seconds (optional).
        since_time: Logs newer than RFC3339 timestamp (optional).
        timestamps: Include timestamps (default: True).
        previous: Get logs from previous container instance (default: False).
        max_token_budget: Maximum tokens for output (default: 18000 — sized so
            the JSON response fits a 25k-token MCP client cap; the internal
            chars/3 estimator runs ~25% optimistic on JSON-escaped log text.
            Raise only for clients with a larger response cap. Applies to
            both adaptive and manual modes.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, Any]: Pod names as keys, logs as values. Includes "_metadata" with processing info.
        Returns {"info": "No pods found..."} if pods are garbage collected - use query_kubearchive tool.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    _gerr = _gate_extension("get_pipelinerun_logs", source)
    if _gerr:
        return _gerr
    # Build log filtering info for logging
    filter_info = []
    if since_time:
        filter_info.append(f"since_time={since_time}")
    elif since_seconds:
        filter_info.append(f"since_seconds={since_seconds}")
    elif tail_lines:
        filter_info.append(f"tail_lines={tail_lines}")

    filter_str = f" with filters: {', '.join(filter_info)}" if filter_info else ""
    logger.info(f"Fetching logs for PipelineRun '{pipelinerun_name}' in ns '{namespace}'{filter_str}...")
    all_logs = {}

    try:
        _ro = ReadOnlyCoreV1.wrap(_clients.core_api)
        # Find pods associated with the PipelineRun using Tekton labels
        # Tekton adds 'tekton.dev/pipelineRun' label to all pods in a PipelineRun
        label_selector = f"tekton.dev/pipelineRun={pipelinerun_name}"

        pod_list = await asyncio.to_thread(
            _ro.list_namespaced_pod,
            namespace=namespace,
            label_selector=label_selector,
        )

        if not pod_list.items:
            # Fallback: Try alternative label format used by some Tekton versions
            label_selector_alt = f"tekton.dev/pipeline={pipelinerun_name}"
            pod_list = await asyncio.to_thread(
                _ro.list_namespaced_pod,
                namespace=namespace,
                label_selector=label_selector_alt,
            )

        if not pod_list.items:
            return {"info": f"No pods found for PipelineRun '{pipelinerun_name}'. Check if the PipelineRun exists and has completed pods."}

        # Get all pod names
        pod_names = [pod.metadata.name for pod in pod_list.items]
        logger.info(f"Found {len(pod_names)} pods for PipelineRun '{pipelinerun_name}'")

        # Check if adaptive mode should be used
        use_adaptive_processing = (tail_lines is None and since_seconds is None and since_time is None)

        if use_adaptive_processing:
            logger.info(f"ADAPTIVE MODE activated for PipelineRun '{pipelinerun_name}' - {len(pod_names)} pods detected")

            # Initialize adaptive processor with configurable budget
            processor = AdaptiveLogProcessor(max_token_budget=max_token_budget)

            # Prioritize pods (failed pods first, recent pods next)
            prioritized_pods = await _prioritize_pipeline_pods(pod_names, namespace, _clients.core_api)

            # Process pods progressively with token management
            processed_pods = 0
            truncated_pods = 0  # Track how many pods had logs truncated
            for pod_name in prioritized_pods:
                # STEP 1: Calculate adaptive tail_lines FIRST based on pipeline size and remaining budget
                adaptive_tail_lines = _calculate_adaptive_tail_lines(
                    len(pod_names), processed_pods, processor.get_remaining_budget()
                )

                # STEP 2: Estimate tokens using the SAME tail_lines that will be used for fetching
                estimated_tokens = await _estimate_pod_log_tokens(namespace, pod_name, tail_lines=adaptive_tail_lines, clients=_clients)

                # STEP 3: Check if we can process this pod within budget
                # GUARANTEE: Always process at least the first pod (highest priority - usually failed)
                is_first_pod = (processed_pods == 0)
                if not is_first_pod and not processor.can_process_more(estimated_tokens):
                    logger.info(f"Token budget reached ({processor.get_usage_percentage():.1f}% used) - processed {processed_pods}/{len(pod_names)} pods")
                    break

                try:
                    # STEP 4: Fetch logs with the calculated adaptive_tail_lines
                    pod_logs = await get_all_pod_logs(
                        pod_name=pod_name,
                        namespace=namespace,
                        k8s_core_api=_clients.core_api,
                        tail_lines=adaptive_tail_lines,
                        timestamps=timestamps,
                        previous=previous
                    )

                    # Format and clean logs
                    if len(pod_logs) == 1:
                        container_name, logs = next(iter(pod_logs.items()))
                        if clean_logs:
                            logs = clean_pipeline_logs(logs)
                        all_logs[pod_name] = logs
                    else:
                        formatted_logs = []
                        for container_name, logs in pod_logs.items():
                            if clean_logs:
                                logs = clean_pipeline_logs(logs)
                            formatted_logs.append(f"--- Container: {container_name} ---")
                            formatted_logs.append(logs)
                            formatted_logs.append(f"--- End Container: {container_name} ---")
                        all_logs[pod_name] = "\n".join(formatted_logs)

                    # HARD LIMIT ENFORCEMENT: Truncate if actual tokens exceed remaining budget
                    remaining_budget = processor.get_remaining_budget()
                    actual_tokens = calculate_context_tokens(str(all_logs[pod_name]))

                    if actual_tokens > remaining_budget:
                        # Truncate logs to fit within remaining budget
                        all_logs[pod_name], was_truncated = _truncate_logs_to_token_limit(
                            all_logs[pod_name], remaining_budget, pod_name
                        )
                        if was_truncated:
                            truncated_pods += 1
                        actual_tokens = calculate_context_tokens(str(all_logs[pod_name]))

                    processor.record_usage(actual_tokens)
                    processed_pods += 1

                    logger.info(f"Processed pod {processed_pods}/{len(pod_names)}: {pod_name} ({actual_tokens:,} tokens, {processor.get_usage_percentage():.1f}% budget used)")

                    # Brief pause for rate limiting
                    await asyncio.sleep(0.2)

                except Exception as e:
                    logger.error(f"Error fetching logs for pod {pod_name}: {e}")
                    all_logs[pod_name] = f"Error fetching logs for pod {pod_name}: {str(e)}"

            # Add adaptive processing metadata
            all_logs["_metadata"] = {
                "adaptive_mode": True,
                "pods_processed": processed_pods,
                "pods_truncated": truncated_pods,
                "pods_skipped": len(pod_names) - processed_pods,
                "total_pods_found": len(pod_names),
                "token_budget_used": f"{processor.get_usage_percentage():.1f}%",
                "token_budget_max": processor.max_token_budget,
                "processing_strategy": f"Pipeline size: {len(pod_names)} pods -> adaptive batching"
            }

        else:
            # MANUAL MODE: Use specified parameters with token budget enforcement
            logger.info(f"MANUAL MODE for PipelineRun '{pipelinerun_name}' - using specified constraints")

            # Initialize processor for token tracking in manual mode
            processor = AdaptiveLogProcessor(max_token_budget=max_token_budget)
            truncated_pods = 0
            skipped_pods = 0  # review MINOR-11: manual mode must report skips too

            async def fetch_pod_logs(pod_name):
                try:
                    pod_logs = await get_all_pod_logs(
                        pod_name=pod_name,
                        namespace=namespace,
                        k8s_core_api=_clients.core_api,
                        tail_lines=tail_lines,
                        since_seconds=since_seconds,
                        since_time=since_time,
                        timestamps=timestamps,
                        previous=previous
                    )
                    if len(pod_logs) == 1:
                        container_name, logs = next(iter(pod_logs.items()))
                        if clean_logs:
                            logs = clean_pipeline_logs(logs)
                        return pod_name, logs
                    else:
                        formatted_logs = []
                        for container_name, logs in pod_logs.items():
                            if clean_logs:
                                logs = clean_pipeline_logs(logs)
                            formatted_logs.append(f"--- Container: {container_name} ---")
                            formatted_logs.append(logs)
                            formatted_logs.append(f"--- End Container: {container_name} ---")
                        return pod_name, "\n".join(formatted_logs)
                except Exception as e:
                    logger.error(f"Error fetching logs for pod {pod_name}: {e}")
                    return pod_name, f"Error fetching logs for pod {pod_name}: {str(e)}"

            # Fetch logs concurrently for all pods
            log_tasks = [fetch_pod_logs(pod_name) for pod_name in pod_names]
            results = await asyncio.gather(*log_tasks)

            # Apply token budget limiting to collected logs
            for pod_name, logs in results:
                remaining_budget = processor.get_remaining_budget()
                actual_tokens = calculate_context_tokens(str(logs))

                if actual_tokens > remaining_budget and remaining_budget > 0:
                    # Truncate logs to fit within remaining budget
                    logs, was_truncated = _truncate_logs_to_token_limit(
                        logs, remaining_budget, pod_name
                    )
                    if was_truncated:
                        truncated_pods += 1
                    actual_tokens = calculate_context_tokens(str(logs))
                elif remaining_budget <= 0:
                    # Skip this pod entirely if budget exhausted
                    logs = f"[Skipped - token budget exhausted]"
                    actual_tokens = calculate_context_tokens(logs)
                    skipped_pods += 1

                all_logs[pod_name] = logs
                processor.record_usage(actual_tokens)

            # Add metadata for manual mode
            all_logs["_metadata"] = {
                "mode": "manual",
                # skipped pods are not "processed" (re-review MINOR-5)
                "pods_processed": len(pod_names) - skipped_pods,
                "pods_truncated": truncated_pods,
                "pods_skipped": skipped_pods,
                "token_budget_used": f"{processor.get_usage_percentage():.1f}%",
                "token_budget_max": max_token_budget,
                "filters_applied": filter_info if filter_info else ["none"]
            }

        return all_logs

    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        return {"error": str(e)}
    except ApiException as e:
        logger.error(f"K8s API error getting PipelineRun pods: {e.status} - {e.reason} - {e.body}")
        return {"error": f"Failed to find pods for PipelineRun: {e.reason}"}
    except Exception as e:
        logger.error(f"Unexpected error getting PipelineRun logs: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred: {str(e)}"}


@mcp.tool()
async def check_resource_constraints(namespace: str, source: str = "") -> Dict[str, Any]:
    """
    Check for resource constraints in a namespace that may impact pipelines.

    Identifies: pending/unschedulable pods, OOMKilled containers, CrashLoopBackOff,
    ImagePullBackOff, high restart counts, and resource quota utilization.

    Args:
        namespace: Kubernetes namespace to inspect.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, Any]: Keys: status (Healthy/Warning/Critical/Error), summary, resource_quotas,
                        pending_pods_due_to_resources, oom_killed_containers, container_issues,
                        high_utilization_quotas, recommendations.
            On namespace not found (404): returns a Dict with keys:
            ``status`` ("Error"), ``summary`` (message), ``error`` (message), ``namespace`` (name),
            and empty lists for all resource/quota/pod fields.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    try:
        _ro = ReadOnlyK8sClient.wrap(_clients.core_api)
        # Verify the namespace exists before doing any work.
        # A missing namespace returns empty pod/quota lists which falsely
        # resolve to status "Healthy" without this guard.
        try:
            await k8s_call(_ro.read_namespace, namespace)
        except ApiException as _ns_exc:
            if _ns_exc.status == 404:
                return {
                    "status": "Error",
                    "summary": f"Namespace {namespace!r} does not exist",
                    "resource_quotas": [],
                    "pending_pods_due_to_resources": [],
                    "oom_killed_containers": [],
                    "container_issues": [],
                    "high_utilization_quotas": [],
                    "recommendations": [],
                    "error": f"Namespace {namespace!r} does not exist",
                    "namespace": namespace,
                }
            raise
        # Get pods in the namespace
        pods = await list_pods(namespace, _clients.core_api, logger)
        pod_analysis_truncated = any("_truncation" in p for p in pods)
        if pod_analysis_truncated:
            logger.warning(
                f"pod list for {namespace} truncated at limit; analysis covers a sample")
        pods = [p for p in pods if "_truncation" not in p]

        # Get resource quotas
        resource_quotas = await k8s_call(_ro.list_namespaced_resource_quota, namespace)

        # Check for resource problems in pod status
        resource_issues = []
        pending_pods = []
        oom_killed_pods = []
        vanished_pods = 0

        # Fetch detailed pod info once per pod that needs inspection. The reads
        # run concurrently (k8s_call bounds them) instead of up to 200
        # sequential requests; results are handled below in list order.
        inspect_names = [p.get("name") for p in pods
                         if p.get("status") in ["Failed", "Pending", "Running"]]
        detailed_by_name = dict(zip(inspect_names, await asyncio.gather(
            *(k8s_call(_ro.read_namespaced_pod, name=n, namespace=namespace)
              for n in inspect_names),
            return_exceptions=True,
        )))

        for pod in pods:
            pod_name = pod.get("name")
            pod_status = pod.get("status")

            if pod_status in ["Failed", "Pending", "Running"]:
                detailed_pod = detailed_by_name[pod_name]
                if isinstance(detailed_pod, ApiException) and detailed_pod.status == 404:
                    # Pod deleted between list and read — normal for
                    # short-lived pods (completed TaskRuns, affinity
                    # assistants). Live finding 2026-08-21 (prd-i01):
                    # this 404 killed the whole namespace scan.
                    vanished_pods += 1
                    logger.debug(
                        f"Pod {pod_name} vanished during scan; skipping")
                    continue
                if isinstance(detailed_pod, BaseException):
                    raise detailed_pod

                # Check for pending pods (potential scheduling issues)
                if pod_status == "Pending" and detailed_pod.status and detailed_pod.status.conditions:
                    for condition in detailed_pod.status.conditions:
                        if condition.type == "PodScheduled" and condition.status == "False":
                            pending_pods.append({
                                "pod": pod_name,
                                "issue": "Unschedulable",
                                "reason": condition.reason or "Unknown",
                                "message": condition.message or ""
                            })
                            break
                    else:
                        pending_pods.append({
                            "pod": pod_name,
                            "issue": "Pending",
                            "reason": "Unknown",
                            "message": "Pod is pending without specific reason"
                        })
                elif pod_status == "Pending":
                    pending_pods.append({
                        "pod": pod_name,
                        "issue": "Pending",
                        "reason": "Unknown",
                        "message": "Pod is pending without specific reason"
                    })

                # Check container statuses for issues
                def _check_container_statuses(statuses, prefix=""):
                    if not statuses:
                        return
                    for container_status in statuses:
                        cname = f"{prefix}{container_status.name}" if prefix else container_status.name
                        # Check current state for waiting issues
                        if hasattr(container_status, "state") and container_status.state:
                            if container_status.state.waiting:
                                reason = container_status.state.waiting.reason
                                if reason in ["CrashLoopBackOff", "OOMKilled", "ImagePullBackOff", "ErrImagePull", "CreateContainerError", "CreateContainerConfigError", "ContainerCreating"]:
                                    resource_issues.append({
                                        "pod": pod_name,
                                        "container": cname,
                                        "issue": reason,
                                        "message": container_status.state.waiting.message or ""
                                    })

                        # Check last_state for OOMKilled (container restarted after OOM)
                        if hasattr(container_status, "last_state") and container_status.last_state:
                            if container_status.last_state.terminated:
                                if container_status.last_state.terminated.reason == "OOMKilled":
                                    oom_killed_pods.append({
                                        "pod": pod_name,
                                        "container": cname,
                                        "issue": "OOMKilled",
                                        "restart_count": container_status.restart_count,
                                        "message": f"Container was OOMKilled and restarted {container_status.restart_count} times"
                                    })

                        # Check for high restart counts (potential resource issues)
                        if container_status.restart_count and container_status.restart_count > 5:
                            resource_issues.append({
                                "pod": pod_name,
                                "container": cname,
                                "issue": "HighRestartCount",
                                "restart_count": container_status.restart_count,
                                "message": f"Container has restarted {container_status.restart_count} times"
                            })

                if detailed_pod.status:
                    _check_container_statuses(detailed_pod.status.container_statuses)
                    _check_container_statuses(detailed_pod.status.init_container_statuses, prefix="init:")

        # Format resource quotas
        quota_data = []
        for quota in resource_quotas.items:
            if quota.status.hard and quota.status.used:
                quota_item = {
                    "name": quota.metadata.name,
                    "resources": {}
                }

                for resource, hard_limit in quota.status.hard.items():
                    used = quota.status.used.get(resource, "0")
                    quota_item["resources"][resource] = {
                        "limit": hard_limit,
                        "used": used,
                        "utilization": calculate_utilization(used, hard_limit)
                    }

                quota_data.append(quota_item)

        # Check for high utilization quotas
        high_utilization = [
            quota_item for quota_item in quota_data
            if any(
                resource.get("utilization", 0) > 80
                for resource in quota_item.get("resources", {}).values()
            )
        ]

        # Determine overall status
        status = "Healthy"
        summary_parts = []

        total_issues = len(resource_issues) + len(pending_pods) + len(oom_killed_pods)

        if oom_killed_pods:
            status = "Critical"
            summary_parts.append(f"{len(oom_killed_pods)} OOMKilled containers")
        if pending_pods:
            status = "Critical" if status != "Critical" else status
            summary_parts.append(f"{len(pending_pods)} pending/unschedulable pods")
        if resource_issues:
            status = "Warning" if status == "Healthy" else status
            summary_parts.append(f"{len(resource_issues)} container issues")
        if high_utilization:
            status = "Warning" if status == "Healthy" else status
            summary_parts.append(f"{len(high_utilization)} quotas with high utilization")

        if summary_parts:
            summary = f"Found: {', '.join(summary_parts)}"
        else:
            summary = "No significant resource constraints detected"

        # Generate recommendations
        recommendations = []
        if oom_killed_pods:
            recommendations.append("Increase memory limits for OOMKilled containers")
            recommendations.append("Review application memory usage patterns")
        if pending_pods:
            unschedulable = [p for p in pending_pods if p.get("issue") == "Unschedulable"]
            if unschedulable:
                recommendations.append("Check node resources - pods cannot be scheduled due to insufficient resources")
            recommendations.append("Review pending pods and their resource requests")
        if resource_issues:
            crash_loops = [i for i in resource_issues if i.get("issue") == "CrashLoopBackOff"]
            image_issues = [i for i in resource_issues if i.get("issue") in ["ImagePullBackOff", "ErrImagePull"]]
            config_errors = [i for i in resource_issues if i.get("issue") in ["CreateContainerError", "CreateContainerConfigError"]]
            high_restarts = [i for i in resource_issues if i.get("issue") == "HighRestartCount"]
            if crash_loops:
                recommendations.append("Investigate CrashLoopBackOff containers - check logs for errors")
            if image_issues:
                recommendations.append("Fix image pull issues - verify image names and registry access")
            if config_errors:
                recommendations.append("Fix container configuration errors - check secrets, configmaps, and volume mounts")
            if high_restarts:
                recommendations.append("Investigate containers with high restart counts")
        if high_utilization:
            recommendations.append("Monitor resource quota usage and consider increasing limits")

        result = {
            "status": status,
            "summary": summary,
            "resource_quotas": quota_data,
            "pending_pods_due_to_resources": pending_pods,
            "oom_killed_containers": oom_killed_pods,
            "container_issues": resource_issues,
            "high_utilization_quotas": high_utilization,
            "recommendations": recommendations
        }
        if pod_analysis_truncated:
            result["pod_analysis_truncated"] = {
                "limit": 200,
                "note": "namespace has more pods than the analysis limit; results cover a sample",
            }
        if vanished_pods:
            result["pods_vanished_during_scan"] = vanished_pods
        return result

    except ApiException as e:
        logger.error(f"Kubernetes API error checking resource constraints in namespace {namespace}: {e}")
        return {
            "status": "Error",
            "summary": f"Kubernetes API error: {str(e)}",
            "resource_quotas": [],
            "pending_pods_due_to_resources": [],
            "oom_killed_containers": [],
            "container_issues": [],
            "high_utilization_quotas": [],
            "recommendations": ["Check cluster connectivity and permissions"],
            "error": str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error checking resource constraints in namespace {namespace}: {e}")
        return {
            "status": "Error",
            "summary": f"Unexpected error: {str(e)}",
            "resource_quotas": [],
            "pending_pods_due_to_resources": [],
            "oom_killed_containers": [],
            "container_issues": [],
            "high_utilization_quotas": [],
            "recommendations": ["Review logs for detailed error information"],
            "error": str(e)
        }


@mcp.tool()
async def detect_anomalies(namespace: str, limit: int = 50, source: str = "") -> Dict[str, Any]:
    """
    Detect anomalies in Tekton PipelineRuns/TaskRuns using z-score statistical analysis.

    Identifies unusually long execution times (threshold: 2.5 standard deviations from mean).

    Args:
        namespace: Kubernetes namespace to analyze.
        limit: Max recent PipelineRuns to analyze (default: 50).
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Keys: pipeline_anomalies, task_anomalies (lists with anomaly details)
        on success.

        Two distinct error shapes exist:

        *Gate error* (invalid or uncapable source — exits via ``_gate_source``
        before the try block):
        ``{"error": message, "tool": "detect_anomalies", "requested_source": source}``
        — pipeline_anomalies and task_anomalies are **absent**.

        *Exception error* (any other failure — API error, etc. — caught by the
        except block):
        ``{"pipeline_anomalies": [], "task_anomalies": [], "error": message}``

        Callers MUST check for the ``"error"`` key regardless of which shape is
        returned; a caller that simply checks for the ``"error"`` key is safe
        either way, as both shapes carry it.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("detect_anomalies", source, ("Inventory",))
            if _gate_err:
                return _gate_err
    try:
        # Get pipeline runs
        pipeline_runs = await list_pipelineruns(namespace, source=source)

        # Limit to the most recent runs
        # Use 'or ""' to handle None values (not just missing keys)
        pipeline_runs = sorted(
            pipeline_runs,
            key=lambda x: x.get("started_at") or "",
            reverse=True
        )[:limit]

        # Get ALL task runs in one API call (bulk fetch instead of N+1)
        all_task_runs = await list_taskruns(namespace, pipeline_run=None, source=source)

        # Create a set of pipeline run names for fast lookup
        pr_names = {pr.get("name") for pr in pipeline_runs}

        # Collect durations for anomaly detection
        pipeline_data = []
        task_data = []

        # Process pipeline runs
        for pr in pipeline_runs:
            # Parse pipeline duration
            if pr.get("status") == "Succeeded" and pr.get("duration") and pr.get("duration") != "unknown":
                try:
                    value = pr.get("duration").split()[0]
                    if value.replace(".", "", 1).isdigit():
                        pipeline_data.append({
                            "name": pr.get("name"),
                            "duration": float(value)
                        })
                except (ValueError, IndexError):
                    continue

        # Process task runs (filter in memory - much faster than N API calls)
        for tr in all_task_runs:
            # Only include tasks belonging to our selected pipeline runs
            tr_pipeline = tr.get("pipeline_run")
            if tr_pipeline not in pr_names:
                continue

            if tr.get("status") == "Succeeded" and tr.get("duration") and tr.get("duration") != "unknown":
                try:
                    value = tr.get("duration").split()[0]
                    if value.replace(".", "", 1).isdigit():
                        task_data.append({
                            "name": tr.get("name"),
                            "duration": float(value),
                            "pipeline_run": tr_pipeline
                        })
                except (ValueError, IndexError):
                    continue

        # Detect anomalies
        pipeline_anomaly_result = detect_anomalies_in_data(
            [d["duration"] for d in pipeline_data], pipeline_data
        )
        task_anomaly_result = detect_anomalies_in_data(
            [d["duration"] for d in task_data], task_data
        )

        # Extract anomaly lists from helper function results
        pipeline_anomalies = []
        if pipeline_anomaly_result.get("anomalies_detected") and pipeline_anomaly_result.get("anomaly_details"):
            for anomaly in pipeline_anomaly_result["anomaly_details"].get("anomalies", []):
                original_data = anomaly.get("original_data", {})
                stats = pipeline_anomaly_result["anomaly_details"]["statistics"]
                pipeline_anomalies.append({
                    "name": original_data.get("name", "unknown"),
                    "reason": f"Unusually long duration (z-score: {anomaly.get('z_score', 0):.2f})",
                    "actual_value": anomaly.get("value"),
                    "expected_range": (
                        max(0, stats["mean"] - 2.5 * stats["std_dev"]),
                        stats["mean"] + 2.5 * stats["std_dev"]
                    )
                })

        task_anomalies = []
        if task_anomaly_result.get("anomalies_detected") and task_anomaly_result.get("anomaly_details"):
            for anomaly in task_anomaly_result["anomaly_details"].get("anomalies", []):
                original_data = anomaly.get("original_data", {})
                stats = task_anomaly_result["anomaly_details"]["statistics"]
                task_anomalies.append({
                    "name": original_data.get("name", "unknown"),
                    "pipeline_run": original_data.get("pipeline_run", "unknown"),
                    "reason": f"Unusually long duration (z-score: {anomaly.get('z_score', 0):.2f})",
                    "actual_value": anomaly.get("value"),
                    "expected_range": (
                        max(0, stats["mean"] - 2.5 * stats["std_dev"]),
                        stats["mean"] + 2.5 * stats["std_dev"]
                    )
                })

        return {
            "pipeline_anomalies": pipeline_anomalies,
            "task_anomalies": task_anomalies
        }

    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        return {
            "pipeline_anomalies": [],
            "task_anomalies": [],
            "error": str(e)
        }


@mcp.tool()
async def smart_get_namespace_events(
    namespace: str,
    last_n_events: Optional[int] = None,
    time_period: Optional[str] = None,
    strategy: str = "auto",
    focus_areas: Optional[List[str]] = None,
    max_context_tokens: int = 8000,
    include_summary: bool = True,
    source: str = ""
) -> Dict[str, Any]:
    """
    Adaptive event analysis for a namespace with automatic volume management.

    When no constraints specified, automatically: estimates volume, applies smart time windows,
    prioritizes errors/warnings, samples within token limits.

    Args:
        namespace: Kubernetes namespace to analyze.
        last_n_events: Exact event count (only if user specifies).
        time_period: Exact time window (only if user specifies).
        strategy: "auto" for adaptive behavior (default).
        focus_areas: Areas to emphasize (default: ["errors", "warnings", "failures"]).
        max_context_tokens: Max output tokens (default: 8000).
        include_summary: Include summary and insights (default: True).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.
                Non-kubernetes sources: capability validated per phase 2b.

    Returns:
        Dict: Events with adaptive filtering, insights, and recommendations.

    Note: ``smart_get_namespace_events`` and ``get_events_smart`` are the same tool;
        prefer ``get_events_smart``.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("smart_get_namespace_events", source, ("Event",))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    # Handle mutable default argument - set default inside function
    if focus_areas is None:
        focus_areas = ["errors", "warnings", "failures"]

    tool_name = "smart_get_namespace_events"
    logger.info(f"[{tool_name}] Starting smart event analysis for namespace '{namespace}'")

    try:
        # Validate inputs
        if not namespace or not namespace.strip():
            return {"error": "Namespace cannot be empty"}

        if max_context_tokens < 1000:
            logger.warning(f"[{tool_name}] Low token limit ({max_context_tokens}), setting to 1000")
            max_context_tokens = 1000

        # Step 1: Determine strategy and apply defaults
        if strategy == "auto":
            strategy = "smart_summary"
            logger.info(f"[{tool_name}] Auto-selected strategy: {strategy}")

        # Step 2: Apply intelligent defaults if no parameters provided - ADAPTIVE MODE
        if last_n_events is None and time_period is None:
            logger.info(f"[{tool_name}] No filters provided - activating ADAPTIVE MODE")

            # Quick volume estimation using very recent events
            try:
                recent_sample = await _get_namespace_events_internal(
                    namespace=namespace,
                    time_period="10m",
                    clients=_clients,
                )

                sample_count = recent_sample.get("filtered_events_count", 0)
                estimated_hourly_events = sample_count * 6  # 10min * 6 = 1 hour

                if estimated_hourly_events > 500:
                    time_period = "30m"
                    logger.info(f"[{tool_name}] HIGH EVENT VOLUME detected (~{estimated_hourly_events}/hour) - using 30min window")
                    if "errors" not in focus_areas:
                        focus_areas = ["errors", "warnings"] + [f for f in focus_areas if f not in ["errors", "warnings"]]
                elif estimated_hourly_events > 50:
                    time_period = "2h"
                    logger.info(f"[{tool_name}] MEDIUM EVENT VOLUME detected (~{estimated_hourly_events}/hour) - using 2h window")
                else:
                    time_period = "6h"
                    logger.info(f"[{tool_name}] LOW EVENT VOLUME detected (~{estimated_hourly_events}/hour) - using 6h window")

            except Exception as e:
                logger.warning(f"[{tool_name}] Volume estimation failed, using safe default: {e}")
                time_period = SMART_EVENTS_CONFIG["defaults"]["default_time_window"]

            logger.info(f"[{tool_name}] ADAPTIVE STRATEGY selected: {time_period} time window")

        # Step 3: Fetch events using internal function
        logger.info(f"[{tool_name}] Fetching events with filters: last_n={last_n_events}, time_period={time_period}")

        raw_result = await _get_namespace_events_internal(
            namespace=namespace,
            last_n_events=last_n_events,
            time_period=time_period,
            clients=_clients,
        )

        if "errors" in raw_result and raw_result["errors"]:
            return {"error": f"Failed to fetch events: {raw_result['errors']}"}

        events_count = raw_result.get("filtered_events_count", 0)
        events_list = raw_result.get("events", [])

        logger.info(f"[{tool_name}] Retrieved {events_count} events, processing with strategy: {strategy}")

        # Step 4: Apply intelligent processing based on strategy
        if strategy == "smart_summary":

            if not events_list:
                return {
                    "namespace": namespace,
                    "strategy_used": "smart_summary",
                    "total_events": 0,
                    "processed_events": 0,
                    "events": [],
                    "summary": {"total_events": 0, "message": "No events found in the specified timeframe"},
                    "insights": ["No events found - this could indicate either a quiet period or issues with event generation"],
                    "recommendations": ["Verify that applications are generating events as expected"],
                    "token_usage": {"total_estimated": 200},
                    "applied_filters": raw_result.get("applied_filters", {}),
                    "smart_features": {
                        "intelligent_defaults": time_period if last_n_events is None else None,
                        "context_overflow_prevention": True,
                        "focus_areas": focus_areas
                    }
                }

            # Apply smart sampling and analysis
            selected_events = smart_sample_string_events(events_list, focus_areas, max_context_tokens)

            # Generate summary if requested
            summary = {}
            if include_summary:
                summary = generate_string_events_summary(selected_events, focus_areas)

            # Generate insights and recommendations
            insights = generate_string_events_insights(selected_events)
            recommendations = generate_string_events_recommendations(selected_events)

            # Calculate token usage
            total_tokens = sum(event["token_estimate"] for event in selected_events)
            summary_tokens = len(str(summary).split()) * 1.3 if summary else 0
            metadata_tokens = 200

            return {
                "namespace": namespace,
                "strategy_used": "smart_summary",
                "total_events": events_count,
                "processed_events": len(selected_events),
                "events": [
                    {
                        "event_string": event["event_string"],
                        "severity": event["severity"],
                        "category": event["category"],
                        "relevance_score": round(event["relevance_score"], 2),
                        "timestamp": event["timestamp"].isoformat(),
                        "token_estimate": event["token_estimate"]
                    }
                    for event in selected_events
                ],
                "summary": summary,
                "insights": insights,
                "recommendations": recommendations,
                "token_usage": {
                    "events_tokens": int(total_tokens),
                    "summary_tokens": int(summary_tokens),
                    "metadata_tokens": metadata_tokens,
                    "total_estimated": int(total_tokens + summary_tokens + metadata_tokens)
                },
                "applied_filters": raw_result.get("applied_filters", {}),
                "smart_features": {
                    "intelligent_defaults": time_period if last_n_events is None else None,
                    "context_overflow_prevention": True,
                    "focus_areas": focus_areas,
                    "classification_applied": True,
                    "smart_sampling": True
                },
                "classification_metadata": {
                    "severity_distribution": {
                        severity.value: len([e for e in selected_events if e["severity"] == severity.value])
                        for severity in EventSeverity
                    },
                    "category_distribution": {
                        category.value: len([e for e in selected_events if e["category"] == category.value])
                        for category in EventCategory
                    }
                }
            }

        elif strategy == "raw":
            # Limited raw processing
            max_raw = SMART_EVENTS_CONFIG["defaults"]["max_events_raw"]
            return {
                "namespace": namespace,
                "strategy_used": "raw_limited",
                "total_events": events_count,
                "processed_events": min(events_count, max_raw),
                "events": events_list[:max_raw] if events_list else [],
                "applied_limits": {
                    "max_raw_events": max_raw,
                    "truncated": events_count > max_raw
                },
                "token_usage": {
                    "total_estimated": min(events_count, max_raw) * 60
                },
                "note": "Raw strategy with safety limits applied to prevent context overflow"
            }

        else:  # progressive or fallback
            return {
                "namespace": namespace,
                "strategy_used": "progressive",
                "total_events": events_count,
                "note": "Progressive analysis strategy - showing overview",
                "events_overview": {
                    "total_found": events_count,
                    "time_period": time_period,
                    "preview": events_list[:5] if events_list else [],
                    "suggestion": "Use smart_summary strategy for detailed analysis"
                },
                "quick_insights": [
                    f"Found {events_count} events in namespace '{namespace}'",
                    "Use 'smart_summary' strategy for intelligent analysis",
                    "Progressive disclosure enables drilling down into specific issues"
                ]
            }

    except Exception as e:
        logger.error(f"[{tool_name}] Unexpected error: {str(e)}", exc_info=True)
        return {
            "error": f"Smart event analysis failed: {str(e)}",
            "fallback_suggestion": "Try using the original get_namespace_events tool with explicit filters"
        }


# @mcp.tool()  # Commented out - Konflux-specific tool
async def get_konflux_components_status() -> Dict[str, Any]:
    """
    Retrieves a comprehensive status overview of all Konflux components across all accessible Kubernetes namespaces.

    This asynchronous function provides a high-level health check and status report for the entire
    Konflux ecosystem deployed within the Kubernetes cluster. It performs:

    1. Discovery of Konflux-related namespaces using pattern matching
    2. Collection of deployment statuses (replicas, availability)
    3. Aggregation of PipelineRun statistics by status
    4. Resource quota usage analysis

    Returns:
        Dict[str, Any]: A dictionary containing comprehensive Konflux status:
            - namespaces: Categorized list of Konflux-related namespaces
            - components: Deployment statuses organized by namespace
            - pipeline_stats: PipelineRun counts and status breakdown per namespace
            - resource_usage: Resource quota utilization per namespace

    Example output structure:
        {
            "namespaces": {
                "core_konflux": ["konflux-ci"],
                "tekton_related": ["tekton-pipelines"],
                ...
            },
            "components": {
                "konflux-ci": {
                    "deployments": [
                        {"name": "controller", "ready": "2/2", ...}
                    ]
                }
            },
            "pipeline_stats": {
                "user-ns-1": {"total": 50, "status_counts": {"Succeeded": 45, "Failed": 5}}
            },
            "resource_usage": {...}
        }
    """
    try:
        logger.info("Retrieving Konflux components status across all namespaces")

        # First identify all Konflux namespaces
        tekton_namespaces = await detect_tekton_namespaces()

        # Initialize results
        results = {
            "namespaces": tekton_namespaces,
            "components": {},
            "pipeline_stats": {},
            "resource_usage": {}
        }

        # Count total namespaces for logging
        total_namespaces = sum(len(ns_list) for ns_list in tekton_namespaces.values())
        logger.info(f"Found {total_namespaces} Konflux-related namespaces to analyze")

        # For each Konflux namespace, get key resources
        for namespace_type, namespaces in tekton_namespaces.items():
            for namespace in namespaces:
                # Get deployments
                try:
                    deployments = await k8s_call(k8s_apps_api.list_namespaced_deployment, namespace)
                    deployment_statuses = []

                    for deployment in deployments.items:
                        deployment_statuses.append({
                            "name": deployment.metadata.name,
                            "ready": f"{deployment.status.ready_replicas or 0}/{deployment.status.replicas}",
                            "up_to_date": deployment.status.updated_replicas,
                            "available": deployment.status.available_replicas
                        })

                    if deployment_statuses:
                        if namespace not in results["components"]:
                            results["components"][namespace] = {}
                        results["components"][namespace]["deployments"] = deployment_statuses
                        logger.debug(f"Found {len(deployment_statuses)} deployments in {namespace}")

                except ApiException as e:
                    logger.warning(f"Could not get deployments in namespace {namespace}: {e}")

                # Get pipeline runs stats
                try:
                    pipeline_runs = await list_pipelineruns(namespace)
                    if pipeline_runs and isinstance(pipeline_runs, list) and not any("error" in pr for pr in pipeline_runs if isinstance(pr, dict)):
                        # Count by status
                        status_counts = {}
                        for pr in pipeline_runs:
                            status = pr.get("status", "Unknown")
                            status_counts[status] = status_counts.get(status, 0) + 1

                        results["pipeline_stats"][namespace] = {
                            "total": len(pipeline_runs),
                            "status_counts": status_counts
                        }
                        logger.debug(f"Found {len(pipeline_runs)} pipeline runs in {namespace}")

                except Exception as e:
                    logger.warning(f"Could not get pipeline runs in namespace {namespace}: {e}")

                # Get resource quotas
                try:
                    resource_quotas = await k8s_call(k8s_core_api.list_namespaced_resource_quota, namespace)
                    if resource_quotas.items:
                        results["resource_usage"][namespace] = []
                        for quota in resource_quotas.items:
                            quota_data = {
                                "name": quota.metadata.name,
                                "resources": {}
                            }

                            if quota.status.hard and quota.status.used:
                                for resource, hard_limit in quota.status.hard.items():
                                    used = quota.status.used.get(resource, "0")
                                    quota_data["resources"][resource] = {
                                        "limit": hard_limit,
                                        "used": used,
                                        "utilization": calculate_utilization(used, hard_limit)
                                    }

                            results["resource_usage"][namespace].append(quota_data)

                except ApiException as e:
                    logger.warning(f"Could not get resource quotas in namespace {namespace}: {e}")

        # Add summary statistics
        total_deployments = sum(
            len(ns_data.get("deployments", []))
            for ns_data in results["components"].values()
        )
        total_pipelines = sum(
            stats.get("total", 0)
            for stats in results["pipeline_stats"].values()
        )

        results["summary"] = {
            "total_namespaces_analyzed": total_namespaces,
            "namespaces_with_deployments": len(results["components"]),
            "total_deployments": total_deployments,
            "namespaces_with_pipelines": len(results["pipeline_stats"]),
            "total_pipeline_runs": total_pipelines
        }

        logger.info(f"Konflux status complete: {total_deployments} deployments, {total_pipelines} pipeline runs")
        return results

    except Exception as e:
        logger.error(f"Error getting Konflux components status: {e}", exc_info=True)
        return {"error": str(e)}


async def get_pod_logs(
    namespace: str,
    pod_name: str,
    container_name: Optional[str] = None,
    tail_lines: Optional[int] = None,
    since_seconds: Optional[int] = None,
    since_time: Optional[str] = None,
    timestamps: bool = True,
    previous: bool = False,
    clients: Optional["K8sClientSet"] = None,
) -> Dict[str, Any]:
    """
    Get logs from a pod using the same interface expected by analysis tools.

    This function wraps get_all_pod_logs to provide a consistent interface
    for pod log retrieval across all tools in the system.

    Args:
        namespace: Kubernetes namespace containing the pod
        pod_name: Name of the pod to get logs from
        container_name: Specific container name (optional)
        tail_lines: Number of lines to retrieve from end of logs
        since_seconds: Retrieve logs newer than this many seconds
        since_time: Retrieve logs newer than this timestamp
        timestamps: Include timestamps in log output
        previous: Retrieve logs from previous container instance
        clients: Optional K8sClientSet for per-instance dispatch; None uses _DefaultClientView.

    Returns:
        Dict with either:
        - {"logs": {"container_name": "logs", ...}} on success
        - {"error": "error_message"} on failure
    """
    _c = clients if clients is not None else _DefaultClientView()
    try:
        # Call the underlying get_all_pod_logs function
        pod_logs = await get_all_pod_logs(
            pod_name=pod_name,
            namespace=namespace,
            k8s_core_api=ReadOnlyCoreV1.wrap(_c.core_api),
            tail_lines=tail_lines,
            since_seconds=since_seconds,
            since_time=since_time,
            timestamps=timestamps,
            previous=previous
        )

        # Check if we got an error response
        if isinstance(pod_logs, dict):
            # Check for error indicators
            error_keys = [k for k in pod_logs.keys() if k.startswith(('error_', 'pod_error', 'no_'))]
            if error_keys:
                error_msg = pod_logs.get(error_keys[0], "Unknown error retrieving logs")
                return {"error": error_msg}

            # Filter by container if specified
            if container_name:
                if container_name in pod_logs:
                    return {"logs": {container_name: pod_logs[container_name]}}
                else:
                    return {"error": f"Container '{container_name}' not found in pod '{pod_name}'"}

            # Return all container logs
            return {"logs": pod_logs}

        # Handle unexpected response format
        return {"error": f"Unexpected response format from get_all_pod_logs: {type(pod_logs)}"}

    except Exception as e:
        logger.error(f"Error in get_pod_logs for pod {pod_name} in namespace {namespace}: {e}")
        return {"error": f"Failed to retrieve logs: {str(e)}"}


@mcp.tool()
async def analyze_logs(log_text: str, source: str = "") -> Dict[str, Any]:
    """
    Analyze log text to extract error patterns and insights.

    Args:
        log_text: Log content string (single entry, multiple lines, or full log file).
        source: Declared provenance of the supplied text (default ""). Any registered
                source is accepted as audit metadata — no cluster contact is made.
                Unknown (unregistered) sources return the canonical unknown-source error.

    Returns:
        Dict[str, Any]: Keys: error_count, error_patterns, categorized_errors, summary.
    """
    _gate_err = _gate_source("analyze_logs", source, ())
    if _gate_err:
        return _gate_err
    return _scan_logs(log_text)


async def analyze_failed_pipeline(namespace: str, pipeline_run: str, source: str = "") -> Dict[str, Any]:
    """
    Perform root cause analysis on a failed Tekton PipelineRun.

    Fetches pipeline/task details, analyzes logs for errors, and provides remediation recommendations.

    Args:
        namespace: Kubernetes namespace of the PipelineRun.
        pipeline_run: Name of the failed PipelineRun.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, Any]: Keys: pipeline_name, pipeline_status, overall_message, failed_task_count,
                        failed_tasks, probable_root_cause, recommended_actions.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    _gerr = _gate_extension("analyze_failed_pipeline", source)
    if _gerr:
        return _gerr
    try:
        logger.info(f"Analyzing failed pipeline '{pipeline_run}' in namespace '{namespace}'")

        # Get pipeline details
        pipeline_details = await get_pipeline_details(
            namespace, pipeline_run, _clients.custom_api,
            functools.partial(list_taskruns, source=source), calculate_duration, logger
        )

        if pipeline_details.get("error_code") == 404:
            return {
                "status": "not_found",
                "namespace": namespace,
                "pipeline_run": pipeline_run,
                "message": (
                    f"PipelineRun '{pipeline_run}' not found in namespace '{namespace}'"
                    " — it may have been pruned or completed and garbage-collected"
                ),
                "suggestions": [
                    "list_pipelineruns to see current runs",
                    "query_kubearchive for archived runs",
                ],
            }

        if "error" in pipeline_details:
            return {"error": pipeline_details["error"]}

        # Check if the pipeline actually failed
        if pipeline_details.get("status") in ("Succeeded", "Unknown"):
            return {
                "error": f"Pipeline status {pipeline_details.get('status')!r} is not a definitive failure",
                "pipeline_status": pipeline_details.get("status")
            }

        # Find failed tasks
        failed_tasks = [
            task for task in pipeline_details.get("task_runs", [])
            if task.get("status") not in (
                "Succeeded", "Running", "Started", "Pending", "TaskRunPending",
                "Unknown", None
            )
        ]

        results = {
            "pipeline_name": pipeline_details.get("pipeline"),
            "pipeline_status": pipeline_details.get("status"),
            "overall_message": pipeline_details.get("message"),
            "failed_task_count": len(failed_tasks),
            "failed_tasks": []
        }

        logger.info(f"Found {len(failed_tasks)} failed tasks in pipeline '{pipeline_run}'")

        # Detailed analysis of each failed task
        for task in failed_tasks:
            task_name = task.get("name")
            task_details = await get_task_details(
                namespace, task_name, _clients.custom_api, calculate_duration, logger
            )

            # Get logs for the pod associated with this task
            pod_name = task_details.get("pod", "unknown")
            pod_logs_available = True
            log_content = ""
            logs_unavailable_reason = None

            if pod_name == "unknown":
                pod_logs_available = False
                logs_unavailable_reason = "No pod associated with this task"
            else:
                pod_logs = await get_pod_logs(namespace, pod_name, clients=_clients)

                # Extract log content as string for analysis
                if isinstance(pod_logs, dict) and "logs" in pod_logs:
                    for container, logs in pod_logs["logs"].items():
                        if isinstance(logs, list):
                            log_content += "\n".join(logs)
                        else:
                            log_content += str(logs)
                elif isinstance(pod_logs, dict) and "error" in pod_logs:
                    pod_logs_available = False
                    error_msg = pod_logs.get("error", "")
                    if "Not Found" in error_msg:
                        logs_unavailable_reason = "Pod was deleted (normal for completed pipelines)"
                    else:
                        logs_unavailable_reason = error_msg

            # Build failed step info from TaskRun status as fallback/supplement
            failed_steps = []
            for step in task_details.get("steps", []):
                if step.get("exit_code") is not None and step.get("exit_code") != 0:
                    failed_steps.append({
                        "step_name": step.get("name"),
                        "exit_code": step.get("exit_code"),
                        "reason": step.get("reason")
                    })

            # Analyze logs if available, otherwise use step info for context
            if pod_logs_available and log_content.strip():
                log_analysis = await analyze_logs(log_content)
                error_patterns = log_analysis.get("error_patterns", [])
                error_categories = log_analysis.get("categorized_errors", {})

                # If log analysis found nothing but steps failed, supplement with step info
                if not error_patterns and failed_steps:
                    task_message = task_details.get("message", "")
                    for step in failed_steps:
                        step_msg = f"Step '{step['step_name']}' failed with exit code {step['exit_code']}"
                        if step.get("reason"):
                            step_msg += f" (reason: {step['reason']})"
                        error_patterns.append(step_msg)
                    if task_message:
                        error_patterns.append(f"Task message: {task_message}")
                    error_categories["step_failures"] = len(failed_steps)
            else:
                # Use step failure info when logs unavailable
                error_patterns = []
                error_categories = {}
                for step in failed_steps:
                    error_patterns.append(f"Step '{step['step_name']}' failed with exit code {step['exit_code']}")
                if failed_steps:
                    error_categories["step_failures"] = len(failed_steps)

            # Build task result
            task_result = {
                "task_name": task.get("task"),
                "task_run": task_name,
                "status": task_details.get("status"),
                "message": task_details.get("message"),
                "error_patterns": error_patterns,
                "error_categories": error_categories,
                "pod": pod_name,
                "failed_steps": failed_steps
            }

            # Add note if logs were unavailable
            if not pod_logs_available:
                task_result["logs_unavailable"] = True
                task_result["logs_unavailable_reason"] = logs_unavailable_reason

            results["failed_tasks"].append(task_result)

        # Determine root cause and recommend actions
        results["probable_root_cause"] = determine_root_cause(results)
        actions = recommend_actions(results)
        seen = set()
        results["recommended_actions"] = [a for a in actions if a not in seen and not seen.add(a)]

        logger.info(f"Pipeline analysis complete. Root cause: {results['probable_root_cause'][:50]}...")
        return results

    except Exception as e:
        logger.error(f"Error analyzing failed pipeline {pipeline_run}: {e}", exc_info=True)
        return {"error": str(e)}


async def list_recent_pipeline_runs(limit: int = 10, source: str = "") -> Dict[str, Any]:
    """
    List recent Tekton PipelineRuns across all accessible namespaces, sorted by start time.

    Args:
        limit: Max PipelineRuns to retrieve (default: 10).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, Any]: Namespace to PipelineRun list on success (``{ns: [run_dicts]}``),
                        where each run has: namespace, name, start_time, status, pipeline, labels;
                        or ``{"error": message}`` when the source is invalid or access is denied.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return {"error": _err["error"]}
    _gerr = _gate_extension("list_recent_pipeline_runs", source)
    if _gerr:
        return {"error": _gerr["error"]}
    results: Dict[str, List[Dict[str, Any]]] = {}

    try:
        logger.info(f"Listing recent pipeline runs across all namespaces (limit: {limit})")

        # Use cluster-wide query with limit for performance (single API call)
        # Use a fixed fetch limit for consistent results regardless of requested limit
        # The API doesn't sort, so we need to fetch enough to ensure we get the most recent
        fetch_limit = 200  # Fixed limit for consistent results

        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)
        pipeline_runs = await k8s_call(_ro.list_cluster_custom_object,
            group="tekton.dev",
            version="v1",
            plural="pipelineruns",
            limit=fetch_limit
        )

        # Collect all pipeline runs
        all_runs: List[Dict[str, Any]] = []

        for pr in pipeline_runs.get("items", []):
            status = pr.get("status", {})
            metadata = pr.get("metadata", {})
            namespace = metadata.get("namespace", "unknown")

            # Get the start time for sorting
            start_time = status.get("startTime")
            if not start_time:
                # If no start time, use creation time
                start_time = metadata.get("creationTimestamp")

            if start_time:
                # Get status from conditions
                conditions = status.get("conditions", [])
                current_status = "Unknown"
                if conditions:
                    current_status = conditions[-1].get("reason", "Unknown")

                # Get pipeline name from multiple sources (same logic as list_pipelineruns)
                spec = pr.get("spec", {})
                labels = metadata.get("labels", {})
                pipeline_name = "unknown"

                # 1. Check spec.pipelineRef.name (direct reference)
                pipeline_ref = spec.get("pipelineRef", {})
                if pipeline_ref and pipeline_ref.get("name"):
                    pipeline_name = pipeline_ref.get("name")

                # 2. Check common Tekton labels (used by Konflux)
                if pipeline_name == "unknown":
                    pipeline_name = (
                        labels.get("tekton.dev/pipeline") or
                        labels.get("pipelines.tekton.dev/pipeline") or
                        labels.get("pipelines.openshift.io/pipeline") or
                        "unknown"
                    )

                # 3. Check inline pipelineSpec
                if pipeline_name == "unknown":
                    pipeline_spec = spec.get("pipelineSpec", {})
                    if pipeline_spec:
                        pipeline_name = (
                            pipeline_spec.get("displayName") or
                            pipeline_spec.get("name") or
                            "inline-pipeline"
                        )

                all_runs.append({
                    "namespace": namespace,
                    "name": metadata.get("name", "unknown"),
                    "start_time": start_time,
                    "status": current_status,
                    "pipeline": pipeline_name,
                    "labels": labels
                })

        logger.info(f"Found {len(all_runs)} pipeline runs from cluster-wide query")

        # Sort by start time (most recent first)
        # Use 'or ""' to handle None values
        all_runs.sort(key=lambda x: x.get("start_time") or "", reverse=True)

        # Group by namespace (limited to top N)
        for run in all_runs[:limit]:
            namespace = run["namespace"]
            if namespace not in results:
                results[namespace] = []
            results[namespace].append(run)

        return results

    except Exception as e:
        logger.error(f"Error listing recent pipeline runs: {e}", exc_info=True)
        return {"error": str(e)}


# @mcp.tool()  # Commented out - Konflux-specific tool
async def track_pipeline_across_namespaces(pipeline_id: str) -> Dict[str, Any]:
    """
    Tracks a specific Konflux pipeline and its associated components across all accessible namespaces.

    This tool provides a comprehensive, holistic view of a Konflux pipeline identified by a unique
    pipeline_id, regardless of which namespace its various execution components reside in.
    Konflux pipelines can span multiple namespaces in multi-tenant or complex deployment scenarios.

    The tracking process involves:
    1. Iterating through all accessible Konflux-related namespaces
    2. Searching for Tekton resources (PipelineRuns, TaskRuns) associated with the pipeline_id
    3. Aggregating status, logs, and metadata of all found components
    4. Constructing a coherent view of the pipeline's execution flow across namespaces

    Args:
        pipeline_id: The unique identifier for the Konflux pipeline to track.
                    This could be a PipelineRun name, Application name, or other identifier
                    that links related resources via labels or naming conventions.

    Returns:
        Dict[str, Any]: Aggregated status and details containing:
            - pipeline_id: The identifier being tracked
            - pipeline_runs: List of associated PipelineRun details with namespace info
            - task_runs: List of associated TaskRun details with namespace info
            - pods: List of related pods with log summaries
            - related_resources: Other resources linked to this pipeline
    """
    try:
        logger.info(f"Tracking pipeline '{pipeline_id}' across all namespaces")

        # Get all relevant namespaces
        tekton_namespaces = await detect_tekton_namespaces()
        all_namespaces = []
        for ns_list in tekton_namespaces.values():
            all_namespaces.extend(ns_list)

        logger.info(f"Searching {len(all_namespaces)} namespaces for pipeline '{pipeline_id}'")

        # Track pipeline components
        results = {
            "pipeline_id": pipeline_id,
            "pipeline_runs": [],
            "task_runs": [],
            "pods": [],
            "related_resources": []
        }

        # Look for pipeline runs in all namespaces
        for namespace in all_namespaces:
            # Look for exact pipeline run by name
            try:
                pipeline_run = await get_pipeline_details(
                    namespace, pipeline_id, k8s_custom_api, list_taskruns, calculate_duration, logger
                )
                if "error" not in pipeline_run:
                    results["pipeline_runs"].append({
                        "namespace": namespace,
                        "details": pipeline_run
                    })

                    # Get related task runs
                    task_runs = await list_taskruns(namespace, pipeline_id)
                    for task_run in task_runs:
                        task_details = await get_task_details(
                            namespace, task_run["name"], k8s_custom_api, calculate_duration, logger
                        )
                        results["task_runs"].append({
                            "namespace": namespace,
                            "details": task_details
                        })

                        # Get related pod
                        pod_name = task_details.get("pod")
                        if pod_name and pod_name != "unknown":
                            pod_logs_result = await get_pod_logs(namespace, pod_name)

                            # Extract log content as string for analysis
                            if isinstance(pod_logs_result, dict) and "logs" in pod_logs_result:
                                log_content = ""
                                for pod, logs in pod_logs_result["logs"].items():
                                    if isinstance(logs, list):
                                        log_content += "\n".join(logs)
                                    else:
                                        log_content += str(logs)
                            else:
                                log_content = str(pod_logs_result) if pod_logs_result else "No pod logs available"

                            log_analysis = await analyze_logs(log_content)

                            results["pods"].append({
                                "namespace": namespace,
                                "name": pod_name,
                                "log_summary": generate_log_summary(
                                    log_content,
                                    log_analysis.get("error_patterns", []),
                                    log_analysis.get("categorized_errors", {})
                                )
                            })
            except Exception as e:
                logger.warning(f"Error tracking pipeline in namespace {namespace}: {e}")

        # Check for pipeline related resources by labels
        truncated_namespaces = []
        for namespace in all_namespaces:
            try:
                # Look for resources with labels related to this pipeline
                pods = await list_pods(namespace, k8s_core_api, logger)
                if any("_truncation" in p for p in pods):
                    logger.warning(
                        f"pod list for {namespace} truncated at limit; analysis covers a sample")
                    truncated_namespaces.append(namespace)
                pods = [p for p in pods if "_truncation" not in p]
                for pod in pods:
                    labels = pod.get("labels", {})
                    # Check if this pod is related to our pipeline
                    if labels and (
                        labels.get("tekton.dev/pipelineRun") == pipeline_id or
                        labels.get("konflux.pipeline") == pipeline_id or
                        pipeline_id in labels.get("tekton.dev/pipelineRun", "") or
                        pipeline_id in pod.get("name", "")
                    ):
                        results["related_resources"].append({
                            "kind": "Pod",
                            "namespace": namespace,
                            "name": pod.get("name"),
                            "status": pod.get("status")
                        })
            except Exception as e:
                logger.warning(f"Error finding related resources in namespace {namespace}: {e}")

        # Add summary
        results["summary"] = {
            "pipeline_runs_found": len(results["pipeline_runs"]),
            "task_runs_found": len(results["task_runs"]),
            "pods_found": len(results["pods"]),
            "related_resources_found": len(results["related_resources"]),
            "namespaces_searched": len(all_namespaces)
        }
        if truncated_namespaces:
            results["pod_analysis_truncated"] = {
                "limit": 200,
                "namespaces": truncated_namespaces,
                "note": "namespace has more pods than the analysis limit; results cover a sample",
            }

        logger.info(f"Pipeline tracking complete: {results['summary']}")
        return results

    except Exception as e:
        logger.error(f"Error tracking pipeline across namespaces: {e}", exc_info=True)
        return {"error": str(e)}


async def find_pipeline(
    pipeline_id_pattern: str,
    include_taskruns: bool = False,
    max_results: int = 100,
    namespaces: Optional[List[str]] = None,
    pipeline_runs_limit: int = 1000,
    task_runs_limit: int = 500,
    source: str = ""
) -> Dict[str, Any]:
    """
    Find Tekton pipelines matching a pattern across all accessible namespaces.

    Searches PipelineRuns/TaskRuns by name, labels, or annotations using cluster-wide queries.

    Args:
        pipeline_id_pattern: Pattern to match (partial name, label value, or substring).
        include_taskruns: Include TaskRuns in search results (default: False for performance).
        max_results: Maximum matching results to return per resource type (default: 100).
        namespaces: Optional list of namespaces to search (default: all namespaces).
        pipeline_runs_limit: Max PipelineRuns to fetch from API (default: 1000).
        task_runs_limit: Max TaskRuns to fetch from API if include_taskruns=True (default: 500).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, Any]: Keys: pipeline_runs, task_runs, pipelines_as_code, all_namespaces_checked,
                        diagnostic_info, substring_matches.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    _gerr = _gate_extension("find_pipeline", source)
    if _gerr:
        return _gerr
    from concurrent.futures import ThreadPoolExecutor

    results = {
        "pipeline_runs": [],
        "task_runs": [],
        "all_namespaces_checked": [],
        "diagnostic_info": {}
    }

    try:
        logger.info(f"Searching for pipeline pattern '{pipeline_id_pattern}' (include_taskruns={include_taskruns}, max_results={max_results})")
        pattern_lower = pipeline_id_pattern.lower()

        # Use ThreadPoolExecutor for parallel API calls
        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=3)
        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)

        def fetch_pipelineruns_namespaced(ns: str):
            try:
                return _ro.list_namespaced_custom_object(
                    group="tekton.dev",
                    version="v1",
                    namespace=ns,
                    plural="pipelineruns",
                    limit=pipeline_runs_limit
                )
            except ApiException as e:
                return {"error": str(e), "items": []}

        def fetch_pipelineruns_cluster():
            try:
                # Cap at 200 to avoid multi-MB responses causing IncompleteRead
                safe_limit = min(pipeline_runs_limit, 200)
                return _ro.list_cluster_custom_object(
                    group="tekton.dev",
                    version="v1",
                    plural="pipelineruns",
                    limit=safe_limit
                )
            except ApiException as e:
                return {"error": str(e), "items": []}

        def fetch_taskruns_namespaced(ns: str):
            try:
                return _ro.list_namespaced_custom_object(
                    group="tekton.dev",
                    version="v1",
                    namespace=ns,
                    plural="taskruns",
                    limit=task_runs_limit
                )
            except ApiException as e:
                return {"error": str(e), "items": []}

        def fetch_taskruns_cluster():
            try:
                # Cap at 100 -- cluster-wide TaskRun LIST is the most expensive
                # call (~97MB response). Prefer namespace-scoped queries instead.
                safe_limit = min(task_runs_limit, 100)
                return _ro.list_cluster_custom_object(
                    group="tekton.dev",
                    version="v1",
                    plural="taskruns",
                    limit=safe_limit
                )
            except ApiException as e:
                return {"error": str(e), "items": []}

        def fetch_repositories():
            try:
                return _ro.list_cluster_custom_object(
                    group="pipelinesascode.tekton.dev",
                    version="v1alpha1",
                    plural="repositories",
                    limit=500
                )
            except ApiException as e:
                return {"error": str(e), "items": []}

        # Fetch based on namespace targeting
        if namespaces:
            # Targeted namespace search - fetch from specific namespaces in parallel
            logger.info(f"Searching in {len(namespaces)} specified namespaces")
            pr_futures = [loop.run_in_executor(executor, fetch_pipelineruns_namespaced, ns) for ns in namespaces]
            pipeline_runs_resps = await asyncio.gather(*pr_futures)
            pipeline_runs_resp = {"items": []}
            for resp in pipeline_runs_resps:
                if "error" not in resp:
                    pipeline_runs_resp["items"].extend(resp.get("items", []))
                else:
                    pipeline_runs_resp["error"] = resp.get("error")

            if include_taskruns:
                tr_futures = [loop.run_in_executor(executor, fetch_taskruns_namespaced, ns) for ns in namespaces]
                task_runs_resps = await asyncio.gather(*tr_futures)
                task_runs_resp = {"items": []}
                for resp in task_runs_resps:
                    if "error" not in resp:
                        task_runs_resp["items"].extend(resp.get("items", []))
                    else:
                        task_runs_resp["error"] = resp.get("error")
            else:
                task_runs_resp = {"items": [], "skipped": True}

            repo_future = loop.run_in_executor(executor, fetch_repositories)
            repositories_resp = await repo_future
        else:
            # Cluster-wide search with limits
            pr_future = loop.run_in_executor(executor, fetch_pipelineruns_cluster)
            repo_future = loop.run_in_executor(executor, fetch_repositories)

            if include_taskruns:
                tr_future = loop.run_in_executor(executor, fetch_taskruns_cluster)
                pipeline_runs_resp, task_runs_resp, repositories_resp = await asyncio.gather(
                    pr_future, tr_future, repo_future
                )
            else:
                pipeline_runs_resp, repositories_resp = await asyncio.gather(pr_future, repo_future)
                task_runs_resp = {"items": [], "skipped": True}

        # Track namespaces found and counts for sampling info
        namespaces_seen = set()
        pr_total_scanned = 0
        tr_total_scanned = 0
        pr_matches_truncated = False
        tr_matches_truncated = False

        # Process PipelineRuns with max_results limit
        if "error" in pipeline_runs_resp:
            results["diagnostic_info"]["pipelineruns_error"] = pipeline_runs_resp["error"]

        pr_items = pipeline_runs_resp.get("items", [])
        for pr in pr_items:
            pr_total_scanned += 1
            namespace = pr.get("metadata", {}).get("namespace", "")
            namespaces_seen.add(namespace)
            pr_name = pr.get("metadata", {}).get("name", "")
            labels = pr.get("metadata", {}).get("labels", {})

            if (pattern_lower in pr_name.lower() or
                    any(pattern_lower in str(v).lower() for v in labels.values())):
                if len(results["pipeline_runs"]) >= max_results:
                    pr_matches_truncated = True
                    break  # Stop processing once max_results reached
                status = pr.get("status", {})
                conditions = status.get("conditions", [{}])
                condition = conditions[-1] if conditions else {}

                results["pipeline_runs"].append({
                    "namespace": namespace,
                    "name": pr_name,
                    "status": condition.get("reason", "Unknown"),
                    "message": condition.get("message", ""),
                    "started_at": status.get("startTime", "unknown"),
                    "completion_time": status.get("completionTime", "unknown"),
                    "labels": labels
                })

        # Process TaskRuns only if include_taskruns is True
        if task_runs_resp.get("skipped"):
            results["diagnostic_info"]["taskruns_skipped"] = "Set include_taskruns=True to search TaskRuns"
        else:
            if "error" in task_runs_resp:
                results["diagnostic_info"]["taskruns_error"] = task_runs_resp["error"]

            tr_items = task_runs_resp.get("items", [])
            for tr in tr_items:
                tr_total_scanned += 1
                namespace = tr.get("metadata", {}).get("namespace", "")
                namespaces_seen.add(namespace)
                tr_name = tr.get("metadata", {}).get("name", "")
                labels = tr.get("metadata", {}).get("labels", {})
                pipeline_run = labels.get("tekton.dev/pipelineRun", "")

                if (pattern_lower in tr_name.lower() or
                    pattern_lower in pipeline_run.lower() or
                        any(pattern_lower in str(v).lower() for v in labels.values())):
                    if len(results["task_runs"]) >= max_results:
                        tr_matches_truncated = True
                        break  # Stop processing once max_results reached
                    status = tr.get("status", {})
                    conditions = status.get("conditions", [{}])
                    condition = conditions[-1] if conditions else {}

                    results["task_runs"].append({
                        "namespace": namespace,
                        "name": tr_name,
                        "pipeline_run": pipeline_run,
                        "status": condition.get("reason", "Unknown"),
                        "message": condition.get("message", ""),
                        "pod_name": status.get("podName", "unknown"),
                        "labels": labels
                    })

        # Process Repositories
        # When namespaces filter is specified, only include repositories from those namespaces
        if "error" in repositories_resp:
            results["diagnostic_info"]["repositories_error"] = repositories_resp["error"]
        for repo in repositories_resp.get("items", []):
            namespace = repo.get("metadata", {}).get("namespace", "")
            repo_name = repo.get("metadata", {}).get("name", "")

            # Skip repositories not in the specified namespaces filter
            if namespaces and namespace not in namespaces:
                continue

            # Only add to namespaces_seen if we're actually considering this repository
            namespaces_seen.add(namespace)

            if pattern_lower in repo_name.lower():
                spec = repo.get("spec", {})
                status = repo.get("status", {})
                results.setdefault("pipelines_as_code", []).append({
                    "namespace": namespace,
                    "name": repo_name,
                    "url": spec.get("url", "unknown"),
                    "runs": status.get("runs", [])
                })

        # Set all_namespaces_checked based on what was actually searched
        # If namespaces filter was provided, show those; otherwise show discovered namespaces
        if namespaces:
            results["all_namespaces_checked"] = sorted(namespaces)
        else:
            results["all_namespaces_checked"] = sorted(namespaces_seen)

        # Add summary with sampling info
        results["summary"] = {
            "pipeline_runs_found": len(results["pipeline_runs"]),
            "task_runs_found": len(results["task_runs"]),
            "namespaces_with_tekton_resources": len(namespaces_seen),
            "pipeline_runs_scanned": pr_total_scanned,
            "task_runs_scanned": tr_total_scanned,
            "pipeline_runs_truncated": pr_matches_truncated,
            "task_runs_truncated": tr_matches_truncated,
            "include_taskruns": include_taskruns,
            "max_results_limit": max_results
        }

        logger.info(f"Pipeline search complete: {results['summary']}")
        return results

    except Exception as e:
        logger.error(f"Error finding pipeline {pipeline_id_pattern}: {e}", exc_info=True)
        return {"error": str(e), "diagnostic_info": results.get("diagnostic_info", {})}


def _is_cancelled_reason(reason: str) -> bool:
    """True for Tekton cancellation reasons (operator action, not a failure).

    Exact-match set (review MINOR-5): a substring check swallowed
    PipelineRunCouldntCancel / TaskRunCouldntCancel, which are genuine
    ERROR conditions (Tekton failed to cancel), not operator actions.
    """
    return (reason or "").lower() in {
        "cancelled", "pipelineruncancelled", "taskruncancelled",
        # Tekton v1 graceful-cancel-during-finally reasons (re-review
        # MAJOR-1: these spell "Running", not "Run")
        "cancelledrunningfinally", "stoppedrunningfinally",
    }


async def get_tekton_pipeline_runs_status(
    pipeline_runs_limit: int = 500,
    task_runs_limit_per_namespace: int = 100,
    max_namespaces: int = 20,
    recent_failures_limit: int = 10,
    long_running_limit: int = 5,
    source: str = ""
) -> Dict[str, Any]:
    """
    Get cluster-wide status summary of all Tekton PipelineRuns and TaskRuns.

    Shows running/succeeded/failed counts, recent failures, and long-running pipelines (>1 hour).

    Args:
        pipeline_runs_limit: Max PipelineRuns to fetch cluster-wide (default: 500).
        task_runs_limit_per_namespace: Max TaskRuns to fetch per namespace (default: 100).
        max_namespaces: Max namespaces to scan for TaskRuns (default: 20).
        recent_failures_limit: Max recent failures to include in output (default: 10).
        long_running_limit: Max long-running pipelines to include (default: 5).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, Any]: Keys: timestamp, sampling_info, pipeline_runs (total, by_status,
                        recent_failures [top N, newest first, genuine failures only],
                        recent_cancelled [top N, operator cancellations],
                        failures_by_namespace, long_running [top N]),
                        task_runs (total, by_status, recent_failures, recent_cancelled,
                        failures_by_namespace), insights. Counts reflect the sample
                        (see sampling_info), not a full cluster census.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    _gerr = _gate_extension("get_tekton_pipeline_runs_status", source)
    if _gerr:
        return _gerr
    try:
        logger.info("Fetching cluster-wide Tekton PipelineRuns and TaskRuns status")

        # Cap the limit to avoid massive responses that cause IncompleteRead errors.
        # Cluster-wide LIST on pipelineruns can return multi-MB responses.
        safe_pr_limit = min(pipeline_runs_limit, 200)
        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)
        _ro_core = ReadOnlyK8sClient.wrap(_clients.core_api)

        # Discovery: one cluster-wide PR list; derive active namespaces from PR metadata.
        # The previous per-namespace probe was broken: the tenant label-selector returned
        # alphabetically-early dormant namespaces, exhausting the cap before reaching
        # namespaces with active runs (F-02, confirmed live on stone-stg-rh01).
        pipeline_runs_result = await k8s_call(_ro.list_cluster_custom_object,
            group="tekton.dev", version="v1",
            plural="pipelineruns", limit=safe_pr_limit
        )
        pipeline_runs_items = pipeline_runs_result.get('items', [])
        active_namespaces = set()
        for pr in pipeline_runs_items:
            ns = pr.get('metadata', {}).get('namespace')
            if ns:
                active_namespaces.add(ns)

        # Tenant-label filter: narrow active_namespaces to known tenant namespaces
        # (option-a controller ruling — keeps the list_namespace call so ReadOnlyK8sClient
        # wraps it per spec 1e; deleting it breaks test_tekton_status_core_read_routes_readonly).
        # Guard: only apply the intersection when it leaves something — a disjoint tenant
        # set (e.g. dormant alphabetical tenants vs. real pipeline namespaces) must not
        # silently zero out active_namespaces (same failure mode as the original F-02 probe).
        try:
            ns_list = await k8s_call(_ro_core.list_namespace,
                label_selector="toolchain.dev.openshift.com/type=tenant"
            )
            tenant_namespaces = {ns.metadata.name for ns in ns_list.items}
            narrowed = active_namespaces & tenant_namespaces
            if narrowed:
                active_namespaces = narrowed
        except Exception as e:
            logger.debug(f"Tenant namespace filter skipped (list_namespace failed): {e}")

        pipeline_runs = {'items': pipeline_runs_items}

        # Fetch TaskRuns only from active namespaces with limits
        task_runs_items = []
        for ns in list(active_namespaces)[:max_namespaces]:
            try:
                ns_task_runs = await k8s_call(_ro.list_namespaced_custom_object,
                    group="tekton.dev", version="v1",
                    namespace=ns, plural="taskruns",
                    limit=task_runs_limit_per_namespace
                )
                task_runs_items.extend(ns_task_runs.get('items', []))
            except Exception as e:
                logger.debug(f"Error fetching TaskRuns from {ns}: {e}")
                continue

        task_runs = {'items': task_runs_items}

        analysis = {
            'timestamp': datetime.now().isoformat(),
            'sampling_info': {
                'pipeline_runs_limit': pipeline_runs_limit,
                'task_runs_limit_per_namespace': task_runs_limit_per_namespace,
                'max_namespaces': max_namespaces,
                'namespaces_sampled': min(len(active_namespaces), max_namespaces),
                'recent_failures_limit': recent_failures_limit,
                'long_running_limit': long_running_limit,
                'note': ('Results are sampled to prevent timeout on large '
                         'clusters — counts and success ratios reflect the '
                         'sample, not a full census of the cluster')
            },
            'pipeline_runs': {
                'total': len(pipeline_runs.get('items', [])),
                'by_status': {},
                'recent_failures': [],
                'recent_cancelled': [],
                'long_running': []
            },
            'task_runs': {
                'total': len(task_runs.get('items', [])),
                'by_status': {},
                'recent_failures': [],
                'recent_cancelled': []
            },
            'insights': []
        }

        logger.info(f"Analyzing {analysis['pipeline_runs']['total']} PipelineRuns and {analysis['task_runs']['total']} TaskRuns")

        # Analyze PipelineRuns
        for pr in pipeline_runs.get('items', []):
            status = pr.get('status', {})
            conditions = status.get('conditions', [])

            # Get latest condition
            if conditions:
                latest_condition = conditions[-1]
                condition_type = latest_condition.get('type', 'Unknown')
                condition_status = latest_condition.get('status', 'Unknown')

                status_key = f"{condition_type}_{condition_status}"
                analysis['pipeline_runs']['by_status'][status_key] = \
                    analysis['pipeline_runs']['by_status'].get(status_key, 0) + 1

                # Check for failures. Cancelled is an operator action, not a
                # failure — live finding 2026-08-21: cancelled runs listed as
                # recent_failures buried the real ones on rh01 and p02.
                if condition_type == 'Succeeded' and condition_status == 'False':
                    failure_info = {
                        'name': pr.get('metadata', {}).get('name', 'unknown'),
                        'namespace': pr.get('metadata', {}).get('namespace', 'unknown'),
                        'reason': latest_condition.get('reason', 'Unknown'),
                        'message': latest_condition.get('message', 'No message')[:200],  # Truncate long messages
                        'start_time': status.get('startTime', 'Unknown')
                    }
                    if _is_cancelled_reason(failure_info['reason']):
                        analysis['pipeline_runs']['recent_cancelled'].append(failure_info)
                    else:
                        analysis['pipeline_runs']['recent_failures'].append(failure_info)

                # Check for long-running pipelines
                start_time_str = status.get('startTime')
                if start_time_str and not status.get('completionTime'):
                    try:
                        start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                        runtime = datetime.now(start_time.tzinfo) - start_time
                        if runtime.total_seconds() > 3600:  # 1 hour
                            long_running_info = {
                                'name': pr.get('metadata', {}).get('name', 'unknown'),
                                'namespace': pr.get('metadata', {}).get('namespace', 'unknown'),
                                'runtime_hours': round(runtime.total_seconds() / 3600, 2),
                                'start_time': start_time_str
                            }
                            analysis['pipeline_runs']['long_running'].append(long_running_info)
                    except Exception as e:
                        logger.debug(f"Error parsing start time for PipelineRun: {e}")

        # Analyze TaskRuns
        for tr in task_runs.get('items', []):
            status = tr.get('status', {})
            conditions = status.get('conditions', [])

            # Get latest condition
            if conditions:
                latest_condition = conditions[-1]
                condition_type = latest_condition.get('type', 'Unknown')
                condition_status = latest_condition.get('status', 'Unknown')

                status_key = f"{condition_type}_{condition_status}"
                analysis['task_runs']['by_status'][status_key] = \
                    analysis['task_runs']['by_status'].get(status_key, 0) + 1

                # Check for failures (cancelled routed separately; see PR loop)
                if condition_type == 'Succeeded' and condition_status == 'False':
                    failure_info = {
                        'name': tr.get('metadata', {}).get('name', 'unknown'),
                        'namespace': tr.get('metadata', {}).get('namespace', 'unknown'),
                        'reason': latest_condition.get('reason', 'Unknown'),
                        'message': latest_condition.get('message', 'No message')[:200],
                        'start_time': status.get('startTime', 'Unknown')
                    }
                    if _is_cancelled_reason(failure_info['reason']):
                        analysis['task_runs']['recent_cancelled'].append(failure_info)
                    else:
                        analysis['task_runs']['recent_failures'].append(failure_info)

        # Aggregate failures by namespace for summary
        pr_failures_by_namespace: Dict[str, int] = {}
        for f in analysis['pipeline_runs']['recent_failures']:
            ns = f.get('namespace', 'unknown')
            pr_failures_by_namespace[ns] = pr_failures_by_namespace.get(ns, 0) + 1

        tr_failures_by_namespace: Dict[str, int] = {}
        for f in analysis['task_runs']['recent_failures']:
            ns = f.get('namespace', 'unknown')
            tr_failures_by_namespace[ns] = tr_failures_by_namespace.get(ns, 0) + 1

        # Store total counts before truncating
        total_pr_failures = len(analysis['pipeline_runs']['recent_failures'])
        total_tr_failures = len(analysis['task_runs']['recent_failures'])
        total_long_running = len(analysis['pipeline_runs']['long_running'])
        total_pr_cancelled = len(analysis['pipeline_runs']['recent_cancelled'])
        total_tr_cancelled = len(analysis['task_runs']['recent_cancelled'])

        # Sort cancelled newest-first and apply the same limit
        for _bucket in (analysis['pipeline_runs'], analysis['task_runs']):
            _bucket['recent_cancelled'].sort(
                key=lambda x: x.get('start_time') or '', reverse=True)
            _bucket['recent_cancelled'] = _bucket['recent_cancelled'][:recent_failures_limit]

        # Sort failures by start_time (most recent first) and apply limit
        # Use 'or ""' to handle None values (not just missing keys)
        analysis['pipeline_runs']['recent_failures'].sort(
            key=lambda x: x.get('start_time') or '', reverse=True
        )
        analysis['pipeline_runs']['recent_failures'] = analysis['pipeline_runs']['recent_failures'][:recent_failures_limit]

        analysis['task_runs']['recent_failures'].sort(
            key=lambda x: x.get('start_time') or '', reverse=True
        )
        analysis['task_runs']['recent_failures'] = analysis['task_runs']['recent_failures'][:recent_failures_limit]

        # Sort long_running by runtime (longest first) and apply limit
        analysis['pipeline_runs']['long_running'].sort(
            key=lambda x: x.get('runtime_hours', 0), reverse=True
        )
        analysis['pipeline_runs']['long_running'] = analysis['pipeline_runs']['long_running'][:long_running_limit]

        # Add counts and aggregations
        analysis['pipeline_runs']['total_failures'] = total_pr_failures
        analysis['pipeline_runs']['failures_by_namespace'] = pr_failures_by_namespace
        analysis['pipeline_runs']['total_long_running'] = total_long_running

        analysis['task_runs']['total_failures'] = total_tr_failures
        analysis['task_runs']['failures_by_namespace'] = tr_failures_by_namespace
        analysis['pipeline_runs']['total_cancelled'] = total_pr_cancelled
        analysis['task_runs']['total_cancelled'] = total_tr_cancelled

        # Generate insights
        if total_pr_failures > 0:
            shown = min(total_pr_failures, recent_failures_limit)
            analysis['insights'].append(f"Found {total_pr_failures} failed PipelineRuns (showing top {shown} most recent)")

        if total_tr_failures > 0:
            shown = min(total_tr_failures, recent_failures_limit)
            analysis['insights'].append(f"Found {total_tr_failures} failed TaskRuns (showing top {shown} most recent)")

        if total_long_running > 0:
            shown = min(total_long_running, long_running_limit)
            analysis['insights'].append(
                f"Found {total_long_running} long-running pipelines >1 hour (showing top {shown} longest)"
            )

        if total_pr_cancelled > 0:
            analysis['insights'].append(
                f"Found {total_pr_cancelled} cancelled PipelineRuns "
                f"(operator action, reported separately from failures)")

        # Add summary insight — exclude running AND cancelled pipelines from
        # the success rate (review MINOR-6: cancellations are operator
        # actions and must not read as reliability loss)
        succeeded_prs = analysis['pipeline_runs']['by_status'].get('Succeeded_True', 0)
        running_prs = analysis['pipeline_runs']['by_status'].get('Succeeded_Unknown', 0)
        completed_prs = analysis['pipeline_runs']['total'] - running_prs - total_pr_cancelled
        if completed_prs > 0:
            success_rate = (succeeded_prs / completed_prs) * 100
            analysis['insights'].append(
                f"Pipeline success rate: {success_rate:.1f}% "
                f"({running_prs} still running, {total_pr_cancelled} cancelled excluded)")
        elif running_prs > 0:
            analysis['insights'].append(f"All {running_prs} pipelines still running — no completed runs to measure")

        logger.info(f"Tekton status analysis complete: {len(analysis['insights'])} insights generated")
        return analysis

    except ApiException as e:
        logger.error(f"API error fetching Tekton resources: {e}")
        return {
            'error': f"Kubernetes API error: {e.reason}",
            'status': e.status,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error fetching Tekton resources: {e}", exc_info=True)
        return {
            'error': f"Failed to fetch Tekton resources: {str(e)}",
            'timestamp': datetime.now().isoformat()
        }


@mcp.tool()
async def detect_log_anomalies(
    logs: str,
    baseline_patterns: Optional[List[str]] = None,
    severity_threshold: str = "medium",
    source: str = ""
) -> Dict[str, Any]:
    """
    Detect anomalies in log data using error frequency, pattern repetition, and timestamp analysis.

    Args:
        logs: Raw log content (newline-separated entries).
        baseline_patterns: Optional expected error patterns for comparison.
        severity_threshold: "low" (most sensitive), "medium", or "high" (least sensitive).
        source: Declared provenance of the supplied text (default ""). Any registered
                source is accepted as audit metadata — no cluster contact is made.
                Unknown (unregistered) sources return the canonical unknown-source error.

    Returns:
        Dict[str, Any]: Keys: anomaly_detected (bool), anomaly_details, analysis_summary.
    """
    _gate_err = _gate_source("detect_log_anomalies", source, ())
    if _gate_err:
        return _gate_err
    return _detect_log_anomalies(logs, baseline_patterns, severity_threshold)


@mcp.tool()
async def search_resources_by_labels(
    resource_types: List[str],
    label_selectors: List[Dict[str, Any]],
    namespaces: Optional[List[str]] = None,
    limit_per_type: int = 100,
    include_metadata_only: bool = False,
    include_status: bool = True,
    sort_by: str = "creation_time",
    sort_order: str = "desc",
    source: str = ""
) -> Dict[str, Any]:
    """
    Search Kubernetes resources by labels across multiple resource types and namespaces.

    Args:
        resource_types: Types to search (e.g., ["pods", "services", "deployments"]).
        label_selectors: Criteria list [{"key": str, "value": str, "operator": "equals|exists|not_equals|in|not_in"}].
        namespaces: Namespaces to search (default: all).
        limit_per_type: Max results per type (default: 100).
        include_metadata_only: Return only metadata (default: False).
        include_status: Include status info (default: True).
        sort_by: "name", "namespace", "creation_time", or "labels" (default: "creation_time").
        sort_order: "asc" or "desc" (default: "desc").
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Search results with resource details, analysis, and recommendations.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err

    start_time = time.time()
    logger.info(f"Starting Kubernetes resource search by labels for types: {resource_types}")

    try:
        _ro_core = ReadOnlyK8sClient.wrap(_clients.core_api)
        _ro_apps = ReadOnlyK8sClient.wrap(_clients.apps_api)
        _ro_batch = ReadOnlyK8sClient.wrap(_clients.batch_api)
        _ro_custom = ReadOnlyK8sClient.wrap(_clients.custom_api)

        # Build label selector string
        label_selector = build_advanced_label_selector(label_selectors)
        logger.info(f"Built label selector: {label_selector}")

        # Get accessible namespaces if not specified
        if namespaces is None:
            try:
                ns_response = await k8s_call(_ro_core.list_namespace)
                accessible_namespaces = [ns.metadata.name for ns in ns_response.items]
                logger.info(f"Found {len(accessible_namespaces)} accessible namespaces")
            except ApiException as e:
                logger.warning(f"Could not list namespaces: {e.reason}. Using default namespace")
                accessible_namespaces = ["default"]
        else:
            accessible_namespaces = namespaces

        all_resources = []
        resource_type_counts = {}
        error_details = []

        # Search each resource type
        for resource_type in resource_types:
            logger.info(f"Searching {resource_type} resources")
            type_count = 0

            try:
                api_info = get_resource_api_info(resource_type)
                if not api_info:
                    error_details.append({
                        "resource_type": resource_type,
                        "namespace": "all",
                        "error_message": f"Unsupported resource type: {resource_type}",
                        "error_code": "UNSUPPORTED_RESOURCE_TYPE"
                    })
                    continue

                resources_found = []

                if api_info.get("namespaced", True):
                    # Search namespaced resources
                    for namespace in accessible_namespaces:
                        try:
                            response = None  # Defence-in-depth: prevent stale response leaking between namespace iterations.
                            if api_info["api"] == "core_v1":
                                api_client = _ro_core
                                method = getattr(api_client, api_info["method"])
                                response = method(
                                    namespace=namespace,
                                    label_selector=label_selector,
                                    limit=limit_per_type
                                )
                            elif api_info["api"] == "apps_v1":
                                api_client = _ro_apps
                                method = getattr(api_client, api_info["method"])
                                response = method(
                                    namespace=namespace,
                                    label_selector=label_selector,
                                    limit=limit_per_type
                                )
                            elif api_info["api"] == "batch_v1":
                                api_client = _ro_batch
                                method = getattr(api_client, api_info["method"])
                                response = method(
                                    namespace=namespace,
                                    label_selector=label_selector,
                                    limit=limit_per_type
                                )
                            elif api_info["api"] == "custom":
                                response = await k8s_call(_ro_custom.list_namespaced_custom_object,
                                    group=api_info["group"],
                                    version=api_info["version"],
                                    namespace=namespace,
                                    plural=api_info["plural"],
                                    label_selector=label_selector,
                                    limit=limit_per_type
                                )
                            if response is None:
                                # Unreachable on today's registry; present for forward safety
                                # against a future api value not covered by the chain above.
                                error_details.append({
                                    "resource_type": resource_type,
                                    "namespace": namespace,
                                    "error_message": f"Unhandled API type for namespaced resource: {api_info['api']}",
                                    "error_code": "UNEXPECTED_ERROR"
                                })
                                continue

                            # Custom objects return dicts, native K8s objects have items attribute
                            if isinstance(response, dict):
                                items = response.get('items', [])
                            elif hasattr(response, 'items'):
                                items = response.items
                            else:
                                items = []

                            for item in items:
                                if hasattr(item, 'to_dict'):
                                    resource_dict = item.to_dict()
                                else:
                                    resource_dict = item

                                processed_resource = extract_resource_info(
                                    resource_dict,
                                    not include_metadata_only,
                                    include_status,
                                    resource_type_hint=resource_type
                                )
                                resources_found.append(processed_resource)
                                type_count += 1

                        except ApiException as e:
                            if e.status not in [403, 404]:
                                error_details.append({
                                    "resource_type": resource_type,
                                    "namespace": namespace,
                                    "error_message": f"API error: {e.reason}",
                                    "error_code": str(e.status)
                                })
                        except Exception as e:
                            error_details.append({
                                "resource_type": resource_type,
                                "namespace": namespace,
                                "error_message": str(e),
                                "error_code": "UNEXPECTED_ERROR"
                            })
                else:
                    # Search cluster-scoped resources
                    try:
                        response = None  # Prevent stale response from leaking between resource types.
                        if api_info["api"] == "core_v1":
                            api_client = _ro_core
                            method = getattr(api_client, api_info["method"])
                            response = method(
                                label_selector=label_selector,
                                limit=limit_per_type
                            )
                        elif api_info["api"] == "custom":
                            # Implementing list_cluster_custom_object requires widening
                            # deploy/rbac-readonly.yaml:171-174 to ["get","list"] and flipping
                            # tests/test_rbac_manifest.py:262 _G→_GL in the same change.
                            error_details.append({
                                "resource_type": resource_type,
                                "namespace": "cluster-scoped",
                                "error_message": "cluster-scoped custom resources are not supported for label search",
                                "error_code": "UNSUPPORTED_CLUSTER_SCOPED_API"
                            })
                        else:
                            # Unreachable on today's registry; present for forward safety
                            # against a future api value with namespaced=False not covered above.
                            error_details.append({
                                "resource_type": resource_type,
                                "namespace": "cluster-scoped",
                                "error_message": f"Unhandled API type for cluster-scoped resource: {api_info['api']}",
                                "error_code": "UNEXPECTED_ERROR"
                            })

                        # Custom objects return dicts, native K8s objects have items attribute.
                        # response is None when a structured rejection was appended above.
                        if response is not None:
                            if isinstance(response, dict):
                                items = response.get('items', [])
                            elif hasattr(response, 'items'):
                                items = response.items
                            else:
                                items = []

                            for item in items:
                                if hasattr(item, 'to_dict'):
                                    resource_dict = item.to_dict()
                                else:
                                    resource_dict = item

                                processed_resource = extract_resource_info(
                                    resource_dict,
                                    not include_metadata_only,
                                    include_status,
                                    resource_type_hint=resource_type
                                )
                                resources_found.append(processed_resource)
                                type_count += 1

                    except ApiException as e:
                        error_details.append({
                            "resource_type": resource_type,
                            "namespace": "cluster-scoped",
                            "error_message": f"API error: {e.reason}",
                            "error_code": str(e.status)
                        })
                    except Exception as e:
                        error_details.append({
                            "resource_type": resource_type,
                            "namespace": "cluster-scoped",
                            "error_message": str(e),
                            "error_code": "UNEXPECTED_ERROR"
                        })

                all_resources.extend(resources_found)
                resource_type_counts[resource_type] = type_count
                logger.info(f"Found {type_count} {resource_type} resources")

            except Exception as e:
                logger.error(f"Error searching {resource_type}: {str(e)}")
                error_details.append({
                    "resource_type": resource_type,
                    "namespace": "all",
                    "error_message": str(e),
                    "error_code": "SEARCH_ERROR"
                })
                resource_type_counts[resource_type] = 0

        # Sort resources
        sorted_resources = sort_resources(all_resources, sort_by, sort_order)

        # Perform analysis
        label_analysis = analyze_labels(sorted_resources)
        namespace_distribution = calculate_namespace_distribution(sorted_resources)

        # Generate recommendations
        recommendations = []
        if len(error_details) > 0:
            recommendations.append({
                "type": "permission_check",
                "description": "Some resources could not be accessed due to permission errors",
                "affected_resources": [err["resource_type"] for err in error_details],
                "suggested_actions": ["Check RBAC permissions", "Verify cluster connectivity", "Confirm resource types exist"]
            })

        if len(sorted_resources) == 0:
            recommendations.append({
                "type": "no_results",
                "description": "No resources found matching the specified label selectors",
                "affected_resources": resource_types,
                "suggested_actions": ["Verify label selector syntax", "Check if resources exist with different labels", "Try broader search criteria"]
            })

        # Calculate duration
        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Build response
        response = {
            "search_summary": {
                "total_resources_found": len(sorted_resources),
                "resource_type_counts": resource_type_counts,
                "namespaces_searched": accessible_namespaces,
                "search_criteria": {
                    "label_selectors": label_selectors,
                    "resource_types": resource_types
                },
                "search_duration_ms": duration_ms
            },
            "resources": sorted_resources,
            "label_analysis": label_analysis,
            "namespace_distribution": namespace_distribution,
            "error_details": error_details,
            "recommendations": recommendations
        }

        logger.info(f"Resource search completed. Found {len(sorted_resources)} resources in {duration_ms}ms")
        return response

    except Exception as e:
        error_msg = f"Unexpected error during resource search: {str(e)}"
        logger.error(error_msg, exc_info=True)

        return {
            "search_summary": {
                "total_resources_found": 0,
                "resource_type_counts": {},
                "namespaces_searched": [],
                "search_criteria": {
                    "label_selectors": label_selectors,
                    "resource_types": resource_types
                },
                "search_duration_ms": round((time.time() - start_time) * 1000, 2)
            },
            "resources": [],
            "label_analysis": {
                "common_labels": [],
                "unique_labels": [],
                "label_patterns": []
            },
            "namespace_distribution": [],
            "error_details": [{
                "resource_type": "system",
                "namespace": "all",
                "error_message": error_msg,
                "error_code": "SYSTEM_ERROR"
            }],
            "recommendations": [{
                "type": "system_error",
                "description": "A system error occurred during the search",
                "affected_resources": resource_types,
                "suggested_actions": ["Check system logs", "Verify cluster connectivity", "Retry the search"]
            }]
        }




@mcp.tool()
async def prometheus_query(
    query: str,
    query_type: str = "instant",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    step: str = "300s",
    cluster: Optional[str] = None,
    format: str = "json",
    namespace_filter: Optional[str] = None,
    limit: Optional[int] = None,
    timeout: int = 30,
    source: str = ""
) -> Dict[str, Any]:
    """
    Execute PromQL queries against Prometheus for cluster metrics.

    Supports instant and range queries with automatic endpoint discovery and authentication.

    Args:
        query: PromQL query string.
        query_type: "instant" or "range" (default: "instant").
        start_time: Start for range queries (ISO 8601 or Unix timestamp).
        end_time: End for range queries (ISO 8601 or Unix timestamp).
        step: Step interval for range queries (default: "300s").
        cluster: Cluster domain override.
        format: "json", "table", or "csv" (default: "json").
        namespace_filter: Regex to filter by namespace.
        limit: Max results to return.
        timeout: Query timeout in seconds (default: 30).
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Query results, metadata, execution info, and analysis.

    Note: ``prometheus_query`` and ``query_metrics`` are the same tool;
        prefer ``query_metrics``.
    """
    # Dispatch: kubernetes sources route via _resolve_k8s; other adapters gate normally.
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("prometheus_query", source, ("Metric",), legacy_adapter="prometheus")
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    start_execution_time = time.time()
    tool_name = "mcp__lumino__prometheus_query"

    logger.info(f"[{tool_name}] Starting Prometheus query execution")
    logger.info(f"[{tool_name}] Query: {query}")
    logger.info(f"[{tool_name}] Type: {query_type}, Format: {format}")

    try:
        # Validate required parameters
        if not query or not query.strip():
            return {
                "status": "error",
                "error_type": "invalid_query",
                "message": "Query parameter is required and cannot be empty",
                "query_executed": "",
                "execution_time": 0,
                "result_count": 0,
                "data": [],
                "suggestions": ["Provide a valid PromQL query", "Example: up{job=\"node-exporter\"}"],
                "errors": ["Empty query provided"]
            }

        # Validate query type
        if query_type not in ["instant", "range"]:
            return {
                "status": "error",
                "error_type": "invalid_query_type",
                "message": f"Invalid query_type '{query_type}'. Must be 'instant' or 'range'",
                "query_executed": query,
                "execution_time": 0,
                "result_count": 0,
                "data": [],
                "suggestions": ["Use query_type='instant' for current values", "Use query_type='range' for time series"],
                "errors": [f"Invalid query_type: {query_type}"]
            }

        # Validate range query parameters
        if query_type == "range":
            if not start_time or not end_time:
                return {
                    "status": "error",
                    "error_type": "missing_time_range",
                    "message": "Range queries require both start_time and end_time parameters",
                    "query_executed": query,
                    "execution_time": 0,
                    "result_count": 0,
                    "data": [],
                    "suggestions": [
                        "Provide start_time and end_time for range queries",
                        "Use ISO 8601 format: '2024-01-01T00:00:00Z'",
                        "Or Unix timestamps: '1704067200'"
                    ],
                    "errors": ["Missing time range parameters for range query"]
                }

        # Named instances: use stored bearer token, never consult the default chain.
        # Default instance (source=''): use the full fallback chain.
        if source:
            auth_token = _instance_tokens.get(source)  # str or None (cert-auth)
            if not auth_token:
                logger.info(
                    f"[{tool_name}] No stored bearer token for {source!r} — "
                    "attempting unauthenticated request (cert-auth cluster or unregistered instance)"
                )
        else:
            auth_token = await _get_k8s_bearer_token()
            if not auth_token:
                logger.info(
                    f"[{tool_name}] No bearer token available - will attempt unauthenticated "
                    "request (common for vanilla Kubernetes Prometheus)"
                )

        # Discover or use Prometheus/Thanos endpoint (source= isolates cache per instance)
        prometheus_url, endpoint_type = await _discover_prometheus_endpoint(
            cluster, custom_api=_clients.custom_api, core_api=_clients.core_api, source=source
        )
        if not prometheus_url:
            return {
                "status": "error",
                "error_type": "endpoint_discovery_failed",
                "message": "Could not discover Prometheus endpoint",
                "query_executed": query,
                "execution_time": 0,
                "result_count": 0,
                "data": [],
                "suggestions": [
                    "Check if Prometheus or Thanos Query is deployed (openshift-monitoring, monitoring, thanos, or observability namespace)",
                    "Verify Prometheus Operator CRDs are installed if using Prometheus Operator",
                    "Ensure OpenShift Routes are accessible if on OpenShift",
                    "Set THANOS_URL or PROMETHEUS_URL environment variable to specify endpoint directly",
                    "Try adding a predefined endpoint in OPENSHIFT_PROMETHEUS_ENDPOINTS config"
                ],
                "errors": ["Prometheus/Thanos endpoint not found"]
            }

        logger.info(f"[{tool_name}] Using {endpoint_type} endpoint: {prometheus_url}")

        # Build query URL and parameters
        if query_type == "instant":
            api_path = "/api/v1/query"
            params = {"query": query}
            if timeout:
                params["timeout"] = f"{timeout}s"
        else:  # range query
            api_path = "/api/v1/query_range"
            params = {
                "query": query,
                "start": _parse_time_parameter(start_time),
                "end": _parse_time_parameter(end_time),
                "step": step
            }
            if timeout:
                params["timeout"] = f"{timeout}s"

        # Add Thanos-specific parameters for deduplicated, consistent results
        if endpoint_type == "thanos":
            params["dedup"] = "true"

        query_url = f"{prometheus_url}{api_path}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Pharos/1.0"
        }
        # Only add Authorization header if token is available, and never in
        # clear text: a discovered http:// service may be one any tenant can create.
        token_withheld = bool(auth_token) and not bearer_token_allowed(query_url)
        if token_withheld:
            logger.warning(f"[{tool_name}] Not sending bearer token over plain http to {query_url}")
        elif auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        logger.info(f"[{tool_name}] Executing query against: {query_url}")

        # Execute Prometheus query
        ssl_context = client_ssl_context(host=prometheus_url)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout + 10)) as session:
            async with session.get(
                query_url, params=params, headers=headers, ssl=ssl_context, allow_redirects=False
            ) as response:
                execution_time = round((time.time() - start_execution_time) * 1000, 2)

                if response.status == 200:
                    response_data = await response.json()
                    logger.info(f"[{tool_name}] Query executed successfully in {execution_time}ms")

                    # Process results
                    processed_results = await _process_prometheus_results(
                        response_data, format, namespace_filter, limit, query, query_type
                    )

                    # Add execution metadata
                    processed_results.update({
                        "status": "success",
                        "query_executed": query,
                        "execution_time": execution_time,
                        "prometheus_endpoint": prometheus_url,
                        "endpoint_type": endpoint_type,
                        "query_type": query_type,
                        "parameters": params
                    })

                    return processed_results

                elif response.status == 400:
                    error_text = await response.text()
                    logger.warning(f"[{tool_name}] Bad request (400): {error_text}")

                    # Try to parse Prometheus error for better suggestions
                    suggestions = _generate_query_suggestions(query, error_text)

                    return {
                        "status": "error",
                        "error_type": "invalid_query",
                        "message": f"PromQL query error: {error_text}",
                        "query_executed": query,
                        "execution_time": execution_time,
                        "result_count": 0,
                        "data": [],
                        "suggestions": suggestions,
                        "errors": [error_text]
                    }

                elif response.status == 401:
                    logger.error(f"[{tool_name}] Authentication failed (401)")
                    return {
                        "status": "error",
                        "error_type": "authentication_failed",
                        "message": "Authentication failed - invalid or expired token",
                        "query_executed": query,
                        "execution_time": execution_time,
                        "result_count": 0,
                        "data": [],
                        "suggestions": ([PLAIN_HTTP_TOKEN_HINT] if token_withheld else []) + [
                            "Refresh your Kubernetes credentials (kubeconfig or ServiceAccount)",
                            "Check if token has expired",
                            "Set PROMETHEUS_TOKEN environment variable with a valid token",
                            "Verify cluster access permissions"
                        ],
                        "errors": ["Authentication failed"]
                    }

                elif response.status == 403:
                    logger.error(f"[{tool_name}] Access forbidden (403)")
                    return {
                        "status": "error",
                        "error_type": "permission_denied",
                        "message": "Access denied - insufficient permissions",
                        "query_executed": query,
                        "execution_time": execution_time,
                        "result_count": 0,
                        "data": [],
                        "suggestions": ([PLAIN_HTTP_TOKEN_HINT] if token_withheld else []) + [
                            "Check RBAC permissions for metrics access",
                            "Verify cluster-monitoring-view role binding",
                            "Contact cluster administrator for monitoring access"
                        ],
                        "errors": ["Permission denied"]
                    }

                else:
                    error_text = await response.text()
                    logger.error(f"[{tool_name}] HTTP error {response.status}: {error_text}")
                    return {
                        "status": "error",
                        "error_type": "http_error",
                        "message": f"HTTP {response.status}: {error_text}",
                        "query_executed": query,
                        "execution_time": execution_time,
                        "result_count": 0,
                        "data": [],
                        "suggestions": [
                            "Check Prometheus service availability",
                            "Verify cluster connectivity",
                            "Try again in a few minutes"
                        ],
                        "errors": [f"HTTP {response.status}: {error_text}"]
                    }

    except asyncio.TimeoutError:
        execution_time = round((time.time() - start_execution_time) * 1000, 2)
        logger.error(f"[{tool_name}] Query timeout after {timeout}s")
        return {
            "status": "error",
            "error_type": "timeout",
            "message": f"Query timed out after {timeout} seconds",
            "query_executed": query,
            "execution_time": execution_time,
            "result_count": 0,
            "data": [],
            "suggestions": [
                "Try a simpler query with shorter time range",
                "Increase timeout parameter",
                "Use more specific label selectors to reduce data"
            ],
            "errors": [f"Timeout after {timeout}s"]
        }

    except aiohttp.ClientSSLError as e:
        execution_time = round((time.time() - start_execution_time) * 1000, 2)
        logger.error(f"[{tool_name}] TLS verification failed: {e}")
        return {
            "status": "error",
            "error_type": "tls_verification_failed",
            "message": f"TLS verification failed for the Prometheus endpoint: {e}",
            "query_executed": query,
            "execution_time": execution_time,
            "result_count": 0,
            "data": [],
            "suggestions": [TLS_HINT],
            "errors": [str(e)]
        }

    except Exception as e:
        execution_time = round((time.time() - start_execution_time) * 1000, 2)
        error_msg = f"Unexpected error during query execution: {str(e)}"
        logger.error(f"[{tool_name}] {error_msg}", exc_info=True)

        return {
            "status": "error",
            "error_type": "unexpected_error",
            "message": error_msg,
            "query_executed": query,
            "execution_time": execution_time,
            "result_count": 0,
            "data": [],
            "suggestions": [
                "Check system logs for details",
                "Verify cluster connectivity",
                "Try a simpler query first"
            ],
            "errors": [str(e)]
        }


# ============================================================================
# SMART LOG ANALYSIS HELPER FUNCTIONS
# ============================================================================
# Note: AdaptiveLogProcessor, _filter_analysis_for_synthesis, _get_logs_with_k8s_client,
# and _filter_logs_by_time_range are imported from helpers.log_analysis;
# _compress_events_for_synthesis is imported from helpers.event_analysis.


# _quick_volume_estimate is imported from helpers.log_analysis


# ============================================================================
# ETCD LOG HELPERS
# ============================================================================
# Note: _handle_api_exception is imported from helpers.utils


# ============================================================================
# SMART LOG ANALYSIS TOOLS
# ============================================================================


@mcp.tool()
async def smart_summarize_pod_logs(
    namespace: str,
    pod_name: str,
    container_name: Optional[str] = None,
    summary_level: str = "detailed",
    focus_areas: Optional[List[str]] = None,
    time_segments: int = 5,
    max_context_tokens: int = 10000,
    since_seconds: Optional[int] = None,
    tail_lines: Optional[int] = None,
    time_period: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    source: str = ""
) -> Dict[str, Any]:
    """
    Adaptive pod log analysis with automatic volume management and multi-pass processing.

    When no time constraints specified, automatically estimates volume and selects optimal time windows.

    Args:
        namespace: Kubernetes namespace.
        pod_name: Pod name to analyze.
        container_name: Specific container (if multiple).
        summary_level: "brief", "detailed", or "comprehensive" (default: "detailed").
        focus_areas: Analysis focus (default: ["errors", "warnings", "performance"]).
        time_segments: Time-based segments to analyze (default: 5).
        max_context_tokens: Max tokens for analysis (default: 10000).
        since_seconds: Only if user specifies exact seconds.
        tail_lines: Only if user specifies exact line count.
        time_period: Only if user specifies period (e.g., "1h", "30m").
        start_time: Only if user specifies exact start time.
        end_time: Only if user specifies exact end time.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.
                For file sources: pod_name is a glob relative to the configured roots;
                namespace and container_name are ignored. File sources are routed;
                other non-kubernetes sources validated per phase 2b.

    Returns:
        Dict[str, Any]: Log analysis with insights, patterns, and recommendations.

    Note: ``smart_summarize_pod_logs`` and ``smart_summarize_logs`` are the same tool;
        prefer ``smart_summarize_logs``.
    """
    # Task 3: k8s discrimination — known kubernetes-adapter source bypasses
    # _route_log_source and uses the legacy k8s else-branch with _clients threaded.
    # File/loki/es sources and source="" continue through _route_log_source unchanged.
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
            _log_adapter = None  # take the legacy-k8s else-branch below
    if _clients is None:
        _log_adapter, _gate_err = _route_log_source("smart_summarize_pod_logs", source)
        if _gate_err:
            return _gate_err
        _clients = _DefaultClientView()
    # Handle mutable default argument - set default inside function
    if focus_areas is None:
        focus_areas = ["errors", "warnings", "performance"]

    start_timestamp = time.time()
    tool_name = "smart_summarize_pod_logs"

    logger.info(f"[{tool_name}] Starting smart log analysis for pod '{pod_name}' in namespace '{namespace}'")
    logger.info(f"[{tool_name}] Parameters: summary_level={summary_level}, focus_areas={focus_areas}, "
                f"time_segments={time_segments}, max_context_tokens={max_context_tokens}")

    # Validate input parameters
    if not namespace or not isinstance(namespace, str):
        error_msg = f"Invalid namespace parameter: {namespace}. Must be a non-empty string."
        logger.error(f"[{tool_name}] {error_msg}")
        return {"error": error_msg}

    if not pod_name or not isinstance(pod_name, str):
        error_msg = f"Invalid pod_name parameter: {pod_name}. Must be a non-empty string."
        logger.error(f"[{tool_name}] {error_msg}")
        return {"error": error_msg}

    if summary_level not in ["brief", "detailed", "comprehensive"]:
        logger.warning(f"[{tool_name}] Invalid summary_level '{summary_level}', defaulting to 'detailed'")
        summary_level = "detailed"

    if time_segments <= 0:
        logger.warning(f"[{tool_name}] Invalid time_segments '{time_segments}', defaulting to 10")
        time_segments = 10

    if max_context_tokens < 500:
        logger.warning(f"[{tool_name}] Very low token limit ({max_context_tokens}), minimum is 500")
        max_context_tokens = 500

    try:
        # Step 1: Retrieve raw logs using existing function
        logger.info(f"[{tool_name}] Retrieving logs from pod '{pod_name}'")

        # V6: hoist window + batch ABOVE the adapter branch so the retention
        # site (below) can see both regardless of which branch runs.
        _batch = None   # F4 trap: must be None when no adapter fetch runs
        _covered = None  # covered_window from Provenance; None for k8s path
        _prov = None    # UnboundLocalError guard: assigned in adapter branch only
        _window = make_time_window(
            since_seconds=since_seconds, time_period=time_period,
            start_time=start_time, end_time=end_time)

        if _log_adapter is not None:
            # FILE/OTLP-SOURCE PATH: bypass k8s entirely (no volume estimate).
            try:
                _batch = await _log_adapter.fetch_logs(
                    Entity(name_or_pattern=pod_name),
                    _window,
                    Limit(max_records=tail_lines, max_bytes=None))
            except AdapterError as _e:
                return {"error": str(_e)}

            _prov = _batch.provenance
            _covered = _prov.covered_window  # None for non-OTLP adapters
            _r = _otlp_retention_or_none(_batch, _window, source)
            if _r is not None:
                return _r

            raw_logs = _logbatch_to_legacy_envelope(_batch)
            time_info = {"method": f"{_source_registry.get(source).adapter}-adapter"}
        else:
            # LEGACY KUBERNETES PATH (source="" or default k8s instance).
            # CHECK FOR ADAPTIVE MODE FIRST (before parsing time parameters)
            user_specified_constraints = (
                since_seconds is not None or
                tail_lines is not None or
                time_period is not None or
                start_time is not None or
                end_time is not None
            )

            if not user_specified_constraints:
                # ADAPTIVE MODE: No user constraints specified
                logger.info(f"[{tool_name}] No time constraints specified - activating ADAPTIVE MODE")

                volume_estimate = await _quick_volume_estimate(namespace, pod_name, clients=_clients, get_logs_fn=get_pod_logs)

                if volume_estimate > 50000:  # High volume
                    log_params = {'tail_lines': 500}  # Conservative for high volume
                    logger.info(f"[{tool_name}] HIGH VOLUME detected ({volume_estimate:,} estimated lines) - using 500 lines with error focus")
                    # Boost error focus for high volume scenarios
                    if "errors" not in focus_areas:
                        focus_areas = ["errors"] + list(focus_areas)
                elif volume_estimate > 10000:  # Medium volume
                    log_params = {'tail_lines': 2000}  # Moderate for medium volume
                    logger.info(f"[{tool_name}] MEDIUM VOLUME detected ({volume_estimate:,} estimated lines) - using 2000 lines")
                else:  # Low volume
                    log_params = {'since_seconds': 7200}  # 2 hours for low volume
                    logger.info(f"[{tool_name}] LOW VOLUME detected ({volume_estimate:,} estimated lines) - using 2 hour window for complete coverage")

                time_info = {'method': 'adaptive', 'strategy': 'volume_based', 'volume_estimate': volume_estimate}

            else:
                # MANUAL MODE: User specified constraints
                logger.info(f"[{tool_name}] User constraints detected - using MANUAL MODE")

                # Parse time parameters with enhanced support
                time_config = parse_time_parameters(
                    since_seconds=since_seconds,
                    time_period=time_period,
                    start_time=start_time,
                    end_time=end_time
                )

                log_params = time_config['log_params'].copy()
                time_info = time_config['time_info']

                if tail_lines is not None:
                    log_params['tail_lines'] = tail_lines

            logger.info(f"[{tool_name}] Time configuration: {time_info}")

            # ADDITIONAL SAFETY: Ensure we don't process too much data even in adaptive mode
            if not log_params and max_context_tokens < 20000:
                # For small token budgets, be extra conservative
                log_params['tail_lines'] = min(1000, max_context_tokens // 10)
                logger.info(f"[{tool_name}] Small token budget detected ({max_context_tokens}), limiting to {log_params['tail_lines']} lines")

            raw_logs = await get_pod_logs(
                namespace=namespace,
                pod_name=pod_name,
                clients=_clients,
                **log_params
            )

        if "error" in raw_logs:
            return {"error": f"Failed to retrieve logs: {raw_logs['error']}"}

        if "logs" not in raw_logs or not raw_logs["logs"]:
            return {
                "error": "No logs found for the specified pod",
                "metadata": {"pod_name": pod_name, "namespace": namespace}
            }

        # Step 2: Process logs for the target container or combine all containers
        all_log_lines = []
        container_info = {}

        for container, logs in raw_logs["logs"].items():
            if container_name and container != container_name:
                continue  # Skip other containers if specific container requested

            if isinstance(logs, list):
                container_lines = logs
            else:
                container_lines = str(logs).split('\n')

            container_info[container] = len(container_lines)
            all_log_lines.extend(container_lines)

        if not all_log_lines:
            return {
                "error": f"No logs found for container '{container_name}'" if container_name else "No log content found",
                "available_containers": list(raw_logs["logs"].keys())
            }

        # Remove empty lines
        all_log_lines = [line for line in all_log_lines if line.strip()]
        total_log_lines = len(all_log_lines)

        logger.info(f"[{tool_name}] Processing {total_log_lines} log lines from {len(container_info)} container(s)")

        # Step 3: Extract patterns based on focus areas
        logger.info(f"[{tool_name}] Extracting patterns for focus areas: {focus_areas}")
        patterns = extract_log_patterns(all_log_lines, focus_areas)

        # Step 4: Sample logs across time segments
        logger.info(f"[{tool_name}] Sampling logs across {time_segments} time segments")
        time_samples = sample_logs_by_time(all_log_lines, time_segments)

        # Step 5: Generate focused summary
        logger.info(f"[{tool_name}] Generating {summary_level} summary")
        summary = generate_focused_summary(patterns, focus_areas, summary_level)

        # Step 6: Prepare representative samples within strict token limits
        representative_samples = {}
        current_tokens = 0

        # Reserve tokens for summary and metadata (be very conservative)
        summary_text = str(summary)
        summary_tokens = calculate_context_tokens(summary_text)
        available_tokens = min(max_context_tokens - summary_tokens - 10000, 15000)  # Cap at 15K for samples

        logger.info(f"[{tool_name}] Summary uses ~{summary_tokens} tokens, {available_tokens} available for samples")

        # Add very limited samples from each focus area
        for area in focus_areas:
            if area in patterns and patterns[area] and current_tokens < available_tokens:
                samples = []
                # Limit to max 3 samples per area and truncate long messages
                for item in patterns[area][:3]:
                    # Truncate sample content to max 200 characters
                    original_content = item["content"]
                    truncated_content = original_content[:200] + "..." if len(original_content) > 200 else original_content

                    sample_item = {
                        "line_number": item["line_number"],
                        "content": truncated_content,
                        "timestamp": item.get("timestamp")
                    }

                    sample_tokens = calculate_context_tokens(truncated_content)

                    if current_tokens + sample_tokens < available_tokens:
                        samples.append(sample_item)
                        current_tokens += sample_tokens
                    else:
                        break

                if samples:
                    representative_samples[area] = samples

        # Step 7: Calculate processing metrics
        processing_time = time.time() - start_timestamp

        # Step 8: Compile final results
        results = {
            "summary": summary,
            "patterns": {k: v for k, v in patterns.items() if v},  # Only non-empty patterns
            "time_segments": {
                "segment_count": len(time_samples),
                "lines_per_segment": {k: len(v) for k, v in time_samples.items()}
            },
            "representative_samples": representative_samples,
            "metadata": {
                "pod_name": pod_name,
                "namespace": namespace,
                "container_info": container_info,
                "analysis_parameters": {
                    "summary_level": summary_level,
                    "focus_areas": focus_areas,
                    "time_segments": time_segments,
                    "max_context_tokens": max_context_tokens
                },
                "processing_metrics": {
                    "total_log_lines": total_log_lines,
                    "processing_time_seconds": round(processing_time, 2),
                    "estimated_tokens_used": current_tokens + summary_tokens,
                    "token_efficiency": f"{((max_context_tokens - current_tokens - summary_tokens) / max_context_tokens * 100):.1f}% unused",
                    "patterns_extracted": sum(len(v) for v in patterns.values())
                },
                # M8b guard: only OTLP populates covered_window, so file/loki/es/k8s
                # sources are byte-identical to their pre-V5 goldens.
                **({"requested_window": list(_prov.requested_window),
                    "covered_window": list(_covered)}
                   if _covered is not None else {}),
            }
        }

        logger.info(f"[{tool_name}] Analysis completed successfully in {processing_time:.2f}s")
        logger.info(f"[{tool_name}] Found {results['metadata']['processing_metrics']['patterns_extracted']} pattern matches")

        # Apply truncation to ensure output fits within token limit
        results = truncate_to_token_limit(results, max_context_tokens)
        if results.get('_truncated'):
            logger.info(f"[{tool_name}] Output truncated to fit within {max_context_tokens} token limit")

        return results

    except Exception as e:
        error_msg = f"Unexpected error during log analysis: {str(e)}"
        logger.error(f"[{tool_name}] {error_msg}", exc_info=True)
        return {
            "error": error_msg,
            "metadata": {
                "pod_name": pod_name,
                "namespace": namespace,
                "processing_time": time.time() - start_timestamp
            }
        }


@mcp.tool()
async def investigate_tls_certificate_issues(
    time_range: str = "24h",
    max_namespaces: int = 20,
    focus_on_system_namespaces: bool = True,
    source: str = "",
) -> Dict[str, Any]:
    """
    Investigate TLS/certificate issues across the cluster with targeted search and analysis.

    Searches system namespaces for TLS error patterns and correlates with certificate events.

    Args:
        time_range: Search time range (default: "24h").
        max_namespaces: Max namespaces to search (default: 20).
        focus_on_system_namespaces: Prioritize system namespaces (default: True).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: TLS issues, affected pods, certificate problems, and remediation suggestions.
    """
    _, _err = _resolve_k8s(source)
    if _err:
        return _err
    try:
        tool_name = "investigate_tls_certificate_issues"
        logger.info(f"[{tool_name}] Starting TLS certificate issue investigation")

        # Get namespaces to search, prioritizing system namespaces
        all_namespaces = await list_namespaces(source=source)

        if focus_on_system_namespaces:
            # Prioritize system namespaces where TLS issues commonly occur
            system_namespaces = [
                ns for ns in all_namespaces
                if any(pattern in ns for pattern in [
                    'openshift-', 'kube-', 'istio-', 'ingress', 'cert-', 'tls-',
                    'monitoring', 'logging', 'registry', 'authentication'
                ])
            ]
            # Add some Tekton/CI-CD namespaces
            tekton_ns = await detect_tekton_namespaces(source=source)
            for category in tekton_ns.values():
                system_namespaces.extend(category[:3])  # Top 3 from each category

            # Scope-relative coverage: discovered = unique in-scope namespaces.
            # Union with all_namespaces ensures cluster_namespaces_total >= len(_scope_ns)
            # even when list_namespaces() returned [] on the first call but
            # detect_tekton_namespaces() populated system_namespaces via a second call
            # (divergent-list_namespaces case — obligation-1 guard).
            _scope = "system_namespaces"
            _scope_ns = set(system_namespaces)
            _all_known_ns = set(all_namespaces) | _scope_ns
            cluster_namespaces_total = len(_all_known_ns)
            excluded_by_scope = cluster_namespaces_total - len(_scope_ns)  # >= 0 always

            # Remove duplicates and apply max_namespaces cap.
            # The cap surfaces as skipped > 0 → "partial"; it is NOT hidden in excluded_by_scope.
            target_namespaces = list(_scope_ns)[:max_namespaces]
        else:
            _scope = "all_namespaces"
            _scope_ns = set(all_namespaces)
            cluster_namespaces_total = len(all_namespaces)
            excluded_by_scope = 0
            target_namespaces = all_namespaces[:max_namespaces]

        logger.info(f"[{tool_name}] Searching {len(target_namespaces)} namespaces for TLS issues")

        # Search for TLS issues across target namespaces
        tls_issues = []
        affected_pods = []
        certificate_problems = []
        searched_namespaces: list[str] = []
        denied_namespaces: list[str] = []  # namespaces where list_pods returned an error dict

        for namespace in target_namespaces:
            try:
                # Get pods in namespace
                pods_info = await list_pods_in_namespace(namespace, source=source)

                # Detect error-dict response from sibling tool (RBAC-denied or API error).
                # list_pods_in_namespace catches ApiException and returns
                # [{"error": "API Error: Forbidden", ...}] — a non-empty list that would
                # pass the isinstance check below.  We must detect it BEFORE appending
                # to searched_namespaces so RBAC-denied namespaces are not counted as scanned.
                if (isinstance(pods_info, list) and pods_info
                        and isinstance(pods_info[0], dict) and "error" in pods_info[0]):
                    denied_namespaces.append(namespace)
                    continue

                searched_namespaces.append(namespace)

                if not isinstance(pods_info, list) or not pods_info:
                    continue

                # Search pod logs for TLS patterns
                for pod_info in pods_info[:3]:  # Limit to 3 pods per namespace
                    if isinstance(pod_info, dict) and 'error' not in pod_info:
                        pod_name = pod_info.get('name', '')

                        try:
                            # Use conservative log analysis focused on TLS issues
                            pod_analysis = await smart_summarize_pod_logs(
                                namespace=namespace,
                                pod_name=pod_name,
                                summary_level="brief",
                                focus_areas=["errors", "security"],
                                max_context_tokens=5000,
                                tail_lines=500,  # Conservative limit
                                source=source,
                            )

                            if "error" not in pod_analysis:
                                # Check for TLS patterns in the analysis
                                patterns = pod_analysis.get("patterns", {})
                                error_patterns = patterns.get("errors", [])

                                tls_related_errors = []
                                for error in error_patterns:
                                    error_content = error.get("content", "").lower()
                                    if any(tls_pattern in error_content for tls_pattern in [
                                        "tls", "certificate", "x509", "ssl", "handshake",
                                        "bad certificate", "certificate verify failed",
                                        "certificate has expired", "certificate authority"
                                    ]):
                                        tls_related_errors.append(error)

                                if tls_related_errors:
                                    tls_issues.extend(tls_related_errors)
                                    affected_pods.append({
                                        "namespace": namespace,
                                        "pod_name": pod_name,
                                        "pod_status": pod_info.get("status", "Unknown"),
                                        "tls_errors": len(tls_related_errors),
                                        "sample_error": tls_related_errors[0].get("content", "")[:150] + "..."
                                    })

                                    logger.info(f"[{tool_name}] Found {len(tls_related_errors)} TLS issues in pod {pod_name}")

                        except Exception as e:
                            logger.debug(f"Error analyzing pod {pod_name} in {namespace}: {e}")
                            continue

                # Also check namespace events for certificate-related events
                try:
                    events_result = await smart_get_namespace_events(
                        namespace=namespace,
                        time_period=time_range,
                        focus_areas=["errors", "warnings"],
                        max_context_tokens=3000,
                        source=source,
                    )

                    if "events" in events_result and events_result["events"]:
                        for event in events_result["events"][:5]:  # Top 5 events
                            event_content = event.get("event_string", "").lower()

                            tls_patterns = ["certificate", "tls", "x509", "ssl", "handshake"]
                            matched_pattern = None
                            for pattern in tls_patterns:
                                if pattern in event_content:
                                    matched_pattern = pattern
                                    break

                            if matched_pattern:
                                certificate_problems.append({
                                    "namespace": namespace,
                                    "event_type": "kubernetes_event",
                                    "severity": event.get("severity", "UNKNOWN"),
                                    "content": event.get("event_string", "")[:200] + "...",
                                    "timestamp": event.get("timestamp", "unknown")
                                })

                except Exception as e:
                    logger.debug(f"Error checking events in {namespace}: {e}")

            except Exception as e:
                logger.debug(f"Error processing namespace {namespace}: {e}")
                continue

        # Build Clause A coverage block (scope-relative).
        # Coverage measures the tool against its DECLARED SCOPE only (system namespaces
        # by default); full-cluster context is disclosed as **extra fields so callers can
        # see what was excluded deliberately.
        #
        # Invariants by construction:
        #   scanned      ≤ len(target_namespaces) ≤ len(_scope_ns) = discovered  (structural)
        #   skipped      = len(_scope_ns) - len(target_namespaces) ≥ 0           (structural)
        #   excluded_by_scope = cluster_namespaces_total - len(_scope_ns) ≥ 0    (union guarantee)
        #
        # I-1: skipped surfaces the max_namespaces cap within scope (not whole-cluster delta).
        # I-2: denied = len(denied_namespaces) — error-dicts detected before append above.
        # I-3: requested = 0 ("all" mode; caller did not name specific namespaces).
        coverage = build_coverage(
            "namespaces",
            requested=0,
            discovered=len(_scope_ns),
            scanned=len(searched_namespaces),
            denied=len(denied_namespaces),
            skipped=len(_scope_ns) - len(target_namespaces),
            requested_mode="all",
            scope=_scope,
            cluster_namespaces_total=cluster_namespaces_total,
            excluded_by_scope=excluded_by_scope,
        )

        # Generate analysis and recommendations
        total_issues = len(tls_issues)
        total_affected_pods = len(affected_pods)
        total_certificate_events = len(certificate_problems)

        analysis_summary = {
            "time_range": time_range,
            "namespaces_searched": len(searched_namespaces),
            "total_tls_issues": total_issues,
            "affected_pods": total_affected_pods,
            "certificate_events": total_certificate_events,
            "investigation_focus": "system_namespaces" if focus_on_system_namespaces else "all_namespaces"
        }

        # Generate specific recommendations for TLS issues
        recommendations = []
        if total_issues > 0:
            recommendations.append(f"Found {total_issues} TLS-related issues across {total_affected_pods} pods")
            recommendations.append("Check certificate expiration dates and CA trust chains")
            recommendations.append("Verify service mesh and ingress TLS configurations")

            if any("expired" in issue.get("content", "").lower() for issue in tls_issues):
                recommendations.append("Certificate expiration detected - immediate renewal required")

            if any("authority" in issue.get("content", "").lower() for issue in tls_issues):
                recommendations.append("Certificate authority issues detected - check CA trust store")

        else:
            if coverage["verdict"] == "complete":
                _excl = coverage.get("excluded_by_scope", 0)
                if _excl > 0:
                    recommendations.append(
                        f"No TLS certificate issues found in {len(searched_namespaces)} system namespaces "
                        f"({_excl} namespaces excluded by scope)"
                    )
                else:
                    recommendations.append(
                        f"No TLS certificate issues found in {len(searched_namespaces)} searched namespaces"
                    )
            elif coverage["verdict"] == "none":
                recommendations.append(
                    "Coverage insufficient: 0 namespaces were searchable — "
                    "TLS health cannot be determined"
                )
            else:  # "partial" — truncated or partially denied
                recommendations.append(
                    f"No TLS issues found in {len(searched_namespaces)} searched namespaces — "
                    "coverage is partial and may not reflect the full cluster state"
                )

        if total_affected_pods > 5:
            recommendations.append("Multiple pods affected - potential cluster-wide certificate issue")

        return {
            "analysis_summary": analysis_summary,
            "tls_issues": tls_issues[:20],  # Limit to top 20 issues
            "affected_pods": affected_pods,
            "certificate_events": certificate_problems,
            "recommendations": recommendations,
            "coverage": coverage,
            "search_metadata": {
                "tool_optimized_for": "tls_certificate_investigations",
                "token_budget_used": "conservative",
                "search_efficiency": f"{total_issues} issues found across {len(searched_namespaces)} namespaces"
            }
        }

    except Exception as e:
        logger.error(f"[{tool_name}] Error in TLS investigation: {str(e)}", exc_info=True)
        return {
            "error": f"TLS investigation failed: {str(e)}",
            "suggestion": "Try using direct pod log analysis for specific pods with TLS issues"
        }


@mcp.tool()
async def conservative_namespace_overview(
    namespace: str,
    max_pods: int = 10,
    focus_areas: Optional[List[str]] = None,
    sample_strategy: str = "smart",
    source: str = "",
) -> Dict[str, Any]:
    """
    Conservative namespace analysis optimized for large namespaces with strict token limits.

    Smart-samples critical pods (failed, high-restart, error states) for rapid issue detection.

    Args:
        namespace: Kubernetes namespace to analyze.
        max_pods: Maximum pods to analyze (default: 10).
        focus_areas: Areas to focus on (default: ["errors", "warnings"]).
        sample_strategy: "smart" for intelligent sampling, "recent" for newest pods.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Analysis results with pod health, issues detected, and recommendations.
    """
    _, _err = _resolve_k8s(source)
    if _err:
        return _err
    # Handle mutable default argument - set default inside function
    if focus_areas is None:
        focus_areas = ["errors", "warnings"]

    try:
        tool_name = "conservative_namespace_overview"
        logger.info(f"[{tool_name}] Starting conservative analysis of namespace '{namespace}' (max {max_pods} pods)")

        # Ultra-conservative token budget
        max_total_tokens = 45000  # Well under any limit
        tokens_per_pod = max_total_tokens // max_pods

        # Get all pods
        pods_info = await list_pods_in_namespace(namespace, source=source)
        if isinstance(pods_info, list) and pods_info and "error" in pods_info[0]:
            return {"error": f"Failed to discover pods: {pods_info[0]['error']}"}

        total_pods = len(pods_info) if isinstance(pods_info, list) else 0
        logger.info(f"[{tool_name}] Found {total_pods} pods, will analyze top {min(max_pods, total_pods)}")

        # Report when no pods are found — may indicate RBAC restrictions
        if total_pods == 0:
            return {
                "overview": {
                    "namespace": namespace,
                    "total_pods": 0,
                    "pods_analyzed": 0,
                    "pods_with_issues": 0,
                    "critical_issues_found": 0,
                    "analysis_strategy": f"conservative sampling of 0/0 pods"
                },
                "pod_findings": {},
                "critical_issues": [],
                "recommendations": [
                    f"No pods found in namespace '{namespace}'",
                    "This may indicate RBAC restrictions preventing pod listing, or the namespace has no running workloads",
                    "Verify access with: kubectl auth can-i list pods -n " + namespace
                ],
                "conservative_metadata": {
                    "token_budget": f"<{max_total_tokens:,} tokens (conservative)",
                    "sampling_strategy": sample_strategy,
                    "coverage_ratio": "0/0",
                    "optimized_for": "large_namespaces",
                    "note": "zero_pods_detected"
                }
            }

        # Smart pod selection based on strategy
        if sample_strategy == "smart" and isinstance(pods_info, list):
            # Prioritize pods likely to have issues
            # Uses container_states (CrashLoopBackOff, ImagePullBackOff, Error, OOMKilled)
            # and restart_count from enhanced list_pods_in_namespace
            error_states = {"CrashLoopBackOff", "ImagePullBackOff", "Error", "OOMKilled", "ContainerCannotRun"}
            prioritized_pods = sorted(pods_info, key=lambda p: (
                p.get("status") == "Failed",  # Failed pods first (pod phase)
                any(state in error_states for state in p.get("container_states", [])),  # Container error states
                p.get("restart_count", 0) > 0,  # Pods with restarts
                p.get("restart_count", 0),  # Higher restart count = higher priority
                "error" in p.get("name", "").lower(),  # Names suggesting issues
                "failed" in p.get("name", "").lower(),
            ), reverse=True)
        else:
            # Recent pods strategy
            prioritized_pods = sorted(pods_info, key=lambda p: p.get("creation_timestamp") or "", reverse=True)

        # Analyze selected pods with strict token limits
        findings = {}
        issues_found = []

        for i, pod_info in enumerate(prioritized_pods[:max_pods]):
            pod_name = pod_info.get("name", "")
            pod_status = pod_info.get("status", "Unknown")

            try:
                # Ultra-conservative pod analysis
                pod_analysis = await smart_summarize_pod_logs(
                    namespace=namespace,
                    pod_name=pod_name,
                    summary_level="brief",
                    focus_areas=focus_areas,
                    max_context_tokens=tokens_per_pod,
                    source=source,
                )

                if "error" not in pod_analysis:
                    # Extract only critical information
                    essential_info = {
                        "status": pod_status,
                        "log_lines": pod_analysis.get("metadata", {}).get("processing_metrics", {}).get("total_log_lines", 0),
                        "patterns_found": pod_analysis.get("metadata", {}).get("processing_metrics", {}).get("patterns_extracted", 0),
                        "has_errors": bool(pod_analysis.get("patterns", {}).get("errors")),
                        "has_warnings": bool(pod_analysis.get("patterns", {}).get("warnings"))
                    }

                    # Extract top issue if any
                    if pod_analysis.get("patterns", {}).get("errors"):
                        top_error = pod_analysis["patterns"]["errors"][0]
                        essential_info["top_issue"] = f"{top_error['content'][:80]}..."
                        issues_found.append(f"Pod {pod_name}: {essential_info['top_issue']}")

                    findings[pod_name] = essential_info

                logger.info(f"[{tool_name}] Analyzed pod {i+1}/{min(max_pods, total_pods)}: {pod_name}")

            except Exception as e:
                logger.warning(f"Failed to analyze pod {pod_name}: {e}")
                findings[pod_name] = {"status": pod_status, "error": str(e)}

        # Generate ultra-compact summary
        summary = {
            "namespace": namespace,
            "total_pods": total_pods,
            "pods_analyzed": len(findings),
            "pods_with_issues": len([f for f in findings.values() if f.get("has_errors") or f.get("has_warnings")]),
            "critical_issues_found": len(issues_found),
            "analysis_strategy": f"conservative sampling of {min(max_pods, total_pods)}/{total_pods} pods"
        }

        # Generate focused recommendations
        recommendations = []
        if issues_found:
            recommendations.append(f"Found {len(issues_found)} issues requiring investigation")
            recommendations.extend(issues_found[:5])  # Top 5 issues only
        else:
            recommendations.append("No critical issues detected in sampled pods")

        if total_pods > max_pods:
            recommendations.append(f"Analyzed {max_pods}/{total_pods} pods - use focused investigation for complete coverage")

        return {
            "overview": summary,
            "pod_findings": findings,
            "critical_issues": issues_found[:5],  # Top 5 only
            "recommendations": recommendations[:5],  # Top 5 only
            "conservative_metadata": {
                "token_budget": f"<{max_total_tokens:,} tokens (conservative)",
                "sampling_strategy": sample_strategy,
                "coverage_ratio": f"{len(findings)}/{total_pods}",
                "optimized_for": "large_namespaces"
            }
        }

    except Exception as e:
        logger.error(f"[{tool_name}] Error in conservative analysis: {str(e)}", exc_info=True)
        return {
            "error": f"Conservative analysis failed: {str(e)}",
            "namespace": namespace,
            "suggestion": "Try analyzing individual pods directly"
        }


@mcp.tool()
async def adaptive_namespace_investigation(
    namespace: str,
    investigation_query: str = "investigate all logs and events for potential issues",
    max_pods: int = 20,
    focus_areas: Optional[List[str]] = None,
    token_budget: int = 200000,
    source: str = "",
) -> Dict[str, Any]:
    """
    Adaptive namespace investigation with progressive analysis and token budget management.

    Best for medium namespaces (5-30 pods). Prioritizes failed/error pods, correlates events.

    Args:
        namespace: Kubernetes namespace to investigate.
        investigation_query: What to investigate (default: "investigate all logs and events for potential issues").
        max_pods: Maximum pods to analyze (default: 20).
        focus_areas: Areas to focus on (default: ["errors", "warnings", "performance"]).
        token_budget: Max tokens for investigation (default: 200000).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Pod analysis, event correlation, findings, and recommendations.
            ``investigation_summary`` contains:
            ``high_or_critical_events_found`` (int): Count of HIGH or CRITICAL severity
                events found during the investigation (renamed from ``critical_events_found``
                in Plan D).
    """
    _, _err = _resolve_k8s(source)
    if _err:
        return _err
    # Handle mutable default argument - set default inside function
    if focus_areas is None:
        focus_areas = ["errors", "warnings", "performance"]

    # Input validation
    if not namespace or not isinstance(namespace, str):
        return {"error": "Invalid namespace parameter: must be a non-empty string"}
    namespace = namespace.strip()
    if not namespace:
        return {"error": "Namespace cannot be empty or whitespace only"}

    if not isinstance(max_pods, int) or max_pods <= 0:
        max_pods = 20  # Reset to default if invalid

    if not isinstance(token_budget, int) or token_budget <= 0:
        token_budget = 200000  # Reset to default if invalid

    try:
        tool_name = "adaptive_namespace_investigation"
        logger.info(f"[{tool_name}] Starting adaptive investigation of namespace '{namespace}'")
        logger.info(f"[{tool_name}] Query: {investigation_query}")
        logger.info(f"[{tool_name}] Token budget: {token_budget:,}, Max pods: {max_pods}")

        # Initialize adaptive processor with specified budget
        processor = AdaptiveLogProcessor(max_token_budget=token_budget)

        # Phase 1: Smart Discovery (10% of budget)
        discovery_budget = int(token_budget * 0.1)
        logger.info(f"[{tool_name}] Phase 1: Discovery (budget: {discovery_budget:,} tokens)")

        # Get all pods in namespace
        pods_info = await list_pods_in_namespace(namespace, source=source)
        if isinstance(pods_info, list) and pods_info and "error" in pods_info[0]:
            return {"error": f"Failed to discover pods: {pods_info[0]['error']}"}

        total_pods = len(pods_info) if isinstance(pods_info, list) else 0
        pods_to_analyze = min(max_pods, total_pods)

        # Early return if no pods found
        if total_pods == 0:
            logger.info(f"[{tool_name}] No pods found in namespace '{namespace}'")
            return {
                "investigation_summary": {
                    "namespace": namespace,
                    "status": "no_pods_found",
                    "message": f"No pods found in namespace '{namespace}'"
                },
                "pod_findings": {},
                "namespace_events": {},
                "critical_issues": [],
                "recommendations": ["Verify namespace exists and has running workloads"]
            }

        # Get namespace events for correlation (compressed for synthesis)
        events_result = await smart_get_namespace_events(
            namespace=namespace,
            strategy="smart_summary",
            focus_areas=focus_areas,
            max_context_tokens=discovery_budget // 2,
            source=source,
        )

        # Validate events_result and compress for synthesis
        if not isinstance(events_result, dict):
            events_result = {"error": "Invalid events result type"}
        compressed_events = _compress_events_for_synthesis(events_result)

        # F-21: count HIGH and CRITICAL events from the FULL event list (pre-compression)
        # so the field does not silently saturate at the 5-entry compression cap.
        event_critical_count = sum(
            1 for e in (events_result.get("events") or [])
            if e.get("severity") in ("HIGH", "CRITICAL")
        )

        # Track actual token usage from events result instead of full budget allocation
        actual_event_tokens = events_result.get("token_usage", {}).get("total_estimated", discovery_budget // 4)
        processor.record_usage(actual_event_tokens)

        # Phase 2: Intelligent Analysis (80% of budget)
        analysis_budget = int(token_budget * 0.8)
        per_pod_budget = analysis_budget // pods_to_analyze if pods_to_analyze > 0 else analysis_budget

        logger.info(f"[{tool_name}] Phase 2: Analysis (budget: {analysis_budget:,} tokens, {per_pod_budget:,} per pod)")

        findings = {}
        critical_issues = []
        pods_analyzed = 0

        # Prioritize pods for analysis
        if isinstance(pods_info, list) and pods_info:
            # Sort pods by priority (failed, high restart count, container error states)
            # Uses container_states and restart_count from enhanced list_pods_in_namespace
            error_states = {"CrashLoopBackOff", "ImagePullBackOff", "Error", "OOMKilled", "ContainerCannotRun"}
            prioritized_pods = sorted(pods_info, key=lambda p: (
                p.get("status") == "Failed",  # Failed pods first (pod phase)
                any(state in error_states for state in p.get("container_states", [])),  # Container error states
                p.get("restart_count", 0) > 0,  # Pods with restarts
                p.get("restart_count", 0),  # Higher restart count = higher priority
                p.get("name", "").endswith(("-failed", "-error")),  # Names indicating issues
            ), reverse=True)

            # Process pods in parallel batches for performance
            # Batch size balances parallelism with token budget checks
            batch_size = 4
            pods_to_process = prioritized_pods[:pods_to_analyze]
            summary_level = "brief" if pods_to_analyze > 10 else "detailed"
            max_tokens_per_pod = min(per_pod_budget, 15000)

            async def analyze_single_pod(pod_info: Dict[str, Any]) -> Dict[str, Any]:
                """Analyze a single pod and return results."""
                pod_name = pod_info.get("name", "")
                pod_status = pod_info.get("status", "Unknown")
                try:
                    pod_analysis = await smart_summarize_pod_logs(
                        namespace=namespace,
                        pod_name=pod_name,
                        summary_level=summary_level,
                        focus_areas=focus_areas,
                        max_context_tokens=max_tokens_per_pod,
                        source=source,
                    )
                    return {"pod_name": pod_name, "pod_status": pod_status, "analysis": pod_analysis, "error": None}
                except Exception as e:
                    logger.warning(f"Failed to analyze pod {pod_name}: {e}")
                    return {"pod_name": pod_name, "pod_status": pod_status, "analysis": None, "error": str(e)}

            # Process in batches
            for batch_start in range(0, len(pods_to_process), batch_size):
                # Check token budget before starting batch
                # GUARANTEE: Always process at least the first batch to ensure meaningful results
                is_first_batch = (batch_start == 0)
                actual_batch_size = min(batch_size, len(pods_to_process) - batch_start)
                batch_budget_needed = per_pod_budget * actual_batch_size

                if not is_first_batch and not processor.can_process_more(batch_budget_needed):
                    logger.info(f"Token budget exhausted - analyzed {pods_analyzed}/{pods_to_analyze} pods")
                    break

                batch = pods_to_process[batch_start:batch_start + batch_size]
                logger.info(f"[{tool_name}] Processing batch of {len(batch)} pods in parallel")

                # Run batch in parallel
                batch_results = await asyncio.gather(*[analyze_single_pod(p) for p in batch])

                # Process batch results
                for result in batch_results:
                    pod_name = result["pod_name"]
                    pod_status = result["pod_status"]

                    if result["error"]:
                        findings[pod_name] = {"status": pod_status, "error": result["error"]}
                    elif result["analysis"] and "error" not in result["analysis"]:
                        # INTELLIGENT FILTERING: Only keep essential data to prevent token overflow
                        filtered_analysis = _filter_analysis_for_synthesis(result["analysis"], focus_areas)

                        findings[pod_name] = {
                            "status": pod_status,
                            "analysis": filtered_analysis,
                            "priority_reason": "failed_pod" if pod_status == "Failed" else "normal_processing"
                        }

                        # Extract critical issues
                        if result["analysis"].get("patterns", {}).get("errors"):
                            critical_issues.extend([
                                f"Pod {pod_name}: {error['content'][:100]}..."
                                for error in result["analysis"]["patterns"]["errors"][:2]
                            ])

                    # Track actual tokens used from analysis metadata, not the full budget allocation
                    actual_pod_tokens = 0
                    if result["analysis"]:
                        actual_pod_tokens = result["analysis"].get("metadata", {}).get(
                            "processing_metrics", {}
                        ).get("estimated_tokens_used", per_pod_budget // 4)
                    processor.record_usage(max(actual_pod_tokens, 100))  # At least 100 tokens per pod
                    pods_analyzed += 1

                logger.info(f"[{tool_name}] Analyzed {pods_analyzed}/{pods_to_analyze} pods so far")

                # Early termination if many critical issues found
                if len(critical_issues) >= 10:
                    logger.info(f"Early termination: {len(critical_issues)} critical issues found")
                    break

        # Phase 3: Synthesis (10% of budget)
        synthesis_budget = int(token_budget * 0.1)
        logger.info(f"[{tool_name}] Phase 3: Synthesis (budget: {synthesis_budget:,} tokens)")

        # Generate comprehensive summary
        investigation_summary = {
            "namespace": namespace,
            "investigation_query": investigation_query,
            "total_pods_found": total_pods,
            "pods_analyzed": pods_analyzed,
            "critical_issues_found": len(critical_issues),
            "high_or_critical_events_found": event_critical_count,
            "token_budget_used": f"{min(processor.get_usage_percentage(), 100.0):.1f}%",
            "adaptive_strategy": "volume-based time windowing with progressive pod analysis"
        }

        # Generate recommendations based on findings
        recommendations = []
        if critical_issues:
            recommendations.append(f"{len(critical_issues)} critical issues require immediate attention")
            recommendations.extend(critical_issues[:5])  # Top 5 issues

        if pods_analyzed < total_pods:
            recommendations.append(f"Only analyzed {pods_analyzed}/{total_pods} pods due to token constraints - consider focused investigation of remaining pods")

        if not critical_issues and pods_analyzed > 5 and event_critical_count == 0:
            recommendations.append("No critical issues detected in analyzed pods - namespace appears healthy")

        # FINAL TOKEN SAFETY: Return compressed results to prevent context overflow
        return {
            "investigation_summary": investigation_summary,
            "pod_findings": findings,  # Already filtered per pod
            "namespace_events": compressed_events,  # Compressed events
            "critical_issues": critical_issues[:10],  # Limit to top 10 critical issues
            "recommendations": recommendations[:8],  # Limit to top 8 recommendations
            "adaptive_metadata": {
                "processing_mode": "adaptive",
                "token_efficiency": f"{(pods_analyzed * 1000 / max(1, processor.used_tokens)):.3f} pods per 1k tokens",
                "tokens_used": processor.used_tokens,
                "coverage": build_coverage(
                    "pods",
                    requested=0,
                    discovered=total_pods,
                    scanned=pods_analyzed,
                    denied=0,
                    requested_mode="all",
                ),
                "data_filtering": "applied to prevent token overflow",
                "synthesis_optimized": True
            }
        }

    except Exception as e:
        logger.error(f"[{tool_name}] Error in adaptive investigation: {str(e)}", exc_info=True)
        return {
            "error": f"Adaptive investigation failed: {str(e)}",
            "namespace": namespace,
            "suggestion": "Try investigating individual pods or use smaller scope"
        }


# ============================================================================
# ETCD LOGS TOOL
# ============================================================================


async def get_etcd_logs(
    tail_lines: Optional[int] = 200,
    since_seconds: Optional[int] = None,
    since_time: Optional[str] = None,
    until_time: Optional[str] = None,
    follow: bool = False,
    timestamps: bool = True,
    previous: bool = False,
    clean_logs: bool = True,
    max_context_tokens: int = 50000,
    source: str = ""
) -> Dict[str, str]:
    """
    Retrieve etcd pod logs from Kubernetes/OpenShift with flexible time and line filtering.

    Auto-detects cluster type and uses appropriate namespace/label selectors.

    Args:
        tail_lines: Lines from end of logs (default: 200, None for all).
        since_seconds: Logs newer than N seconds (measured relative to the time of the API
            call, not to any timestamp in the log content; overrides tail_lines).
        since_time: Logs newer than RFC3339 timestamp (overrides since_seconds).
        until_time: Logs older than RFC3339 timestamp (requires since_time or since_seconds).
        follow: Stream logs in real-time (default: False).
        timestamps: Include timestamps (default: True).
        previous: Get logs from previous container instance (default: False).
        clean_logs: Clean/format logs (default: True).
        max_context_tokens: Output token budget (default 50000). Per-pod log strings are truncated (last-newline boundary + notice) to fit; a _truncation summary key is added when any pod was cut.
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict[str, str]: Pod names as keys, logs as values.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return {"error": _err["error"]}
    _gerr = _gate_extension("get_etcd_logs", source)
    if _gerr:
        return {"error": _gerr["error"]}
    tool_name = "get_etcd_logs_k8s_client"
    logger.info(f"Tool '{tool_name}' started with params: tail_lines={tail_lines}, "
                f"since_seconds={since_seconds}, since_time={since_time}, until_time={until_time}, "
                f"follow={follow}, timestamps={timestamps}, previous={previous}, "
                f"clean_logs={clean_logs}")
    if follow:
        logger.warning(f"[{tool_name}] follow=True is not supported; returning a log snapshot")

    # ── Output-bounding helper (sync; captures max_context_tokens) ──────────
    def _cap(results: Dict[str, str]) -> Dict[str, str]:
        """Truncate per-pod log entries to stay within max_context_tokens.

        Skips non-log keys (error_/info_/final_summary/critical_ prefixes)
        in both the divisor and truncation, mirroring the until_time guards.
        Adds results["_truncation"] when any entry was cut.
        """
        _SKIP = ("error_", "info_", "final_summary", "critical_")
        log_keys = [k for k in results if not k.startswith(_SKIP)]
        n_log_entries = len(log_keys)
        if n_log_entries == 0:
            return results
        per_entry = max(200, max_context_tokens // max(1, n_log_entries))
        n_truncated = 0
        for k in log_keys:
            text, was_truncated = _truncate_logs_to_token_limit(results[k], per_entry, k)
            if was_truncated:
                results[k] = text
                n_truncated += 1
        if n_truncated:
            results["_truncation"] = (
                f"{n_truncated} pod log(s) truncated to ~{per_entry} tokens each "
                f"(max_context_tokens={max_context_tokens})"
            )
        return results
    # ────────────────────────────────────────────────────────────────────────

    # Validate input parameters
    parsed_since_time = None
    parsed_until_time = None

    if since_time:
        try:
            # Validate RFC3339 timestamp format
            parsed_since_time = datetime.fromisoformat(since_time.replace('Z', '+00:00'))
        except ValueError as e:
            logger.error(f"[{tool_name}] Invalid since_time format: {since_time}")
            return {"critical_error": f"Invalid since_time format '{since_time}'. Use RFC3339 format (e.g., '2024-01-15T10:30:00Z' or '2024-01-15T10:30:00'): {str(e)}"}

    if until_time:
        try:
            # Validate RFC3339 timestamp format
            parsed_until_time = datetime.fromisoformat(until_time.replace('Z', '+00:00'))
        except ValueError as e:
            logger.error(f"[{tool_name}] Invalid until_time format: {until_time}")
            return {"critical_error": f"Invalid until_time format '{until_time}'. Use RFC3339 format (e.g., '2024-01-15T11:30:00Z' or '2024-01-15T11:30:00'): {str(e)}"}

        # Ensure until_time requires since_time or since_seconds
        if not since_time and not since_seconds:
            logger.error(f"[{tool_name}] until_time requires since_time or since_seconds to be specified")
            return {"critical_error": "until_time parameter requires either since_time or since_seconds to define a time range"}

        # Ensure timestamps are enabled for accurate filtering
        if not timestamps:
            logger.warning(f"[{tool_name}] until_time specified but timestamps=False. Enabling timestamps for accurate filtering.")
            timestamps = True

        # Validate time range logic
        if parsed_since_time and parsed_until_time and parsed_until_time <= parsed_since_time:
            logger.error(f"[{tool_name}] until_time must be after since_time")
            return {"critical_error": f"Invalid time range: until_time ({until_time}) must be after since_time ({since_time})"}

    if since_seconds is not None and since_seconds < 0:
        logger.error(f"[{tool_name}] Invalid since_seconds: {since_seconds}")
        return {"critical_error": f"since_seconds must be non-negative, got: {since_seconds}"}

    if tail_lines is not None and tail_lines <= 0:
        logger.error(f"[{tool_name}] Invalid tail_lines: {tail_lines}")
        return {"critical_error": f"tail_lines must be positive, got: {tail_lines}"}

    accumulated_results: Dict[str, str] = {}
    strategies_attempted = []
    logs_successfully_fetched = False

    # --- Strategy 1: OpenShift ---
    os_namespace = "openshift-etcd"
    os_label_selector = "k8s-app=etcd"
    os_container = "etcd"
    strategies_attempted.append("OpenShift")

    ro = ReadOnlyCoreV1.wrap(_clients.core_api)

    logger.info(f"[{tool_name}] Attempting OpenShift etcd strategy: ns='{os_namespace}', label='{os_label_selector}'")
    try:
        pod_list_os = await asyncio.to_thread(
            ro.list_namespaced_pod,
            namespace=os_namespace,
            label_selector=os_label_selector,
            timeout_seconds=10
        )
        if pod_list_os.items:
            pod_names_os = [pod.metadata.name for pod in pod_list_os.items if pod.metadata and pod.metadata.name]
            logger.info(f"[{tool_name}] OpenShift strategy: Found {len(pod_names_os)} etcd pod(s). Fetching logs.")

            log_params = {
                'tail_lines': tail_lines,
                'since_seconds': since_seconds,
                'since_time': since_time,
                'follow': False,  # never stream (C06); see warning above
                'timestamps': timestamps,
                'previous': previous,
                'clean_logs': clean_logs
            }

            if await asyncio.to_thread(_get_logs_with_k8s_client, ro, pod_names_os, os_namespace, os_container, accumulated_results, log_params):
                # Apply time range filtering if until_time is specified
                if parsed_until_time:
                    logger.info(f"[{tool_name}] Applying time range filter: until {until_time}")
                    for pod_name in list(accumulated_results.keys()):
                        if not pod_name.startswith("error_") and not pod_name.startswith("info_"):
                            original_length = len(accumulated_results[pod_name])
                            accumulated_results[pod_name] = _filter_logs_by_time_range(
                                accumulated_results[pod_name],
                                parsed_until_time
                            )
                            filtered_length = len(accumulated_results[pod_name])
                            logger.info(f"[{tool_name}] Filtered logs for {pod_name}: {original_length} -> {filtered_length} characters")

                logger.info(f"[{tool_name}] Successfully fetched logs using OpenShift strategy")
                logs_successfully_fetched = True
            else:
                logger.warning(f"[{tool_name}] OpenShift strategy: Found pods but failed to fetch any logs")
        else:
            logger.info(f"[{tool_name}] OpenShift strategy: No etcd pods found")
            accumulated_results["info_openshift_no_pods"] = f"No pods found in namespace '{os_namespace}' with label '{os_label_selector}'"

    except ApiException as e:
        _handle_api_exception(e, tool_name, "OpenShift", os_namespace, os_label_selector, accumulated_results)
    except Exception as e:
        logger.error(f"[{tool_name}] OpenShift strategy: Unexpected error: {str(e)}", exc_info=True)
        accumulated_results["error_openshift_unexpected"] = str(e)

    if logs_successfully_fetched:
        return _cap(accumulated_results)

    # --- Strategy 2: Standard Kubernetes ---
    kube_namespace = "kube-system"
    kube_label_selector = "component=etcd"
    kube_container = "etcd"
    strategies_attempted.append("StandardK8s")

    logger.info(f"[{tool_name}] Attempting standard Kubernetes etcd strategy: ns='{kube_namespace}', label='{kube_label_selector}'")
    standard_k8s_results: Dict[str, str] = {}

    try:
        pod_list_kube = await asyncio.to_thread(
            ro.list_namespaced_pod,
            namespace=kube_namespace,
            label_selector=kube_label_selector,
            timeout_seconds=10
        )
        if pod_list_kube.items:
            pod_names_kube = [pod.metadata.name for pod in pod_list_kube.items if pod.metadata and pod.metadata.name]
            logger.info(f"[{tool_name}] Standard K8s strategy: Found {len(pod_names_kube)} etcd pod(s). Fetching logs.")

            log_params = {
                'tail_lines': tail_lines,
                'since_seconds': since_seconds,
                'since_time': since_time,
                'follow': False,  # never stream (C06); see warning above
                'timestamps': timestamps,
                'previous': previous,
                'clean_logs': clean_logs
            }

            if await asyncio.to_thread(_get_logs_with_k8s_client, ro, pod_names_kube, kube_namespace, kube_container, standard_k8s_results, log_params):
                # Apply time range filtering if until_time is specified
                if parsed_until_time:
                    logger.info(f"[{tool_name}] Applying time range filter: until {until_time}")
                    for pod_name in list(standard_k8s_results.keys()):
                        if not pod_name.startswith("error_") and not pod_name.startswith("info_"):
                            original_length = len(standard_k8s_results[pod_name])
                            standard_k8s_results[pod_name] = _filter_logs_by_time_range(
                                standard_k8s_results[pod_name],
                                parsed_until_time
                            )
                            filtered_length = len(standard_k8s_results[pod_name])
                            logger.info(f"[{tool_name}] Filtered logs for {pod_name}: {original_length} -> {filtered_length} characters")

                logger.info(f"[{tool_name}] Successfully fetched logs using standard Kubernetes strategy")
                return _cap(standard_k8s_results)
            else:
                logger.warning(f"[{tool_name}] Standard K8s strategy: Found pods but failed to fetch any logs")
                accumulated_results.update(standard_k8s_results)
        else:
            logger.info(f"[{tool_name}] Standard K8s strategy: No etcd pods found")
            accumulated_results["info_kube_no_pods"] = f"No pods found in namespace '{kube_namespace}' with label '{kube_label_selector}'"

    except ApiException as e:
        _handle_api_exception(e, tool_name, "StandardK8s", kube_namespace, kube_label_selector, accumulated_results)
    except Exception as e:
        logger.error(f"[{tool_name}] Standard K8s strategy: Unexpected error: {str(e)}", exc_info=True)
        accumulated_results["error_kube_unexpected"] = str(e)

    # Final summary
    has_actual_logs = any(
        not key.startswith(("error_", "info_", "critical_"))
        for key in accumulated_results
    )

    if not has_actual_logs:
        summary_message = (f"Failed to fetch etcd logs from any cluster type. "
                          f"Attempted strategies: {', '.join(strategies_attempted)}. "
                          f"Check RBAC permissions and cluster configuration.")

        if not accumulated_results:
            accumulated_results["final_summary"] = summary_message
        else:
            # Prepend summary for context
            final_results = {"final_summary": summary_message}
            final_results.update(accumulated_results)
            accumulated_results = final_results

    logger.info(f"[{tool_name}] Log fetching complete. Results: {len(accumulated_results)} entries")
    return _cap(accumulated_results)


@mcp.tool()
async def stream_analyze_pod_logs(
    namespace: str,
    pod_name: str,
    container_name: Optional[str] = None,
    chunk_size: int = 5000,
    analysis_mode: str = "errors_and_warnings",
    time_window: Optional[str] = None,
    follow: bool = False,
    max_chunks: int = 50,
    since_seconds: Optional[int] = None,
    tail_lines: Optional[int] = None,
    time_period: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_context_tokens: int = 50000,
    source: str = ""
) -> Dict[str, Any]:
    """
    Stream and analyze pod logs in chunks with progressive pattern detection.

    Processes logs in manageable chunks for memory efficiency and real-time insights.

    Args:
        namespace: Kubernetes namespace.
        pod_name: Pod name to stream logs from.
        container_name: Specific container (if multiple).
        chunk_size: Lines per chunk (default: 5000).
        analysis_mode: "errors_only", "errors_and_warnings" (default), "full_analysis", or "custom_patterns".
        time_window: Time window for historical logs (e.g., "1h", "6h", "24h").
        follow: Stream logs in real-time (default: False).
        max_chunks: Max chunks to process (default: 50).
        since_seconds: Logs from last N seconds.
        tail_lines: Limit to last N lines.
        time_period: Time period (e.g., "1h", "30m").
        start_time: Start time (ISO format).
        end_time: End time (ISO format).
        max_context_tokens: Maximum tokens for output (default: 50000).
        source: Telemetry source name (default "" = the default configured instance). For file sources: pod_name is a glob relative to the configured roots; namespace and container_name are ignored. File sources are routed; other non-default sources land in later phases.

    Returns:
        Dict[str, Any]: Keys: chunks, overall_summary, trending_patterns, recommendations, metadata.

    Note: ``stream_analyze_pod_logs`` and ``stream_analyze_logs`` are the same tool;
        prefer ``stream_analyze_logs``.
    """
    _clients = None
    _log_adapter = None
    if source:
        _entry = _source_registry._entries.get(source)
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
    if _clients is None:
        _log_adapter, _gate_err = _route_log_source("stream_analyze_pod_logs", source)
        if _gate_err:
            return _gate_err
        _clients = _DefaultClientView()
    start_timestamp = time.time()
    tool_name = "stream_analyze_pod_logs"

    logger.info(f"[{tool_name}] Starting streaming log analysis for pod '{pod_name}' in namespace '{namespace}'")
    logger.info(f"[{tool_name}] Parameters: chunk_size={chunk_size}, analysis_mode={analysis_mode}, "
                f"follow={follow}, max_chunks={max_chunks}")

    # Validate input parameters
    if not namespace or not isinstance(namespace, str):
        error_msg = f"Invalid namespace parameter: {namespace}. Must be a non-empty string."
        logger.error(f"[{tool_name}] {error_msg}")
        return {"error": error_msg}

    if not pod_name or not isinstance(pod_name, str):
        error_msg = f"Invalid pod_name parameter: {pod_name}. Must be a non-empty string."
        logger.error(f"[{tool_name}] {error_msg}")
        return {"error": error_msg}

    if chunk_size < 1000 or chunk_size > 10000:
        logger.warning(f"[{tool_name}] chunk_size {chunk_size} out of range [1000-10000], setting to 5000")
        chunk_size = 5000

    if analysis_mode not in ["errors_only", "errors_and_warnings", "full_analysis", "custom_patterns"]:
        logger.warning(f"[{tool_name}] Invalid analysis_mode '{analysis_mode}', defaulting to 'errors_and_warnings'")
        analysis_mode = "errors_and_warnings"

    try:
        # Initialize stream processor
        processor = LogStreamProcessor(chunk_size=chunk_size, analysis_mode=analysis_mode)

        # Parse time parameters with enhanced support (prioritize new parameters over legacy time_window)
        if time_period or start_time or end_time or since_seconds:
            # Use new enhanced time parsing
            time_config = parse_time_parameters(
                since_seconds=since_seconds,
                time_period=time_period,
                start_time=start_time,
                end_time=end_time
            )
            log_params = time_config['log_params'].copy()
            time_info = time_config['time_info']
            logger.info(f"[{tool_name}] Using enhanced time configuration: {time_info}")
        else:
            # Fall back to legacy time_window for backward compatibility
            log_params = {}
            if time_window:
                # Convert time window to seconds
                time_mapping = {"1h": 3600, "6h": 21600, "24h": 86400, "1d": 86400}
                if time_window in time_mapping:
                    log_params['since_seconds'] = time_mapping[time_window]
                    logger.info(f"[{tool_name}] Using legacy time_window: {time_window}")
                else:
                    logger.warning(f"[{tool_name}] Unknown time_window '{time_window}', ignoring")

        # Handle tail_lines parameter
        if tail_lines is not None:
            log_params['tail_lines'] = tail_lines
        elif 'since_seconds' not in log_params:
            # AGGRESSIVE DEFAULT: Always limit tail_lines for streaming to prevent token overflow
            log_params['tail_lines'] = 2000
            logger.warning(f"[{tool_name}] No time constraints specified, defaulting to 2000 tail lines to prevent token overflow")

        # V6: hoist window + batch ABOVE the adapter branch so the retention
        # site (below) can see both regardless of which branch runs.
        _batch = None   # F4 trap: must be None when no adapter fetch runs
        _covered = None  # covered_window from Provenance; None for k8s path
        _window = make_time_window(
            since_seconds=since_seconds, time_period=time_period,
            start_time=start_time, end_time=end_time)

        # Retrieve logs
        logger.info(f"[{tool_name}] Retrieving logs from pod '{pod_name}'")
        if _log_adapter is not None:
            try:
                _batch = await _log_adapter.fetch_logs(
                    Entity(name_or_pattern=pod_name),
                    _window,
                    Limit(max_records=tail_lines, max_bytes=None))
            except AdapterError as _e:
                return {"error": str(_e)}

            _prov = _batch.provenance
            _covered = _prov.covered_window  # None for non-OTLP adapters
            _r = _otlp_retention_or_none(_batch, _window, source)
            if _r is not None:
                return _r

            raw_logs = _logbatch_to_legacy_envelope(_batch)
        else:
            raw_logs = await get_pod_logs(
                namespace=namespace,
                pod_name=pod_name,
                clients=_clients,
                **log_params
            )

        if "error" in raw_logs:
            return {"error": f"Failed to retrieve logs: {raw_logs['error']}"}

        if "logs" not in raw_logs or not raw_logs["logs"]:
            return {
                "error": "No logs found for the specified pod",
                "metadata": {"pod_name": pod_name, "namespace": namespace}
            }

        # Process logs from target container
        all_log_lines = []
        container_info = {}

        for container, logs in raw_logs["logs"].items():
            if container_name and container != container_name:
                continue

            if isinstance(logs, list):
                container_lines = logs
            else:
                container_lines = str(logs).split('\n')

            container_info[container] = len(container_lines)
            all_log_lines.extend(container_lines)

        if not all_log_lines:
            return {
                "error": f"No logs found for container '{container_name}'" if container_name else "No log content found",
                "available_containers": list(raw_logs["logs"].keys())
            }

        # Remove empty lines
        all_log_lines = [line for line in all_log_lines if line.strip()]
        total_log_lines = len(all_log_lines)

        logger.info(f"[{tool_name}] Streaming analysis of {total_log_lines} log lines in chunks of {chunk_size}")

        # Stream process logs
        chunk_results = []
        lines_processed = 0
        chunks_processed = 0

        for line in all_log_lines:
            if chunks_processed >= max_chunks:
                logger.info(f"[{tool_name}] Reached max_chunks limit ({max_chunks}), stopping")
                break

            chunk_result = processor.add_line(line)
            lines_processed += 1

            if chunk_result:
                chunk_results.append(chunk_result)
                chunks_processed += 1
                logger.info(f"[{tool_name}] Processed chunk {chunks_processed}: {chunk_result['chunk_summary']['total_issues']} issues found")

        # Process any remaining lines
        final_chunk = processor.finalize()
        if final_chunk:
            chunk_results.append(final_chunk)
            chunks_processed += 1

        # Generate overall summary and trending analysis
        overall_summary = generate_streaming_summary(chunk_results)
        trending_patterns = analyze_trending_patterns(chunk_results)
        recommendations = generate_streaming_recommendations(overall_summary, trending_patterns)

        # Calculate processing metrics
        processing_time = time.time() - start_timestamp

        results = {
            "chunks": chunk_results,
            "overall_summary": overall_summary,
            "trending_patterns": trending_patterns,
            "recommendations": recommendations,
            "metadata": {
                "pod_name": pod_name,
                "namespace": namespace,
                "container_info": container_info,
                "analysis_parameters": {
                    "chunk_size": chunk_size,
                    "analysis_mode": analysis_mode,
                    "follow": follow,
                    "max_chunks": max_chunks
                },
                "processing_metrics": {
                    "total_log_lines": total_log_lines,
                    "lines_processed": lines_processed,
                    "chunks_processed": chunks_processed,
                    "processing_time_seconds": round(processing_time, 2),
                    "average_chunk_processing_time": round(processing_time / max(chunks_processed, 1), 3)
                },
                # Covered-window conditional window attachment (M8b guard): only
                # OTLP populates covered_window so file/loki/es/k8s are byte-identical.
                **({"requested_window": list(_batch.provenance.requested_window),
                    "covered_window": list(_covered)}
                   if _covered is not None else {}),
            }
        }

        logger.info(f"[{tool_name}] Streaming analysis completed in {processing_time:.2f}s")
        logger.info(f"[{tool_name}] Processed {chunks_processed} chunks with {overall_summary.get('total_issues', 0)} total issues")

        # Apply truncation to ensure output fits within token limit
        results = truncate_to_token_limit(results, max_context_tokens)
        if results.get('_truncated'):
            logger.info(f"[{tool_name}] Output truncated to fit within {max_context_tokens} token limit")

        return results

    except Exception as e:
        error_msg = f"Unexpected error during streaming log analysis: {str(e)}"
        logger.error(f"[{tool_name}] {error_msg}", exc_info=True)
        return {
            "error": error_msg,
            "metadata": {
                "pod_name": pod_name,
                "namespace": namespace,
                "processing_time": time.time() - start_timestamp
            }
        }


# Dispatch table for analyze_pod_logs_hybrid — phase 1b swaps entries for engine-backed impls.
_HYBRID_STRATEGIES: dict[str, Callable] = {
    "summarize": smart_summarize_pod_logs,
    "stream": stream_analyze_pod_logs,
}


@mcp.tool()
async def analyze_pod_logs_hybrid(
    namespace: str,
    pod_name: str,
    container_name: Optional[str] = None,
    strategy: str = "auto",
    request_type: str = "investigation",
    urgency: str = "medium",
    use_cache: bool = True,
    custom_params: Optional[Dict[str, Any]] = None,
    source: str = ""
) -> Dict[str, Any]:
    """
    Hybrid log analyzer with intelligent strategy selection and caching.

    Automatically selects best analysis approach based on context and urgency.

    Args:
        namespace: Kubernetes namespace.
        pod_name: Pod name to analyze.
        container_name: Specific container (if multiple).
        strategy: "auto" (default), "smart_summary", "streaming", or "hybrid".
        request_type: "investigation", "troubleshooting", or "monitoring".
        urgency: "low", "medium" (default), "high", or "critical".
        use_cache: Use intelligent caching (default: True).
        custom_params: Custom parameters for strategies.
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict[str, Any]: Keys: strategy_used, analysis_results, supplementary_insights,
                        performance_metrics, recommendations, cache_info.

    Note: ``analyze_pod_logs_hybrid`` and ``analyze_logs_hybrid`` are the same tool;
        prefer ``analyze_logs_hybrid``.
    """
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("analyze_pod_logs_hybrid", source, ("Log",))
            if _gate_err:
                return _gate_err
    start_timestamp = time.time()
    tool_name = "analyze_pod_logs_hybrid"

    logger.info(f"[{tool_name}] Starting hybrid log analysis for pod '{pod_name}' in namespace '{namespace}'")
    logger.info(f"[{tool_name}] Parameters: strategy={strategy}, request_type={request_type}, "
                f"urgency={urgency}, use_cache={use_cache}")

    # Validate input parameters
    if not namespace or not isinstance(namespace, str):
        error_msg = f"Invalid namespace parameter: {namespace}. Must be a non-empty string."
        logger.error(f"[{tool_name}] {error_msg}")
        return {"error": error_msg}

    if not pod_name or not isinstance(pod_name, str):
        error_msg = f"Invalid pod_name parameter: {pod_name}. Must be a non-empty string."
        logger.error(f"[{tool_name}] {error_msg}")
        return {"error": error_msg}

    # Normalize parameters
    valid_strategies = ["auto", "smart_summary", "streaming", "hybrid"]
    if strategy not in valid_strategies:
        logger.warning(f"[{tool_name}] Invalid strategy '{strategy}', defaulting to 'auto'")
        strategy = "auto"

    valid_request_types = ["investigation", "troubleshooting", "monitoring"]
    if request_type not in valid_request_types:
        logger.warning(f"[{tool_name}] Invalid request_type '{request_type}', defaulting to 'investigation'")
        request_type = "investigation"

    valid_urgency_levels = ["low", "medium", "high", "critical"]
    if urgency not in valid_urgency_levels:
        logger.warning(f"[{tool_name}] Invalid urgency '{urgency}', defaulting to 'medium'")
        urgency = "medium"

    try:
        # Check cache first if enabled
        cache_key_params = {
            "container_name": container_name,
            "strategy": strategy,
            "request_type": request_type,
            "urgency": urgency,
            "custom_params": custom_params
        }

        cached_result = None
        if use_cache:
            cached_result = analysis_cache.get(namespace, pod_name, cache_key_params)
            if cached_result:
                logger.info(f"[{tool_name}] Returning cached result")
                cached_result["cache_info"] = {"cache_hit": True, "cache_age_seconds": time.time() - start_timestamp}
                return cached_result

        # Estimate log characteristics for strategy selection
        log_size_estimate = StrategySelector.estimate_log_size(namespace, pod_name)

        # Create analysis context
        context = LogAnalysisContext(
            log_size_estimate=log_size_estimate,
            pod_name=pod_name,
            namespace=namespace,
            request_type=request_type,
            urgency=urgency,
            time_sensitivity=(urgency in ["high", "critical"]),
            follow_up_analysis=False
        )

        # Select optimal strategy
        if strategy == "auto":
            available_strategies = [LogAnalysisStrategy.SMART_SUMMARY, LogAnalysisStrategy.STREAMING]
            selected_strategy = StrategySelector.select_strategy(context, available_strategies)
        else:
            strategy_mapping = {
                "smart_summary": LogAnalysisStrategy.SMART_SUMMARY,
                "streaming": LogAnalysisStrategy.STREAMING,
                "hybrid": LogAnalysisStrategy.HYBRID
            }
            selected_strategy = strategy_mapping[strategy]

        logger.info(f"[{tool_name}] Selected strategy: {selected_strategy.value} based on log_size={log_size_estimate}, "
                   f"urgency={urgency}, request_type={request_type}")

        # Prepare strategy-specific parameters
        strategy_params = custom_params.copy() if custom_params else {}
        strategy_params.update({
            "namespace": namespace,
            "pod_name": pod_name,
            "container_name": container_name,
            "source": source,
        })

        # Execute primary strategy
        primary_results = None
        supplementary_results = {}

        if selected_strategy == LogAnalysisStrategy.SMART_SUMMARY:
            # Configure smart summary based on context
            if urgency in ["high", "critical"]:
                strategy_params.update({
                    "summary_level": "brief",
                    "max_context_tokens": 5000,
                    "time_segments": 3
                })
            elif urgency == "low":
                strategy_params.update({
                    "summary_level": "comprehensive",
                    "max_context_tokens": 15000,
                    "time_segments": 10
                })
            else:
                strategy_params.update({
                    "summary_level": "detailed",
                    "max_context_tokens": 8000,
                    "time_segments": 5
                })

            primary_results = await _HYBRID_STRATEGIES["summarize"](**strategy_params)

        elif selected_strategy == LogAnalysisStrategy.STREAMING:
            # Configure streaming based on context
            if urgency == "critical":
                strategy_params.update({
                    "chunk_size": 1000,
                    "analysis_mode": "errors_only",
                    "max_chunks": 20
                })
            elif request_type == "troubleshooting":
                strategy_params.update({
                    "chunk_size": 3000,
                    "analysis_mode": "errors_and_warnings",
                    "max_chunks": 30
                })
            else:
                strategy_params.update({
                    "chunk_size": 5000,
                    "analysis_mode": "full_analysis",
                    "max_chunks": 50
                })

            primary_results = await _HYBRID_STRATEGIES["stream"](**strategy_params)

        elif selected_strategy == LogAnalysisStrategy.HYBRID:
            # Run both strategies and combine results
            summary_params = strategy_params.copy()
            summary_params.update({
                "summary_level": "detailed",
                "max_context_tokens": 20000,
                "time_segments": 8
            })

            streaming_params = strategy_params.copy()
            streaming_params.update({
                "chunk_size": 4000,
                "analysis_mode": "errors_and_warnings",
                "max_chunks": 25
            })

            # Run both analyses
            summary_result = await _HYBRID_STRATEGIES["summarize"](**summary_params)
            streaming_result = await _HYBRID_STRATEGIES["stream"](**streaming_params)

            # Combine results
            primary_results = {
                "combined_analysis": {
                    "summary_analysis": summary_result,
                    "streaming_analysis": streaming_result
                },
                "hybrid_insights": combine_analysis_results(summary_result, streaming_result)
            }

        # Generate supplementary insights based on primary results
        supplementary_results = generate_supplementary_insights(primary_results, context)

        # Generate performance metrics
        processing_time = time.time() - start_timestamp
        performance_metrics = {
            "processing_time_seconds": round(processing_time, 2),
            "strategy_selected": selected_strategy.value,
            "strategy_selection_reason": get_strategy_selection_reason(context, selected_strategy),
            "log_size_estimate": log_size_estimate,
            "cache_enabled": use_cache
        }

        # Generate recommendations based on strategy and results
        recommendations = generate_hybrid_recommendations(primary_results, context, selected_strategy)

        # Compile final results
        results = {
            "strategy_used": {
                "strategy": selected_strategy.value,
                "selection_reason": performance_metrics["strategy_selection_reason"],
                "context": {
                    "request_type": request_type,
                    "urgency": urgency,
                    "log_size_estimate": log_size_estimate
                }
            },
            "analysis_results": primary_results,
            "supplementary_insights": supplementary_results,
            "performance_metrics": performance_metrics,
            "recommendations": recommendations,
            "cache_info": {
                "cache_hit": False,
                "cache_enabled": use_cache,
                "cache_key_generated": use_cache
            }
        }

        # Cache results if enabled
        if use_cache and primary_results and "error" not in primary_results:
            analysis_cache.set(namespace, pod_name, cache_key_params, results)

        logger.info(f"[{tool_name}] Hybrid analysis completed in {processing_time:.2f}s using {selected_strategy.value}")

        return results

    except Exception as e:
        error_msg = f"Unexpected error during hybrid log analysis: {str(e)}"
        logger.error(f"[{tool_name}] {error_msg}", exc_info=True)
        return {
            "error": error_msg,
            "metadata": {
                "pod_name": pod_name,
                "namespace": namespace,
                "strategy_attempted": strategy,
                "processing_time": time.time() - start_timestamp
            }
        }


# _progressive_event_analysis_core is imported from helpers.event_analysis


@mcp.tool()
async def progressive_event_analysis(
    namespace: str,
    analysis_level: str = "overview",
    time_period: Optional[str] = None,
    event_filters: Optional[Dict[str, Any]] = None,
    seed_event_id: Optional[str] = None,
    focus_areas: Optional[List[str]] = None,
    source: str = ""
) -> Dict[str, Any]:
    """
    Progressive event analysis with multiple detail levels and correlation detection.

    Args:
        namespace: Kubernetes namespace to analyze.
        analysis_level: "overview", "detailed", "correlation", or "deep_dive" (default: "overview").
        time_period: Time window (e.g., "2h", "4h", "1d").
        event_filters: Filters like {"severity": ["CRITICAL"], "category": ["FAILURE"]}.
        seed_event_id: Event ID for correlation analysis.
        focus_areas: Areas to emphasize (default: ["errors", "warnings", "failures"]).
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Analysis results based on selected level.
    """
    _core_gate = _gate_source
    if source:
        _entry = _source_registry._entries.get(source)
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
            _core_gate = lambda *_a, **_k: None
    response, _ = await _progressive_event_analysis_core(
        namespace=namespace,
        analysis_level=analysis_level,
        time_period=time_period,
        event_filters=event_filters,
        seed_event_id=seed_event_id,
        focus_areas=focus_areas,
        source=source,
        smart_events_fn=smart_get_namespace_events,
        gate_fn=_core_gate,
    )
    return response


@mcp.tool()
async def advanced_event_analytics(
    namespace: str,
    time_period: Optional[str] = None,
    include_ml_patterns: bool = True,
    include_log_correlation: bool = True,
    include_metrics_correlation: bool = True,
    include_runbook_suggestions: bool = True,
    analysis_depth: str = "comprehensive",
    source: str = ""
) -> Dict[str, Any]:
    """
    Advanced ML-powered event analytics with log/metrics integration and runbook suggestions.

    Args:
        namespace: Kubernetes namespace to analyze.
        time_period: Time window (e.g., "4h", "1d", "12h").
        include_ml_patterns: Enable ML pattern detection (default: True).
        include_log_correlation: Correlate with log data (default: True).
        include_metrics_correlation: Correlate with metrics (default: True).
        include_runbook_suggestions: Generate runbook suggestions (default: True).
        analysis_depth: "basic", "comprehensive" (default), or "deep".
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Advanced analytics with ML insights, correlations, and runbook suggestions.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("advanced_event_analytics", source, ("Event",))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    tool_name = "advanced_event_analytics"

    # Validate analysis_depth
    valid_depths = {"basic", "comprehensive", "deep"}
    if analysis_depth not in valid_depths:
        return {"error": f"Invalid analysis_depth '{analysis_depth}'. Must be one of: {', '.join(sorted(valid_depths))}"}

    logger.info(f"[{tool_name}] Starting advanced analytics for namespace '{namespace}'")

    try:
        # Step 1: Get base event data — scale progressive analysis to depth
        depth_to_level = {"basic": "overview", "comprehensive": "detailed", "deep": "deep_dive"}
        base_level = depth_to_level.get(analysis_depth, "detailed")
        # When source was already resolved by _resolve_k8s, bypass the core's internal
        # gate — _resolve_k8s already validated the instance; a second gate call would
        # produce a confusing "phase 3" error with the wrong tool name.
        _core_gate = (lambda *_a, **_k: None) if source else _gate_source
        base_result, classified_events = await _progressive_event_analysis_core(
            namespace=namespace,
            analysis_level=base_level,
            time_period=time_period,
            source=source,
            smart_events_fn=smart_get_namespace_events,
            gate_fn=_core_gate,
        )

        if "error" in base_result:
            return {"error": f"Failed to get base event data: {base_result['error']}"}

        # Build events_data from the core's classified_events (full list, not 3-capped).
        # The core returns datetime objects in the 'timestamp' field; guard before
        # calling fromisoformat.
        events_data = []
        for event in classified_events:
            ts_raw = event.get("timestamp")
            if isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                try:
                    ts = datetime.fromisoformat(ts_raw)
                except (ValueError, TypeError):
                    ts = datetime.now()
            events_data.append({
                "event_string": event.get("event_string", ""),
                "severity": event.get("severity"),
                "category": event.get("category"),
                "timestamp": ts,
                "relevance_score": event.get("relevance_score", 0),
            })

        if not events_data:
            # Fallback: even without events, try log and metrics correlation if enabled
            fallback_result = {
                "namespace": namespace,
                "analysis_type": "advanced_analytics",
                "analysis_depth": analysis_depth,
                "total_events_analyzed": 0,
                "time_period": time_period,
                "generated_at": datetime.now().isoformat(),
                "note": "No Kubernetes events found; performing log/metrics-only analysis"
            }
            has_fallback_data = False

            if include_log_correlation:
                try:
                    log_integrator = LogMetricsIntegrator([])
                    log_correlation = await log_integrator.correlate_with_logs(namespace, time_period or "2h")
                    fallback_result["log_correlation"] = log_correlation
                    has_fallback_data = True
                except Exception as e:
                    logger.warning(f"[{tool_name}] Log correlation fallback failed: {e}")

            if include_metrics_correlation:
                try:
                    if not include_log_correlation:
                        log_integrator = LogMetricsIntegrator([])
                    metrics_correlation = await log_integrator.correlate_with_metrics(namespace)
                    fallback_result["metrics_correlation"] = metrics_correlation
                    has_fallback_data = True
                except Exception as e:
                    logger.warning(f"[{tool_name}] Metrics correlation fallback failed: {e}")

            if include_runbook_suggestions:
                fallback_result["runbook_suggestions"] = [
                    "No events detected — check if event generation is working in this namespace",
                    "Verify namespace has active workloads: kubectl get pods -n " + namespace,
                    "Check if events are being garbage collected prematurely"
                ]
                has_fallback_data = True

            if not has_fallback_data:
                fallback_result["message"] = "No events available and fallback analysis produced no data"
                fallback_result["suggestion"] = "Try a longer time period or different namespace"

            return fallback_result

        # Initialize analysis result
        analytics_result = {
            "namespace": namespace,
            "analysis_type": "advanced_analytics",
            "analysis_depth": analysis_depth,
            "total_events_analyzed": len(events_data),
            "time_period": time_period,
            "generated_at": datetime.now().isoformat(),
            "base_analysis": base_result
        }

        # Step 2: ML-powered pattern detection
        if include_ml_patterns:
            logger.info(f"[{tool_name}] Running ML pattern detection")
            ml_detector = MLPatternDetector(events_data)
            ml_patterns = ml_detector.detect_patterns()
            analytics_result["ml_patterns"] = ml_patterns
        else:
            analytics_result["ml_patterns"] = {"disabled": True}

        # Step 3: Log correlation
        if include_log_correlation:
            logger.info(f"[{tool_name}] Correlating with log data")
            log_integrator = LogMetricsIntegrator(events_data)
            log_correlation = await log_integrator.correlate_with_logs(namespace, time_period or "2h")
            analytics_result["log_correlation"] = log_correlation

        # Step 4: Metrics correlation
        if include_metrics_correlation:
            logger.info(f"[{tool_name}] Correlating with metrics")
            if not include_log_correlation:
                log_integrator = LogMetricsIntegrator(events_data)
            metrics_correlation = await log_integrator.correlate_with_metrics(namespace)
            analytics_result["metrics_correlation"] = metrics_correlation

        # Step 5: Runbook suggestions
        if include_runbook_suggestions:
            logger.info(f"[{tool_name}] Generating runbook suggestions")
            runbook_engine = RunbookSuggestionEngine(
                events_data,
                analytics_result.get("ml_patterns", {})
            )
            runbook_suggestions = runbook_engine.suggest_runbooks()
            analytics_result["runbook_suggestions"] = runbook_suggestions

        # Step 6: Generate comprehensive insights
        analytics_result["comprehensive_insights"] = await generate_comprehensive_insights(
            analytics_result,
            analysis_depth
        )

        # Step 7: Risk assessment and recommendations
        analytics_result["risk_assessment"] = assess_overall_risk(analytics_result)
        analytics_result["strategic_recommendations"] = generate_strategic_recommendations(analytics_result)

        logger.info(f"[{tool_name}] Advanced analytics completed successfully")
        return analytics_result

    except Exception as e:
        logger.error(f"[{tool_name}] Error in advanced analytics: {str(e)}", exc_info=True)
        return {
            "error": f"Advanced analytics failed: {str(e)}",
            "suggestion": "Try with reduced analysis scope or shorter time period"
        }


@mcp.tool()
async def automated_triage_rca_report_generator(
    failure_identifier: str,
    namespace: Optional[str] = None,
    investigation_depth: str = "standard",
    include_related_failures: bool = True,
    time_window: str = "2h",
    generate_timeline: bool = True,
    include_remediation: bool = True,
    source: str = ""
) -> Dict[str, Any]:
    """
    Generate automated Root Cause Analysis (RCA) report for pipeline/pod failures.

    Performs log analysis, resource checks, event correlation, and provides remediation suggestions.

    Args:
        failure_identifier: Pipeline run name, pod name, or failure event ID.
        namespace: Optional namespace where the failure occurred. If not provided, searches across detected CI/CD namespaces.
        investigation_depth: "quick", "standard" (default), or "deep".
        include_related_failures: Analyze related recent failures (default: True).
        time_window: Time window for related events (default: "2h").
        generate_timeline: Generate event timeline (default: True).
        include_remediation: Include remediation steps (default: True).
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: RCA report with summary, timeline, root cause, diagnostics, and remediation.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("automated_triage_rca_report_generator", source, ("Log", "Event", "Inventory"))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    # Validate investigation_depth
    valid_depths = {"quick", "standard", "deep"}
    if investigation_depth not in valid_depths:
        return {"error": f"Invalid investigation_depth '{investigation_depth}'. Must be one of: {', '.join(sorted(valid_depths))}"}

    try:
        logger.info(f"Starting automated RCA for failure: {failure_identifier}")
        investigation_start = datetime.now().isoformat()

        # Initialize report structure
        report = {
            "investigation_summary": {
                "failure_id": failure_identifier,
                "investigation_started": investigation_start,
                "failure_type": "Unknown",
                "severity": "Medium",
                "root_cause_confidence": 0.0
            },
            "failure_timeline": [],
            "root_cause_analysis": {
                "primary_cause": {},
                "contributing_factors": [],
                "affected_systems": []
            },
            "diagnostic_data": {
                "logs_analyzed": {},
                "resource_analysis": {},
                "configuration_issues": [],
                "dependency_failures": []
            },
            "remediation_plan": {
                "immediate_actions": [],
                "preventive_measures": []
            },
            "related_incidents": []
        }

        # Parse time window
        time_hours = 2
        if time_window.endswith('h'):
            time_hours = int(time_window[:-1])
        elif time_window.endswith('m'):
            time_hours = int(time_window[:-1]) / 60

        # Step 1: Identify failure type and locate namespace
        failure_context = await identify_failure_context(
            failure_identifier,
            functools.partial(detect_tekton_namespaces, source=source),
            _clients.custom_api,
            _clients.core_api,
            logger,
            namespace,
        )
        if not failure_context["found"]:
            report["investigation_summary"]["failure_type"] = "Not Found"
            report["investigation_summary"]["severity"] = "Low"
            report["investigation_summary"]["search_note"] = failure_context.get(
                "search_note", f"Resource '{failure_identifier}' not found in any namespace"
            )
            report["investigation_summary"]["namespaces_searched"] = failure_context.get("namespaces_searched", [])
            report["remediation_plan"] = {
                "immediate_actions": [
                    f"Verify the resource name '{failure_identifier}' is correct",
                    "The resource may have been garbage collected by Tekton pruner",
                    "Try using the query_kubearchive tool to retrieve archived logs",
                    "Check if there are related events: kubectl get events -n <namespace> --field-selector involvedObject.name=<name>",
                ],
                "preventive_measures": [
                    "Investigate sooner after failures (before GC runs)",
                    "Consider increasing Tekton resource retention period",
                ]
            }
            return report

        # Handle GC'd resources found via events
        gc_detected = failure_context.get("gc_detected", False)
        target_namespace = failure_context["namespace"]
        failure_type = failure_context["type"]
        report["investigation_summary"]["failure_type"] = failure_type

        if gc_detected:
            report["investigation_summary"]["gc_detected"] = True
            report["investigation_summary"]["note"] = (
                f"Resource was garbage collected but {failure_context.get('event_count', 0)} "
                f"event(s) were found. Analysis is based on available event data."
            )
            # Populate timeline from the events we found
            gc_events = failure_context.get("events", [])
            report["failure_timeline"] = [
                {
                    "timestamp": ev.get("last_timestamp", "unknown"),
                    "event": ev.get("reason", "unknown"),
                    "message": ev.get("message", ""),
                    "type": ev.get("type", "Normal"),
                    "source": "kubernetes_event"
                }
                for ev in gc_events
            ]

        # Bind source to internal tool references so all helper calls hit the named
        # instance.  Without this, helpers that accept a bare function reference would
        # call the tool with no source= and silently use the default cluster.
        _analyze_failed = functools.partial(analyze_failed_pipeline, source=source) if source else analyze_failed_pipeline
        _get_logs = functools.partial(get_pod_logs, clients=_clients) if source else get_pod_logs
        _smart_events = functools.partial(smart_get_namespace_events, source=source) if source else smart_get_namespace_events
        _list_prs = functools.partial(list_pipelineruns, source=source) if source else list_pipelineruns

        # Step 2: Core failure analysis based on type
        if failure_type == "pipelinerun":
            primary_analysis = await analyze_pipeline_failure(target_namespace, failure_identifier, investigation_depth, _analyze_failed, analyze_pipeline_performance, _get_logs, analyze_logs, detect_log_anomalies, analyze_pipeline_dependencies, logger)
        elif failure_type == "pod":
            primary_analysis = await analyze_pod_failure(target_namespace, failure_identifier, investigation_depth, _clients.core_api, _get_logs, analyze_logs, detect_log_anomalies, _smart_events, logger)
        else:
            primary_analysis = await analyze_generic_failure(target_namespace, failure_identifier, investigation_depth, _smart_events, logger)

        # Step 3: Build failure timeline
        timeline_events = []
        if generate_timeline:
            timeline_events = await build_failure_timeline(target_namespace, failure_identifier, time_hours, _smart_events, logger)
            if timeline_events:
                report["failure_timeline"] = timeline_events
            # If no new timeline events found but we have GC events, keep those
            elif not report.get("failure_timeline"):
                report["failure_timeline"] = []

        # Step 4: Correlate with related failures
        related_failures = []
        if include_related_failures:
            related_failures = await find_related_failures(target_namespace, failure_identifier, time_hours, investigation_depth, _list_prs, logger)
            report["related_incidents"] = related_failures

        # Step 5: Advanced correlation and root cause analysis
        root_cause_data = await perform_advanced_rca(
            primary_analysis, timeline_events, related_failures, investigation_depth, categorize_errors, logger
        )

        # Step 6: Resource and configuration analysis
        resource_analysis = await analyze_resource_constraints(target_namespace, failure_identifier, _clients.core_api, logger)
        config_analysis = await analyze_configuration_issues(target_namespace, failure_identifier, logger)

        # Step 7: Compile comprehensive analysis
        report["root_cause_analysis"] = root_cause_data["root_cause_analysis"]
        report["diagnostic_data"] = {
            "logs_analyzed": primary_analysis.get("logs_analyzed", {}),
            "resource_analysis": resource_analysis,
            "configuration_issues": config_analysis,
            "dependency_failures": root_cause_data.get("dependency_failures", [])
        }

        # Step 8: Generate remediation plan
        if include_remediation:
            remediation_plan = await generate_remediation_plan(
                root_cause_data, primary_analysis, resource_analysis, config_analysis, recommend_actions, logger
            )
            report["remediation_plan"] = remediation_plan

        # Step 9: Calculate confidence and severity
        confidence_score = calculate_confidence_score(primary_analysis, root_cause_data, timeline_events)
        severity_analysis = assess_failure_severity(
            primary_analysis, root_cause_data, resource_analysis, config_analysis,
            related_incidents=related_failures,
        )
        severity = severity_analysis["severity_level"]

        report["investigation_summary"]["root_cause_confidence"] = confidence_score
        report["investigation_summary"]["severity"] = severity
        report["investigation_summary"]["severity_score"] = severity_analysis["severity_score"]

        logger.info(f"RCA completed for {failure_identifier} with confidence: {confidence_score:.2f}")
        return report

    except Exception as e:
        logger.error(f"Error in automated RCA for {failure_identifier}: {str(e)}", exc_info=True)
        return {
            "investigation_summary": {
                "failure_id": failure_identifier,
                "investigation_started": datetime.now().isoformat(),
                "failure_type": "Error",
                "severity": "High",
                "root_cause_confidence": 0.0
            },
            "failure_timeline": [],
            "root_cause_analysis": {"primary_cause": {"error": str(e)}, "contributing_factors": [], "affected_systems": []},
            "diagnostic_data": {"logs_analyzed": {}, "resource_analysis": {}, "configuration_issues": [], "dependency_failures": []},
            "remediation_plan": {"immediate_actions": ["Check tool logs for detailed error information"], "preventive_measures": []},
            "related_incidents": []
        }


@mcp.tool()
async def check_cluster_certificate_health(
    warning_threshold_days: int = 30,
    critical_threshold_days: int = 7,
    include_system_certs: bool = True,
    namespaces: Optional[List[str]] = None,
    certificate_types: Optional[List[str]] = None,
    source: str = "",
) -> Dict[str, Any]:
    """
    Scan for expiring certificates across the cluster to prevent service disruptions.

    Scans TLS secrets, system certificates, and provides renewal recommendations.

    Args:
        warning_threshold_days: Days before expiration for warning (default: 30).
        critical_threshold_days: Days before expiration for critical alert (default: 7).
        include_system_certs: Include system certificates (default: True).
        namespaces: Namespaces to scan (default: all accessible).
        certificate_types: Types to check: "tls", "ca", "client", "server" (default: all).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Certificate health with expiration timeline, recommendations, and security findings.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    try:
        _ro = ReadOnlyK8sClient.wrap(_clients.core_api)
        logger.info(f"Starting cluster certificate health scan with thresholds: warning={warning_threshold_days}d, critical={critical_threshold_days}d")

        # Initialize result structure
        result = {
            "scan_summary": {
                "total_certificates": 0,
                "healthy_certificates": 0,
                "warning_certificates": 0,
                "critical_certificates": 0,
                "expired_certificates": 0,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "namespaces_scanned": 0,
                "namespaces_skipped_rbac": 0,
                "namespaces_total": 0
            },
            "certificate_details": [],
            "system_certificates": [],
            "expiration_timeline": [],
            "renewal_recommendations": [],
            "security_findings": [],
            "certificate_authorities": [],
            "coverage": {},  # will be replaced by build_coverage() after scanning
        }

        # Determine namespaces to scan
        target_namespaces = namespaces or []
        if not target_namespaces:
            # Get all accessible namespaces
            try:
                all_ns = await k8s_call(_ro.list_namespace)
                target_namespaces = [ns.metadata.name for ns in all_ns.items if ns.metadata and ns.metadata.name]
                logger.info(f"Scanning all {len(target_namespaces)} accessible namespaces")
            except ApiException as e:
                logger.warning(f"Could not list all namespaces, using default set: {e.reason}")
                target_namespaces = ['default', 'kube-system', 'openshift-config', 'openshift-ingress']

        # Set default certificate types
        if not certificate_types:
            certificate_types = ["tls", "ca", "client", "server"]

        certificates_found = []
        ca_certificates = {}
        scanned_namespaces = []
        skipped_namespaces_rbac = []
        failed_namespaces = []  # namespaces that returned non-403 API errors
        # System-namespace extras added by include_system_certs — tracked separately
        # so the caller-facing coverage denominator stays scope-relative (D2 ruling).
        _sys_ns_scanned: list = []  # tool-added system namespaces scanned successfully
        _sys_ns_denied: list = []   # tool-added system namespaces RBAC-denied

        # Scan for TLS secrets in each namespace
        for namespace in target_namespaces:
            try:
                logger.debug(f"Scanning namespace: {namespace}")
                secrets = await k8s_call(_ro.list_namespaced_secret, namespace)
                scanned_namespaces.append(namespace)

                for secret in secrets.items:
                    if not secret.data:
                        continue

                    # Check if secret contains certificate data
                    cert_keys = ['tls.crt', 'ca.crt', 'cert', 'certificate', 'client.crt', 'server.crt']

                    for key in cert_keys:
                        if key in secret.data:
                            try:
                                # Decode base64 certificate data
                                cert_data = base64.b64decode(secret.data[key]).decode('utf-8')

                                # Handle certificate chains (multiple certificates)
                                cert_blocks = cert_data.split('-----END CERTIFICATE-----')

                                for i, cert_block in enumerate(cert_blocks):
                                    if '-----BEGIN CERTIFICATE-----' in cert_block:
                                        full_cert = cert_block + '-----END CERTIFICATE-----'
                                        cert_info = parse_certificate(full_cert)

                                        if cert_info:
                                            cert_details = {
                                                "certificate_info": {
                                                    "name": f"{secret.metadata.name}_{key}_{i}" if i > 0 else f"{secret.metadata.name}_{key}",
                                                    "namespace": namespace,
                                                    "secret_name": secret.metadata.name,
                                                    "key_name": key,
                                                    "type": secret.type or "Opaque"
                                                },
                                                "certificate_data": cert_info,
                                                "validity": {
                                                    "not_before": cert_info['not_before'],
                                                    "not_after": cert_info['not_after'],
                                                    "days_remaining": cert_info['days_remaining'],
                                                    "status": categorize_certificate_status(
                                                        cert_info['days_remaining'],
                                                        warning_threshold_days,
                                                        critical_threshold_days
                                                    )
                                                },
                                                "usage": {
                                                    "is_ca": cert_info.get('is_ca', False) or 'ca' in key.lower(),
                                                    "is_client": 'client' in key.lower(),
                                                    "is_server": 'server' in key.lower() or 'tls' in key.lower(),
                                                    "san_domains": cert_info.get('san', [])
                                                },
                                                "chain_validation": {
                                                    "is_self_signed": cert_info.get('subject_cn') == cert_info.get('issuer_cn'),
                                                    "issuer": cert_info.get('issuer_cn', 'Unknown'),
                                                    "chain_length": len(cert_blocks) if len(cert_blocks) > 1 else 1
                                                }
                                            }

                                            certificates_found.append(cert_details)

                                            # Track CA certificates
                                            if cert_details["usage"]["is_ca"]:
                                                ca_name = cert_info.get('subject_cn', 'Unknown CA')
                                                if ca_name not in ca_certificates:
                                                    ca_certificates[ca_name] = {
                                                        "ca_name": ca_name,
                                                        "issued_certificates": 0,
                                                        "ca_expiry": cert_info['not_after'],
                                                        "trust_status": "trusted" if not cert_details["chain_validation"]["is_self_signed"] else "self-signed"
                                                    }
                                                ca_certificates[ca_name]["issued_certificates"] += 1

                            except Exception as e:
                                logger.debug(f"Could not parse certificate {key} in secret {secret.metadata.name}: {e}")
                                continue

            except ApiException as e:
                if e.status == 403:
                    logger.debug(f"Access denied to namespace {namespace}: {e.reason}")
                    if namespace not in skipped_namespaces_rbac:
                        skipped_namespaces_rbac.append(namespace)
                else:
                    logger.warning(f"Error scanning namespace {namespace}: {e.reason}")
                    failed_namespaces.append(namespace)
                continue

        # Process OpenShift system certificates if requested
        # Always scan system cert namespaces when include_system_certs=True,
        # even when specific namespaces were provided (they may have been RBAC-blocked)
        if include_system_certs:
            try:
                # Try to get OpenShift cluster certificates
                system_cert_namespaces = [
                    'openshift-config',
                    'openshift-ingress',
                    'openshift-ingress-operator',
                    'openshift-kube-apiserver',
                    'openshift-etcd'
                ]

                for sys_ns in system_cert_namespaces:
                    if sys_ns not in scanned_namespaces:
                        try:
                            secrets = await k8s_call(_ro.list_namespaced_secret, sys_ns)
                            scanned_namespaces.append(sys_ns)
                            _sys_ns_scanned.append(sys_ns)
                            for secret in secrets.items:
                                if secret.data:
                                    for key in ['tls.crt', 'ca.crt']:
                                        if key in secret.data:
                                            try:
                                                # Properly parse the certificate
                                                cert_data = base64.b64decode(secret.data[key]).decode('utf-8')
                                                if '-----BEGIN CERTIFICATE-----' in cert_data:
                                                    cert_info = parse_certificate(cert_data)
                                                    if cert_info:
                                                        status = categorize_certificate_status(
                                                            cert_info['days_remaining'],
                                                            warning_threshold_days,
                                                            critical_threshold_days
                                                        )
                                                        result["system_certificates"].append({
                                                            "component": sys_ns.replace('openshift-', ''),
                                                            "certificate_purpose": secret.metadata.name,
                                                            "subject_cn": cert_info.get('subject_cn', 'Unknown'),
                                                            "expiry_date": cert_info.get('not_after', 'Unknown'),
                                                            "days_remaining": cert_info.get('days_remaining', 0),
                                                            "status": status,
                                                            "auto_renewal": True,
                                                            "renewal_mechanism": "OpenShift Certificate Operator"
                                                        })
                                            except Exception as parse_err:
                                                logger.debug(f"Could not parse system cert {secret.metadata.name}/{key}: {parse_err}")
                        except ApiException as e:
                            if e.status == 403:
                                # Tool-added system namespace: track separately,
                                # NOT in the caller-facing skipped_namespaces_rbac.
                                if sys_ns not in _sys_ns_denied:
                                    _sys_ns_denied.append(sys_ns)
                            else:
                                if sys_ns not in failed_namespaces:
                                    failed_namespaces.append(sys_ns)
                            continue

            except Exception as e:
                logger.debug(f"Could not scan system certificates: {e}")

        # Update scan summary
        total_certs = len(certificates_found)
        healthy_count = len([c for c in certificates_found if c["validity"]["status"] == "healthy"])
        warning_count = len([c for c in certificates_found if c["validity"]["status"] == "warning"])
        critical_count = len([c for c in certificates_found if c["validity"]["status"] == "critical"])
        expired_count = len([c for c in certificates_found if c["validity"]["status"] == "expired"])

        # Caller-relative counts: exclude tool-added system namespaces so the
        # coverage verdict reflects what the CALLER requested, not what the tool
        # added on its own.  System outcomes are surfaced in coverage extras.
        _sys_ns_set = set(_sys_ns_scanned)
        _caller_scanned = [ns for ns in scanned_namespaces if ns not in _sys_ns_set]
        _requested = len(namespaces) if namespaces else 0
        _discovered = len(_caller_scanned) + len(skipped_namespaces_rbac) + len(failed_namespaces)

        result["scan_summary"].update({
            "total_certificates": total_certs,
            "healthy_certificates": healthy_count,
            "warning_certificates": warning_count,
            "critical_certificates": critical_count,
            "expired_certificates": expired_count,
            "namespaces_scanned": len(_caller_scanned),
            "namespaces_skipped_rbac": len(skipped_namespaces_rbac),
            "namespaces_total": _discovered  # consistent with coverage.discovered
        })

        # Build Clause A coverage block — replaces the old scan_coverage key.
        # failed_namespaces (non-403 API errors) are included in discovered and
        # reported as skipped so the tautology discovered = scanned + denied does
        # not make the skipped partial-trigger permanently dead.
        # System namespace extras (tool-added) are reported as informational fields,
        # not folded into the caller-facing denominator (D2 ruling: scope-relative).
        result["coverage"] = build_coverage(
            "namespaces",
            requested=_requested,
            discovered=_discovered,
            scanned=len(_caller_scanned),
            denied=len(skipped_namespaces_rbac),
            skipped=len(failed_namespaces),
            requested_mode="explicit" if namespaces else "all",
            system_namespaces_added=len(_sys_ns_scanned),
            system_namespaces_denied=len(_sys_ns_denied),
        )

        # RBAC warning: only about the CALLER's denied namespaces.
        if len(skipped_namespaces_rbac) > len(_caller_scanned):
            result["security_findings"].append({
                "type": "rbac_limitation",
                "severity": "high" if result["coverage"]["verdict"] == "none" else "warning",
                "message": f"RBAC restrictions prevented scanning {len(skipped_namespaces_rbac)} namespaces. "
                          f"Only {len(_caller_scanned)} namespaces were accessible. "
                          "Consider granting 'list secrets' permission for comprehensive certificate scanning."
            })

        # Informational note when the tool's own system namespace additions were denied.
        if _sys_ns_denied:
            result["security_findings"].append({
                "type": "system_namespace_rbac",
                "severity": "info",
                "message": (
                    f"System certificate namespaces added by this tool: "
                    f"{len(_sys_ns_denied)} of {len(_sys_ns_scanned) + len(_sys_ns_denied)} "
                    f"were RBAC-denied ({', '.join(_sys_ns_denied)}). "
                    "Grant 'list secrets' in these namespaces for OpenShift system certificate coverage."
                ),
            })

        # Filter certificates by type if specified
        if certificate_types and "all" not in certificate_types:
            filtered_certs = []
            for cert in certificates_found:
                cert_usage = cert["usage"]
                if ("tls" in certificate_types and cert_usage["is_server"]) or \
                   ("ca" in certificate_types and cert_usage["is_ca"]) or \
                   ("client" in certificate_types and cert_usage["is_client"]) or \
                   ("server" in certificate_types and cert_usage["is_server"]):
                    filtered_certs.append(cert)
            certificates_found = filtered_certs

        result["certificate_details"] = certificates_found

        # Generate expiration timeline
        timeline_dict = defaultdict(list)
        for cert in certificates_found:
            if cert["validity"]["days_remaining"] >= 0:  # Don't include expired certs in timeline
                expiry_date = cert["certificate_data"]["not_after"][:10]  # Just the date part
                timeline_dict[expiry_date].append({
                    "name": cert["certificate_info"]["name"],
                    "namespace": cert["certificate_info"]["namespace"],
                    "days_remaining": cert["validity"]["days_remaining"],
                    "status": cert["validity"]["status"]
                })

        # Sort timeline by date
        sorted_timeline = []
        for date in sorted(timeline_dict.keys()):
            sorted_timeline.append({
                "date": date,
                "certificates_expiring": timeline_dict[date]
            })

        result["expiration_timeline"] = sorted_timeline[:30]  # Limit to next 30 expiration dates

        # Generate renewal recommendations
        for cert in certificates_found:
            if cert["validity"]["status"] in ["critical", "warning", "expired"]:
                urgency = "immediate" if cert["validity"]["status"] in ["critical", "expired"] else "soon"

                recommendation = {
                    "certificate": cert["certificate_info"]["name"],
                    "namespace": cert["certificate_info"]["namespace"],
                    "urgency": urgency,
                    "renewal_method": "manual",
                    "steps": [
                        f"Generate new certificate for {cert['certificate_data'].get('subject_cn', 'unknown subject')}",
                        f"Update secret {cert['certificate_info']['secret_name']} in namespace {cert['certificate_info']['namespace']}",
                        "Restart affected pods/services"
                    ],
                    "automation_available": cert["certificate_info"]["namespace"].startswith("openshift-")
                }

                if cert["certificate_info"]["namespace"].startswith("openshift-"):
                    recommendation["renewal_method"] = "OpenShift Certificate Operator"
                    recommendation["steps"] = [
                        "Certificate should auto-renew via OpenShift Certificate Operator",
                        "If not auto-renewing, check cluster operator status",
                        "Manual intervention may be required"
                    ]

                result["renewal_recommendations"].append(recommendation)

        # Generate security findings
        for cert in certificates_found:
            cert_data = cert["certificate_data"]

            # Check for weak algorithms
            if "sha1" in cert_data.get("signature_algorithm", "").lower():
                result["security_findings"].append({
                    "certificate": cert["certificate_info"]["name"],
                    "finding_type": "weak_algorithm",
                    "description": f"Certificate uses weak SHA-1 signature algorithm",
                    "severity": "medium",
                    "recommendation": "Replace with SHA-256 or stronger algorithm"
                })

            # Check for self-signed certificates
            if cert["chain_validation"]["is_self_signed"] and not cert["usage"]["is_ca"]:
                result["security_findings"].append({
                    "certificate": cert["certificate_info"]["name"],
                    "finding_type": "self_signed",
                    "description": "Self-signed certificate detected",
                    "severity": "low",
                    "recommendation": "Consider using CA-signed certificate for production"
                })

            # Check for short validity periods
            if cert["validity"]["days_remaining"] < critical_threshold_days and cert["validity"]["status"] != "expired":
                result["security_findings"].append({
                    "certificate": cert["certificate_info"]["name"],
                    "finding_type": "short_validity",
                    "description": f"Certificate expires in {cert['validity']['days_remaining']} days",
                    "severity": "high",
                    "recommendation": "Renew certificate immediately"
                })

        # Add CA information
        result["certificate_authorities"] = list(ca_certificates.values())

        logger.info(f"Certificate health scan completed: {total_certs} certificates found, {critical_count + expired_count} require immediate attention")
        return result

    except Exception as e:
        logger.error(f"Error during certificate health check: {str(e)}", exc_info=True)
        return {
            "scan_summary": {
                "total_certificates": 0,
                "healthy_certificates": 0,
                "warning_certificates": 0,
                "critical_certificates": 0,
                "expired_certificates": 0,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            },
            "certificate_details": [],
            "system_certificates": [],
            "expiration_timeline": [],
            "renewal_recommendations": [],
            "security_findings": [],
            "certificate_authorities": []
        }


async def get_machine_config_pool_status(
    pool_names: Optional[List[str]] = None,
    include_node_details: bool = True,
    include_update_history: bool = True,
    filter_updating: bool = False,
    source: str = ""
) -> Dict[str, Any]:
    """
    Monitor OpenShift Machine Config Pools for node configuration and update rollouts.

    Analyzes pool status, update progress, and configuration drift.

    Args:
        pool_names: Pools to monitor (default: all).
        include_node_details: Include node status per pool (default: True).
        include_update_history: Include update history (default: True).
        filter_updating: Only show updating pools (default: False).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Keys: pools_overview, machine_config_pools, recent_config_changes, issues,
              update_recommendations.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    _gerr = _gate_extension("get_machine_config_pool_status", source)
    if _gerr:
        return _gerr
    logger.info("Starting machine config pool status analysis")

    try:
        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)
        _ro_core = ReadOnlyK8sClient.wrap(_clients.core_api)
        # Query MachineConfigPool resources using Kubernetes Custom Resource API
        logger.info("Querying MachineConfigPool resources from OpenShift Machine Config Operator")

        pools_response = await k8s_call(_ro.list_cluster_custom_object,
            group="machineconfiguration.openshift.io",
            version="v1",
            plural="machineconfigpools"
        )

        all_pools = pools_response.get("items", [])
        logger.info(f"Found {len(all_pools)} machine config pools in cluster")

        # Filter pools if specific names requested
        if pool_names:
            filtered_pools = []
            for pool in all_pools:
                pool_name = pool.get("metadata", {}).get("name", "")
                if pool_name in pool_names:
                    filtered_pools.append(pool)
            pools_to_analyze = filtered_pools
            logger.info(f"Filtered to {len(pools_to_analyze)} requested pools: {pool_names}")
        else:
            pools_to_analyze = all_pools

        # Analyze each pool
        analyzed_pools = []
        for pool in pools_to_analyze:
            pool_analysis = analyze_machine_config_pool_status(pool)
            analyzed_pools.append(pool_analysis)

        # Filter for updating pools if requested
        if filter_updating:
            analyzed_pools = [pool for pool in analyzed_pools if pool.get("update_progress", {}).get("is_updating", False)]
            logger.info(f"Filtered to {len(analyzed_pools)} pools currently updating")

        # Generate pools overview
        total_pools = len(analyzed_pools)
        healthy_pools = len([pool for pool in analyzed_pools if pool.get("status") == "ready"])
        updating_pools = len([pool for pool in analyzed_pools if pool.get("update_progress", {}).get("is_updating", False)])
        degraded_pools = len([pool for pool in analyzed_pools if pool.get("status") == "degraded"])

        pools_overview = {
            "total_pools": total_pools,
            "healthy_pools": healthy_pools,
            "updating_pools": updating_pools,
            "degraded_pools": degraded_pools
        }

        # Get recent machine config changes if requested
        recent_config_changes = []
        if include_update_history:
            try:
                logger.info("Querying recent MachineConfig changes")
                machine_configs_response = await k8s_call(_ro.list_cluster_custom_object,
                    group="machineconfiguration.openshift.io",
                    version="v1",
                    plural="machineconfigs"
                )

                machine_configs = machine_configs_response.get("items", [])

                # Sort by creation time and get recent ones
                sorted_configs = sorted(
                    machine_configs,
                    key=lambda x: x.get("metadata", {}).get("creationTimestamp", ""),
                    reverse=True
                )[:10]  # Get last 10 configs

                for config in sorted_configs:
                    metadata = config.get("metadata", {})
                    recent_config_changes.append({
                        "config_name": metadata.get("name", "unknown"),
                        "created_time": metadata.get("creationTimestamp", "unknown"),
                        "changes": ["Configuration details would require detailed diff analysis"],
                        "affected_pools": metadata.get("labels", {}).get("machineconfiguration.openshift.io/role", "unknown")
                    })

            except Exception as e:
                logger.warning(f"Could not retrieve machine config history: {e}")
                recent_config_changes = []

        # Detect issues across all pools
        all_issues = []
        for pool in analyzed_pools:
            pool_issues = detect_pool_issues(pool)
            all_issues.extend(pool_issues)

        # Generate recommendations
        update_recommendations = generate_update_recommendations(analyzed_pools)

        # Add node details if requested and include_node_details is True
        if include_node_details:
            logger.info("Adding detailed node status to pool analysis")
            # One bounded, off-loop node fetch shared by every pool — the
            # previous per-pool sync list_node() paid the full cluster list
            # once per pool ON the event loop (2026-08-21 freeze class).
            try:
                _all_nodes = await list_nodes_bounded(_ro_core)
            except Exception as e:
                logger.warning(f"Could not retrieve nodes for pool node details: {e}")
                _all_nodes = None
                for pool in analyzed_pools:
                    # Surfaced, not silent: an empty node_status with no error
                    # marker is indistinguishable from "no nodes match this
                    # pool's selector" (review round 1).
                    pool["node_status"] = []
                    pool["node_status_error"] = type(e).__name__
            for pool in (analyzed_pools if _all_nodes is not None else []):
                try:
                    # Query nodes that belong to this pool based on node selector.
                    # Real MachineConfigPools nest labels under matchLabels —
                    # unwrap it (bug 4: the flat iteration matched zero nodes
                    # on every real pool). matchExpressions are not evaluated;
                    # only the matchLabels equality part filters here.
                    pool_config = pool.get("configuration", {})
                    node_selector = pool_config.get("node_selector", {}) or {}
                    if "matchLabels" in node_selector or "matchExpressions" in node_selector:
                        _has_expressions = bool(node_selector.get("matchExpressions"))
                        node_selector = node_selector.get("matchLabels") or {}
                        if not node_selector and _has_expressions:
                            # matchExpressions-only pool: an empty label map
                            # would match EVERY node (review MAJOR-2 — this
                            # commit must not over-claim the fleet). Report
                            # honestly instead of guessing.
                            pool["node_status"] = []
                            pool["node_selector_unsupported"] = "matchExpressions"
                            continue
                        if _has_expressions:
                            # matchLabels applied; matchExpressions not
                            # evaluated — the node list is a SUPERSET
                            # (re-review MINOR-4: say so explicitly)
                            pool["node_selector_partial"] = "matchExpressions"

                    # Filter the shared node list by the pool's selector labels
                    nodes = _all_nodes
                    matching_nodes = []

                    for node in nodes.items:
                        node_labels = node.metadata.labels or {}
                        # Check if node matches the pool's node selector
                        matches = True
                        for key, value in node_selector.items():
                            if node_labels.get(key) != value:
                                matches = False
                                break

                        if matches:
                            node_status = {
                                "name": node.metadata.name,
                                "ready": False,
                                "machine_config": "unknown",
                                "last_update": "unknown"
                            }

                            # Check node readiness
                            for condition in node.status.conditions or []:
                                if condition.type == "Ready":
                                    node_status["ready"] = condition.status == "True"
                                    break

                            # Extract machine config info from annotations
                            annotations = node.metadata.annotations or {}
                            node_status["machine_config"] = annotations.get(
                                "machineconfiguration.openshift.io/currentConfig", "unknown"
                            )
                            node_status["last_update"] = annotations.get(
                                "machineconfiguration.openshift.io/lastAppliedDrift", "unknown"
                            )

                            matching_nodes.append(node_status)

                    pool["node_status"] = matching_nodes

                except Exception as e:
                    logger.warning(f"Could not retrieve node details for pool {pool.get('name')}: {e}")
                    pool["node_status"] = []

        result = {
            "pools_overview": pools_overview,
            "machine_config_pools": analyzed_pools,
            "recent_config_changes": recent_config_changes,
            "issues": all_issues,
            "update_recommendations": update_recommendations
        }

        logger.info(f"Machine config pool analysis complete: {total_pools} pools analyzed, "
                   f"{len(all_issues)} issues found, {len(update_recommendations)} recommendations generated")

        return result

    except ApiException as e:
        error_msg = f"Kubernetes API error while querying machine config pools: {e.status} - {e.reason}"
        logger.error(error_msg)
        return {
            "pools_overview": {"total_pools": 0, "healthy_pools": 0, "updating_pools": 0, "degraded_pools": 0},
            "machine_config_pools": [],
            "recent_config_changes": [],
            "issues": [{
                "pool": "api_error",
                "issue_type": "api_access",
                "description": error_msg,
                "affected_nodes": [],
                "severity": "high",
                "remediation": "Check RBAC permissions for machineconfiguration.openshift.io resources"
            }],
            "update_recommendations": []
        }

    except Exception as e:
        error_msg = f"Unexpected error during machine config pool analysis: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "pools_overview": {"total_pools": 0, "healthy_pools": 0, "updating_pools": 0, "degraded_pools": 0},
            "machine_config_pools": [],
            "recent_config_changes": [],
            "issues": [{
                "pool": "system_error",
                "issue_type": "analysis_failure",
                "description": error_msg,
                "affected_nodes": [],
                "severity": "high",
                "remediation": "Check system logs and OpenShift Machine Config Operator status"
            }],
            "update_recommendations": []
        }


async def get_openshift_cluster_operator_status(
    operator_names: Optional[List[str]] = None,
    include_conditions: bool = True,
    show_version_info: bool = True,
    filter_degraded: bool = False,
    include_dependencies: bool = False,
    source: str = ""
) -> Dict[str, Any]:
    """
    Check health and status of OpenShift cluster operators for platform functionality.

    Analyzes operator conditions, versions, and dependencies.

    Args:
        operator_names: Operators to check (default: all).
        include_conditions: Include condition details (default: True).
        show_version_info: Include version info (default: True).
        filter_degraded: Only show operators with issues (default: False).
        include_dependencies: Show operator dependencies (default: False).
        source: Kubernetes instance name (default "" = the default cluster).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Keys: cluster_info, operator_status, health_summary, critical_issues, dependencies.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    _gerr = _gate_extension("get_openshift_cluster_operator_status", source)
    if _gerr:
        return _gerr
    logger.info("Starting OpenShift cluster operator status analysis")

    try:
        _ro = ReadOnlyK8sClient.wrap(_clients.custom_api)
        # Query ClusterOperator resources from OpenShift Config API
        logger.info("Querying ClusterOperator resources from OpenShift Config API")

        operators_response = await k8s_call(_ro.list_cluster_custom_object,
            group="config.openshift.io",
            version="v1",
            plural="clusteroperators"
        )

        all_operators = operators_response.get("items", [])
        logger.info(f"Found {len(all_operators)} cluster operators")

        # Filter operators if specific names requested
        if operator_names:
            filtered_operators = []
            for operator in all_operators:
                op_name = operator.get("metadata", {}).get("name", "")
                if op_name in operator_names:
                    filtered_operators.append(operator)
            operators_to_analyze = filtered_operators
            logger.info(f"Filtered to {len(operators_to_analyze)} requested operators: {operator_names}")
        else:
            operators_to_analyze = all_operators

        # Get cluster version information
        cluster_info = {}
        try:
            cluster_version_response = await k8s_call(_ro.list_cluster_custom_object,
                group="config.openshift.io",
                version="v1",
                plural="clusterversions"
            )
            cluster_versions = cluster_version_response.get("items", [])
            if cluster_versions:
                cv = cluster_versions[0]  # There's typically only one
                cv_status = cv.get("status", {})
                cluster_info = {
                    "cluster_version": cv_status.get("desired", {}).get("version", "unknown"),
                    "cluster_id": cv.get("spec", {}).get("clusterID", "unknown"),
                    "infrastructure_status": cv_status.get("infrastructure", {}).get("status", "unknown"),
                    "update_available": len(cv_status.get("availableUpdates", [])) > 0,
                    "current_update": cv_status.get("history", [{}])[0] if cv_status.get("history") else {}
                }
        except Exception as e:
            logger.warning(f"Could not retrieve cluster version info: {e}")
            cluster_info = {
                "cluster_version": "unknown",
                "cluster_id": "unknown",
                "infrastructure_status": "unknown",
                "update_available": False,
                "current_update": {}
            }

        # Analyze each operator
        analyzed_operators = []
        for operator in operators_to_analyze:
            metadata = operator.get("metadata", {})
            status = operator.get("status", {})

            operator_analysis = {
                "name": metadata.get("name", "unknown"),
                "namespace": metadata.get("namespace", "cluster-scoped"),
                "status": "unknown",
                "available": False,
                "progressing": False,
                "degraded": False
            }

            # Analyze conditions - always parse for health assessment, only include raw in output if requested
            conditions = status.get("conditions", [])
            conditions_analysis = analyze_operator_conditions(conditions)
            operator_analysis["available"] = conditions_analysis["available"]
            operator_analysis["progressing"] = conditions_analysis["progressing"]
            operator_analysis["degraded"] = conditions_analysis["degraded"]
            if include_conditions:
                operator_analysis["conditions_analysis"] = conditions_analysis
                operator_analysis["conditions"] = conditions

            # Calculate overall status
            if operator_analysis["degraded"]:
                operator_analysis["status"] = "degraded"
            elif not operator_analysis["available"]:
                operator_analysis["status"] = "unavailable"
            elif operator_analysis["progressing"]:
                operator_analysis["status"] = "progressing"
            else:
                operator_analysis["status"] = "available"

            # Add version information
            if show_version_info:
                versions = status.get("versions", [])
                if versions:
                    # Find operator version (usually the first one or one named 'operator')
                    operator_version = "unknown"
                    for version in versions:
                        if version.get("name") == "operator" or len(versions) == 1:
                            operator_version = version.get("version", "unknown")
                            break
                    operator_analysis["version"] = operator_version
                else:
                    operator_analysis["version"] = "unknown"

            # Add related objects info
            operator_analysis["related_objects"] = status.get("relatedObjects", [])

            analyzed_operators.append(operator_analysis)

        # Calculate health summary from ALL operators before filtering
        total_operators = len(analyzed_operators)
        healthy_operators = len([op for op in analyzed_operators if op.get("status") == "available"])
        degraded_operators = len([op for op in analyzed_operators if op.get("degraded", False)])

        # Filter degraded operators if requested (after counting)
        if filter_degraded:
            analyzed_operators = [op for op in analyzed_operators if op.get("degraded", False) or op.get("status") != "available"]
            logger.info(f"Filtered to {len(analyzed_operators)} operators with issues")

        overall_health = "healthy"
        if total_operators == 0:
            overall_health = "undetermined"
        elif degraded_operators > 0:
            overall_health = "degraded"
        elif healthy_operators < total_operators:
            overall_health = "warning"

        health_summary = {
            "total_operators": total_operators,
            "healthy_operators": healthy_operators,
            "degraded_operators": degraded_operators,
            "overall_health": overall_health
        }

        # Identify critical issues
        critical_issues = identify_critical_issues(analyzed_operators)

        # Build response
        response = {
            "cluster_info": cluster_info,
            "operator_status": analyzed_operators,
            "health_summary": health_summary,
            "critical_issues": critical_issues
        }

        # Add dependencies if requested
        if include_dependencies:
            dependencies = analyze_operator_dependencies(analyzed_operators)
            response["dependencies"] = dependencies

        logger.info(f"Cluster operator analysis complete. Health: {overall_health}, Issues: {len(critical_issues)}")
        return response

    except ApiException as e:
        error_msg = f"API error accessing cluster operators: {e.status} - {e.reason}"
        logger.error(error_msg)

        if e.status == 403:
            error_msg += ". Check RBAC permissions for config.openshift.io resources"
            logger.info("Attempting fallback analysis using standard Kubernetes resources...")

            # Fallback: Use standard Kubernetes resources to provide alternative health info
            try:
                fallback_result = await _get_fallback_cluster_health(_clients.core_api)
                fallback_result["critical_issues"].insert(0, {
                    "component": "openshift-api-access",
                    "severity": "warning",
                    "issue": "Limited permissions for OpenShift cluster operators. Using fallback analysis.",
                    "impact": "Reduced visibility into OpenShift-specific operator status",
                    "recommended_action": "Grant access to config.openshift.io resources for full OpenShift monitoring"
                })
                return fallback_result
            except Exception as fallback_error:
                logger.error(f"Fallback analysis also failed: {fallback_error}")

        elif e.status == 404:
            error_msg += ". ClusterOperator resource not found - may not be an OpenShift cluster"
            logger.info("Attempting fallback analysis for non-OpenShift cluster...")

            # Fallback for non-OpenShift clusters
            try:
                fallback_result = await _get_fallback_cluster_health(_clients.core_api)
                fallback_result["critical_issues"].insert(0, {
                    "component": "cluster-type-detection",
                    "severity": "info",
                    "issue": "Not an OpenShift cluster - using standard Kubernetes health analysis",
                    "impact": "OpenShift-specific operator monitoring not available",
                    "recommended_action": "Use standard Kubernetes monitoring tools for this cluster type"
                })
                return fallback_result
            except Exception as fallback_error:
                logger.error(f"Fallback analysis failed: {fallback_error}")

        return {
            "cluster_info": {},
            "operator_status": [],
            "health_summary": {"total_operators": 0, "healthy_operators": 0, "degraded_operators": 0, "overall_health": "unknown"},
            "critical_issues": [{"component": "api-access", "severity": "critical", "issue": error_msg, "impact": "Cannot assess cluster operator status", "recommended_action": "Check cluster access and RBAC permissions"}],
            "dependencies": [] if include_dependencies else None
        }

    except Exception as e:
        error_msg = f"Unexpected error analyzing cluster operators: {str(e)}"
        logger.error(error_msg, exc_info=True)

        return {
            "cluster_info": {},
            "operator_status": [],
            "health_summary": {"total_operators": 0, "healthy_operators": 0, "degraded_operators": 0, "overall_health": "unknown"},
            "critical_issues": [{"component": "system-error", "severity": "critical", "issue": error_msg, "impact": "Cannot assess cluster operator status", "recommended_action": "Check system logs and cluster connectivity"}],
            "dependencies": [] if include_dependencies else None
        }


# Namespaces mapped per cluster in one live_system_topology_mapper call. Each
# namespace costs ~10 Kubernetes list calls; beyond this the call takes minutes
# and the graph exceeds any context budget. Narrow with namespace_filter.
MAX_TOPOLOGY_NAMESPACES = 100


@mcp.tool()
async def live_system_topology_mapper(
    cluster_names: Optional[List[str]] = None,
    component_types: Optional[List[str]] = None,
    namespace_filter: Optional[str] = None,
    depth_limit: Optional[int] = 5,
    include_metrics: Optional[bool] = False,
    output_format: Optional[str] = "json",
    skip_on_permission_denied: Optional[bool] = True,
    max_context_tokens: int = 50000,
    source: str = ""
) -> Dict[str, Any]:
    """
    Generate real-time dependency graph of Kubernetes/Tekton components and their interconnections.

    Maps Services, Deployments, Pipelines, PVCs, and their relationships via ownerReferences and selectors.

    Args:
        cluster_names: Clusters to map (default: all).
        component_types: Filter by types (services, deployments, pipelines, pvcs, etc.). Note: secrets are NOT included by default.
        namespace_filter: Regex pattern to filter namespaces.
        depth_limit: Max dependency depth (default: 5).
        include_metrics: Include resource metrics (default: False).
        output_format: "json" (default), "graphviz", or "mermaid".
        skip_on_permission_denied: Continue mapping other resources if permission denied (default: True).
        max_context_tokens: Output token budget (default 50000). Over budget, edges then nodes are staged-truncated (keep-first order) and a _truncation key reports what was dropped.
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Topology graph with nodes, edges, summary, metadata, and permission report.

    Note: ``live_system_topology_mapper`` and ``topology_mapper`` are the same tool;
        prefer ``topology_mapper``.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("live_system_topology_mapper", source, ("Inventory",))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    try:
        logger.info(f"Starting live system topology mapping with filters: clusters={cluster_names}, "
                   f"types={component_types}, namespace_filter={namespace_filter}")

        start_time = time.time()

        # Get multi-cluster clients
        cluster_clients = await get_multi_cluster_topology_clients(_clients.core_api, _clients.custom_api, _clients.apps_api, _clients.storage_api, _clients.batch_api)

        if not cluster_clients:
            return {
                "topology": {"nodes": [], "edges": []},
                "summary": {"total_nodes": 0, "total_relationships": 0, "clusters_mapped": 0, "potential_blast_radius": {}},
                "error": "No cluster clients available for topology mapping",
                "last_updated": datetime.now().isoformat()
            }

        # Filter clusters if specified
        if cluster_names:
            cluster_clients = {k: v for k, v in cluster_clients.items() if k in cluster_names}

        # Default component types if not specified
        # Note: secrets are NOT included by default due to common RBAC restrictions
        # ReplicaSets are included to show complete Deployment→ReplicaSet→Pod ownership chain
        if not component_types:
            component_types = ["deployments", "replicasets", "services", "pods", "persistentvolumeclaims",
                             "configmaps", "pipelineruns", "pipelines", "taskruns", "tasks"]

        nodes = []
        edges = []
        cluster_stats = {}
        namespace_truncation: Dict[str, Dict[str, int]] = {}

        # Track permission issues
        permissions_report = {
            "accessible": [],
            "denied": [],
            "errors": []
        }

        for cluster_name, clients in cluster_clients.items():
            logger.info(f"Mapping topology for cluster: {cluster_name}")
            cluster_stats[cluster_name] = {"nodes": 0, "edges": 0}

            try:
                core_api = clients["core_api"]
                apps_api = clients["apps_api"]
                custom_api = clients["custom_api"]
                storage_api = clients["storage_api"]

                # Get all namespaces
                all_namespaces = []
                try:
                    ns_list = await asyncio.to_thread(core_api.list_namespace)
                    all_namespaces = [ns.metadata.name for ns in ns_list.items]

                    # Apply namespace filter if specified
                    if namespace_filter:
                        try:
                            pattern = _safe_compile_namespace_filter(namespace_filter)
                            all_namespaces = [ns for ns in all_namespaces if pattern.search(ns)]
                        except (re.error, ValueError) as e:
                            logger.warning(f"Invalid namespace filter regex '{namespace_filter}': {e}")

                except Exception as e:
                    logger.warning(f"Failed to list namespaces in cluster {cluster_name}: {e}")
                    continue

                if len(all_namespaces) > MAX_TOPOLOGY_NAMESPACES:
                    namespace_truncation[cluster_name] = {
                        "total": len(all_namespaces), "mapped": MAX_TOPOLOGY_NAMESPACES}
                    logger.warning(
                        f"Cluster {cluster_name}: mapping the first {MAX_TOPOLOGY_NAMESPACES} of "
                        f"{len(all_namespaces)} namespaces; use namespace_filter to choose")
                    all_namespaces = all_namespaces[:MAX_TOPOLOGY_NAMESPACES]

                logger.info(f"Processing {len(all_namespaces)} namespaces in cluster {cluster_name} in parallel")

                # Process all namespaces in parallel using asyncio.gather
                namespace_tasks = [
                    _process_namespace_topology(
                        namespace=ns,
                        cluster_name=cluster_name,
                        component_types=component_types,
                        core_api=core_api,
                        apps_api=apps_api,
                        custom_api=custom_api,
                        include_metrics=include_metrics,
                        skip_on_permission_denied=skip_on_permission_denied,
                        logger=logger
                    )
                    for ns in all_namespaces
                ]

                namespace_results = await asyncio.gather(*namespace_tasks, return_exceptions=True)

                # Aggregate results from all namespaces
                for i, result in enumerate(namespace_results):
                    if isinstance(result, Exception):
                        logger.warning(f"Error processing namespace {all_namespaces[i]} in cluster {cluster_name}: {result}")
                        continue

                    nodes.extend(result["nodes"])
                    edges.extend(result["edges"])
                    cluster_stats[cluster_name]["nodes"] += result["stats"]["nodes"]
                    cluster_stats[cluster_name]["edges"] += result["stats"]["edges"]
                    permissions_report["accessible"].extend(result["permissions"]["accessible"])
                    permissions_report["denied"].extend(result["permissions"]["denied"])
                    permissions_report["errors"].extend(result["permissions"]["errors"])


            except Exception as e:
                logger.error(f"Error processing cluster {cluster_name}: {e}")
                continue

        # Calculate summary statistics
        total_nodes = len(nodes)
        total_edges = len(edges)
        clusters_mapped = len([c for c in cluster_stats.values() if c["nodes"] > 0])

        # Calculate potential blast radius using depth_limit
        blast_radius = {}
        if total_nodes > 0:
            # Create NetworkX graph for analysis
            G = nx.DiGraph()
            for node in nodes:
                G.add_node(node["id"], **node)
            for edge in edges:
                G.add_edge(edge["source"], edge["target"], **edge)

            # Calculate metrics using depth_limit for traversal analysis
            if G.nodes():
                # Find nodes reachable within depth_limit from each node
                max_reachable = 0
                critical_nodes_list = []

                for node_id in G.nodes():
                    # Use BFS with depth limit to find reachable nodes
                    reachable = set()
                    queue = [(node_id, 0)]
                    visited = {node_id}

                    while queue:
                        current, current_depth = queue.pop(0)
                        if current_depth >= depth_limit:
                            continue
                        for neighbor in G.neighbors(current):
                            if neighbor not in visited:
                                visited.add(neighbor)
                                reachable.add(neighbor)
                                queue.append((neighbor, current_depth + 1))

                    if len(reachable) > max_reachable:
                        max_reachable = len(reachable)

                    # Mark as critical if can affect many nodes within depth_limit
                    if len(reachable) > 5:
                        critical_nodes_list.append({
                            "node_id": node_id,
                            "affected_count": len(reachable)
                        })

                blast_radius = {
                    "depth_limit_used": depth_limit,
                    "most_connected_components": len(list(nx.connected_components(G.to_undirected()))),
                    "average_degree": sum(dict(G.degree()).values()) / len(G.nodes()) if G.nodes() else 0,
                    "critical_nodes": len(critical_nodes_list),
                    "max_blast_radius": max_reachable,
                    "critical_nodes_details": critical_nodes_list[:10]  # Top 10 critical nodes
                }

        execution_time = time.time() - start_time

        # Deduplicate permission report entries
        permissions_report["accessible"] = list(set(permissions_report["accessible"]))
        permissions_report["denied"] = list(set(permissions_report["denied"]))

        result = {
            "topology": {
                "nodes": nodes,
                "edges": edges
            },
            "summary": {
                "total_nodes": total_nodes,
                "total_relationships": total_edges,
                "clusters_mapped": clusters_mapped,
                "potential_blast_radius": blast_radius,
                "cluster_stats": cluster_stats,
                "execution_time_seconds": round(execution_time, 2)
            },
            "permissions": permissions_report,
            "last_updated": datetime.now().isoformat()
        }

        # Log permissions summary
        if permissions_report["denied"]:
            logger.warning(f"Permission denied for {len(permissions_report['denied'])} resource types")
        if permissions_report["errors"]:
            logger.warning(f"Errors encountered for {len(permissions_report['errors'])} resource types")

        logger.info(f"Topology mapping completed: {total_nodes} nodes, {total_edges} edges across {clusters_mapped} clusters in {execution_time:.2f}s")

        # Bound BEFORE format conversion so graphviz/mermaid render the same
        # (possibly truncated) graph the json view reports (live-sweep finding:
        # 1.32MB at depth_limit=1 on a 12-pod namespace).
        if namespace_truncation:
            result["namespace_truncation"] = namespace_truncation
            result["summary"]["note"] = (
                f"Mapped at most {MAX_TOPOLOGY_NAMESPACES} namespaces per cluster; "
                "use namespace_filter to choose which ones"
            )
        result = _bound_topology_result(result, max_context_tokens)
        bounded_topo = result.get("topology", {})

        # Handle different output formats
        if output_format == "graphviz":
            result["graphviz"] = convert_to_graphviz(
                bounded_topo.get("nodes", []), bounded_topo.get("edges", []))
        elif output_format == "mermaid":
            result["mermaid"] = convert_to_mermaid(
                bounded_topo.get("nodes", []), bounded_topo.get("edges", []))

        return result

    except Exception as e:
        logger.error(f"Unexpected error during topology mapping: {str(e)}", exc_info=True)
        return {
            "topology": {"nodes": [], "edges": []},
            "summary": {"total_nodes": 0, "total_relationships": 0, "clusters_mapped": 0, "potential_blast_radius": {}},
            "error": f"Failed to generate topology: {str(e)}",
            "last_updated": datetime.now().isoformat()
        }


@mcp.tool()
@log_tool_execution
async def predictive_log_analyzer(
    prediction_window: str = "6h",
    confidence_threshold: float = 0.75,
    log_sources: Optional[List[str]] = None,
    namespaces: Optional[List[str]] = None,
    max_namespaces: int = 20,
    force_retrain: bool = False,
    source: str = ""
) -> Dict[str, Any]:
    """
    Predict failures using ML analysis of historical log patterns before critical outages occur.

    Uses anomaly detection algorithms to correlate log patterns with failure events.
    Supports persistent model storage for faster subsequent calls.

    Args:
        prediction_window: Time window - "1h", "6h", "24h", "7d" (default: "6h").
        confidence_threshold: Min confidence for predictions 0.0-1.0 (default: 0.75).
        log_sources: Sources to analyze - pods, services, nodes (default: all).
        namespaces: Specific namespaces to analyze (default: auto-detect active namespaces).
        max_namespaces: Maximum namespaces to scan when auto-detecting (default: 20).
        force_retrain: Force model retraining even if cached model is valid (default: False).
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Keys: predictions, model_performance, anomaly_scores, trend_analysis, model_info.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("predictive_log_analyzer", source, ("Log",))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    try:
        logger.info(f"Starting predictive log analysis with window: {prediction_window}, threshold: {confidence_threshold}")

        # Validate parameters
        valid_windows = ["1h", "6h", "24h", "7d"]
        if prediction_window not in valid_windows:
            raise ValueError(f"Invalid prediction_window. Must be one of: {valid_windows}")

        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0.0 and 1.0")

        # Initialize persistence components (lazy loading)
        try:
            from helpers.ml_persistence import (
                ModelPersistenceManager,
                TrainingDataStore,
                FailureEventCollector,
                ModelVersionManager,
                build_labels_from_correlations
            )
            model_manager = ModelPersistenceManager()
            training_store = TrainingDataStore()
            failure_collector = FailureEventCollector(training_store)
            version_manager = ModelVersionManager(model_manager, training_store)
            persistence_available = True
        except Exception as e:
            logger.warning(f"ML persistence not available, using ephemeral training: {e}")
            persistence_available = False
            model_manager = None
            training_store = None
            failure_collector = None
            version_manager = None

        # Initialize result structure
        result = {
            "predictions": [],
            "model_performance": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "last_training_time": datetime.now().isoformat()
            },
            "anomaly_scores": [],
            "trend_analysis": {
                "error_rate_trend": "stable",
                "resource_trend": "stable",
                "performance_trend": "stable"
            },
            "model_info": {
                "model_id": None,
                "loaded_from_cache": False,
                "training_samples": 0,
                "has_failure_labels": False,
                "persistence_enabled": persistence_available
            }
        }

        # Get recent logs from various sources
        log_sources = log_sources or ["pods", "services", "nodes"]
        all_logs = []
        _ro = ReadOnlyCoreV1.wrap(_clients.core_api)  # defensive hoist: both pods block (READ 1/2) and persistence block (READ 3) use _ro; hoisting future-proofs if persistence ever runs without pods (currently unreachable — target_namespaces is also pods-block-scoped)

        for _log_source in log_sources:
            try:
                if _log_source == "pods":
                    # Determine target namespaces
                    if namespaces:
                        # Use user-provided namespaces
                        target_namespaces = namespaces
                        logger.info(f"Using user-specified namespaces: {target_namespaces}")
                    else:
                        # Auto-detect active namespaces, prioritizing those with tekton/pipeline activity
                        all_ns = await list_namespaces(source=source)
                        try:
                            tekton_ns = await detect_tekton_namespaces(source=source)
                            active_ns = []
                            for category in tekton_ns.values():
                                active_ns.extend(category)
                            # Deduplicate and limit
                            target_namespaces = list(set(active_ns))[:max_namespaces] if active_ns else all_ns[:max_namespaces]
                        except Exception:
                            # Fallback to alphabetical if tekton detection fails
                            target_namespaces = all_ns[:max_namespaces]
                        logger.info(f"Auto-detected {len(target_namespaces)} active namespaces")

                    for ns in target_namespaces:
                        try:
                            pods = await k8s_call(_ro.list_namespaced_pod, namespace=ns, limit=50)
                            for pod in pods.items:
                                # Include Running pods for proactive analysis, plus Failed/Succeeded for historical
                                if pod.status.phase in ["Running", "Failed", "Succeeded"]:
                                    try:
                                        pod_logs = normalize_pod_log_text(
                                            await k8s_call(_ro.read_namespaced_pod_log,
                                                name=pod.metadata.name,
                                                namespace=ns,
                                                tail_lines=100,
                                                timeout=LOG_TIMEOUT
                                            ))
                                        all_logs.extend(pod_logs.split('\n'))
                                    except ApiException:
                                        continue  # Skip pods without accessible logs
                        except ApiException:
                            continue  # Skip inaccessible namespaces

            except Exception as e:
                logger.warning(f"Failed to collect logs from {_log_source}: {str(e)}")
                continue

        # Return early if no logs collected - never fabricate analysis from fake data
        if not all_logs:
            logger.warning("No logs collected from any source - returning insufficient data")
            result["trend_analysis"]["error_rate_trend"] = "no_data"
            result["model_performance"] = {
                "accuracy": None,
                "precision": None,
                "recall": None,
                "note": "No log data available for analysis"
            }
            return result

        # Filter out empty lines
        all_logs = [log for log in all_logs if log.strip()]

        if len(all_logs) < 10:
            logger.warning(f"Insufficient log data for analysis: {len(all_logs)} lines")
            result["trend_analysis"]["error_rate_trend"] = "insufficient_data"
            return result

        logger.info(f"Analyzing {len(all_logs)} log lines for predictive patterns")

        # Preprocess log data
        log_df = preprocess_log_data(all_logs)

        # Extract features for ML analysis
        features = extract_log_features(log_df)

        # Collect failure events and correlate with logs if persistence is available
        labels = None
        if persistence_available and failure_collector and training_store:
            try:
                # Collect failure events from the target namespaces
                for ns in target_namespaces:
                    try:
                        # Collect from Kubernetes events - use dict format for FailureEventCollector
                        events_as_dicts = await _get_namespace_events_as_dicts(ns, limit=100, clients=_clients)
                        if events_as_dicts:
                            count = failure_collector.collect_from_events(events_as_dicts, ns)
                            logger.debug(f"Collected {count} failure labels from events in {ns}")

                        # Collect from pod statuses
                        pods = await k8s_call(_ro.list_namespaced_pod, namespace=ns, limit=50)
                        failure_collector.collect_from_pod_status(pods.items, ns)
                    except Exception as e:
                        logger.debug(f"Failed to collect failure events from {ns}: {e}")

                # Get recent failure labels for correlation
                from datetime import timedelta
                historical_failures = training_store.get_failure_labels_in_window(
                    start_time=datetime.now() - timedelta(hours=2),
                    end_time=datetime.now()
                )

                # Store log samples first so they get database IDs for correlation
                stored_samples = []
                for idx, row in log_df.iterrows():
                    if idx < 500:  # Limit to avoid excessive storage
                        sample_data = {
                            "timestamp": row.get("timestamp"),
                            "namespace": target_namespaces[0] if target_namespaces else "unknown",
                            "features": features[idx].tolist() if idx < len(features) else [],
                            "raw_message": str(row.get("raw_message", ""))[:500],
                            "log_level": row.get("log_level"),
                            "error_indicators": int(row.get("error_indicators", 0)),
                            "message_entropy": float(row.get("message_entropy", 0.0))
                        }
                        sample_id = training_store.store_log_sample(sample_data)
                        if sample_id:
                            stored_samples.append({
                                "id": sample_id,
                                "timestamp": sample_data["timestamp"],
                                "namespace": sample_data["namespace"]
                            })

                # Correlate stored log samples with failures using database IDs
                if historical_failures and stored_samples:
                    correlations = failure_collector.correlate_logs_with_failures(
                        stored_samples, historical_failures, time_window_minutes=30
                    )
                    if correlations:
                        labels = build_labels_from_correlations(correlations, len(log_df))
                        logger.info(f"Created {len(correlations)} log-failure correlations")

            except Exception as e:
                logger.warning(f"Failed to collect/correlate failure events: {e}")

        # Train or load model with persistence
        if persistence_available and model_manager and version_manager:
            try:
                anomaly_model, model_id, model_metadata = train_or_load_model(
                    features=features,
                    model_manager=model_manager,
                    version_manager=version_manager,
                    labels=labels,
                    force_retrain=force_retrain
                )

                # Update result with model info
                result["model_info"].update({
                    "model_id": model_id,
                    "loaded_from_cache": model_metadata.get("loaded_from_cache", False),
                    "training_samples": model_metadata.get("training_samples", len(features)),
                    "has_failure_labels": labels is not None and len(labels) > 0,
                    "created_at": model_metadata.get("created_at")
                })

                # Use performance metrics from model if available
                perf = model_metadata.get("performance_metrics", {})
                if perf:
                    result["model_performance"].update({
                        "accuracy": perf.get("accuracy", 0.0),
                        "precision": perf.get("precision", 0.0),
                        "recall": perf.get("recall", 0.0),
                        "last_training_time": model_metadata.get("created_at", datetime.now().isoformat())
                    })
            except Exception as e:
                logger.warning(f"Persistence-based training failed, falling back to ephemeral: {e}")
                anomaly_model = train_anomaly_model(features)
        else:
            # Fallback to ephemeral training
            anomaly_model = train_anomaly_model(features)

        anomaly_scores = anomaly_model.decision_function(features)
        anomaly_predictions = anomaly_model.predict(features)

        # Update model performance if not already set by persistence
        # Note: without labeled validation data, precision/recall cannot be computed
        if result["model_performance"]["accuracy"] == 0.0:
            normal_predictions = anomaly_predictions == 1
            accuracy = np.mean(normal_predictions) if len(normal_predictions) > 0 else 0.0
            result["model_performance"].update({
                "accuracy": float(accuracy),
                "precision": None,
                "recall": None,
                "note": "Precision/recall require labeled validation data - not available"
            })

        # Generate aggregate anomaly scores per namespace
        # anomaly_scores are per-log-line, so aggregate by namespace using mean score
        if target_namespaces:
            # Calculate per-namespace aggregated scores from per-line scores
            lines_per_ns = max(1, len(anomaly_scores) // max(1, len(target_namespaces)))
            threshold = -0.5  # Typical anomaly threshold for Isolation Forest

            for i, ns in enumerate(target_namespaces[:min(10, len(target_namespaces))]):
                start_idx = i * lines_per_ns
                end_idx = min(start_idx + lines_per_ns, len(anomaly_scores))
                if start_idx < len(anomaly_scores):
                    ns_scores = anomaly_scores[start_idx:end_idx]
                    mean_score = float(np.mean(ns_scores))
                    anomalous_lines = int(np.sum(ns_scores < threshold))
                    status = "anomalous" if mean_score < threshold else "normal"

                    result["anomaly_scores"].append({
                        "component": ns,
                        "score": mean_score,
                        "threshold": threshold,
                        "status": status,
                        "anomalous_log_lines": anomalous_lines,
                        "total_log_lines": len(ns_scores)
                    })

        # Analyze patterns for failure prediction - pass historical failures for correlation
        historical_failures_for_analysis = []
        if persistence_available and training_store:
            try:
                from datetime import timedelta
                historical_failures_for_analysis = training_store.get_failure_labels_in_window(
                    start_time=datetime.now() - timedelta(hours=24),
                    end_time=datetime.now()
                )
            except Exception as e:
                logger.debug(f"Could not retrieve historical failures: {e}")

        pattern_analysis = analyze_log_patterns_for_failure_prediction(
            log_df, historical_failures_for_analysis
        )

        # Generate predictions using both pattern analysis and labeled data
        predictions = generate_failure_predictions(
            pattern_analysis,
            confidence_threshold,
            prediction_window,
            historical_failures=historical_failures_for_analysis,
            labels=labels
        )
        result["predictions"] = predictions

        # Analyze trends
        error_logs = log_df[log_df['log_level'].isin(['ERROR', 'FATAL', 'PANIC'])]
        error_rate = len(error_logs) / len(log_df) if len(log_df) > 0 else 0.0

        if error_rate > 0.15:
            result["trend_analysis"]["error_rate_trend"] = "increasing"
        elif error_rate < 0.05:
            result["trend_analysis"]["error_rate_trend"] = "decreasing"
        else:
            result["trend_analysis"]["error_rate_trend"] = "stable"

        # Resource trend based on log patterns
        resource_indicators = log_df['raw_message'].str.contains(
            r'memory|cpu|disk|storage|resource', case=False, na=False
        ).sum()

        if resource_indicators > len(log_df) * 0.1:
            result["trend_analysis"]["resource_trend"] = "concerning"
        else:
            result["trend_analysis"]["resource_trend"] = "stable"

        # Performance trend based on response times and timeouts
        performance_indicators = log_df['raw_message'].str.contains(
            r'timeout|slow|latency|performance|delay', case=False, na=False
        ).sum()

        if performance_indicators > len(log_df) * 0.08:
            result["trend_analysis"]["performance_trend"] = "degrading"
        else:
            result["trend_analysis"]["performance_trend"] = "stable"

        # Update has_failure_labels to correctly reflect historical failures used
        result["model_info"]["has_failure_labels"] = (
            (labels is not None and len(labels) > 0) or
            (historical_failures_for_analysis and len(historical_failures_for_analysis) > 0)
        )

        logger.info(f"Predictive analysis complete: {len(predictions)} predictions generated")
        return result

    except Exception as e:
        logger.error(f"Error in predictive log analysis: {str(e)}", exc_info=True)
        return {
            "predictions": [],
            "model_performance": {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "last_training_time": datetime.now().isoformat()
            },
            "anomaly_scores": [],
            "trend_analysis": {
                "error_rate_trend": "error",
                "resource_trend": "error",
                "performance_trend": "error"
            },
            "model_info": {
                "model_id": None,
                "loaded_from_cache": False,
                "training_samples": 0,
                "has_failure_labels": False,
                "persistence_enabled": False
            },
            "error": str(e)
        }


@mcp.tool()
@log_tool_execution
async def manage_prediction_training_data(
    action: str = "stats",
    failure_type: Optional[str] = None,
    namespace: Optional[str] = None,
    resource_name: Optional[str] = None,
    severity: Optional[str] = None,
    collect_from_namespaces: Optional[List[str]] = None,
    max_namespaces: int = 10,
    source: str = ""
) -> Dict[str, Any]:
    """
    Manage training data for the predictive log analyzer.

    This tool allows viewing, collecting, and managing failure labels used for
    supervised learning in the predictive_log_analyzer.

    Args:
        action: Action to perform:
            - "stats": Get training data statistics (default)
            - "list_failures": List recent failure labels
            - "add_failure": Manually add a failure label
            - "collect": Trigger failure collection from namespaces
            - "cleanup": Remove old training data
        failure_type: For add_failure - type of failure (e.g., "crash", "oom", "image", "timeout")
        namespace: For add_failure/list_failures - namespace filter
        resource_name: For add_failure - name of the affected resource
        severity: For add_failure - severity level ("critical", "high", "medium", "low")
        collect_from_namespaces: For collect - specific namespaces to collect from
        max_namespaces: For collect - maximum namespaces when auto-detecting
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict with action results: statistics, failure list, or operation status.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("manage_prediction_training_data", source, ("Log", "Event", "Inventory"))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    # Gate precedes unknown-action validation: validate the source before the verb — intentional.
    try:
        from helpers.ml_persistence import (
            TrainingDataStore,
            FailureEventCollector,
            ModelPersistenceManager
        )

        training_store = TrainingDataStore()
        model_manager = ModelPersistenceManager()

        result = {
            "action": action,
            "success": True,
            "timestamp": datetime.now().isoformat()
        }

        if action == "stats":
            # Get comprehensive training data statistics
            stats = training_store.get_statistics()

            # Get model info
            models = model_manager.list_models()
            current_model_id = model_manager.get_current_model_id()

            result["statistics"] = {
                "training_data": stats,
                "models": {
                    "total_models": len(models),
                    "current_model_id": current_model_id,
                    "recent_models": [
                        {
                            "model_id": m.get("model_id"),
                            "created_at": m.get("created_at"),
                            "training_samples": m.get("training_samples", 0)
                        }
                        for m in models[-5:]
                    ] if models else []
                },
                "recommendations": []
            }

            # Add recommendations
            if stats.get("total_failure_labels", 0) < 10:
                result["statistics"]["recommendations"].append(
                    "Collect more failure labels using action='collect' to improve predictions"
                )
            if stats.get("total_log_samples", 0) < 100:
                result["statistics"]["recommendations"].append(
                    "Run predictive_log_analyzer to collect more log samples"
                )
            if stats.get("total_correlations", 0) == 0:
                result["statistics"]["recommendations"].append(
                    "No log-failure correlations yet. Labels will be correlated during analysis."
                )

        elif action == "list_failures":
            # List recent failure labels
            from datetime import timedelta
            failures = training_store.get_failure_labels_in_window(
                start_time=datetime.now() - timedelta(days=7),
                end_time=datetime.now()
            )

            # Filter by namespace if specified
            if namespace:
                failures = [f for f in failures if f.get("namespace") == namespace]

            result["failures"] = failures[:50]  # Limit to 50
            result["total_count"] = len(failures)
            result["filter_applied"] = {"namespace": namespace} if namespace else None

        elif action == "add_failure":
            # Manually add a failure label
            if not failure_type:
                result["success"] = False
                result["error"] = "failure_type is required for add_failure action"
                return result

            label = {
                "failure_type": failure_type,
                "severity": severity or "medium",
                "namespace": namespace or "unknown",
                "resource_name": resource_name or "manual_entry",
                "resource_type": "manual",
                "failure_time": datetime.now().isoformat(),
                "detection_source": "manual",
                "error_category": failure_type,
                "metadata": {
                    "source": "manage_prediction_training_data",
                    "added_by": "user"
                }
            }

            label_id = training_store.store_failure_label(label)

            if label_id:
                result["label_id"] = label_id
                result["message"] = f"Successfully added failure label for '{failure_type}'"
            else:
                result["success"] = False
                result["message"] = "Failed to add label (may be duplicate)"

        elif action == "collect":
            # Trigger failure collection from namespaces
            failure_collector = FailureEventCollector(training_store)
            collected_counts = {
                "from_events": 0,
                "from_pods": 0,
                "from_pipelines": 0,
                "namespaces_scanned": 0
            }

            # Determine namespaces to scan
            if collect_from_namespaces:
                target_namespaces = collect_from_namespaces
            else:
                # Auto-detect active namespaces
                try:
                    all_ns = await list_namespaces(source=source)
                    tekton_ns = await detect_tekton_namespaces(source=source)
                    active_ns = []
                    for category in tekton_ns.values():
                        active_ns.extend(category)
                    target_namespaces = list(set(active_ns))[:max_namespaces] if active_ns else all_ns[:max_namespaces]
                except Exception:
                    target_namespaces = []

            _ro = ReadOnlyCoreV1.wrap(_clients.core_api)
            for ns in target_namespaces:
                try:
                    collected_counts["namespaces_scanned"] += 1

                    # Collect from events - use dict format for FailureEventCollector
                    try:
                        events_as_dicts = await _get_namespace_events_as_dicts(ns, limit=200, clients=_clients)
                        if events_as_dicts:
                            count = failure_collector.collect_from_events(events_as_dicts, ns)
                            collected_counts["from_events"] += count
                    except Exception as e:
                        logger.debug(f"Failed to collect events from {ns}: {e}")

                    # Collect from pod statuses
                    try:
                        pods = await k8s_call(_ro.list_namespaced_pod, namespace=ns, limit=100)
                        count = failure_collector.collect_from_pod_status(pods.items, ns)
                        collected_counts["from_pods"] += count
                    except Exception as e:
                        logger.debug(f"Failed to collect pod statuses from {ns}: {e}")

                    # Collect from pipeline runs
                    try:
                        prs = await list_pipelineruns(namespace=ns, source=source)
                        if prs and isinstance(prs, list):
                            # Filter to failed pipelines
                            failed_prs = [pr for pr in prs if pr.get("status") in TERMINAL_FAILURE_PR_STATUSES]
                            count = failure_collector.collect_from_pipeline_runs(
                                [{"status": {"conditions": [{"type": "Succeeded", "status": "False", "message": pr.get("status", "")}]},
                                  "metadata": {"name": pr.get("name"), "creationTimestamp": pr.get("started_at")},
                                  "spec": {"pipelineRef": {"name": pr.get("pipeline", "")}}}
                                 for pr in failed_prs],
                                ns
                            )
                            collected_counts["from_pipelines"] += count
                    except Exception as e:
                        logger.debug(f"Failed to collect pipeline runs from {ns}: {e}")

                except Exception as e:
                    logger.debug(f"Failed to scan namespace {ns}: {e}")

            result["collected"] = collected_counts
            result["total_collected"] = sum([
                collected_counts["from_events"],
                collected_counts["from_pods"],
                collected_counts["from_pipelines"]
            ])
            result["message"] = f"Collected {result['total_collected']} failure labels from {collected_counts['namespaces_scanned']} namespaces"

        elif action == "cleanup":
            # Clean up old training data
            deleted_data = training_store.cleanup_old_data(max_age_days=90)
            deleted_models = model_manager.cleanup_old_models(max_age_days=30, keep_min=3)

            result["cleanup_results"] = {
                "training_data_deleted": deleted_data,
                "models_deleted": deleted_models
            }
            result["message"] = f"Cleaned up {deleted_data} old data records and {deleted_models} old models"

        else:
            result["success"] = False
            result["error"] = f"Unknown action: {action}. Valid actions: stats, list_failures, add_failure, collect, cleanup"

        return result

    except ImportError as e:
        return {
            "action": action,
            "success": False,
            "error": f"ML persistence module not available: {e}",
            "message": "Install required dependencies: pip install joblib scikit-learn"
        }
    except Exception as e:
        logger.error(f"Error in manage_prediction_training_data: {e}", exc_info=True)
        return {
            "action": action,
            "success": False,
            "error": str(e)
        }



@mcp.tool()
@log_tool_execution
async def resource_bottleneck_forecaster(
    forecast_horizon: str = "24h",
    resource_types: Optional[List[str]] = None,
    namespaces: Optional[List[str]] = None,
    trend_analysis_period: str = "7d",
    source: str = ""
) -> Dict[str, Any]:
    """
    Forecast resource bottlenecks by analyzing utilization trends and predicting exhaustion points.

    Uses time-series analysis to predict CPU, memory, disk, and network capacity constraints.

    Args:
        forecast_horizon: Forecast window - "1h", "6h", "24h", "7d", "30d" (default: "24h").
        resource_types: Resources to analyze - cpu, memory, disk, network, pvc (default: all).
        namespaces: Specific namespaces to focus on.
        trend_analysis_period: Historical period for trends (default: "7d").
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Keys: forecasts, capacity_recommendations, cluster_overview, historical_accuracy.
    """
    # Dispatch: kubernetes sources route via _resolve_k8s; other adapters gate normally.
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("resource_bottleneck_forecaster", source, ("Metric", "Inventory"))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    try:
        logger.info(f"Starting resource bottleneck forecasting for horizon: {forecast_horizon}")

        # Default resource types if not specified
        if resource_types is None:
            resource_types = ["cpu", "memory", "disk", "network", "pvc"]

        # Test Prometheus connectivity using the tool
        try:
            test_query_result = await prometheus_query("up", source=source)
            if test_query_result.get("status") != "success":
                logger.warning("Could not connect to Prometheus endpoint, using mock data")
                return {
                    "forecasts": [],
                    "capacity_recommendations": [{
                        "resource": "monitoring",
                        "current_capacity": "unavailable",
                        "recommended_capacity": "install_prometheus_or_check_connectivity",
                        "scaling_urgency": "high",
                        "implementation_options": ["Check Prometheus deployment", "Verify RBAC permissions", "Check cluster connectivity"]
                    }],
                    "cluster_overview": {
                        "overall_health": "monitoring_unavailable",
                        "most_constrained_resources": [],
                        "fastest_growing_consumers": [],
                        "capacity_runway": {}
                    },
                    "historical_accuracy": {
                        "previous_predictions": 0,
                        "accuracy_rate": 0.0,
                        "last_validation": datetime.now().isoformat()
                    }
                }
        except Exception as e:
            logger.warning(f"Error testing Prometheus connectivity: {str(e)}")
            return {
                "forecasts": [],
                "capacity_recommendations": [{
                    "resource": "monitoring",
                    "current_capacity": "error",
                    "recommended_capacity": "fix_monitoring_setup",
                    "scaling_urgency": "high",
                    "implementation_options": ["Check Prometheus deployment", "Verify authentication", "Review cluster configuration"]
                }],
                "cluster_overview": {
                    "overall_health": "monitoring_error",
                    "most_constrained_resources": [],
                    "fastest_growing_consumers": [],
                    "capacity_runway": {}
                },
                "historical_accuracy": {
                    "previous_predictions": 0,
                    "accuracy_rate": 0.0,
                    "last_validation": datetime.now().isoformat()
                }
            }

        # Analyze node-level resources
        forecasts = []
        if "cpu" in resource_types or "memory" in resource_types or "disk" in resource_types:
            node_forecasts = await _analyze_node_resources_new(trend_analysis_period, forecast_horizon, logger, query_fn=functools.partial(prometheus_query, source=source), core_api=_clients.core_api)

            if namespaces:
                # When specific namespaces are requested, limit node output to prevent
                # bloated responses (56+ nodes * 3 resource types * mountpoints = 200+ entries).
                # Strategy: keep top 5 nodes by max utilization across all resource types.
                MAX_NODES = 5

                # Group forecasts by node
                node_max_usage = {}
                node_has_exhaustion = {}
                for f in node_forecasts:
                    node = f.get('resource_identifier', {}).get('node', f.get('resource_identifier', {}).get('instance', 'unknown'))
                    usage = f.get('current_usage', {}).get('value', 0)
                    node_max_usage[node] = max(node_max_usage.get(node, 0), usage)
                    if f.get('predicted_exhaustion'):
                        node_has_exhaustion[node] = True

                # Select top nodes: exhaustion-approaching first, then highest utilization
                sorted_nodes = sorted(
                    node_max_usage.keys(),
                    key=lambda n: (node_has_exhaustion.get(n, False), node_max_usage[n]),
                    reverse=True
                )
                keep_nodes = set(sorted_nodes[:MAX_NODES])

                # Filter forecasts to only keep selected nodes
                trimmed = [f for f in node_forecasts
                           if f.get('resource_identifier', {}).get('node', f.get('resource_identifier', {}).get('instance', '')) in keep_nodes]
                forecasts.extend(trimmed)

                if len(node_forecasts) > len(trimmed):
                    logger.info(f"Trimmed node forecasts from {len(node_forecasts)} entries ({len(node_max_usage)} nodes) "
                                f"to {len(trimmed)} entries ({len(keep_nodes)} nodes)")
            else:
                forecasts.extend(node_forecasts)

        # Analyze namespace-specific resources if specified
        if namespaces:
            for namespace in namespaces:
                try:
                    # Namespace CPU usage
                    namespace_cpu_query = f'sum(rate(container_cpu_usage_seconds_total{{namespace="{namespace}"}}[5m])) * 100'

                    # Get current namespace resource usage
                    cpu_result = await prometheus_query(namespace_cpu_query, source=source)
                    if cpu_result.get("status") == "success" and cpu_result.get("data"):
                        data = cpu_result["data"]
                        if data and len(data) > 0 and 'value' in data[0]:
                            cpu_usage = float(data[0]['value'])

                            # Add namespace-specific forecast
                            forecasts.append({
                                'resource_type': 'namespace_cpu',
                                'resource_identifier': {'namespace': namespace, 'metric': 'cpu_usage_cores'},
                                'current_usage': {'value': cpu_usage, 'unit': 'cores'},
                                'predicted_exhaustion': None,  # Would need trend analysis
                                'growth_rate': {'value': 0, 'unit': 'cores_per_5min'},
                                'contributing_factors': ['pod_scaling', 'workload_changes']
                            })

                    # Namespace memory usage — try primary metric, then fallback
                    memory_queries = [
                        f'sum(container_memory_working_set_bytes{{namespace="{namespace}"}}) / 1024 / 1024 / 1024',
                        f'sum(container_memory_usage_bytes{{namespace="{namespace}"}}) / 1024 / 1024 / 1024'
                    ]
                    memory_usage_gb = 0
                    for memory_query in memory_queries:
                        memory_result = await prometheus_query(memory_query, source=source)
                        if memory_result.get("status") == "success" and memory_result.get("data"):
                            data = memory_result["data"]
                            if data and len(data) > 0:
                                raw_val = data[0].get('value', [0, '0'])
                                if isinstance(raw_val, list) and len(raw_val) >= 2:
                                    memory_usage_gb = float(raw_val[1])
                                elif isinstance(raw_val, (str, int, float)):
                                    memory_usage_gb = float(raw_val)
                                if memory_usage_gb > 0:
                                    break

                    if memory_usage_gb > 0:
                        forecasts.append({
                            'resource_type': 'namespace_memory',
                            'resource_identifier': {'namespace': namespace, 'metric': 'memory_usage_gb'},
                            'current_usage': {'value': memory_usage_gb, 'unit': 'GB'},
                            'predicted_exhaustion': None,  # Would need trend analysis
                            'growth_rate': {'value': 0, 'unit': 'GB_per_5min'},
                            'contributing_factors': ['pod_scaling', 'memory_leaks', 'cache_growth']
                        })

                except Exception as e:
                    logger.warning(f"Could not analyze namespace {namespace}: {str(e)}")

        # Generate capacity recommendations
        capacity_recommendations = []
        critical_forecasts = [f for f in forecasts if f.get('predicted_exhaustion')]

        for forecast in critical_forecasts:
            resource_type = forecast['resource_type']
            current_usage = forecast['current_usage']['value']

            urgency = "low"
            if forecast['predicted_exhaustion']:
                try:
                    exhaustion_time = datetime.fromisoformat(forecast['predicted_exhaustion'].replace('Z', '+00:00'))
                    time_to_exhaustion = exhaustion_time - datetime.now(exhaustion_time.tzinfo)

                    if time_to_exhaustion.total_seconds() < 3600:  # 1 hour
                        urgency = "critical"
                    elif time_to_exhaustion.total_seconds() < 86400:  # 24 hours
                        urgency = "high"
                    elif time_to_exhaustion.total_seconds() < 604800:  # 7 days
                        urgency = "medium"
                except:
                    urgency = "medium"

            if resource_type == "cpu":
                capacity_recommendations.append({
                    "resource": f"cpu_{forecast['resource_identifier']['node']}",
                    "current_capacity": f"{current_usage:.1f}%",
                    "recommended_capacity": "scale_up_nodes" if current_usage > 70 else "optimize_workloads",
                    "scaling_urgency": urgency,
                    "implementation_options": [
                        "Add worker nodes",
                        "Implement CPU limits",
                        "Optimize container resource requests",
                        "Consider pod autoscaling"
                    ]
                })
            elif resource_type == "memory":
                capacity_recommendations.append({
                    "resource": f"memory_{forecast['resource_identifier']['node']}",
                    "current_capacity": f"{current_usage:.1f}%",
                    "recommended_capacity": "increase_memory" if current_usage > 80 else "review_memory_usage",
                    "scaling_urgency": urgency,
                    "implementation_options": [
                        "Upgrade node memory",
                        "Implement memory limits",
                        "Review memory-intensive workloads",
                        "Enable memory optimization"
                    ]
                })

        # Analyze cluster overview
        cluster_overview = await _analyze_cluster_capacity_new(_clients.core_api, logger, query_fn=functools.partial(prometheus_query, source=source))

        # Historical accuracy - not tracked (requires prediction validation pipeline)
        historical_accuracy = {
            "previous_predictions": len(forecasts),
            "accuracy_rate": None,
            "last_validation": None,
            "note": "Prediction validation not implemented - accuracy not tracked"
        }

        result = {
            "forecasts": forecasts,
            "capacity_recommendations": capacity_recommendations,
            "cluster_overview": cluster_overview,
            "historical_accuracy": historical_accuracy
        }

        logger.info(f"Completed resource bottleneck forecasting. Generated {len(forecasts)} forecasts and {len(capacity_recommendations)} recommendations")
        return result

    except Exception as e:
        logger.error(f"Error in resource bottleneck forecasting: {str(e)}", exc_info=True)
        return {
            "forecasts": [],
            "capacity_recommendations": [{
                "resource": "error",
                "current_capacity": "unknown",
                "recommended_capacity": "check_monitoring_setup",
                "scaling_urgency": "medium",
                "implementation_options": ["Verify Prometheus deployment", "Check RBAC permissions"]
            }],
            "cluster_overview": {
                "overall_health": "error",
                "most_constrained_resources": [],
                "fastest_growing_consumers": [],
                "capacity_runway": {}
            },
            "historical_accuracy": {
                "previous_predictions": 0,
                "accuracy_rate": 0.0,
                "last_validation": datetime.now().isoformat()
            }
        }


# Tool 19: Semantic Log Search
@mcp.tool()
async def semantic_log_search(
    query: str,
    time_range: str = "1h",
    namespaces: Optional[List[str]] = None,
    severity_levels: Optional[List[str]] = None,
    max_results: int = 100,
    context_lines: int = 3,
    group_similar: bool = True,
    source: str = ""
) -> Dict[str, Any]:
    """
    Search logs using keyword-based queries across live pod logs, events, and Tekton resources.

    Uses substring matching with Kubernetes/Tekton entity recognition and relevance ranking.

    Args:
        query: Keyword or phrase to search for (substring matched; entity keywords like pod
            names or pipeline names are also recognized).
        time_range: Time range - "1h", "6h", "24h", "7d" (default: "1h").
        namespaces: Specific namespaces to search (default: auto-detect relevant namespaces).
        severity_levels: Log severity levels to include.
        max_results: Maximum results to return (default: 100).
        context_lines: Surrounding lines per match (default: 3).
        group_similar: Group similar log entries (default: True).
        source: Telemetry source name (default "" = the default configured instance). Phase 2b validates capability only; per-source routing lands in phase 3.

    Returns:
        Dict: Keys: query_interpretation, search_results, result_summary, suggestions.
    """
    _clients = None
    if source:
        try:
            _entry = _source_registry.get(source)
        except KeyError:
            _entry = None
        if _entry is not None and _entry.adapter == "kubernetes":
            _clients, _err = _resolve_k8s(source)
            if _err:
                return _err
        else:
            _gate_err = _gate_source("semantic_log_search", source, ("Log", "Event"))
            if _gate_err:
                return _gate_err
    if _clients is None:
        _clients = _DefaultClientView()
    logger.info(f"Starting semantic log search for query: '{query}' with time_range: {time_range}")

    try:
        # === Query Understanding and Interpretation ===
        query_interpretation = interpret_semantic_query(query, time_range)
        logger.info(f"Query interpreted as: {query_interpretation['interpreted_intent']}")

        # === Determine Search Strategy ===
        search_strategy = determine_search_strategy(query_interpretation)
        logger.info(f"Using search strategy: {search_strategy['strategy']}")

        # === Entity Recognition and Context Building ===
        identified_components = extract_k8s_entities(query)
        logger.info(f"Identified components: {identified_components}")

        # Bind source to internal tool references so all helper calls hit the named
        # instance.  Without this, helpers that accept a bare function reference would
        # call the tool with no source= and silently use the default cluster.
        _list_ns = functools.partial(list_namespaces, source=source) if source else list_namespaces
        _detect_tekton = functools.partial(detect_tekton_namespaces, source=source) if source else detect_tekton_namespaces
        _get_logs = functools.partial(get_pod_logs, clients=_clients) if source else get_pod_logs
        _smart_events = functools.partial(smart_get_namespace_events, source=source) if source else smart_get_namespace_events
        _list_prs = functools.partial(list_pipelineruns, source=source) if source else list_pipelineruns

        # === Build Search Parameters ===
        search_params = {
            'namespaces': await _get_target_namespaces(namespaces, identified_components, _list_ns, _detect_tekton),
            'time_range': time_range,
            'severity_levels': severity_levels or ['error', 'warn', 'info', 'debug'],
            'max_results': max_results,
            'context_lines': context_lines
        }

        # === Execute Semantic Search ===
        search_results = []
        sources_searched = 0

        # Search across identified namespaces with fixed function calls
        for namespace in search_params['namespaces']:
            logger.info(f"Searching namespace: {namespace}")
            try:
                namespace_results = []

                # Get pods in namespace
                pods_info = await list_pods_in_namespace(namespace, source=source)

                # Search pod logs with correct arguments
                for pod_info in pods_info[:5]:  # Limit to 5 pods per namespace for performance
                    if isinstance(pod_info, dict) and 'error' not in pod_info:
                        try:
                            pod_logs_result = await _search_pod_logs_semantically(
                                pod_info, namespace, query_interpretation, search_params,
                                _get_logs, _build_log_params, find_semantic_matches
                            )
                            if pod_logs_result:
                                namespace_results.extend(pod_logs_result)
                        except Exception as e:
                            logger.debug(f"Error searching pod logs in {namespace}: {e}")
                            continue

                # Search events with correct arguments
                try:
                    events_result = await _search_events_semantically(
                        namespace, query_interpretation, search_params,
                        _smart_events, calculate_semantic_relevance,
                        identify_match_reasons, extract_log_metadata
                    )
                    if events_result:
                        namespace_results.extend(events_result)
                except Exception as e:
                    logger.debug(f"Error searching events in {namespace}: {e}")

                # Search Tekton resources if relevant
                if any(comp in ['pipelinerun', 'taskrun', 'pipeline'] for comp in query_interpretation.get('semantic_keywords', [])):
                    try:
                        tekton_results = await _search_tekton_resources_semantically(
                            namespace, query_interpretation, search_params,
                            _list_prs, calculate_semantic_relevance
                        )
                        if tekton_results:
                            namespace_results.extend(tekton_results)
                    except Exception as e:
                        logger.debug(f"Error searching Tekton resources in {namespace}: {e}")

                search_results.extend(namespace_results)

            except Exception as e:
                logger.warning(f"Error searching namespace {namespace}: {e}")
                continue

            sources_searched += 1

            # Respect max_results limit
            if len(search_results) >= max_results:
                search_results = search_results[:max_results]
                break

        # === Semantic Ranking and Relevance Scoring ===
        ranked_results = rank_results_by_semantic_relevance(
            search_results, query_interpretation, group_similar
        )

        # === Pattern Analysis ===
        common_patterns = identify_common_patterns(ranked_results)
        severity_distribution = analyze_severity_distribution(ranked_results)

        # === Generate Suggestions ===
        suggestions = generate_semantic_suggestions(
            query_interpretation, ranked_results
        )

        # === Build Final Response ===
        return {
            "query_interpretation": {
                "original_query": query,
                "interpreted_intent": query_interpretation['interpreted_intent'],
                "search_strategy": search_strategy['strategy'],
                "identified_components": identified_components,
                "time_scope": time_range
            },
            "search_results": ranked_results,
            "result_summary": {
                "total_matches": len(ranked_results),
                "sources_searched": sources_searched,
                "common_patterns": common_patterns,
                "severity_distribution": severity_distribution
            },
            "suggestions": suggestions
        }

    except Exception as e:
        logger.error(f"Error in semantic log search: {str(e)}", exc_info=True)
        return {
            "query_interpretation": {
                "original_query": query,
                "interpreted_intent": "Error processing query",
                "search_strategy": "error",
                "identified_components": [],
                "time_scope": time_range
            },
            "search_results": [],
            "result_summary": {
                "total_matches": 0,
                "sources_searched": 0,
                "common_patterns": [],
                "severity_distribution": {}
            },
            "suggestions": {
                "related_queries": [],
                "broader_search": "Try simplifying your query",
                "narrower_search": "Add more specific terms"
            },
            "error": str(e)
        }


async def _report_sim_progress(ctx, step: int, total: int, message: str) -> None:
    """Best-effort MCP progress notification; never fails the tool.

    Live finding 2026-08-20: long simulations emitted no progress, so the MCP
    client aborted at its idle timeout even though the server finished.
    """
    if ctx is None:
        return
    try:
        await ctx.report_progress(step, total, message)
    except Exception as exc:  # client gone / no progressToken — non-fatal
        logger.debug(f"progress notification failed (non-fatal): {exc}")


# NEW TOOL: SIMULATION SCENARIOS
@mcp.tool()
async def what_if_scenario_simulator(
    scenario_type: str,
    changes: Dict[str, Any],
    scope: Optional[Dict[str, Any]] = None,
    simulation_duration: str = "24h",
    load_profile: str = "current",
    risk_tolerance: str = "moderate",
    source: str = "",
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Simulate impact of configuration changes before applying to live system with risk assessment.

    Uses Monte Carlo simulation and load modeling based on historical data.

    Args:
        scenario_type: Type - "resource_limits", "scaling", "configuration", "deployment".
        changes: Changes to simulate with before/after values.
        scope: Simulation scope - clusters, namespaces, components.
        simulation_duration: Duration - "1h", "24h", "7d" (default: "24h").
        load_profile: Expected load - "current", "peak", "custom" (default: "current").
        risk_tolerance: Risk level - "conservative", "moderate", "aggressive" (default: "moderate").
        source: Kubernetes instance name (default "" = the default configured instance).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict: Keys: simulation_id, impact_analysis, risk_assessment, affected_components, recommendations.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    try:
        # Generate unique simulation ID
        import uuid
        from datetime import datetime

        simulation_id = f"sim-{uuid.uuid4().hex[:8]}-{int(datetime.now().timestamp())}"

        logger.info(f"Starting what-if scenario simulation {simulation_id} for {scenario_type}")

        # Validate input parameters
        valid_scenario_types = ["resource_limits", "scaling", "configuration", "deployment"]
        if scenario_type not in valid_scenario_types:
            return {
                "simulation_id": simulation_id,
                "error": f"Invalid scenario_type '{scenario_type}'. Must be one of: {valid_scenario_types}"
            }

        valid_durations = ["1h", "24h", "7d"]
        if simulation_duration not in valid_durations:
            return {
                "simulation_id": simulation_id,
                "error": f"Invalid simulation_duration '{simulation_duration}'. Must be one of: {valid_durations}"
            }

        valid_load_profiles = ["current", "peak", "custom"]
        if load_profile not in valid_load_profiles:
            return {
                "simulation_id": simulation_id,
                "error": f"Invalid load_profile '{load_profile}'. Must be one of: {valid_load_profiles}"
            }

        valid_risk_levels = ["conservative", "moderate", "aggressive"]
        if risk_tolerance not in valid_risk_levels:
            return {
                "simulation_id": simulation_id,
                "error": f"Invalid risk_tolerance '{risk_tolerance}'. Must be one of: {valid_risk_levels}"
            }

        if not changes or not isinstance(changes, dict):
            return {
                "simulation_id": simulation_id,
                "error": "Changes parameter must be a non-empty dictionary with before/after values"
            }

        # Set default scope if not provided
        if scope is None:
            scope = {
                "clusters": [source or "current"],
                "namespaces": ["all"],
                "components": ["all"]
            }

        # Bind source to list_namespaces so both helper calls hit the named instance.
        # Without this, helpers that accept a bare function reference would call
        # list_namespaces with no source= and silently enumerate the default cluster.
        _list_ns = functools.partial(list_namespaces, source=source) if source else list_namespaces

        # Collect baseline system data
        await _report_sim_progress(ctx, 1, 5, "collecting baseline system data")
        baseline_data = await collect_baseline_system_data(
            scope, _clients.core_api, _list_ns, list_pods,
            progress_cb=lambda msg: _report_sim_progress(ctx, 1, 5, msg))

        # Build system behavior models
        await _report_sim_progress(ctx, 2, 5, "building behavior models")
        behavior_models = await build_system_behavior_models(baseline_data, scenario_type)

        # Load historical performance data for calibration (using real Prometheus data)
        # Per-instance partial: bind resolved clients + token + source (R8 — Task 6).
        # For named instances (source != ""), bearer_token is read from the store.
        # For the default instance (source == ""), _BEARER_SENTINEL is used so the
        # full default fallback chain (_get_k8s_bearer_token) is consulted as before.
        _prom_bearer = _instance_tokens.get(source) if source else _BEARER_SENTINEL
        await _report_sim_progress(ctx, 3, 5, "loading historical Prometheus data")
        historical_data = await load_historical_performance_data(
            scope,
            simulation_duration,
            prometheus_query_fn=functools.partial(
                _execute_prometheus_query_internal,
                custom_api=_clients.custom_api,
                core_api=_clients.core_api,
                bearer_token=_prom_bearer,
                source=source,
            ),
        )

        # Calibrate simulation models with historical data
        calibrated_models = calibrate_simulation_models(behavior_models, historical_data, load_profile)

        # Run Monte Carlo simulation for uncertainty quantification
        await _report_sim_progress(ctx, 4, 5, "running Monte Carlo simulation")
        simulation_results = await run_monte_carlo_simulation(
            calibrated_models,
            changes,
            scenario_type,
            simulation_duration,
            risk_tolerance
        )

        # Analyze impact on different system aspects
        impact_analysis = analyze_system_impact(simulation_results, baseline_data, scenario_type)

        # Identify affected components and their dependency graph
        await _report_sim_progress(ctx, 4, 5, "identifying affected components")
        affected_components = await identify_affected_components(
            changes, scope, scenario_type, _clients.core_api, _clients.apps_api, list_pods, _list_ns
        )

        # Perform risk assessment
        risk_assessment = perform_risk_assessment(
            simulation_results,
            impact_analysis,
            affected_components,
            risk_tolerance
        )

        # Calculate simulation quality metrics
        simulation_quality = calculate_simulation_quality(
            baseline_data,
            historical_data,
            calibrated_models,
            logger
        )

        # Generate recommendations
        recommendations = generate_simulation_recommendations(
            impact_analysis,
            risk_assessment,
            simulation_quality,
            scenario_type,
            logger
        )

        # Compile final results
        result = {
            "simulation_id": simulation_id,
            "scenario_description": f"{scenario_type.replace('_', ' ').title()} simulation over {simulation_duration}",
            "simulation_parameters": {
                "scenario_type": scenario_type,
                "duration": simulation_duration,
                "load_profile": load_profile,
                "risk_tolerance": risk_tolerance,
                "scope": scope,
                "changes": changes
            },
            "impact_analysis": impact_analysis,
            "affected_components": affected_components,
            "risk_assessment": risk_assessment,
            "simulation_quality": simulation_quality,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat(),
            "simulation_duration_seconds": convert_duration_to_seconds(simulation_duration)
        }

        logger.info(f"Completed simulation {simulation_id} with {len(affected_components)} affected components")
        await _report_sim_progress(ctx, 5, 5, "simulation complete")
        return result

    except Exception as e:
        logger.error(f"Error in what-if scenario simulation: {str(e)}", exc_info=True)
        return {
            "simulation_id": simulation_id if 'simulation_id' in locals() else "unknown",
            "error": f"Simulation failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }

async def _query_archived_plrs_for_trace(
    namespace: str,
    since_time: Optional[str] = None,
    until_time: Optional[str] = None,
    source: str = "",
    limit: int = 200,
    label_selector: Optional[str] = None,
    timeout_seconds: float = 90.0,
) -> List[Dict[str, Any]]:
    """Raw archived PipelineRun objects for the pipeline_tracer KubeArchive
    fallback (live finding 2026-08-20: prod GC prunes PLRs within ~2h, so
    live-only traces miss builds that provably happened).

    Best-effort by contract: returns [] on ANY unavailability (no token, no
    endpoint, archive error, or timeout_seconds exceeded) — the tracer's live
    path must never break because the archive is unreachable.  Returns raw
    objects (metadata/status intact) because the tracer's matcher needs
    labels+annotations, which the formatted query_kubearchive output drops.

    label_selector: pass an exact selector (e.g. pipelinesascode.tekton.dev/sha=
    <full-sha>) whenever the trace type allows it — live measurement 2026-08-20
    on kflux-prd-rh03/hummingbird-tenant: selector query 1.4s vs ~13min for the
    bare time-window dredge of the same namespace (which also truncates at
    `limit` newest-first and missed the target builds entirely).
    """
    try:
        if source and not _instance_tokens.get(source):
            return []
        _clients, _err = _resolve_k8s(source)
        if _err is not None:
            return []
        _discovery = get_discovery(
            source=source,
            k8s_core_api=_clients.core_api,
            k8s_custom_api=_clients.custom_api,
            k8s_networking_api=_clients.networking_api,
        )
        if _discovery is None:
            return []
        _ka_token = _instance_tokens.get(source) if source else await _get_k8s_bearer_token()
        ka_client = await setup_kubearchive_client(
            endpoint_discovery=_discovery,
            k8s_core_api=_clients.core_api,
            k8s_auth_token=_ka_token,
            source=source,
        )
        result = await asyncio.wait_for(
            ka_client.query_resources(
                resource_type="pipelinerun",
                namespace=namespace,
                label_selector=label_selector,
                creation_timestamp_after=normalize_to_rfc3339(since_time.strip()) if since_time else None,
                creation_timestamp_before=normalize_to_rfc3339(until_time.strip()) if until_time else None,
                limit=min(max(1, limit), 1000),
            ),
            timeout=timeout_seconds,
        )
        if result.get("status") != "success":
            return []
        data = result.get("data", {})
        if "items" in data:
            return data["items"]
        if data.get("metadata", {}).get("name"):
            return [data]
        return []
    except Exception as e:
        logging.getLogger("lumino-mcp.kubearchive").debug(
            "archive fallback unavailable for %s/%s: %s", source or "default", namespace, e
        )
        return []


@mcp.tool()
async def query_kubearchive(
    resource_type: str,
    namespace: str,
    name: Optional[str] = None,
    label_selector: Optional[str] = None,
    field_selector: Optional[str] = None,
    since_time: Optional[str] = None,
    until_time: Optional[str] = None,
    include_logs: bool = False,
    container: Optional[str] = None,
    limit: int = 100,
    output_format: str = "summary",
    source: str = "",
) -> Dict[str, Any]:
    """
    Query archived Kubernetes resources from KubeArchive (historical data no longer on the cluster).

    Single entry point for archived resources and their logs: set include_logs=True to attach logs
    for pipelinerun, taskrun, and pod results (use an exact name when you only need one resource).
    Optional container selects a container for multi-container pods.

    Args:
        resource_type: One of pipelinerun, taskrun, pod, release, snapshot (case-insensitive).
        namespace: Kubernetes namespace to search.
        name: Optional resource name; wildcards supported (e.g. my-pipeline-*).
        label_selector: Kubernetes label selector string.
        field_selector: Kubernetes field selector string (KubeArchive support may vary).
        since_time: Lower bound for creation time (RFC3339 or ISO date).
        until_time: Upper bound for creation time (RFC3339 or ISO date).
        include_logs: If True, fetch logs for each matching pod, taskrun, or pipelinerun.
        container: Optional container name (pods; passed to KubeArchive when include_logs=True).
        limit: Max resources to return (1-1000; out-of-range values are clamped).
        output_format: summary, detailed, or yaml.
        source: Kubernetes instance name (default "" = the default configured instance).
                Discovered/connected instances accepted; see list_sources.

    Returns:
        Dict with kubearchive_status, kubearchive_endpoint, resources, total_count, time_range,
        filters_applied, message, and error when applicable.
    """
    _clients, _err = _resolve_k8s(source)
    if _err:
        return _err
    # Normalize: the default instance's canonical name is an alias for ""; treat
    # it identically so the ambient token chain, KUBEARCHIVE_HOST env, and default
    # discovery all apply.  Must come after _resolve_k8s so that truly unknown
    # names are rejected before we ever reach this normalisation.
    if source == _source_registry.default_kubernetes_instance():
        source = ""
    ka_logger = logging.getLogger("lumino-mcp.query_kubearchive")
    valid_types = ["pipelinerun", "taskrun", "pod", "release", "snapshot"]
    valid_formats = ["summary", "detailed", "yaml"]
    filters_applied = {
        "resource_type": resource_type,
        "namespace": namespace,
        "name": name,
        "label_selector": label_selector,
        "field_selector": field_selector,
        "container": container,
    }

    def _base_response(
        status: str,
        resources: Optional[List[Any]] = None,
        total: int = 0,
        endpoint: Optional[str] = None,
        error: Optional[str] = None,
        message: Optional[str] = None,
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "kubearchive_status": status,
            "resources": resources if resources is not None else [],
            "total_count": total,
            "time_range": {"since": since_time, "until": until_time},
            "filters_applied": filters_applied,
        }
        if endpoint is not None:
            out["kubearchive_endpoint"] = endpoint
        if message:
            out["message"] = message
        if error:
            out["error"] = error
        return out

    ka_logger.info(
        "query_kubearchive resource_type=%s namespace=%s include_logs=%s container=%s limit=%s output_format=%s",
        resource_type,
        namespace,
        include_logs,
        container,
        limit,
        output_format,
    )

    try:
        if resource_type.lower() not in valid_types:
            return _base_response(
                "error",
                error=f"Invalid resource_type '{resource_type}'. Must be one of: {', '.join(valid_types)}",
                message="Validation failed",
            )

        if output_format not in valid_formats:
            return _base_response(
                "error",
                error=f"Invalid output_format '{output_format}'. Must be one of: {', '.join(valid_formats)}",
                message="Validation failed",
            )

        orig_limit = limit
        if limit < 1 or limit > 1000:
            limit = min(max(1, limit), 1000)
            ka_logger.warning("limit adjusted from %s to %s (valid range 1-1000)", orig_limit, limit)

        if since_time:
            try:
                since_time = normalize_to_rfc3339(since_time.strip())
            except ValueError as e:
                return _base_response(
                    "error",
                    error=f"Invalid since_time: {e}. Use RFC3339 or ISO date, e.g. 2024-01-15T10:30:00Z or 2024-01-15",
                    message="Validation failed",
                )

        if until_time:
            try:
                until_time = normalize_to_rfc3339(until_time.strip())
            except ValueError as e:
                return _base_response(
                    "error",
                    error=f"Invalid until_time: {e}. Use RFC3339 or ISO date, e.g. 2024-01-15T10:30:00Z or 2024-01-15",
                    message="Validation failed",
                )

        # BUG 1 fix (review B2): fail closed for named sources with no stored bearer
        # token before any discovery or HTTP.  Named sources registered via cert-auth
        # kubeconfig contexts have _instance_tokens[source] = None; KubeArchive
        # requires a bearer token.  Mirror the prometheus.py bearer_token=None
        # fail-closed contract (_execute_prometheus_query_internal:704-705).
        if source and not _instance_tokens.get(source):
            return _base_response(
                "error",
                error="token_unavailable",
                message=(
                    f"No bearer token stored for named source '{source}'. "
                    "KubeArchive requires a bearer token; cert-auth kubeconfig "
                    "contexts do not provide one.  Run connect_cluster with a "
                    f"bearer-token kubeconfig context for '{source}' to store a token."
                ),
            )

        _discovery = get_discovery(
            source=source,
            k8s_core_api=_clients.core_api,
            k8s_custom_api=_clients.custom_api,
            k8s_networking_api=_clients.networking_api,
        )
        if _discovery is None:
            if os.getenv("KUBEARCHIVE_ENABLED", "true").lower() == "false":
                # Replicate the availability-check path output so the characterization
                # golden for KUBEARCHIVE_ENABLED=false is unchanged by the factory move.
                _sug = [
                    "Deploy KubeArchive (https://github.com/kubearchive/kubearchive)",
                    "Set KUBEARCHIVE_HOST to your KubeArchive API base URL",
                    "Example: export KUBEARCHIVE_HOST='https://kubearchive-api-server.kubearchive.svc.cluster.local:8081'",
                ]
                out = _base_response(
                    "error",
                    error="KubeArchive endpoint not discovered",
                    message="KubeArchive unavailable",
                )
                out["suggestions"] = _sug
                return out
            return _base_response(
                "error",
                error="Kubernetes API clients are not initialized. Load kubeconfig or run in-cluster.",
                message="KubeArchive discovery requires CoreV1Api and CustomObjectsApi",
            )

        availability = await check_kubearchive_availability(_discovery)
        ka_endpoint = availability.get("endpoint")
        if not availability.get("available"):
            msg = availability.get("message", "KubeArchive not available")
            ka_logger.warning("KubeArchive availability check failed: %s", msg)
            sug = [
                "Deploy KubeArchive (https://github.com/kubearchive/kubearchive)",
                "Set KUBEARCHIVE_HOST to your KubeArchive API base URL",
                "Example: export KUBEARCHIVE_HOST='https://kubearchive-api-server.kubearchive.svc.cluster.local:8081'",
            ]
            out = _base_response(
                "error",
                error=msg,
                message="KubeArchive unavailable",
            )
            if ka_endpoint:
                out["kubearchive_endpoint"] = ka_endpoint
            out["suggestions"] = sug
            return out

        _ka_token = _instance_tokens.get(source) if source else await _get_k8s_bearer_token()
        ka_client = await setup_kubearchive_client(
            endpoint_discovery=_discovery,
            k8s_core_api=_clients.core_api,
            k8s_auth_token=_ka_token,
            source=source,
        )

        result = await query_kubearchive_resources(
            kubearchive_client=ka_client,
            resource_type=resource_type,
            namespace=namespace,
            name=name,
            label_selector=label_selector,
            field_selector=field_selector,
            since_time=since_time,
            until_time=until_time,
            include_logs=include_logs,
            container=container,
            limit=limit,
            output_format=output_format,
        )

        result["filters_applied"] = filters_applied
        result["kubearchive_endpoint"] = ka_endpoint

        if result.get("kubearchive_status") == "success":
            n = result.get("total_count", 0)
            result["message"] = (
                f"Found {n} archived resource(s)" if n else "No archived resources found matching criteria"
            )
        else:
            if "message" not in result:
                result["message"] = result.get("error", "KubeArchive query failed")

        ka_logger.info("query_kubearchive completed status=%s count=%s", result.get("kubearchive_status"), result.get("total_count"))
        return result

    except Exception as e:
        ka_logger.error("query_kubearchive failed: %s", e, exc_info=True)
        out = _base_response("error", error=str(e), message="Unexpected error")
        _discovery_err = get_discovery(
            source=source,
            k8s_core_api=_clients.core_api,
            k8s_custom_api=_clients.custom_api,
            k8s_networking_api=_clients.networking_api,
        )
        if _discovery_err is not None:
            try:
                ep = await _discovery_err.discover_endpoint()
                if ep:
                    out["kubearchive_endpoint"] = ep
            except Exception:
                pass
        return out

# ── Extension activation (§4.6.1) — LAST in module so every helper/tool above is in scope ──
import sys  # round-1 F2: server-mcp.py has NO existing `import sys` — without this the block NameErrors at import
from core.extension import ToolRegistry, DetectContext, activate_extensions, detect_and_register
# round-2 F3: this import line is a REQUIRED Task-3 edit (server-mcp.py imports none of these today; place
# the import here in the activation block, NOT with the :188-193 core imports, to keep the diff local).

_discovery_cache: dict = {}   # keyed by instance name; frozenset of API group names
_discovery_call_count: int = 0  # incremented on every real (non-cached) API call; spy in tests


async def _discover_api_groups(instance: str) -> frozenset:
    """Read /apis once per instance via the RO client; cache the result.

    Resolves the instance's apis_api via _resolve_k8s (round-1 F4): for the
    default instance the _DefaultClientView.apis_api property constructs
    ReadOnlyK8sClient.wrap(client.ApisApi()) fresh — byte-matching today's
    behaviour.  For non-default instances the frozen K8sClientSet.apis_api
    field is used.

    get_api_versions() is wrapped in asyncio.to_thread (round-1 F3) so the
    2-second timeout in detect_and_register is genuinely cancellable — a bare
    sync I/O call inside asyncio.wait_for cannot be cancelled mid-flight.

    Never called under builtin on/off profiles — only exercised by auto-mode
    detection.  A module-level counter allows the inertness spy to assert
    zero calls after import.
    """
    global _discovery_call_count
    if instance in _discovery_cache:
        return _discovery_cache[instance]
    _discovery_call_count += 1
    view, _err = _resolve_k8s(instance)
    apis_api = view.apis_api
    api_versions = await asyncio.to_thread(apis_api.get_api_versions)
    groups = frozenset(g.name for g in api_versions.groups)
    if instance not in _disconnected_instances:  # no write-back for a name disconnected mid-flight
        _discovery_cache[instance] = groups
    return groups


def _load_intree_extensions(cfg) -> list:
    """Import each configured in-tree extension and return its EXTENSION object.

    Only extensions present in both cfg.extensions and INTREE_EXTENSIONS are
    loaded, sorted alphabetically so activation order is deterministic.
    """
    import importlib
    from core.extension import INTREE_EXTENSIONS
    result = []
    for name in sorted(INTREE_EXTENSIONS):
        if name in cfg.extensions:
            mod = importlib.import_module(f"extensions.{name}")
            result.append(mod.EXTENSION)
    return result


def _detect_ctx(instance: Optional[str] = None) -> DetectContext:
    """Build the DetectContext for a specific kubernetes instance.

    Default None resolves to _source_registry.default_kubernetes_instance() at call
    time, not at def time — ensures renamed-default sources work end-to-end (M3).
    A literal default would bind at function-definition time before module-end
    registry state is final; resolution inside the body avoids that.
    Callers that pass an explicit instance string are unaffected.
    """
    if instance is None:
        instance = _source_registry.default_kubernetes_instance()
    return DetectContext(
        config=_lumino_config,
        adapters=_source_registry,
        instance=instance,
        discover_api_groups=_discover_api_groups,
    )


# ── Phase 2e Task 2: dial-free kubeconfig-context discovery + connection state ──


def _discover_kube_contexts(cfg=None) -> list:
    """Return non-current kubeconfig context names, name-sorted (dial-free).

    Reads local kubeconfig via list_kube_config_contexts (no network I/O).
    On any error (missing file, parse error, in-cluster with no file) returns [].
    Honors `sources.kubernetes.options.discover_contexts` toggle (default True).

    cfg: pass explicitly in tests; defaults to the module-level _lumino_config.
    """
    if cfg is None:
        cfg = _lumino_config
    # Toggle: `sources.<default_k8s_name>.options.get("discover_contexts", True)`.
    # Use the registry's default instance name — not the literal "kubernetes" —
    # so renamed-default sources (e.g. "prod-hub") are honoured correctly (M3).
    _default_k8s_name = _source_registry.default_kubernetes_instance()
    k8s_sc = cfg.sources.get(_default_k8s_name) if _default_k8s_name else None
    if k8s_sc is not None and not k8s_sc.options.get("discover_contexts", True):
        return []
    try:
        contexts, active_ctx = config.list_kube_config_contexts()
        current_name = active_ctx["name"] if active_ctx else None
        return sorted(
            ctx["name"] for ctx in contexts
            if ctx["name"] != current_name
        )
    except Exception as exc:
        logger.debug(f"kubeconfig context discovery failed (non-fatal): {exc}")
        return []


def _scan_kubeconfig_dir(cfg=None) -> None:
    """Scan kubeconfig_dir for *.yaml / *.kubeconfig files; register each context dial-free.

    Feature is OFF when the default k8s source's options lack 'kubeconfig_dir' (no default dir).
    Non-recursive; files name-sorted; per-file list_kube_config_contexts(config_file=path)
    in try/except (malformed / unreadable → debug-log + skip, scan continues).

    Collision naming (deterministic):
      candidate = context name
      if candidate in registry-or-scan → f"{Path(path).stem}#{ctx}"
      if THAT also in registry-or-scan → skip (F2 import-crash guard — never raise here)

    Registers each accepted instance via add_instance (state="configured", default=False,
    conn_state "unconnected").  Records (original_context_name, path_str) in
    _kubeconfig_dir_paths so _resolve_k8s can build the client correctly at call time.

    cfg: pass explicitly in tests; defaults to module-level _lumino_config.
    """
    if cfg is None:
        cfg = _lumino_config
    _default_k8s_name = _source_registry.default_kubernetes_instance()
    k8s_sc = cfg.sources.get(_default_k8s_name) if _default_k8s_name else None
    if k8s_sc is None:
        return
    kube_dir = k8s_sc.options.get("kubeconfig_dir")
    if not kube_dir:
        return

    kube_dir_path = Path(kube_dir)
    if not kube_dir_path.is_dir():
        logger.debug(f"kubeconfig_dir {kube_dir!r} is not a directory or does not exist (non-fatal)")
        return

    # Capabilities mirror the default k8s instance (or fall back to the adapter default).
    caps = (
        _source_registry.get(_default_k8s_name).capabilities
        if _default_k8s_name else _ADAPTER_CAPABILITIES["kubernetes"]
    )

    # Name-sorted non-recursive scan of *.yaml and *.kubeconfig files.
    files = sorted(
        p for p in kube_dir_path.iterdir()
        if p.is_file() and p.suffix in (".yaml", ".kubeconfig")
    )

    # Snapshot of names currently in the registry (includes entries added mid-scan).
    registered_names = {e.name for e in _source_registry.entries()}

    for path in files:
        try:
            contexts, _ = config.list_kube_config_contexts(config_file=str(path))
        except Exception as exc:
            logger.debug(
                f"kubeconfig_dir: skip {path.name!r} (unreadable/malformed): {exc}"
            )
            continue

        for ctx_entry in contexts:
            ctx = ctx_entry["name"]
            instance_name = ctx
            if instance_name in registered_names:
                # Collision — try deterministic stem#ctx rename
                instance_name = f"{path.stem}#{ctx}"
                if instance_name in registered_names:
                    logger.debug(
                        f"kubeconfig_dir: skip context {ctx!r} from {path.name!r} "
                        f"(both {ctx!r} and {path.stem!r}#{ctx!r} already registered)"
                    )
                    continue

            try:
                _source_registry.add_instance(SourceEntry(
                    name=instance_name,
                    adapter="kubernetes",
                    capabilities=caps,
                    state="configured",
                    default=False,
                ))
            except ValueError:
                # Race / re-entry guard: never raise in the module-end block (F2 lesson)
                logger.debug(
                    f"kubeconfig_dir: skip {instance_name!r} (registry collision guard)"
                )
                continue

            _k8s_conn_state[instance_name] = "unconnected"
            # Store ORIGINAL context name (not the potentially renamed instance_name)
            _kubeconfig_dir_paths[instance_name] = (ctx, str(path))
            # Store bearer token for per-instance Prometheus auth (None for cert-auth kubeconfigs).
            _instance_tokens[instance_name] = _extract_kubeconfig_token(str(path), ctx)
            registered_names.add(instance_name)


# Populate _k8s_conn_state (default instance = "connected"; discovered = "unconnected").
# Collision guard (F2): skip contexts whose name is already in the registry to
# prevent add_instance ValueError from crashing the module import.
_default_k8s = _source_registry.default_kubernetes_instance()
if _default_k8s:
    _k8s_conn_state[_default_k8s] = "connected"

_k8s_existing = {e.name for e in _source_registry.entries()}
_k8s_default_caps = (
    _source_registry.get(_default_k8s).capabilities
    if _default_k8s else _ADAPTER_CAPABILITIES["kubernetes"]
)
for _ctx in _discover_kube_contexts(_lumino_config):
    if _ctx in _k8s_existing:
        continue  # collision guard: skip names already in the registry
    _source_registry.add_instance(SourceEntry(
        name=_ctx,
        adapter="kubernetes",
        capabilities=_k8s_default_caps,
        state="configured",
        default=False,
    ))
    _k8s_conn_state[_ctx] = "unconnected"

# ── Phase 2e-b Task 5: kubeconfig_dir directory scan (dial-free) ─────────────
_scan_kubeconfig_dir(_lumino_config)

# ── End phase 2e Task 2 / phase 2e-b Task 5 ──────────────────────────────────


_extension_facade = ToolRegistry(
    server_module=sys.modules[__name__], mcp=mcp,
    config=_lumino_config, adapters=_source_registry, packs={})

_extension_states = activate_extensions(
    _lumino_config, _load_intree_extensions(_lumino_config), _extension_facade,
    _detect_ctx())

# ── Phase 2c: canonical tool names (spec §4.4 Naming/compat) ─────────────────
# One body, two registrations. The old @mcp.tool() registration is untouched
# (old-name parity blocks byte-identical; internal callers and golden patches
# keep the old module symbols). The canonical name is registered ADDITIVELY
# against the SAME already-wrapped function object, so Tool.from_function
# derives a byte-equal schema/description — zero drift by construction.
# A collision here is a programmer error in an in-tree literal map, so raising
# at import is CORRECT (fail-fast in CI) — unlike the kubeconfig discovery
# block, which must never raise on runtime data (the 2e F2 rule).
_CANONICAL_ALIASES: Dict[str, str] = {
    "analyze_pod_logs_hybrid": "analyze_logs_hybrid",
    "live_system_topology_mapper": "topology_mapper",
    "prometheus_query": "query_metrics",
    "smart_get_namespace_events": "get_events_smart",
    "smart_summarize_pod_logs": "smart_summarize_logs",
    "stream_analyze_pod_logs": "stream_analyze_logs",
}

for _old_name, _canonical_name in _CANONICAL_ALIASES.items():
    if _canonical_name in mcp._tool_manager._tools:            # R1 collision guard
        raise ValueError(
            f"canonical tool name {_canonical_name!r} already registered")
    mcp.add_tool(globals()[_old_name], name=_canonical_name)

for _name, _fn in _extension_facade.registered.items():
    globals()[_name] = _fn   # getattr(server, name) keeps working for goldens/readonly tests