# tests/test_readonly_guard.py
"""Spec SS4.7 tripwire: extracted layers contain no write-capable API usage."""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
# Entire source tree: all .py under src/ plus the top-level entry-point.
SCOPES = list((REPO / "src").rglob("*.py")) + [REPO / "main.py"]
# scripts/*.py is deliberately out of scope today (zero write verbs, no kubernetes
# import) and should be folded in if scripts ever touch a cluster.
WRITE_RE = re.compile(r"\.(create_|patch_|delete_|replace_|connect_)[a-z_]+\(")

# Allowlist: (relpath, substring) pairs — each exempts lines in the named file
# that contain the given substring.
ALLOWLIST = [
    # stdlib TLS context construction, not a k8s write
    ("src/core/tls.py", "ssl.create_default_context("),
    # local joblib model file delete — ml_persistence.py has ZERO k8s clients
    ("src/helpers/ml_persistence.py", "self.delete_model("),
]

# ---------------------------------------------------------------------------
# EXEC_RE tripwire: subprocess exec-mutation guard (M1/M2/M3-pinned, empty allowlist).
# adm is in MUT deliberately: `oc adm policy add-cluster-role-to-user` is
# the exact escalation pattern this exists to catch and no other verb covers it.
# ---------------------------------------------------------------------------
CLI = r"kubectl|oc"
MUT = (
    r"create|apply|patch|delete|replace|edit|scale|annotate|label|set"
    r"|cordon|drain|taint|expose|rollout|adm"
)
# Flag-interposed: argv list form OR command-string form; up to 4 interposed
# flag-like tokens (a token starting with `-`, plus its optional value token)
# allowed between the CLI name and the mutating verb.
# Covered: flag-interposed mutations up to 4 flags between CLI and verb, e.g.:
#   ['kubectl','-n','default','create','sa','x']
#   ['oc','--context','p02','delete','pod','x']
#   "kubectl -n default create sa x"
# Rejects non-flag-adjacent prose: "kubectl to create ...",
#   "kubectl not found, cannot create ...", and the collapsed :696 warning
#   ('oc login'. On vanilla Kubernetes: set — the words between oc and set
#   are not flag-shaped, so 0 flag groups match and oc-set is non-adjacent).
# The allowlist must remain EMPTY forever.
# Uncoverable blind spot: computed argv (`cmd = ["kubectl"] + verbs`,
#   runtime f-strings) — requires taint analysis; no fix proposed.
_Q_FLAG = r"""['"]-[^'"]*['"]"""          # quoted argv token starting with -
_Q_VAL  = r"""['"][^'"]*['"]"""           # any quoted argv token (flag value)
_F_ARGV = rf"""(?:\s*,\s*{_Q_FLAG}(?:\s*,\s*{_Q_VAL})?)"""  # one flag item (argv)
_F_STR  = r"""(?:\s+-\S+(?:\s+\S+)?)"""  # one flag item (string)
EXEC_RE = re.compile(
    rf"['\"](?:{CLI})['\"]"          # quoted CLI tool (argv form)
    rf"{_F_ARGV}{{0,4}}"             # up to 4 interposed flag items (argv)
    r"\s*,\s*"                        # comma separator before verb
    rf"['\"](?:{MUT})['\"]"          # quoted mutating verb
    rf"|\b(?:{CLI}){_F_STR}{{0,4}}\s+(?:{MUT})\b"  # command-string form
)
EXEC_ALLOWLIST: list[tuple[str, str]] = []


def _scan_source(relpath: str, text: str) -> list[str]:
    """Return write-verb hits in *text*, excluding allowlisted (relpath, substring) pairs.

    When an allowlisted substring is present in a line, that substring is removed
    (all occurrences) and WRITE_RE is re-applied to the remainder.  A line containing
    BOTH an allowlisted call and a genuine k8s write is therefore still flagged —
    the exemption cannot be used as cover for a co-located write.
    """
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if WRITE_RE.search(line):
            remainder = line
            for rp, sub in ALLOWLIST:
                if relpath == rp and sub in remainder:
                    remainder = remainder.replace(sub, "")
            if WRITE_RE.search(remainder):
                hits.append(f"{relpath}:{i}: {line.strip()}")
    return hits


def test_no_write_verbs_in_extracted_layers():
    hits = []
    for py in SCOPES:
        hits.extend(_scan_source(str(py.relative_to(REPO)), py.read_text()))
    assert not hits, "write-capable API calls in read-only layers:\n" + "\n".join(hits)


def test_scan_source_catches_delete_namespaced_pod():
    """Unit: _scan_source flags a delete_namespaced_pod call in a non-allowlisted file."""
    result = _scan_source(
        "src/server-mcp.py",
        "        self.core_v1.delete_namespaced_pod(name, ns)\n",
    )
    assert result, "_scan_source must return a hit for delete_namespaced_pod in server-mcp.py"


def test_scan_source_allowlist_anchored_to_ml_persistence():
    """Unit: delete_model in a file OTHER than ml_persistence.py is NOT exempted."""
    result = _scan_source(
        "src/adapters/otlp/rings.py",
        "        self.delete_model(x)\n",
    )
    assert result, "_scan_source must flag delete_model in rings.py (allowlist anchored to ml_persistence.py)"


def test_scan_source_collocated_write_still_caught():
    """Unit: allowlist strips its own substring but a co-located k8s write still fires.

    Mutation: revert _scan_source to whole-line exemption → this test fails.
    """
    result = _scan_source(
        "src/core/tls.py",
        "ctx = ssl.create_default_context(); self.core_v1.delete_namespaced_pod(a, b)\n",
    )
    assert result, (
        "_scan_source must flag a co-located delete_namespaced_pod even when "
        "ssl.create_default_context() is allowlisted"
    )


def test_scan_source_allowlist_site_still_exempt():
    """Unit: a standalone allowlisted call in the legitimate file produces no hit."""
    result = _scan_source(
        "src/core/tls.py",
        "ctx = ssl.create_default_context()\n",
    )
    assert not result, (
        "_scan_source must not flag ssl.create_default_context() alone in core/tls.py"
    )


def test_scope_covers_full_source_tree():
    """Scope tripwire: SCOPES must enumerate every .py under src/ plus main.py.

    An exclusion of any file — including new modules added later — fails this test.
    Mutation: revert SCOPES to the old 4-subpackage form → this test fails.
    """
    scope_set = set(SCOPES)
    assert REPO / "main.py" in scope_set, "main.py missing from SCOPES"
    assert REPO / "src" / "server-mcp.py" in scope_set, "src/server-mcp.py missing from SCOPES"
    expected = len(list((REPO / "src").rglob("*.py"))) + 1  # +1 for main.py
    assert len(SCOPES) == expected, (
        f"SCOPES has {len(SCOPES)} files; filesystem has {expected} "
        f"(src/**/*.py={expected - 1} + main.py)"
    )


# Round-2 N4: the engines-layer import rule is ENFORCED, not just documented.
ALLOWED_HELPERS_IMPORTS = {"extract_error_patterns", "categorize_errors",
                           "generate_log_summary"}


def test_engines_import_rule():
    import ast
    violations = []
    for py in (REPO / "src" / "engines").rglob("*.py"):
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod.startswith("helpers"):
                    bad = {a.name for a in node.names} - ALLOWED_HELPERS_IMPORTS
                    if bad:
                        violations.append(f"{py.name}: from {mod} import {bad}")
                if mod.startswith("kubernetes"):
                    violations.append(f"{py.name}: from {mod} import ...")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith(("kubernetes", "helpers")):
                        violations.append(f"{py.name}: import {a.name}")
    assert not violations, "engines-layer import rule violations:\n" + "\n".join(violations)


def test_get_all_pod_logs_retains_readonly_wrap():
    """Deletion tripwire: the shared log-fetch gateway must keep its wrap."""
    src = (REPO / "src" / "helpers" / "utils.py").read_text()
    assert "ReadOnlyCoreV1.wrap" in src, "get_all_pod_logs lost its read-only wrap"


def test_log_path_readonly_inventory():
    """Living inventory: every log-tool fetch is read-only-routed, each proven
    by a BEHAVIORAL spy/routing test (goldens can't prove routing). Add new log
    fetches here with their test reference."""
    covered = {
        "get_pod_logs": "characterization/test_readonly_routing.py::test_get_pod_logs_forwards_readonly_client",
        "get_all_pod_logs": "test_k8s_logs_fetch.py::test_get_all_pod_logs_wraps_client_internally",
        "get_etcd_logs": "test_readonly_log_path.py::test_get_etcd_logs_routes_readonly",
        "predictive_log_analyzer": "test_readonly_log_path.py::test_predictive_routes_readonly",
        "manage_prediction_training_data": "test_readonly_log_path.py::test_manage_collect_routes_readonly",
        "_prioritize_pipeline_pods": "test_readonly_log_path.py::test_prioritize_routes_readonly",
        "get_pipelinerun_logs": "test_readonly_log_path.py::test_get_pipelinerun_logs_routes_readonly",
    }
    assert len(covered) == 7


def test_failure_analysis_retains_readonly_wraps():
    """Deletion tripwire: all three failure_analysis helpers must keep their
    param-local read-only reassignment (identify_failure_context,
    analyze_pod_failure, analyze_resource_constraints)."""
    src = (REPO / "src" / "helpers" / "failure_analysis.py").read_text()
    count = src.count("ReadOnlyCoreV1.wrap")
    assert count == 3, (
        f"Expected exactly 3 ReadOnlyCoreV1.wrap calls in failure_analysis.py "
        f"(one per helper); found {count}"
    )


def test_event_path_readonly_inventory():
    """Living inventory: every event-path / RCA CoreV1 fetch is
    read-only-routed, each proven by a BEHAVIORAL spy/routing test (goldens
    can't prove routing).  Add new event fetches here with their test
    reference."""
    covered = {
        "_get_namespace_events_internal": "characterization/test_readonly_event_path.py::test_namespace_events_internal_routes_readonly",
        "_get_namespace_events_as_dicts": "characterization/test_readonly_event_path.py::test_namespace_events_as_dicts_routes_readonly",
        "identify_failure_context.read_namespaced_pod": "test_readonly_failure_analysis.py::test_identify_pod_read_routes_readonly",
        "identify_failure_context.list_namespaced_event": "test_readonly_failure_analysis.py::test_identify_event_fallback_routes_readonly",
        "analyze_pod_failure": "test_readonly_failure_analysis.py::test_analyze_pod_failure_routes_readonly",
        "analyze_resource_constraints": "test_readonly_failure_analysis.py::test_analyze_resource_constraints_routes_readonly",
    }
    assert len(covered) == 6


def test_failure_analysis_retains_custom_readonly_wrap():
    """Deletion tripwire: identify_failure_context must keep its CustomObjects
    wrap (exactly one ReadOnlyK8sClient.wrap in the module; the three
    ReadOnlyCoreV1.wrap calls are guarded by the phase-1c tripwire above)."""
    src = (REPO / "src" / "helpers" / "failure_analysis.py").read_text()
    count = src.count("ReadOnlyK8sClient.wrap")
    assert count == 1, (
        f"Expected exactly 1 ReadOnlyK8sClient.wrap in failure_analysis.py; "
        f"found {count}")


def test_customobjects_readonly_inventory():
    """Living inventory: every CustomObjects fetch routed in phase 1d, each
    proven by a BEHAVIORAL spy/routing test.  Add new custom-object fetches
    here with their test reference."""
    covered = {
        "list_pipelineruns": "characterization/test_readonly_pipeline_path.py::test_list_pipelineruns_routes_readonly",
        "list_taskruns": "characterization/test_readonly_pipeline_path.py::test_list_taskruns_routes_readonly",
        "list_recent_pipeline_runs": "characterization/test_readonly_pipeline_path.py::test_list_recent_pipeline_runs_routes_readonly",
        "find_pipeline": "characterization/test_readonly_pipeline_path.py::test_find_pipeline_routes_readonly",
        "get_tekton_pipeline_runs_status": "characterization/test_readonly_pipeline_path.py::test_tekton_status_routes_readonly",
        "get_pipeline_details": "test_readonly_pipeline_details.py::test_get_pipeline_details_routes_readonly",
        "get_task_details": "test_readonly_pipeline_details.py::test_get_task_details_routes_readonly",
        "topology_client_factory": "test_readonly_topology_clients.py::test_topology_factory_returns_readonly_clients",
        "identify_failure_context.pipelinerun": "test_readonly_failure_analysis.py::test_identify_plr_read_routes_readonly",
        "identify_failure_context.taskrun": "test_readonly_failure_analysis.py::test_identify_tr_read_routes_readonly",
        "_discover_prometheus_via_routes": "characterization/test_readonly_custom_misc.py::test_prometheus_route_discovery_routes_readonly",
        "_discover_prometheus_via_operator_crd": "characterization/test_readonly_custom_misc.py::test_prometheus_crd_discovery_routes_readonly",
        "get_machine_config_pool_status": "characterization/test_readonly_custom_misc.py::test_machine_config_pool_routes_readonly",
        "get_openshift_cluster_operator_status": "characterization/test_readonly_custom_misc.py::test_cluster_operator_routes_readonly",
    }
    assert len(covered) == 14


def test_kubearchive_client_raw_tripwire():
    """MUST-STAY-RAW tripwire: KubeArchiveClient's auth paths read api_client
    (:705/:730); the class-level client must never be wrapped."""
    src = (REPO / "src" / "helpers" / "kubearchive_integration.py").read_text()
    assert "self.k8s_core_api.api_client" in src  # auth path still exists
    assert "self.k8s_core_api = ReadOnlyK8sClient.wrap" not in src


def test_generic_tools_expose_source_param():
    """Phase-2b guard: every spec-SS4.4 generic tool exposes source: str = ""
    in its registered schema.  Grep-based (schema-level proof lives in the
    parity tests); this pins the tool list so a future refactor can't silently
    drop the param."""
    src = (REPO / "src" / "server-mcp.py").read_text()
    generic_tools = [
        "analyze_logs", "smart_summarize_pod_logs", "stream_analyze_pod_logs",
        "analyze_pod_logs_hybrid", "detect_log_anomalies", "semantic_log_search",
        "predictive_log_analyzer", "manage_prediction_training_data",
        "smart_get_namespace_events", "progressive_event_analysis",
        "advanced_event_analytics", "detect_anomalies", "prometheus_query",
        "resource_bottleneck_forecaster", "automated_triage_rca_report_generator",
        "live_system_topology_mapper",
    ]
    assert len(generic_tools) == 16
    missing = [t for t in generic_tools
               if f"async def {t}(" in src and
               "source: str = \"\"" not in src.split(f"async def {t}(")[1].split("->")[0]]
    assert not missing, f"generic tools missing source param: {missing}"


def test_phase1e_readonly_inventory():
    """Living inventory: phase-1e routed reads, each proven by a BEHAVIORAL
    spy test.  MUST-NEVER-WRAP set: server-mcp.py _get_fallback_cluster_health
    api_client sites; kubearchive KubeArchiveClient.k8s_core_api.
    KubeArchiveEndpointDiscovery.k8s_networking_api remains raw (single
    read_namespaced_ingress site, NetworkingV1 — future pass)."""
    covered = {
        "list_namespaces": "characterization/test_readonly_core_tools.py::test_list_namespaces_routes_readonly",
        "list_pods_in_namespace": "characterization/test_readonly_core_tools.py::test_list_pods_in_namespace_routes_readonly",
        "utils.list_pods": "test_readonly_helper_params.py::test_utils_list_pods_routes_readonly",
        "check_resource_constraints": "characterization/test_readonly_core_tools.py::test_check_resource_constraints_routes_readonly",
        "get_tekton_pipeline_runs_status.core": "characterization/test_readonly_core_tools.py::test_tekton_status_core_read_routes_readonly",
        "get_kubernetes_resource": "characterization/test_readonly_dispatchers.py (6 family tests)",
        "search_resources_by_labels": "characterization/test_readonly_dispatchers.py (3 branch tests)",
        "_discover_prometheus_via_operator_crd.core": "characterization/test_readonly_discovery_certs.py::test_prom_crd_core_read_routes_readonly",
        "_discover_prometheus_via_services": "characterization/test_readonly_discovery_certs.py::test_prom_services_discovery_routes_readonly",
        "_discover_thanos_via_services": "characterization/test_readonly_discovery_certs.py::test_thanos_services_discovery_routes_readonly",
        "check_cluster_certificate_health": "characterization/test_readonly_discovery_certs.py::test_cert_health_routes_readonly",
        "get_multi_cluster_clients": "test_readonly_helper_params.py::test_multi_cluster_clients_factory_returns_readonly",
        "follow_lifecycle_chain": "test_readonly_helper_params.py::test_follow_lifecycle_chain_wraps_custom_api",
        "collect_baseline_system_data": "test_readonly_helper_params.py::test_collect_baseline_routes_readonly",
        "_get_active_node_names": "characterization/test_readonly_forecaster_tracer.py::test_active_node_names_routes_readonly",
        "_analyze_cluster_capacity_new": "characterization/test_readonly_forecaster_tracer.py::test_cluster_capacity_helper_routes_readonly",
        "get_machine_config_pool_status.node": "characterization/test_readonly_forecaster_tracer.py::test_mcp_node_read_routes_readonly",
        "_get_fallback_cluster_health.partial": "characterization/test_readonly_forecaster_tracer.py::test_fallback_health_partial_wrap",
        "KubeArchiveEndpointDiscovery": "test_readonly_kubearchive.py::test_endpoint_discovery_wraps_clients",
        "KubeArchiveClient._get_ssl_context": "test_readonly_kubearchive.py::test_ssl_context_read_routes_readonly",
        "identify_affected_components": "test_readonly_helper_params.py::test_identify_affected_components_routes_readonly",
    }
    assert len(covered) == 21


# ---------------------------------------------------------------------------
# EXEC_RE tree scan and unit tests (M1/M2/M3/M4-pinned).
# ---------------------------------------------------------------------------

def _scan_source_exec(relpath: str, text: str) -> list[str]:
    """Return exec-mutation hits in *text*, excluding EXEC_ALLOWLIST entries.

    Parallel to _scan_source for WRITE_RE: strips allowlisted substrings before
    re-applying EXEC_RE so a co-located genuine exec still fires.
    """
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if EXEC_RE.search(line):
            remainder = line
            for rp, sub in EXEC_ALLOWLIST:
                if relpath == rp and sub in remainder:
                    remainder = remainder.replace(sub, "")
            if EXEC_RE.search(remainder):
                hits.append(f"{relpath}:{i}: {line.strip()}")
    return hits


def test_no_exec_mutations_in_source_tree():
    """SS4.7-exec tripwire: no subprocess calls exec kubectl/oc with a mutating
    verb exist in the source tree.  EXEC_ALLOWLIST must remain empty; adding an
    entry is an audited change requiring this assertion's deletion in the same
    commit plus written justification.  Reuses SCOPES — not a copy, not a subset.
    """
    hits = []
    for py in SCOPES:  # same SCOPES object as WRITE_RE scan, not a copy
        hits.extend(_scan_source_exec(str(py.relative_to(REPO)), py.read_text()))
    assert not hits, "exec-mutation subprocess calls in source:\n" + "\n".join(hits)


def test_exec_allowlist_is_empty():
    """EXEC_RE allowlist must remain empty forever.

    Adding an entry is an audited change: delete this assertion in the same
    commit as the allowlist entry, and include written justification explaining
    why the subprocess exec is safe and non-escalating.
    """
    assert EXEC_ALLOWLIST == [], (
        f"EXEC_RE allowlist must remain empty; got {EXEC_ALLOWLIST!r}"
    )


def test_exec_scan_positive_argv():
    """M1a positive: argv list with kubectl + mutating verb is flagged."""
    result = _scan_source_exec(
        "src/helpers/kubearchive_integration.py",
        "    subprocess.run(['kubectl', 'create', 'clusterrolebinding', 'x'],\n",
    )
    assert result, "argv kubectl-create must be flagged by _scan_source_exec"


def test_exec_scan_positive_string():
    """M1a positive: command string with oc + mutating verb is flagged."""
    result = _scan_source_exec(
        "src/helpers/kubearchive_integration.py",
        '    subprocess.run("oc apply -f x")\n',
    )
    assert result, "oc apply in a command string must be flagged by _scan_source_exec"


def test_exec_scan_positive_argv_flag_interposed():
    """Flag-interposed positive: argv list with -n namespace flags before verb is flagged."""
    result = _scan_source_exec(
        "src/helpers/kubearchive_integration.py",
        "    subprocess.run(['kubectl','-n','default','create','sa','x'],\n",
    )
    assert result, "kubectl with '-n','default' before 'create' in argv must be flagged"


def test_exec_scan_positive_argv_context_flag():
    """Flag-interposed positive: --context flag between CLI and verb is flagged."""
    result = _scan_source_exec(
        "src/helpers/kubearchive_integration.py",
        "    r = ['oc','--context','p02','delete','pod','x']\n",
    )
    assert result, "oc with '--context','p02' before 'delete' in argv must be flagged"


def test_exec_scan_positive_string_flag_interposed():
    """Flag-interposed positive: command string with flags between CLI and verb is flagged."""
    result = _scan_source_exec(
        "src/helpers/kubearchive_integration.py",
        '    subprocess.run("kubectl -n default create sa x")\n',
    )
    assert result, "kubectl with '-n default' before 'create' in command string must be flagged"


@pytest.mark.parametrize("line", [
    # Non-mutating verbs: these must never match regardless of adjacency.
    "    subprocess.run(['kubectl', 'get', 'pods'])\n",
    "    subprocess.run(['oc', 'whoami', '-t'])\n",
    "    'kubectl port-forward'\n",
    # Prose negatives from the live source tree (verbatim copies) — these use
    # mutating verb names but are non-adjacent prose, so adjacency rejects them.
    '                    "Check node conditions: kubectl get node <name> -o yaml",\n',
    '                    "Verify access with: kubectl auth can-i list pods -n " + namespace\n',
    # Flag-interposed oracle: these two prose lines (deleted in T1 from the
    # removed _create_local_dev_token() body — kept here as hardcoded strings
    # to preserve the negative contract) are the only cases in THIS parametrize
    # where the flag-interposed pattern rejects but bounded 40-char proximity
    # (\bkubectl\b.{0,40}?\bMUT\b) accepts.
    # Measured with the bounded M1b pattern on the post-removal source tree
    # (re-verified after widening to flag-interposed):
    #   - 0 other in-scope lines match bounded proximity but not the widened pattern.
    #   - The collapsed warning (kubearchive_integration.py:696, single physical
    #     line) adds 1 more: 'oc login'. ... set — \boc\b to \bset\b is 32
    #     chars, within 40.  That line makes the tree scan go red under M1b.
    # M1b mutation total: exactly 2 unit failures (here) + 1 tree-scan failure.
    # (Flag-interposed forms are now COVERED; computed argv remains uncoverable.)
    "            # Use kubectl to create ClusterRole with proper permissions\n",
    '            logger.debug("kubectl not found, cannot create local dev token")\n',
])
def test_exec_scan_negative(line):
    """M1b negative: non-mutating or non-adjacent patterns must not be flagged."""
    result = _scan_source_exec("src/helpers/kubearchive_integration.py", line)
    assert not result, f"_scan_source_exec must not flag: {line!r}"
