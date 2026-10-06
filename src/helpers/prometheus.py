"""Prometheus/Thanos discovery, query execution, and result formatting."""

import re
import os
import time
import logging
import aiohttp
from typing import Dict, List, Optional, Any
from kubernetes import client
from core.k8s_async import k8s_call, k8s_offload
from core.namespace_trust import namespace_is_trusted
from core.readonly_client import ReadOnlyK8sClient
from core.tls import PLAIN_HTTP_TOKEN_HINT, TLS_HINT, bearer_token_allowed, client_ssl_context
from helpers.utils import _safe_compile_namespace_filter, _is_running_in_cluster

logger = logging.getLogger("lumino-mcp")

# OpenShift cluster Prometheus endpoints (for mcp__lumino__prometheus_query)
OPENSHIFT_PROMETHEUS_ENDPOINTS = {
    # Add known cluster endpoints here as fallback
    # Format: "cluster-name": {"url": "https://prometheus-endpoint-url"}
}


class PrometheusEndpointCache:
    """Cache for discovered Prometheus/Thanos endpoints with TTL."""

    def __init__(self, ttl_seconds: int = 300):  # 5 minute default cache
        self._cache: Dict[Any, tuple] = {}  # cache_key -> (endpoint, endpoint_type, timestamp)
        self._ttl = ttl_seconds

    def get(self, cache_key: Any = "default") -> Optional[tuple]:
        """Get cached endpoint if valid. Returns (url, endpoint_type) or None."""
        if cache_key in self._cache:
            endpoint, endpoint_type, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self._ttl:
                logger.debug(f"Cache hit for {endpoint_type} endpoint: {endpoint}")
                return (endpoint, endpoint_type)
            else:
                del self._cache[cache_key]
        return None

    def set(self, endpoint: str, cache_key: Any = "default", endpoint_type: str = "prometheus") -> None:
        """Cache endpoint with its type."""
        self._cache[cache_key] = (endpoint, endpoint_type, time.time())
        logger.debug(f"Cached {endpoint_type} endpoint: {endpoint}")

    def invalidate(self, cache_key: Any = "default") -> None:
        """Invalidate cache entry."""
        if cache_key in self._cache:
            del self._cache[cache_key]


# Global cache instance for Prometheus endpoints
_prometheus_endpoint_cache = PrometheusEndpointCache()

# Sentinel that distinguishes "caller did not supply a token" from explicit None.
# _execute_prometheus_query_internal uses this to decide between:
#   _BEARER_SENTINEL  → consult the full default fallback chain (_get_k8s_bearer_token)
#   None (explicit)   → return token_unavailable error (named-instance cert-auth)
#   str               → use the provided token directly, never touch the default chain
_BEARER_SENTINEL = object()


def _extract_kubeconfig_token(path: str, context: str) -> Optional[str]:
    """Extract the bearer token for *context* from a kubeconfig file at *path*.

    Returns the token string if found and non-empty, None if the context uses
    cert-auth or the token field is absent.  Never raises — all exceptions are
    logged at DEBUG and None is returned.

    Args:
        path:    Absolute path to the kubeconfig YAML file.
        context: Name of the context whose user's token to read.
    """
    try:
        import yaml
        with open(path, "r") as fh:
            kc = yaml.safe_load(fh)
        if not isinstance(kc, dict):
            return None
        contexts = {
            c["name"]: (c.get("context") or {})
            for c in (kc.get("contexts") or [])
            if isinstance(c, dict) and "name" in c
        }
        ctx = contexts.get(context)
        if not ctx:
            return None
        user_name = ctx.get("user")
        if not user_name:
            return None
        users = {
            u["name"]: (u.get("user") or {})
            for u in (kc.get("users") or [])
            if isinstance(u, dict) and "name" in u
        }
        user_entry = users.get(user_name, {})
        token = user_entry.get("token")
        if token and isinstance(token, str) and token.strip():
            return token.strip()
        return None
    except Exception as exc:
        logger.debug(
            "_extract_kubeconfig_token: could not read token from %s context %s: %s",
            path, context, exc,
        )
        return None


async def _get_k8s_bearer_token() -> Optional[str]:
    """
    Get a fresh bearer token for Prometheus authentication.

    Fallback chain:
    1. Run `oc whoami -t` for a fresh OpenShift token (handles token refresh)
    2. Read the token directly from the kubeconfig file (honors $KUBECONFIG, multi-path)
    3. Extract from in-memory Kubernetes client config (last resort)
    4. Read from ServiceAccount token file (in-cluster)
    5. Environment variable (PROMETHEUS_TOKEN, OPENSHIFT_TOKEN, OC_TOKEN)
    """
    # Method 1: Get fresh token via `oc whoami -t` (most reliable for OpenShift)
    try:
        import subprocess
        result = subprocess.run(
            ["oc", "whoami", "-t"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            token = result.stdout.strip()
            logger.debug("Obtained fresh bearer token via 'oc whoami -t'")
            return token
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("oc CLI not available or timed out")
    except Exception as e:
        logger.debug(f"Could not get token via oc: {e}")

    # Method 2: Read the token directly from the kubeconfig file (honors $KUBECONFIG, multi-path).
    # Delegates to _extract_kubeconfig_token for the per-context token lookup.
    try:
        import yaml

        kubeconfig_env = os.environ.get("KUBECONFIG", "")
        if kubeconfig_env:
            kubeconfig_paths = [os.path.expanduser(p) for p in kubeconfig_env.split(os.pathsep)]
        else:
            kubeconfig_paths = [os.path.expanduser("~/.kube/config")]

        for kc_path in kubeconfig_paths:
            if not kc_path or not os.path.exists(kc_path):
                continue
            try:
                with open(kc_path, "r") as fh:
                    kc = yaml.safe_load(fh)
                if not isinstance(kc, dict):
                    continue
                current_context = kc.get("current-context")
                if not current_context:
                    continue
                token = _extract_kubeconfig_token(kc_path, current_context)
                if token:
                    logger.debug("Obtained bearer token from kubeconfig file: %s", kc_path)
                    return token
            except Exception as inner_e:
                logger.debug("Could not read token from kubeconfig %s: %s", kc_path, inner_e)
    except Exception as e:
        logger.debug(f"Could not read token from kubeconfig file: {e}")

    # Method 3: Extract from in-memory Kubernetes client config (may be stale)
    try:
        from kubernetes.client import Configuration

        k8s_config = Configuration.get_default_copy()

        if k8s_config.api_key and k8s_config.api_key.get('authorization'):
            auth_header = k8s_config.api_key['authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                logger.debug("Using bearer token from in-memory k8s client config (may be stale)")
                return token

    except Exception as e:
        logger.debug(f"Could not extract token from k8s client config: {e}")

    # Method 4: Read from ServiceAccount token file (in-cluster scenario)
    SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    try:
        if os.path.exists(SA_TOKEN_PATH):
            with open(SA_TOKEN_PATH, 'r') as f:
                token = f.read().strip()
                if token:
                    logger.info("Successfully obtained token from ServiceAccount token file")
                    return token
    except Exception as e:
        logger.debug(f"Could not read ServiceAccount token: {e}")

    # Method 5: Environment variable fallback
    token = os.getenv("PROMETHEUS_TOKEN") or os.getenv("OPENSHIFT_TOKEN") or os.getenv("OC_TOKEN")
    if token:
        logger.info("Using token from environment variable")
        return token

    logger.error("Could not obtain authentication token from any source")
    return None


async def _discover_prometheus_via_routes(custom_api) -> Optional[str]:
    """
    Discover Prometheus endpoint via OpenShift Routes.

    Looks for routes in openshift-monitoring namespace:
    - prometheus-k8s (primary Prometheus)
    - thanos-querier (Thanos frontend)
    """
    if not custom_api:
        logger.debug("CustomObjectsApi not available for route discovery")
        return None

    try:
        _ro = ReadOnlyK8sClient.wrap(custom_api)
        # Query routes in openshift-monitoring namespace
        routes = await k8s_call(_ro.list_namespaced_custom_object,
            group="route.openshift.io",
            version="v1",
            namespace="openshift-monitoring",
            plural="routes"
        )

        # Priority order: prefer Thanos (unified, deduplicated view) over direct Prometheus
        preferred_routes = ["thanos-querier", "prometheus-k8s"]

        route_items = routes.get("items", [])
        route_map = {r.get("metadata", {}).get("name"): r for r in route_items}

        for route_name in preferred_routes:
            if route_name in route_map:
                route = route_map[route_name]
                spec = route.get("spec", {})
                host = spec.get("host")

                if host:
                    # Determine protocol (check TLS termination)
                    tls = spec.get("tls")
                    protocol = "https" if tls else "http"
                    endpoint = f"{protocol}://{host}"

                    logger.info(f"Discovered Prometheus via OpenShift route '{route_name}': {endpoint}")
                    return endpoint

        # Fallback: any route with 'prometheus' in the name
        for route in route_items:
            route_name = route.get("metadata", {}).get("name", "")
            if "prometheus" in route_name.lower():
                host = route.get("spec", {}).get("host")
                if host:
                    tls = route.get("spec", {}).get("tls")
                    protocol = "https" if tls else "http"
                    endpoint = f"{protocol}://{host}"
                    logger.info(f"Discovered Prometheus via route '{route_name}': {endpoint}")
                    return endpoint

    except client.rest.ApiException as e:
        if e.status == 404:
            logger.debug("OpenShift routes API not available (not an OpenShift cluster)")
        else:
            logger.warning(f"Error querying OpenShift routes: {e}")
    except Exception as e:
        logger.warning(f"Error discovering Prometheus via routes: {e}")

    return None


# Cluster-wide searches (label selectors, Prometheus CRs) accept only these
# namespaces: anyone who can create a Service or CR in their own namespace
# must not be able to choose the metrics endpoint. Names outside openshift-*
# can be self-provisioned on OpenShift, so every match is also checked with
# namespace_is_trusted. Prometheus in another namespace: set PROMETHEUS_URL /
# THANOS_URL.
TRUSTED_MONITORING_NAMESPACES = frozenset({
    "openshift-monitoring",
    "openshift-user-workload-monitoring",
    "monitoring",
    "prometheus",
    "thanos",
    "kube-prometheus",
    "observability",
})


async def _first_trusted_service(services, core_api):
    """First service in a trusted monitoring namespace, or None."""
    for service in services.items:
        namespace = service.metadata.namespace
        if namespace in TRUSTED_MONITORING_NAMESPACES:
            if await k8s_offload(namespace_is_trusted, core_api, namespace):
                return service
            continue
        logger.warning(
            f"Ignoring Prometheus/Thanos service {service.metadata.namespace}/{service.metadata.name}: "
            "namespace is not a trusted monitoring namespace (set PROMETHEUS_URL or THANOS_URL to use it)"
        )
    return None


async def _discover_prometheus_via_operator_crd(custom_api, core_api) -> Optional[str]:
    """
    Discover Prometheus via Prometheus Operator CRDs.

    Looks for:
    - Prometheus custom resources (monitoring.coreos.com/v1)
    - Associated services
    """
    if not custom_api or not core_api:
        logger.debug("API clients not available for Prometheus Operator CRD discovery")
        return None

    try:
        _ro = ReadOnlyK8sClient.wrap(custom_api)
        _ro_core = ReadOnlyK8sClient.wrap(core_api)
        # List all Prometheus custom resources cluster-wide
        prometheus_resources = await k8s_call(_ro.list_cluster_custom_object,
            group="monitoring.coreos.com",
            version="v1",
            plural="prometheuses"
        )

        for prom in prometheus_resources.get("items", []):
            metadata = prom.get("metadata", {})
            name = metadata.get("name")
            namespace = metadata.get("namespace")

            if not name or not namespace:
                continue
            if namespace not in TRUSTED_MONITORING_NAMESPACES or not await k8s_offload(namespace_is_trusted, core_api, namespace):
                logger.warning(
                    f"Ignoring Prometheus CR {namespace}/{name}: namespace is not a trusted "
                    "monitoring namespace (set PROMETHEUS_URL to use it)"
                )
                continue

            # The Prometheus Operator creates a service with pattern: prometheus-<name>
            service_name = f"prometheus-{name}"

            try:
                service = await k8s_call(_ro_core.read_namespaced_service,
                    name=service_name,
                    namespace=namespace
                )

                # Get service port (default Prometheus port is 9090)
                ports = service.spec.ports or []
                port = 9090
                for p in ports:
                    if p.name in ["web", "http", "prometheus"] or p.port == 9090:
                        port = p.port
                        break

                # Construct in-cluster service URL
                endpoint = f"http://{service_name}.{namespace}.svc.cluster.local:{port}"
                logger.info(f"Discovered Prometheus via Operator CRD: {endpoint}")
                return endpoint

            except client.rest.ApiException as e:
                logger.debug(f"Could not find service for Prometheus '{name}': {e}")
                continue

    except client.rest.ApiException as e:
        if e.status == 404:
            logger.debug("Prometheus Operator CRDs not available")
        else:
            logger.warning(f"Error querying Prometheus CRDs: {e}")
    except Exception as e:
        logger.warning(f"Error discovering Prometheus via Operator CRD: {e}")

    return None


async def _discover_prometheus_via_services(core_api) -> Optional[str]:
    """
    Discover Prometheus by searching for services with prometheus-related labels/names.

    Search criteria:
    - Services with 'prometheus' in name
    - Services with label 'app=prometheus' or 'app.kubernetes.io/name=prometheus'
    - Services exposing port 9090
    """
    if not core_api:
        logger.debug("CoreV1Api not available for service discovery")
        return None

    try:
        _ro = ReadOnlyK8sClient.wrap(core_api)
        # Search common monitoring namespaces first
        monitoring_namespaces = [
            "openshift-monitoring",
            "monitoring",
            "prometheus",
            "kube-prometheus",
            "observability"
        ]

        # First, try specific namespaces
        for namespace in monitoring_namespaces:
            try:
                services = await k8s_call(_ro.list_namespaced_service, namespace=namespace)
                if not services.items or not await k8s_offload(namespace_is_trusted, core_api, namespace):
                    continue

                # Prioritize actual Prometheus server services (not alertmanager, pushgateway, etc.)
                # Priority: prometheus-server > prometheus-k8s > prometheus > any with prometheus in name
                priority_names = ["prometheus-server", "prometheus-k8s", "prometheus"]
                excluded_suffixes = ["-alertmanager", "-pushgateway", "-node-exporter",
                                   "-kube-state-metrics", "-headless", "-operated"]

                # First pass: look for priority names
                for priority_name in priority_names:
                    for service in services.items:
                        name = service.metadata.name
                        if name == priority_name:
                            ports = service.spec.ports or []
                            port = 9090
                            for p in ports:
                                # Accept common Prometheus ports: 9090, 80, 443
                                if p.port in [9090, 80, 443] or (p.name and p.name in ["web", "http", "https"]):
                                    port = p.port
                                    break
                            endpoint = f"http://{name}.{namespace}.svc.cluster.local:{port}"
                            logger.info(f"Discovered Prometheus service (priority match): {endpoint}")
                            return endpoint

                # Second pass: look for services with 'prometheus' but exclude non-server services
                for service in services.items:
                    name = service.metadata.name
                    if "prometheus" in name.lower():
                        # Skip non-server services
                        if any(name.lower().endswith(suffix) for suffix in excluded_suffixes):
                            continue

                        ports = service.spec.ports or []
                        port = 9090
                        for p in ports:
                            if p.port in [9090, 80, 443] or (p.name and p.name in ["web", "http", "https"]):
                                port = p.port
                                break

                        endpoint = f"http://{name}.{namespace}.svc.cluster.local:{port}"
                        logger.info(f"Discovered Prometheus service: {endpoint}")
                        return endpoint

            except client.rest.ApiException as e:
                if e.status != 404:
                    logger.debug(f"Namespace '{namespace}' not accessible: {e}")
                continue

        # Try cluster-wide search with label selectors (trusted namespaces only)
        label_selectors = [
            "app=prometheus",
            "app.kubernetes.io/name=prometheus",
            "app.kubernetes.io/component=prometheus"
        ]

        for label_selector in label_selectors:
            try:
                services = await k8s_call(_ro.list_service_for_all_namespaces,
                    label_selector=label_selector
                )

                service = await _first_trusted_service(services, core_api)
                if service:
                    name = service.metadata.name
                    namespace = service.metadata.namespace

                    ports = service.spec.ports or []
                    port = 9090
                    for p in ports:
                        if p.port == 9090 or (p.name and p.name in ["web", "http"]):
                            port = p.port
                            break

                    endpoint = f"http://{name}.{namespace}.svc.cluster.local:{port}"
                    logger.info(f"Discovered Prometheus via label selector '{label_selector}': {endpoint}")
                    return endpoint

            except client.rest.ApiException as e:
                logger.debug(f"Error with label selector '{label_selector}': {e}")
                continue

    except Exception as e:
        logger.warning(f"Error discovering Prometheus via services: {e}")

    return None


async def _discover_thanos_via_services(core_api) -> Optional[str]:
    """
    Discover Thanos Query endpoint by searching for Thanos services.

    Thanos Query implements the Prometheus HTTP API, so once discovered
    it can be used interchangeably with Prometheus for PromQL queries.

    Search criteria:
    - Services with 'thanos-query' or 'thanos-querier' in name
    - Services with Thanos-related labels
    - Common Thanos Query ports: 9090, 10902 (HTTP), 9091
    """
    if not core_api:
        logger.debug("CoreV1Api not available for Thanos service discovery")
        return None

    try:
        _ro = ReadOnlyK8sClient.wrap(core_api)
        monitoring_namespaces = [
            "openshift-monitoring",
            "monitoring",
            "thanos",
            "observability",
            "kube-prometheus",
        ]

        priority_names = ["thanos-query-frontend", "thanos-querier", "thanos-query"]
        thanos_http_ports = [9090, 9091, 80, 443]

        # First pass: check known monitoring namespaces for priority service names
        for namespace in monitoring_namespaces:
            try:
                services = await k8s_call(_ro.list_namespaced_service, namespace=namespace)
                if not services.items or not await k8s_offload(namespace_is_trusted, core_api, namespace):
                    continue

                for priority_name in priority_names:
                    for service in services.items:
                        if service.metadata.name == priority_name:
                            ports = service.spec.ports or []
                            port = 9090
                            for p in ports:
                                if p.port in thanos_http_ports or (p.name and p.name in ["http", "web", "https"]):
                                    port = p.port
                                    break
                            endpoint = f"http://{priority_name}.{namespace}.svc.cluster.local:{port}"
                            logger.info(f"Discovered Thanos Query service (priority match): {endpoint}")
                            return endpoint

                # Second pass: any service with 'thanos' and 'query' in the name
                for service in services.items:
                    name = service.metadata.name.lower()
                    if "thanos" in name and ("query" in name or "querier" in name):
                        ports = service.spec.ports or []
                        port = 9090
                        for p in ports:
                            if p.port in thanos_http_ports or (p.name and p.name in ["http", "web", "https"]):
                                port = p.port
                                break
                        endpoint = f"http://{service.metadata.name}.{namespace}.svc.cluster.local:{port}"
                        logger.info(f"Discovered Thanos Query service: {endpoint}")
                        return endpoint

            except client.rest.ApiException as e:
                if e.status != 404:
                    logger.debug(f"Namespace '{namespace}' not accessible for Thanos discovery: {e}")
                continue

        # Cluster-wide label-based search (trusted namespaces only)
        label_selectors = [
            "app.kubernetes.io/name=thanos-query",
            "app.kubernetes.io/component=query,app.kubernetes.io/name=thanos",
            "app=thanos-query",
            "app=thanos-querier",
        ]

        for label_selector in label_selectors:
            try:
                services = await k8s_call(_ro.list_service_for_all_namespaces,
                    label_selector=label_selector
                )
                service = await _first_trusted_service(services, core_api)
                if service:
                    name = service.metadata.name
                    namespace = service.metadata.namespace
                    ports = service.spec.ports or []
                    port = 9090
                    for p in ports:
                        if p.port in thanos_http_ports or (p.name and p.name in ["http", "web"]):
                            port = p.port
                            break
                    endpoint = f"http://{name}.{namespace}.svc.cluster.local:{port}"
                    logger.info(f"Discovered Thanos Query via label selector '{label_selector}': {endpoint}")
                    return endpoint

            except client.rest.ApiException as e:
                logger.debug(f"Error with Thanos label selector '{label_selector}': {e}")
                continue

    except Exception as e:
        logger.warning(f"Error discovering Thanos Query via services: {e}")

    return None


async def _discover_prometheus_endpoint(cluster_override: Optional[str] = None, *, custom_api=None, core_api=None, source: str = "") -> tuple:
    """
    Discover Prometheus or Thanos Query endpoint using multiple strategies.

    Returns a (url, endpoint_type) tuple where endpoint_type is "thanos" or "prometheus".
    Thanos Query is preferred when available since it provides a unified, deduplicated view.

    Priority order:
    0. THANOS_URL env var (explicit Thanos override — default instance only)
    1. PROMETHEUS_URL env var (explicit Prometheus override — default instance only)
    2. Predefined cluster endpoints
    3. Cache (keyed by (source, cluster_override) for per-instance isolation)
    4. Auto-discovery (Thanos first, then Prometheus)
    5. Predefined fallback endpoints

    Args:
        cluster_override: Optional cluster name for predefined endpoint lookup
        custom_api: Optional CustomObjectsApi client for discovery
        core_api: Optional CoreV1Api client for discovery
        source: Source instance name; '' means the default instance.
                Named instances skip env overrides to prevent cross-cluster bleed.

    Returns:
        (endpoint_url, endpoint_type) tuple, or (None, None) if not found
    """
    # 0-1. Env overrides apply ONLY to the default instance.
    # Named instances always use discovery so the wrong cluster's endpoint is never used.
    if not source:
        # 0. Check for THANOS_URL environment variable (highest priority)
        env_thanos_url = os.getenv("THANOS_URL")
        if env_thanos_url:
            logger.info(f"Using Thanos endpoint from THANOS_URL environment variable: {env_thanos_url}")
            return (env_thanos_url, "thanos")

        # 1. Check for PROMETHEUS_URL environment variable
        env_prometheus_url = os.getenv("PROMETHEUS_URL")
        if env_prometheus_url:
            logger.info(f"Using Prometheus endpoint from PROMETHEUS_URL environment variable: {env_prometheus_url}")
            return (env_prometheus_url, "prometheus")

    # 2. Check for cluster override in predefined endpoints
    if cluster_override and cluster_override in OPENSHIFT_PROMETHEUS_ENDPOINTS:
        endpoint = OPENSHIFT_PROMETHEUS_ENDPOINTS[cluster_override].get("url")
        if endpoint:
            endpoint_type = OPENSHIFT_PROMETHEUS_ENDPOINTS[cluster_override].get("type", "prometheus")
            logger.info(f"Using predefined {endpoint_type} endpoint for cluster '{cluster_override}': {endpoint}")
            return (endpoint, endpoint_type)

    # 3. Cache: keyed by (source, cluster_override) for per-instance isolation.
    # Pre-Task-4 code used a plain string key; the tuple ensures source A and source B
    # never share a cache slot even when cluster_override is the same.
    cache_key = (source or "default", cluster_override or "")
    cached = _prometheus_endpoint_cache.get(cache_key)
    if cached:
        logger.info(f"Using cached {cached[1]} endpoint: {cached[0]}")
        return cached

    # 4. Discovery chain - order depends on runtime environment
    # Thanos discovery comes first: if Thanos is deployed, it's the intended query interface.
    # Each entry: (method_name, discovery_func, endpoint_type)
    if _is_running_in_cluster():
        discovery_methods = [
            ("Thanos Query Services", lambda: _discover_thanos_via_services(core_api), "thanos"),
            ("Prometheus Services", lambda: _discover_prometheus_via_services(core_api), "prometheus"),
            ("Prometheus Operator CRD", lambda: _discover_prometheus_via_operator_crd(custom_api, core_api), "prometheus"),
            ("OpenShift Routes", lambda: _discover_prometheus_via_routes(custom_api), None),  # type detected from route name
        ]
    else:
        discovery_methods = [
            ("OpenShift Routes", lambda: _discover_prometheus_via_routes(custom_api), None),  # type detected from route name
            ("Thanos Query Services", lambda: _discover_thanos_via_services(core_api), "thanos"),
            ("Prometheus Operator CRD", lambda: _discover_prometheus_via_operator_crd(custom_api, core_api), "prometheus"),
            ("Prometheus Services", lambda: _discover_prometheus_via_services(core_api), "prometheus"),
        ]

    for method_name, discovery_func, method_type in discovery_methods:
        try:
            logger.debug(f"Attempting discovery via: {method_name}")
            endpoint = await discovery_func()
            if endpoint:
                # For OpenShift Routes, detect type from the discovered endpoint/route name
                if method_type is None:
                    endpoint_type = "thanos" if "thanos" in endpoint.lower() else "prometheus"
                else:
                    endpoint_type = method_type
                _prometheus_endpoint_cache.set(endpoint, cache_key, endpoint_type=endpoint_type)
                return (endpoint, endpoint_type)
        except Exception as e:
            logger.warning(f"Discovery method '{method_name}' failed: {e}")
            continue

    # 5. Fallback to predefined endpoints (try all except 'local')
    for cluster_name, config in OPENSHIFT_PROMETHEUS_ENDPOINTS.items():
        if cluster_name != "local":
            endpoint = config.get("url")
            if endpoint:
                endpoint_type = config.get("type", "prometheus")
                logger.info(f"Using fallback {endpoint_type} endpoint: {endpoint}")
                _prometheus_endpoint_cache.set(endpoint, cache_key, endpoint_type=endpoint_type)
                return (endpoint, endpoint_type)

    logger.error("Could not discover Prometheus/Thanos endpoint via any method")
    return (None, None)


async def _execute_prometheus_query_internal(
    query: str,
    timeout: int = 30,
    *,
    custom_api=None,
    core_api=None,
    bearer_token=_BEARER_SENTINEL,
    source: str = "",
) -> Dict[str, Any]:
    """
    Internal helper to execute Prometheus/Thanos queries from within other tools.

    Args:
        query: PromQL query string
        timeout: Query timeout in seconds
        custom_api: Optional CustomObjectsApi client for endpoint discovery
        core_api: Optional CoreV1Api client for endpoint discovery
        bearer_token: Token selection control:
            _BEARER_SENTINEL (default) — run the full default fallback chain
                (_get_k8s_bearer_token: oc → kubeconfig → in-memory → SA → env).
            None (explicit) — return a structured token_unavailable error without
                making an HTTP call.  Used by named-instance callers that have no
                stored token (cert-auth or unregistered instance).
            str — use this value directly as the Bearer token; the default chain
                is never consulted.
        source: Source instance name; '' means the default instance.
                Passed through to _discover_prometheus_endpoint for cache isolation
                and env-override gating.

    Returns:
        Dict with 'success', 'data' (list of results), 'endpoint_type', and 'error' if failed
    """
    try:
        prometheus_url, endpoint_type = await _discover_prometheus_endpoint(
            custom_api=custom_api, core_api=core_api, source=source
        )
        if not prometheus_url:
            return {"success": False, "data": [], "error": "Could not discover Prometheus/Thanos endpoint"}

        # Resolve authentication token according to bearer_token parameter.
        # _BEARER_SENTINEL  → full default fallback chain (oc → kubeconfig → ...).
        # None (explicit)   → token_unavailable: caller asserts no token is available.
        # str               → use directly; never touch the default chain.
        if bearer_token is _BEARER_SENTINEL:
            auth_token = await _get_k8s_bearer_token()
        elif bearer_token is None:
            return {"success": False, "data": [], "error": "token_unavailable"}
        else:
            auth_token = bearer_token

        api_path = "/api/v1/query"
        params = {"query": query, "timeout": f"{timeout}s"}

        # Add Thanos-specific parameters for deduplicated results
        if endpoint_type == "thanos":
            params["dedup"] = "true"

        query_url = f"{prometheus_url}{api_path}"

        headers = {
            "Accept": "application/json",
            "User-Agent": "Pharos/1.0"
        }

        # Never send the token in clear text: a discovered http:// service may
        # be one any tenant can create.
        token_withheld = bool(auth_token) and not bearer_token_allowed(query_url)
        if token_withheld:
            logger.warning(f"Not sending bearer token over plain http to {query_url}")
        elif auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        ssl_context = client_ssl_context(host=prometheus_url)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout + 10)) as session:
            async with session.get(
                query_url, params=params, headers=headers, ssl=ssl_context, allow_redirects=False
            ) as response:
                if response.status == 200:
                    response_data = await response.json()
                    result_data = response_data.get("data", {})
                    raw_results = result_data.get("result", [])
                    return {"success": True, "data": raw_results, "endpoint_type": endpoint_type, "error": None}
                else:
                    error_text = await response.text()
                    logger.warning(f"Prometheus query failed with status {response.status}: {error_text}")
                    error = f"HTTP {response.status}: {error_text}"
                    if token_withheld and response.status in (401, 403):
                        error = f"{error}. {PLAIN_HTTP_TOKEN_HINT}"
                    return {"success": False, "data": [], "endpoint_type": endpoint_type, "error": error}

    except aiohttp.ClientSSLError as e:
        logger.error(f"TLS error executing internal Prometheus query: {e}")
        return {"success": False, "data": [], "error": f"{e}. {TLS_HINT}"}
    except Exception as e:
        logger.error(f"Error executing internal Prometheus query: {e}")
        return {"success": False, "data": [], "error": str(e)}


async def _process_prometheus_results(
    response_data: Dict[str, Any],
    format_type: str,
    namespace_filter: Optional[str],
    limit: Optional[int],
    original_query: str,
    query_type: str
) -> Dict[str, Any]:
    """Process and format Prometheus query results."""
    try:
        result_data = response_data.get("data", {})
        result_type = result_data.get("resultType", "")
        raw_results = result_data.get("result", [])

        # Apply namespace filtering if specified
        if namespace_filter:
            try:
                namespace_pattern = _safe_compile_namespace_filter(namespace_filter)
                filtered_results = []

                for result in raw_results:
                    metric = result.get("metric", {})
                    namespace = metric.get("namespace", "")
                    if namespace and namespace_pattern.search(namespace):
                        filtered_results.append(result)

                raw_results = filtered_results
                logger.info(f"Applied namespace filter '{namespace_filter}', {len(raw_results)} results remain")

            except (re.error, ValueError) as e:
                logger.warning(f"Invalid namespace filter regex '{namespace_filter}': {e}")

        # Apply limit if specified
        if limit and len(raw_results) > limit:
            raw_results = raw_results[:limit]
            logger.info(f"Limited results to {limit} items")

        # Apply safety limit to prevent excessive response sizes (max 500 series)
        MAX_SERIES_LIMIT = 500
        if len(raw_results) > MAX_SERIES_LIMIT:
            logger.warning(f"Truncating {len(raw_results)} series to {MAX_SERIES_LIMIT} to prevent excessive response size")
            raw_results = raw_results[:MAX_SERIES_LIMIT]

        # Format results based on requested format
        if format_type == "table":
            formatted_data = _format_as_table(raw_results, result_type)
        elif format_type == "csv":
            formatted_data = _format_as_csv(raw_results, result_type)
        else:  # json format (default)
            formatted_data = _format_as_json(raw_results, result_type)

        # Generate summary and analysis
        summary = _generate_result_summary(raw_results, result_type, original_query)
        suggestions = _generate_related_query_suggestions(original_query, raw_results)

        return {
            "result_count": len(raw_results),
            "result_type": result_type,
            "data": formatted_data,
            "summary": summary,
            "suggestions": suggestions,
            "errors": [],
            "metadata": {
                "namespace_filter": namespace_filter,
                "limit": limit,
                "format": format_type,
                "query_type": query_type
            }
        }

    except Exception as e:
        logger.error(f"Error processing Prometheus results: {e}")
        return {
            "result_count": 0,
            "result_type": "unknown",
            "data": [],
            "summary": "Error processing results",
            "suggestions": ["Check query syntax", "Try simpler query"],
            "errors": [str(e)]
        }


def _format_as_table(results: List[Dict], result_type: str) -> str:
    """Format results as a human-readable table."""
    if not results:
        return "No data returned"

    try:
        if result_type == "vector":
            # Instant query results
            headers = ["Metric"] + list(results[0].get("metric", {}).keys()) + ["Value"]
            rows = []

            for result in results:
                metric = result.get("metric", {})
                value = result.get("value", ["", ""])[1] if result.get("value") else "N/A"

                metric_name = metric.get("__name__", "")
                row = [metric_name] + [metric.get(key, "") for key in headers[1:-1]] + [value]
                rows.append(row)

        elif result_type == "matrix":
            # Range query results
            headers = ["Metric", "Namespace", "Values (timestamp:value)"]
            rows = []

            for result in results:
                metric = result.get("metric", {})
                values = result.get("values", [])

                metric_name = metric.get("__name__", "")
                namespace = metric.get("namespace", "")

                # Format values as timestamp:value pairs (limit to first 5 for readability)
                value_pairs = [f"{ts}:{val}" for ts, val in values[:5]]
                if len(values) > 5:
                    value_pairs.append(f"... ({len(values) - 5} more)")

                rows.append([metric_name, namespace, ", ".join(value_pairs)])

        else:
            return f"Unsupported result type for table format: {result_type}"

        if not rows:
            return "No data to display"

        # Calculate column widths
        col_widths = [max(len(str(header)), max(len(str(row[i])) for row in rows)) for i, header in enumerate(headers)]

        # Build table
        table_lines = []

        # Header
        header_line = " | ".join(header.ljust(col_widths[i]) for i, header in enumerate(headers))
        table_lines.append(header_line)
        table_lines.append("-" * len(header_line))

        # Rows
        for row in rows:
            row_line = " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(headers)))
            table_lines.append(row_line)

        return "\n".join(table_lines)

    except Exception as e:
        logger.error(f"Error formatting table: {e}")
        return f"Error formatting table: {e}"


def _format_as_csv(results: List[Dict], result_type: str) -> str:
    """Format results as CSV."""
    if not results:
        return "No data returned"

    try:
        import csv
        import io

        output = io.StringIO()

        if result_type == "vector":
            # Instant query results
            fieldnames = ["metric_name"] + list(results[0].get("metric", {}).keys()) + ["value", "timestamp"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                metric = result.get("metric", {})
                value_data = result.get("value", ["", ""])

                row = {
                    "metric_name": metric.get("__name__", ""),
                    "value": value_data[1] if len(value_data) > 1 else "",
                    "timestamp": value_data[0] if len(value_data) > 0 else ""
                }
                row.update({k: v for k, v in metric.items() if k != "__name__"})
                writer.writerow(row)

        elif result_type == "matrix":
            # Range query results - flatten time series
            fieldnames = ["metric_name", "namespace", "timestamp", "value"]
            if results:
                additional_labels = set()
                for result in results:
                    metric = result.get("metric", {})
                    additional_labels.update(k for k in metric.keys() if k not in ["__name__", "namespace"])
                fieldnames.extend(sorted(additional_labels))

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                metric = result.get("metric", {})
                values = result.get("values", [])

                base_row = {
                    "metric_name": metric.get("__name__", ""),
                    "namespace": metric.get("namespace", "")
                }
                base_row.update({k: v for k, v in metric.items() if k not in ["__name__", "namespace"]})

                for timestamp, value in values:
                    row = base_row.copy()
                    row.update({"timestamp": timestamp, "value": value})
                    writer.writerow(row)

        return output.getvalue()

    except Exception as e:
        logger.error(f"Error formatting CSV: {e}")
        return f"Error formatting CSV: {e}"


def _format_as_json(results: List[Dict], result_type: str) -> List[Dict]:
    """Format results as structured JSON."""
    try:
        formatted_results = []

        for result in results:
            metric = result.get("metric", {})

            if result_type == "vector":
                # Instant query
                value_data = result.get("value", [])
                formatted_result = {
                    "metric": metric,
                    "value": value_data[1] if len(value_data) > 1 else None,
                    "timestamp": value_data[0] if len(value_data) > 0 else None,
                    "formatted_value": _format_metric_value(metric.get("__name__", ""), value_data[1] if len(value_data) > 1 else None)
                }

            elif result_type == "matrix":
                # Range query - downsample to avoid excessive response size
                values = result.get("values", [])
                total_count = len(values)

                # Calculate statistical summary instead of returning all raw data
                numeric_values = []
                for v in values:
                    try:
                        numeric_values.append(float(v[1]))
                    except (ValueError, TypeError, IndexError):
                        pass

                stats = {}
                if numeric_values:
                    sorted_vals = sorted(numeric_values)
                    stats = {
                        "min": round(min(numeric_values), 4),
                        "max": round(max(numeric_values), 4),
                        "avg": round(sum(numeric_values) / len(numeric_values), 4),
                        "latest": round(numeric_values[-1], 4),
                        "first": round(numeric_values[0], 4),
                        "p50": round(sorted_vals[len(sorted_vals) // 2], 4),
                        "p95": round(sorted_vals[int(len(sorted_vals) * 0.95)], 4) if len(sorted_vals) > 1 else round(sorted_vals[0], 4),
                    }

                # Downsample values to max 50 points for trend visualization
                MAX_DATAPOINTS = 50
                sampled_values = []
                if total_count > MAX_DATAPOINTS:
                    step = total_count / MAX_DATAPOINTS
                    for i in range(MAX_DATAPOINTS):
                        idx = int(i * step)
                        sampled_values.append(values[idx])
                else:
                    sampled_values = values

                formatted_result = {
                    "metric": metric,
                    "statistics": stats,
                    "values": sampled_values,  # Keep as "values" for backward compatibility
                    "value_count": total_count,
                    "sampled_count": len(sampled_values),
                    "downsampled": total_count > MAX_DATAPOINTS,
                    "time_range": {
                        "start": values[0][0] if values else None,
                        "end": values[-1][0] if values else None
                    }
                }

            else:
                # Fallback
                formatted_result = result

            formatted_results.append(formatted_result)

        return formatted_results

    except Exception as e:
        logger.error(f"Error formatting JSON: {e}")
        return [{"error": f"Error formatting results: {e}"}]


def _format_metric_value(metric_name: str, value: Optional[str]) -> str:
    """Format metric value with appropriate units."""
    if value is None:
        return "N/A"

    try:
        numeric_value = float(value)

        # Format based on metric name patterns
        if "cpu" in metric_name.lower():
            if "seconds" in metric_name.lower():
                return f"{numeric_value:.3f} CPU seconds"
            else:
                return f"{numeric_value:.3f} CPU cores"
        elif "memory" in metric_name.lower() or "bytes" in metric_name.lower():
            # Convert bytes to human readable
            if numeric_value >= 1024**3:
                return f"{numeric_value / (1024**3):.2f} GB"
            elif numeric_value >= 1024**2:
                return f"{numeric_value / (1024**2):.2f} MB"
            elif numeric_value >= 1024:
                return f"{numeric_value / 1024:.2f} KB"
            else:
                return f"{numeric_value:.0f} bytes"
        elif "percentage" in metric_name.lower() or "percent" in metric_name.lower():
            return f"{numeric_value:.1f}%"
        else:
            return f"{numeric_value:.3f}"

    except (ValueError, TypeError):
        return str(value)


def _generate_result_summary(results: List[Dict], result_type: str, query: str) -> str:
    """Generate human-readable summary of query results."""
    if not results:
        return f"No data returned for query: {query}"

    try:
        summary_parts = []

        # Basic count
        summary_parts.append(f"Found {len(results)} metric series")

        # Analyze namespaces
        namespaces = set()
        for result in results:
            metric = result.get("metric", {})
            if "namespace" in metric:
                namespaces.add(metric["namespace"])

        if namespaces:
            summary_parts.append(f"across {len(namespaces)} namespaces: {', '.join(sorted(list(namespaces))[:5])}")
            if len(namespaces) > 5:
                summary_parts[-1] += f" and {len(namespaces) - 5} more"

        # Analyze metric types
        metric_names = set()
        for result in results:
            metric = result.get("metric", {})
            if "__name__" in metric:
                metric_names.add(metric["__name__"])

        if metric_names:
            summary_parts.append(f"Metric types: {', '.join(sorted(list(metric_names))[:3])}")
            if len(metric_names) > 3:
                summary_parts[-1] += f" and {len(metric_names) - 3} more"

        return ". ".join(summary_parts) + "."

    except Exception as e:
        logger.error(f"Error generating summary: {e}")
        return f"Query returned {len(results)} results"


def _generate_query_suggestions(query: str, error_message: str) -> List[str]:
    """Generate helpful suggestions based on query and error."""
    suggestions = []

    # Common PromQL syntax errors
    if "parse error" in error_message.lower():
        suggestions.extend([
            "Check PromQL syntax - ensure proper use of operators and functions",
            "Verify metric names and label selectors are correctly formatted",
            "Example: up{job=\"node-exporter\"} or rate(http_requests_total[5m])"
        ])

    if "unknown metric" in error_message.lower() or "not found" in error_message.lower():
        suggestions.extend([
            "Check if the metric name is spelled correctly",
            "Try querying available metrics with: {__name__=~\".*\"}",
            "Verify the metric is actually being scraped by Prometheus"
        ])

    if "timeout" in error_message.lower():
        suggestions.extend([
            "Try a shorter time range for range queries",
            "Use more specific label selectors to reduce data volume",
            "Consider using recording rules for complex queries"
        ])

    # Query-specific suggestions
    if "rate(" in query and "[" not in query:
        suggestions.append("rate() function requires a time range: rate(metric[5m])")

    if "{" in query and "}" in query:
        if "=~" in query:
            suggestions.append("Ensure regex patterns are valid and properly escaped")

    # Default suggestions if no specific ones
    if not suggestions:
        suggestions.extend([
            "Check Prometheus documentation for correct PromQL syntax",
            "Try a simpler query first to test connectivity",
            "Verify you have access to the metrics you're querying"
        ])

    return suggestions


def _generate_related_query_suggestions(original_query: str, results: List[Dict]) -> List[str]:
    """Generate suggestions for related queries based on results."""
    suggestions = []

    try:
        if not results:
            suggestions.extend([
                "Try expanding the time range if using a range query",
                "Check if the metric exists: {__name__=~\".*metric_name.*\"}",
                "List all available metrics: {__name__=~\".*\"}"
            ])
            return suggestions

        # Extract metric names from results
        metric_names = set()
        namespaces = set()

        for result in results:
            metric = result.get("metric", {})
            if "__name__" in metric:
                metric_names.add(metric["__name__"])
            if "namespace" in metric:
                namespaces.add(metric["namespace"])

        # Suggest related queries
        if metric_names:
            example_metric = list(metric_names)[0]
            if "cpu" in example_metric:
                suggestions.append("Related memory usage: sum(container_memory_working_set_bytes) by (namespace)")
            elif "memory" in example_metric:
                suggestions.append("Related CPU usage: sum(rate(container_cpu_usage_seconds_total[5m])) by (namespace)")

            if "rate(" not in original_query and "_total" in example_metric:
                suggestions.append(f"Rate calculation: rate({example_metric}[5m])")

        if namespaces and len(namespaces) > 1:
            suggestions.append(f"Filter by specific namespace: {{namespace=\"{list(namespaces)[0]}\"}}")

        if "topk(" not in original_query:
            suggestions.append(f"Top 10 results: topk(10, {original_query})")

        # Time-based suggestions
        if "range" not in original_query:
            suggestions.append(f"Historical data: {original_query} over time range")

    except Exception as e:
        logger.error(f"Error generating related suggestions: {e}")

    return suggestions[:5]  # Limit to 5 suggestions
