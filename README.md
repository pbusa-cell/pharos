# Pharos MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-1.10%2B-green.svg)](https://modelcontextprotocol.io/)
[![PyPI](https://img.shields.io/pypi/v/pharos.svg)](https://pypi.org/project/pharos/)

<!-- mcp-name: io.github.geored/pharos -->

An open source MCP (Model Context Protocol) server empowering SREs with intelligent observability, predictive analytics, and AI-driven automation across Kubernetes, OpenShift, and Tekton environments.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [Profiles](#profiles)
- [ML Model Persistence](#ml-model-persistence)
- [KubeArchive Integration](#kubearchive-integration)
- [Prometheus/Thanos Integration](#prometheusthanos-integration)
- [Available Tools](#available-tools)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [MCP Client Integration](#mcp-client-integration)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Acknowledgments](#acknowledgments)

> **Compatibility note**: the internal `LUMINO_` env prefix, the `lumino-mcp` logger
> tree and the `~/.lumino/` data directory are retained for compatibility with existing
> deployments; they will be renamed in a future major release with a deprecation window.

## Overview

Pharos MCP Server transforms how Site Reliability Engineers (SREs) and DevOps teams interact with Kubernetes clusters. By exposing 49 specialized tools through the Model Context Protocol, it enables AI assistants to:

- **Monitor** cluster health, resources, and pipeline status in real-time
- **Analyze** logs, events, and anomalies using statistical and ML techniques
- **Troubleshoot** failed pipelines with automated root cause analysis
- **Predict** resource bottlenecks and potential issues before they occur
- **Simulate** configuration changes to assess impact before deployment

## Features

### Kubernetes & OpenShift Operations

- Namespace and pod management
- Resource querying with flexible output formats
- Label-based resource search across clusters
- OpenShift operator and MachineConfigPool status
- etcd log analysis

### Tekton Pipeline Intelligence

- Pipeline and task run monitoring across namespaces
- Detailed log retrieval with optional cleaning
- Failed pipeline root cause analysis
- Cross-cluster pipeline tracing
- CI/CD performance baselining

### Advanced Log Analysis

- Smart log summarization with configurable detail levels
- Streaming analysis for large log volumes
- Hybrid analysis combining multiple strategies
- Semantic search using NLP techniques
- Anomaly detection with severity classification

### Predictive & Proactive Monitoring

- Statistical anomaly detection using z-score analysis
- Predictive log analysis for early warning
- Resource bottleneck forecasting
- Certificate health monitoring with expiry alerts
- TLS certificate issue investigation

### Event Intelligence

- Smart event retrieval with multiple strategies
- Progressive event analysis (overview to deep-dive)
- Advanced analytics with ML pattern detection
- Log-event correlation

### Simulation & What-If Analysis

- Monte Carlo simulation for configuration changes
- Impact analysis before deployment
- Risk assessment with configurable tolerance
- Affected component identification

## Quick Start

Get started with LUMINO in under 2 minutes:

### For Claude Code CLI Users (Easiest)

Simply ask Claude Code to provision the Pharos MCP server for you by pasting this prompt:

```text
Provision the Pharos MCP server as a project-local MCP integration:

1. Clone the repository:
   git clone https://TBD-NEW-REMOTE
   cd pharos

2. Install Python dependencies using uv:
   uv sync

3. Create .mcp.json in the current project root (NOT inside pharos) with this configuration.
   IMPORTANT: Replace <ABSOLUTE_PATH_TO_PHAROS> with the actual absolute path to the cloned pharos directory:

   {
     "mcpServers": {
       "pharos": {
         "type": "stdio",
         "command": "<ABSOLUTE_PATH_TO_PHAROS>/.venv/bin/python",
         "args": ["<ABSOLUTE_PATH_TO_PHAROS>/main.py"],
         "env": {
           "PYTHONUNBUFFERED": "1"
         }
       }
     }
   }

4. After creating .mcp.json, inform the user to:
   - Exit Claude Code completely
   - Connect to their Kubernetes or OpenShift cluster (kubectl/oc login)
   - Restart Claude Code in this project directory
   - They will see a prompt to approve the Pharos MCP server
   - Once approved, Pharos tools will be available (check with /mcp command)
```

### For Other MCP Clients

Choose your preferred installation method:

- **MCPM**: pending re-publish under the new remote (see [MCP Client Integration](#mcp-client-integration))
- **Manual Setup**: See detailed [MCP Client Integration](#mcp-client-integration) instructions

### Verify Installation

Once installed, test with a simple query:

```text
"List all namespaces in my Kubernetes cluster"
```

## Prerequisites

### Required

- **Python 3.10 or higher** - Core runtime
- **MCP Client** - One of:
  - [Claude Desktop](https://claude.ai/download)
  - [Claude Code CLI](https://github.com/anthropics/claude-code)
  - [Gemini CLI](https://github.com/google/generative-ai-cli)
  - [Cursor IDE](https://cursor.sh/)

### For Kubernetes Features

- **Kubernetes/OpenShift Access** - Valid kubeconfig with read permissions
- **RBAC Permissions** - Ability to list pods, namespaces, and other resources

### Optional (Recommended)

- **[uv](https://docs.astral.sh/uv/)** - Faster dependency management than pip
- **[MCPM](https://TBD-NEW-REMOTE)** - Easiest installation experience
- **Prometheus** - For advanced metrics and forecasting features

## Installation

### Using uv (recommended)

```bash
# Clone the repository
git clone https://TBD-NEW-REMOTE
cd pharos

# Install dependencies
uv sync

# Run the server
uv run python main.py
```

### Using pip

```bash
# Clone the repository
git clone https://TBD-NEW-REMOTE
cd pharos

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Run the server
python main.py
```

## Usage

### Local Mode (stdio transport)

By default, the server runs in local mode using stdio transport, suitable for direct integration with MCP clients:

```bash
python main.py
```

### Kubernetes Mode (HTTP streaming transport)

When running inside Kubernetes, set the namespace environment variable to enable HTTP streaming:

```bash
export KUBERNETES_NAMESPACE=my-namespace
python main.py
```

The server automatically detects the environment and switches transport modes.

## Usage Examples

### 🔍 Intelligent Root Cause Analysis

Investigate and diagnose complex failures with automated analysis:

```text
"Generate a comprehensive RCA report for the failed pipeline run 'build-api-pr-456' in namespace ci-cd"
```

```text
"Analyze what caused pod crashes in namespace production over the last 6 hours and correlate with resource events"
```

```text
"Investigate the TLS certificate issues affecting services in namespace ingress-nginx"
```

### 🎯 Predictive Intelligence & Forecasting

Anticipate problems before they impact your systems:

```text
"Predict resource bottlenecks across all production namespaces for the next 48 hours"
```

```text
"Analyze historical pipeline performance and detect anomalies in build times for the last 30 days"
```

```text
"Check cluster certificate health and alert me about any certificates expiring in the next 60 days"
```

```text
"Use predictive log analysis to identify potential failures in namespace monitoring before they occur"
```

### 🧪 Simulation & What-If Analysis

Test changes safely before applying them to production:

```text
"Simulate the impact of increasing memory limits to 4Gi for all pods in namespace backend-services"
```

```text
"Run a what-if scenario for scaling deployments to 10 replicas and analyze resource consumption"
```

```text
"Simulate configuration changes for nginx ingress controller and assess risk to existing traffic"
```

### 🗺️ Topology & Dependency Mapping

Understand system architecture and component relationships:

```text
"Generate a live topology map of all services, deployments, and their dependencies in namespace microservices"
```

```text
"Map the complete dependency graph for the payment-service including all connected resources"
```

```text
"Show me the topology of components affected by the cert-manager service"
```

### 🔬 Advanced Investigation & Forensics

Deep-dive into complex issues with multi-faceted analysis:

```text
"Perform an adaptive namespace investigation for production - analyze logs, events, and resource patterns"
```

```text
"Create a detailed investigation report for resource constraints and bottlenecks in namespace data-processing"
```

```text
"Trace pipeline execution for commit SHA abc123def from source to deployment across all namespaces"
```

```text
"Search logs semantically for 'authentication failures related to expired tokens' across the last 24 hours"
```

### 📊 CI/CD Pipeline Intelligence

Optimize and troubleshoot your continuous delivery pipelines:

```text
"Establish performance baselines for all Tekton pipelines and flag runs deviating by more than 2 standard deviations"
```

```text
"Trace the complete pipeline flow for image 'api:v2.5.3' from build to production deployment"
```

```text
"Analyze failed pipeline runs in namespace tekton-pipelines and identify common failure patterns"
```

```text
"Compare current pipeline run times against 30-day baseline and highlight performance degradation"
```

### 🎨 Progressive Event Analysis

Multi-level event investigation from overview to deep-dive:

```text
"Start with an overview of events in namespace kube-system, then drill down into critical issues"
```

```text
"Perform advanced event analytics with ML pattern detection for namespace monitoring over the last 12 hours"
```

```text
"Correlate events with pod logs to identify the root cause of CrashLoopBackOff in namespace applications"
```

### 🚀 Real-Time Monitoring & Alerts

Stay informed about cluster health and pipeline status:

```text
"Show me the status of all Tekton pipeline runs cluster-wide and highlight long-running pipelines"
```

```text
"List all failed TaskRuns in the last hour with error details and recommended actions"
```

```text
"Monitor OpenShift cluster operators and alert on any degraded components"
```

```text
"Check MachineConfigPool status and show which nodes are being updated"
```

### 🔐 Security & Compliance

Ensure cluster security and certificate management:

```text
"Scan all namespaces for expiring certificates and generate a renewal schedule"
```

```text
"Investigate TLS certificate issues causing handshake failures in namespace istio-system"
```

```text
"Audit all secrets and configmaps for sensitive data exposure patterns"
```

### 📈 Advanced Analytics & ML Insights

Leverage machine learning for pattern detection:

```text
"Use streaming log analysis to process large log volumes from namespace data-pipeline with error pattern detection"
```

```text
"Detect anomalies in log patterns using ML analysis with medium severity threshold for namespace api-gateway"
```

```text
"Analyze resource utilization trends using Prometheus metrics and forecast capacity needs"
```

## Configuration

### Kubernetes Authentication

The server automatically detects Kubernetes configuration:

1. **In-cluster config** - When running inside a Kubernetes pod
2. **Local kubeconfig** - When running locally (uses `~/.kube/config`)

### Environment Variables

See also the transport env vars (`LUMINO_TRANSPORT`, `LUMINO_BIND_HOST`, `LUMINO_HTTP_TOKEN`, …) in the [MCP Client Integration](#mcp-client-integration) section and `config.example.yaml` for the full transport reference.

| Variable | Default | Purpose |
|----------|---------|---------|
| `LUMINO_PROFILE` | `konflux` | Built-in profile: `konflux` (49 tools), `kubernetes` (37), `standalone` (37). See [Profiles](#profiles). |
| `LUMINO_CONFIG` | *(none)* | Path to a `config.yaml` file; overrides `LUMINO_PROFILE` when set. |
| `KUBECONFIG` | `~/.kube/config` | Path to kubeconfig; multiple clusters or non-default location. |
| `KUBERNETES_NAMESPACE` | *(none)* | Namespace for in-cluster mode; also triggers streamable-http transport. |
| `K8S_NAMESPACE` | *(none)* | Alternative to `KUBERNETES_NAMESPACE`. |
| `KUBEARCHIVE_HOST` | Auto-detected | Explicit KubeArchive API endpoint URL. |
| `KUBEARCHIVE_ENABLED` | `true` | Set to `false` to disable KubeArchive queries entirely. |
| `KUBEARCHIVE_TOKEN` | Auto-detected | Bearer token for KubeArchive auth; operator-supplied credential for vanilla-k8s local dev (priority 1.5 — checked after a constructor-supplied token, before the in-cluster SA token). |
| `PROMETHEUS_URL` | Auto-detected | Prometheus server URL; takes lower priority than `THANOS_URL`. |
| `THANOS_URL` | Auto-detected | Thanos Query endpoint URL; takes priority over `PROMETHEUS_URL`. |
| `PROMETHEUS_TOKEN` | Auto-detected | Bearer token for Prometheus/Thanos auth (checked first). |
| `OPENSHIFT_TOKEN` | Auto-detected | OpenShift bearer token for Prometheus/Thanos (checked second). |
| `OC_TOKEN` | Auto-detected | Last-resort token fallback for Prometheus/Thanos auth. |
| `LUMINO_TLS_CA_BUNDLE` | *(none)* | PEM file of extra trusted CAs for Prometheus/Thanos and KubeArchive HTTPS (for example a cluster's self-signed ingress CA). Added to the system CAs, the `certifi` bundle and, in a pod, the OpenShift service CA. An unreadable path is an error. |
| `LUMINO_TLS_INSECURE_SKIP_VERIFY` | `false` | Set to `true` to turn off certificate verification for Prometheus/Thanos and KubeArchive requests. Last resort: these requests carry your bearer token. Each use is logged as a warning. |
| `LUMINO_STRICT_MODEL_LOADING` | `true` | ML model integrity enforcement. Set to `false` to allow loading unsigned legacy models (ml_persistence). |
| `TOKENIZERS_PARALLELISM` | `false` (set by server) | HuggingFace tokenizers thread safety; the server sets this to `false` automatically when the optional `logan` pack loads. |
| `LUMINO_DISABLE_TELEMETRY` | *(any value)* | **No-op.** This variable is not read by `src/` or `main.py`. It appears in test scrub lists for historical reasons only. |
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `MCP_SERVER_LOG_LEVEL` | `INFO` | MCP framework log level; separate from application logging. |
| `PYTHONUNBUFFERED` | *(none)* | Disable Python output buffering; recommended for MCP clients. |

## Profiles

Pharos ships three built-in profiles selectable via `LUMINO_PROFILE` (or the `profile:` key in `config.yaml`). These counts are machine-verified by `tests/test_profile_docs.py` — changing them triggers a test failure (M5 drift defence).

| Profile | Tools | Sources declared | Notes |
|---------|-------|-----------------|-------|
| `konflux` (default) | **49** | kubernetes, prometheus, kubearchive (disabled) | Registers all tools including the 12 Tekton/OpenShift/Konflux extension tools. |
| `kubernetes` | **37** | kubernetes, prometheus | Same 37-tool set as `standalone`; the difference is which sources are declared. |
| `standalone` | **37** | **none** | Registers the same 37 k8s-shaped tools as `kubernetes`, but declares zero sources. All tool calls will fail at dispatch until the operator adds `file`, `loki`, `elasticsearch`, or `otlp` source entries in `config.yaml`. The "analysis harness mode" described in the spec is the **intent**, not the default behaviour. |

**The 12 extension tools** present under `konflux` but absent under `kubernetes`/`standalone`:

```
analyze_failed_pipeline         ci_cd_performance_baselining_tool
find_pipeline                   get_etcd_logs
get_machine_config_pool_status  get_openshift_cluster_operator_status
get_pipelinerun_logs            get_tekton_pipeline_runs_status
list_pipelineruns               list_recent_pipeline_runs
list_taskruns                   pipeline_tracer
```

**Canonical aliases** (6 tool pairs added in phase 2c) are registered unconditionally regardless of profile. Both the canonical and the original name dispatch to the same function body and produce identical output; no consumer change is required. See the canonical-name table in [docs/MIGRATION.md](docs/MIGRATION.md#canonical-name-aliases-44).

For migration notes from the upstream `b6c24f27` snapshot or the GitLab 21-tool downstream, see [docs/MIGRATION.md](docs/MIGRATION.md).

## ML Model Persistence

The `predictive_log_analyzer` tool persists trained ML models and training data locally in `~/.lumino/`. This enables model reuse across server restarts and incremental learning from historical failure patterns.

### Directory Structure

```text
~/.lumino/
├── models/                     # Trained ML models
│   ├── {model_id}.joblib       # Serialized model (e.g. IsolationForest via joblib)
│   ├── {model_id}.meta.json    # Model metadata (created, last used, performance metrics)
│   └── model_index.json        # Index tracking all models and the current active model
└── training_data/              # Training data store
    └── training_data.db        # SQLite database
```

Model IDs follow the pattern `predictive_log_v1_YYYYMMDD_HHMMSS`.

### Training Data Database

The SQLite database (`training_data.db`) contains four tables:

| Table | Purpose |
|-------|---------|
| `log_samples` | Preprocessed log samples with extracted features, namespace, pod name, error indicators, and message entropy |
| `failure_labels` | Failure events collected from Kubernetes events, failed PipelineRuns, and unhealthy pod statuses. Failure types include: `oom`, `crash`, `image`, `scheduling`, `storage`, `config`, `health`, `network`, `timeout`, `pipeline_failure`, `permission`, `resource_limits`, `general`, `pod_failure` |
| `log_failure_correlations` | Time-proximity correlations between log samples and failure events (scored 0.5--1.0 based on temporal distance within a 30-minute window) |
| `training_runs` | Training run history recording model_id, samples used, labels used, performance metrics, and completion status |

All four tables define a `cluster_id` column for multi-cluster support. Currently, only `log_samples` and `failure_labels` actively populate it during writes; `log_failure_correlations` and `training_runs` leave it NULL. The cluster ID is derived from the active kubeconfig context name (e.g. `api-stone-prod-p02-hjvn-p1-openshiftapps-com:6443`) or falls back to `in-cluster-{KUBERNETES_SERVICE_HOST}` when running inside a pod.

### Clearing Stale Data

**Programmatic cleanup** via the `manage_prediction_training_data` tool (action `cleanup`):

- `cleanup_old_models(max_age_days=30, keep_min=3)` -- removes models older than 30 days, always keeping the 3 most recent
- `cleanup_old_data(max_age_days=90)` -- removes log samples, failure labels, and correlations older than 90 days

**Manual cleanup**:

```bash
rm -rf ~/.lumino/              # Clear everything (models + training data)
rm -rf ~/.lumino/models/       # Clear just models
rm -rf ~/.lumino/training_data/ # Clear just training data (SQLite DB)
```

**Disk usage note**: Models accumulate over time. The default cleanup keeps models up to 30 days old with a minimum of 3 retained. Training data is kept for 90 days. Run the `manage_prediction_training_data` tool with action `cleanup` periodically to reclaim disk space.

## KubeArchive Integration

KubeArchive stores Kubernetes resources off-cluster and provides a REST API for historical resource states and logs. LUMINO uses KubeArchive as a fallback when pods, PipelineRuns, or TaskRuns have been garbage-collected from the live cluster. The `query_kubearchive` tool queries this archive transparently.

### Endpoint Auto-Discovery

The endpoint is discovered automatically using a 4-step chain (first match wins):

1. **`KUBEARCHIVE_HOST` environment variable** (highest priority)
2. **OpenShift Route** named `kubearchive-api-server` in namespaces: `product-kubearchive`, `kubearchive`, `default`
3. **Kubernetes Ingress** named `kubearchive-api-server` in the same namespaces
4. **Kubernetes Service** named `kubearchive-api-server` (in-cluster DNS: `https://kubearchive-api-server.<namespace>.svc.cluster.local:<port>`)

Pharos does not guess route hostnames from the cluster domain: any project admin can claim such a hostname with a custom-host route. If Pharos cannot read the route, set `KUBEARCHIVE_HOST`.

Results are cached at startup. On connection failure, the cache is cleared and re-probed on the next request.

Steps 2 to 4 skip a namespace that Pharos cannot read or that is a self-provisioned OpenShift project (it has the `openshift.io/requester` annotation), because any user can create a project with a free name such as `kubearchive`. If KubeArchive runs in a namespace created with `oc new-project`, set `KUBEARCHIVE_HOST` (default source only; named sources have no override yet).

### Local Development (Port-Forwarding)

When running outside the cluster, if an in-cluster Service endpoint is discovered (step 4), LUMINO automatically sets up `kubectl port-forward`:

```bash
kubectl port-forward -n {namespace} svc/kubearchive-api-server {local_port}:{remote_port}
```

- Tries ports 8081--8090, then falls back to a system-assigned port
- The port-forward process is auto-started and auto-cleaned up on server exit
- If `kubectl` is not available, LUMINO logs a manual fallback command for the user

### Authentication

KubeArchive authentication uses the following priority chain:

1. Provided token (from constructor / previous session)
2. In-cluster service account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`)
3. Existing Kubernetes client token (extracted from the API client initialized at server startup)
4. OpenShift `oc whoami -t` token (for OpenShift clusters)
5. Auto-created short-lived service account token (`kubectl create token`, 1-hour duration, Kubernetes only)

### KubeArchive Configuration

See the [Configuration](#configuration) section above for `KUBEARCHIVE_HOST` and `KUBEARCHIVE_ENABLED` environment variables.

## Prometheus/Thanos Integration

LUMINO auto-discovers Prometheus or Thanos Query endpoints for the `prometheus_query`, `resource_bottleneck_forecaster`, and `ci_cd_performance_baselining_tool` tools. Thanos Query implements the Prometheus HTTP API and is preferred when available since it provides a unified, deduplicated view across replicas.

### Endpoint Discovery Priority

| Priority | Source | Endpoint Type |
|----------|--------|---------------|
| 0 | `THANOS_URL` env var | thanos |
| 1 | `PROMETHEUS_URL` env var | prometheus |
| 2 | Predefined cluster endpoints (in code) | varies |
| 3 | 5-minute TTL cache | cached |
| 4 | Auto-discovery chain (see below) | detected |
| 5 | Predefined fallback endpoints | varies |

Auto-discovery order depends on runtime environment:

- **In-cluster**: Thanos services --> Prometheus services --> Prometheus Operator CRD --> OpenShift Routes
- **Local/outside cluster**: OpenShift Routes --> Thanos services --> Prometheus Operator CRD --> Prometheus services

### Auto-Discovery Details

**OpenShift Routes**: Searches the `openshift-monitoring` namespace. Prefers the `thanos-querier` route over `prometheus-k8s`. Falls back to any route with `prometheus` in the name. Detects protocol from TLS termination config.

**Thanos Services**: Searches namespaces `openshift-monitoring`, `monitoring`, `thanos`, `observability`, `kube-prometheus`. Priority service names: `thanos-query-frontend`, `thanos-querier`, `thanos-query`. Also searches via label selectors: `app.kubernetes.io/name=thanos-query`, `app.kubernetes.io/component=query,app.kubernetes.io/name=thanos`, `app=thanos-query`, `app=thanos-querier` (trusted namespaces only, see below).

**Prometheus Services**: Searches namespaces `openshift-monitoring`, `monitoring`, `prometheus`, `kube-prometheus`, `observability`. Priority service names: `prometheus-server`, `prometheus-k8s`, `prometheus`. Also searches via label selectors: `app=prometheus`, `app.kubernetes.io/name=prometheus`, `app.kubernetes.io/component=prometheus` (trusted namespaces only, see below).

**Prometheus Operator CRD**: Discovers via `monitoring.coreos.com/v1` Prometheus custom resources and their associated services (pattern: `prometheus-{name}` in the same namespace). Only custom resources in trusted namespaces are used.

**Trusted namespaces**: a namespace other than `default` and outside `openshift-*` / `kube-*` is used only if Pharos can read it and it is not a self-provisioned OpenShift project (no `openshift.io/requester` annotation). Label-selector and custom-resource matches are also accepted only in `openshift-monitoring`, `openshift-user-workload-monitoring`, `monitoring`, `prometheus`, `thanos`, `kube-prometheus` and `observability`. A Service or Prometheus resource in any other namespace is ignored (with a warning in the log). If your Prometheus or Thanos runs in another namespace, set `PROMETHEUS_URL` or `THANOS_URL`.

### Prometheus/Thanos Authentication

Authentication for Prometheus/Thanos uses the following 5 methods in priority order:

1. `oc whoami -t` -- fresh OpenShift token (most reliable for OpenShift)
2. Re-read kubeconfig file for current token
3. In-memory Kubernetes client config token
4. ServiceAccount token file (`/var/run/secrets/kubernetes.io/serviceaccount/token`)
5. Environment variables: `PROMETHEUS_TOKEN`, `OPENSHIFT_TOKEN`, `OC_TOKEN` (checked in that order)

The token is sent only over HTTPS with certificate verification, or to a loopback host. It is never sent over plain `http` to another host, and redirects are not followed. If the endpoint uses a private CA, set `LUMINO_TLS_CA_BUNDLE`.

Upgrade notes:

- A `THANOS_URL`/`PROMETHEUS_URL` that uses `http://` with a non-loopback host no longer receives the token. If it needs authentication, use its `https` URL or a local port-forward.
- KubeArchive always verifies TLS except on loopback. If Pharos cannot read the KubeArchive CA secret (for example `product-kubearchive` without RBAC for it), set `LUMINO_TLS_CA_BUNDLE` to that CA.

### Configuration Example

```json
{
  "env": {
    "THANOS_URL": "https://thanos-querier.example.com",
    "PROMETHEUS_TOKEN": "your-bearer-token"
  }
}
```

**Note**: The endpoint cache has a 5-minute TTL. If you change `THANOS_URL` or `PROMETHEUS_URL` at runtime, the new value takes effect on the next query.

## Available Tools

### Kubernetes Core (5 tools)

| Tool | Description |
|------|-------------|
| `list_namespaces` | List all namespaces in the cluster |
| `list_pods_in_namespace` | List pods with status and placement info |
| `get_kubernetes_resource` | Get any Kubernetes resource with flexible output |
| `search_resources_by_labels` | Search resources across namespaces by labels |
| `query_kubearchive` | Query archived Kubernetes resources from KubeArchive with optional log retrieval |

### Tekton Pipelines (6 tools)

| Tool | Description |
|------|-------------|
| `list_pipelineruns` | List PipelineRuns with status and timing |
| `list_taskruns` | List TaskRuns, optionally filtered by pipeline |
| `get_pipelinerun_logs` | Retrieve pipeline logs with optional cleaning |
| `list_recent_pipeline_runs` | Recent pipelines across all namespaces |
| `find_pipeline` | Find pipelines by pattern matching |
| `get_tekton_pipeline_runs_status` | Cluster-wide pipeline status summary |

### Log Analysis (8 tools)

| Tool | Description |
|------|-------------|
| `analyze_logs` | Extract error patterns from log text |
| `smart_summarize_pod_logs` | Intelligent log summarization |
| `stream_analyze_pod_logs` | Streaming analysis for large logs |
| `analyze_pod_logs_hybrid` | Combined analysis strategies |
| `detect_log_anomalies` | Anomaly detection with severity levels |
| `semantic_log_search` | NLP-based semantic log search |
| `templatize_pod_logs` | Cluster logs into unique structural templates using Drain3 (requires optional `logan` dependency) |
| `deep_analyze_pod_logs` | Classify log templates into golden signals and fault categories using zero-shot ML (requires optional `logan` dependency) |


### Event Analysis (3 tools)

| Tool | Description |
|------|-------------|
| `smart_get_namespace_events` | Smart event retrieval with strategies |
| `progressive_event_analysis` | Multi-level event analysis |
| `advanced_event_analytics` | ML-powered event pattern detection |

### Failure Analysis & RCA (2 tools)

| Tool | Description |
|------|-------------|
| `analyze_failed_pipeline` | Root cause analysis for failed pipelines |
| `automated_triage_rca_report_generator` | Automated incident reports |

### Resource Monitoring (4 tools)

| Tool | Description |
|------|-------------|
| `check_resource_constraints` | Detect resource issues in namespace |
| `detect_anomalies` | Statistical anomaly detection |
| `prometheus_query` | Execute PromQL queries |
| `resource_bottleneck_forecaster` | Predict resource exhaustion |

### Namespace Investigation (2 tools)

| Tool | Description |
|------|-------------|
| `conservative_namespace_overview` | Focused namespace health check |
| `adaptive_namespace_investigation` | Dynamic investigation based on query |

### Certificate & Security (2 tools)

| Tool | Description |
|------|-------------|
| `investigate_tls_certificate_issues` | Find TLS-related problems |
| `check_cluster_certificate_health` | Certificate expiry monitoring |

### OpenShift Specific (3 tools)

| Tool | Description |
|------|-------------|
| `get_machine_config_pool_status` | MachineConfigPool status and updates |
| `get_openshift_cluster_operator_status` | Cluster operator health |
| `get_etcd_logs` | etcd log retrieval and analysis |

### CI/CD Performance (2 tools)

| Tool | Description |
|------|-------------|
| `ci_cd_performance_baselining_tool` | Pipeline performance baselines |
| `pipeline_tracer` | Trace pipelines by commit, PR, or image |

### Topology & Prediction (3 tools)

| Tool | Description |
|------|-------------|
| `live_system_topology_mapper` | Real-time system topology mapping |
| `predictive_log_analyzer` | Predict issues from log patterns |
| `manage_prediction_training_data` | Manage training data for predictive log analyzer |

### Simulation (1 tool)

| Tool | Description |
|------|-------------|
| `what_if_scenario_simulator` | Simulate configuration changes |

## Architecture

```text
pharos/
├── main.py                 # Entry point with transport detection
├── src/
│   ├── server-mcp.py       # MCP server with all 49 tools
│   └── helpers/
│       ├── constants.py              # Shared constants
│       ├── event_analysis.py         # Event processing logic
│       ├── failure_analysis.py       # RCA algorithms
│       ├── kubearchive_integration.py # KubeArchive API client & discovery
│       ├── log_analysis.py           # Log processing
│       ├── ml_persistence.py         # ML model & training data storage
│       ├── resource_topology.py      # Topology mapping
│       ├── semantic_search.py        # NLP search
│       └── utils.py                  # Utility functions
└── pyproject.toml          # Project configuration
```

## How It Works

LUMINO acts as a bridge between AI assistants and your Kubernetes infrastructure through the Model Context Protocol:

```text
┌─────────────────────────────────────────────────────────────────┐
│                        AI Assistant Layer                        │
│          (Claude Desktop, Claude Code CLI, Gemini CLI)          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Natural Language Queries
                             │ "Analyze failed pipelines"
                             │ "Predict resource bottlenecks"
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Model Context Protocol                       │
│                      (MCP Communication)                         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Tool Invocations & Results
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Pharos MCP Server                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Log Analysis │  │ Event Intel  │  │  Predictive  │         │
│  │   (6 tools)  │  │  (3 tools)   │  │  (2 tools)   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Pipeline   │  │  Simulation  │  │   Topology   │         │
│  │  (6 tools)   │  │  (1 tool)    │  │  (2 tools)   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Kubernetes API Calls
                             │ Prometheus Queries
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Kubernetes/OpenShift Cluster                  │
│                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │   Pods   │  │ Services │  │ Tekton   │  │etcd/Logs │       │
│  └──────────┘  └──────────┘  │Pipelines │  └──────────┘       │
│  ┌──────────┐  ┌──────────┐  └──────────┘  ┌──────────┐       │
│  │  Events  │  │ Configs  │  ┌──────────┐  │Prometheus│       │
│  └──────────┘  └──────────┘  │OpenShift │  └──────────┘       │
│                               │Operators │                       │
│                               └──────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow

1. **User Query** → AI assistant receives natural language request
2. **MCP Translation** → Assistant converts query to appropriate tool calls
3. **LUMINO Processing** → Server executes Kubernetes/Prometheus operations
4. **Data Analysis** → ML/statistical algorithms process raw data
5. **AI Synthesis** → Assistant formats results into human-readable insights

### Key Features

- **Minimal Local State** - Queries cluster in real-time; optional ML model persistence in `~/.lumino/` for predictive analytics (see [ML Model Persistence](#ml-model-persistence))
- **Automatic Transport Detection** - Switches between stdio (local) and HTTP (K8s) modes
- **Token Budget Management** - Adaptive strategies to handle large log volumes
- **Intelligent Caching** - Smart caching for frequently accessed data
- **Security First** - Uses existing kubeconfig RBAC permissions, no separate auth

## MCP Client Integration

### Method 1: Using MCPM

> **Note**: MCPM installation of Pharos is pending re-publish under the new remote.
> The registry IDs (`@owner/pharos`) cannot be claimed until the remote repository
> is established.  Once the remote is set up, this section will be updated with the
> correct MCPM install command.  Until then, use **Method 2 (Manual Configuration)**
> below, or the provisioning prompt in the [Quick Start](#quick-start) section.

---

### Method 2: Manual Configuration

If you prefer manual setup or need to configure Claude Desktop / Cursor, follow these client-specific guides:

#### Claude Desktop

1. **Find your config file location**:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. **Add LUMINO configuration**:

```json
{
  "mcpServers": {
    "lumino": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/pharos",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

3. **Restart Claude Desktop**

4. **Verify**: Look for the hammer icon (🔨) in Claude Desktop to see available tools

---

#### Claude Code CLI

**Option A: Using MCPM** (see Method 1 above)

**Option B: Automatic Provisioning via Claude Code** (Recommended and easiest way)

Copy and paste the provisioning prompt from the [Quick Start](#for-claude-code-cli-users-easiest) section above into Claude Code. Claude will clone the repository, install dependencies, and configure the MCP server for your project.

**Option C: Manual Configuration**

1. **Clone and install**:

```bash
git clone https://TBD-NEW-REMOTE
cd pharos
uv sync  # Creates .venv with all dependencies
```

2. **Create `.mcp.json`** in your project root (for project-local config) or update `~/.claude.json` (for global config):

```json
{
  "mcpServers": {
    "lumino": {
      "type": "stdio",
      "command": "/absolute/path/to/pharos/.venv/bin/python",
      "args": ["/absolute/path/to/pharos/main.py"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

**Important**: Replace `/absolute/path/to/pharos` with the actual absolute path where you cloned the repository (e.g., `/Users/username/projects/pharos`).

3. **Verify installation**:

```bash
# Check MCP servers
claude mcp list

# Test with a query
claude "List all namespaces in my cluster"
```

---

#### Gemini CLI

**Option A: Using MCPM** (Recommended - see Method 1 above)

**Option B: Manual Configuration**

1. **Find your config file location**:
   - macOS/Linux: `~/.config/gemini/mcp_servers.json`
   - Windows: `%APPDATA%\gemini\mcp_servers.json`

2. **Add LUMINO configuration**:

```json
{
  "mcpServers": {
    "lumino": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/pharos",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

3. **Verify installation**:

```bash
# Check MCP servers
gemini mcp list

# Test with a query
gemini "Show me failed pipeline runs"
```

---

#### Cursor IDE

1. **Open Cursor Settings**:
   - Press `Cmd+,` (macOS) or `Ctrl+,` (Windows/Linux)
   - Search for "MCP" or "Model Context Protocol"

2. **Add MCP Server Configuration**:

In Cursor's MCP settings, add:

```json
{
  "mcpServers": {
    "lumino": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/pharos",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

**Alternative - Using Cursor's settings.json**:

1. Open Command Palette (`Cmd+Shift+P` or `Ctrl+Shift+P`)
2. Type "Preferences: Open User Settings (JSON)"
3. Add the MCP configuration:

```json
{
  "mcp.servers": {
    "lumino": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/pharos",
        "python",
        "main.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

3. **Restart Cursor IDE**

4. **Verify**: Open Cursor's AI chat and check if LUMINO tools are available

---

### Configuration Notes

**Replace `/path/to/pharos`** with the actual path where you cloned the repository:

```bash
# Example paths:
# macOS/Linux: /Users/username/projects/pharos
# Windows: C:\Users\username\projects\pharos

# If installed via MCPM:
# ~/.mcp/servers/pharos/
```

**Environment Variables** (optional):

Add these to the `env` section if needed:

```json
{
  "env": {
    "PYTHONUNBUFFERED": "1",
    "KUBERNETES_NAMESPACE": "default",
    "PROMETHEUS_URL": "http://prometheus:9090",
    "LOG_LEVEL": "INFO"
  }
}
```

---

### Using Alternative Python Package Managers

#### With pip instead of uv

```json
{
  "command": "python",
  "args": [
    "/path/to/pharos/main.py"
  ]
}
```

**Note**: Ensure you've activated the virtual environment first:

```bash
cd /path/to/pharos
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

#### With poetry

```json
{
  "command": "poetry",
  "args": [
    "run",
    "python",
    "main.py"
  ],
  "cwd": "/path/to/pharos"
}
```

---

### Testing Your Configuration

After configuring any client, test the connection:

1. **Check if tools are loaded**:
   - Claude Desktop: Look for 🔨 hammer icon
   - Claude Code CLI: `claude mcp list`
   - Gemini CLI: `gemini mcp list`
   - Cursor: Check AI chat for available tools

2. **Test a simple query**:

```text
"List all namespaces in my Kubernetes cluster"
```

3. **Check server logs** (if issues):

```bash
# Run server manually to see errors
cd /path/to/pharos
uv run python main.py
```

Expected output:
```text
MCP Server running in stdio mode
Available tools: 49
Waiting for requests...
```

---

### Advanced Configuration

#### Multiple Clusters

Configure multiple LUMINO instances for different clusters:

```json
{
  "mcpServers": {
    "lumino-prod": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pharos", "python", "main.py"],
      "env": {
        "KUBECONFIG": "/path/to/prod-kubeconfig.yaml"
      }
    },
    "pharos-dev": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pharos", "python", "main.py"],
      "env": {
        "KUBECONFIG": "/path/to/dev-kubeconfig.yaml"
      }
    }
  }
}
```

#### Custom Log Level

```json
{
  "env": {
    "LOG_LEVEL": "DEBUG",
    "MCP_SERVER_LOG_LEVEL": "DEBUG"
  }
}
```

---

### Supported Transports

The server automatically detects the appropriate transport:

- **stdio** - For local desktop integrations (Claude Desktop, Claude Code CLI, Gemini CLI, Cursor)
- **streamable-http** - For Kubernetes/OpenShift deployments

Transport is controlled by environment variables (precedence: env > k8s auto-detect > stdio):

| Variable | Default | Description |
|---|---|---|
| `LUMINO_TRANSPORT` | auto-detect | `stdio` or `streamable-http`; explicit override |
| `LUMINO_BIND_HOST` | `127.0.0.1` | Listen host; set `0.0.0.0` in containers |
| `LUMINO_BIND_PORT` | `8000` | Listen port |
| `LUMINO_STATELESS_HTTP` | `false` | Set `true` for stateless Route/Ingress deployments |
| `LUMINO_HTTP_TOKEN` | *(none)* | Bearer token — **runtime secret, never baked into images** |

**Fail-closed security contract:** non-localhost bind (`0.0.0.0` / remote IP) without a token causes main.py to refuse startup. The `/health` endpoint is always unauthenticated; all other paths require `Authorization: Bearer <token>` when a token is configured.

See `config.example.yaml` for the full env-var reference including the TLS-at-Route/Ingress requirement and single-replica `stateless_http` caveat.

---

### OTLP/HTTP Ingest (phase 5) — second inbound surface

When an `otlp` source is declared and ENABLED in `config.yaml`, Lumino starts a second HTTP listener on its own port (default `4318`) for OTLP/HTTP log ingestion. This is a **separate inbound surface** from the MCP transport (spec §4.7):

| Surface | Default port | Auth | TLS |
|---|---|---|---|
| MCP streamable-http (`LUMINO_HTTP_TOKEN`) | 8000 | Bearer (fail-closed non-localhost) | at Route/Ingress |
| OTLP ingest (`LUMINO_OTLP_TOKEN`) | 4318 | Bearer (fail-closed non-localhost) | at Route/Ingress |

OTLP ingest environment variables (set at runtime, never in config files):

| Variable | Default | Description |
|---|---|---|
| `LUMINO_OTLP_TOKEN` | *(none)* | Bearer token — **runtime secret, never baked into images** |
| `LUMINO_OTLP_BIND_HOST` | `127.0.0.1` | Ingest listen host; set `0.0.0.0` in containers |
| `LUMINO_OTLP_BIND_PORT` | `4318` | Ingest listen port; not baked into Containerfile |

**Security warning:** localhost ingest is unauthenticated by default — set `LUMINO_OTLP_TOKEN` on any shared host. Without a token, any local process can push fabricated telemetry that the LLM will summarize. This is a local data-poisoning risk, not just local read access.

**Single-replica constraint:** the OTLP ring is in-process memory. Run a single replica or pin the collector to one replica; cross-replica ring sharing is not implemented.

See `config.example.yaml` for the full OTLP configuration reference including mandatory bounds, collector snippet, behavior table, and memory-bound disclosure.

## Performance Considerations

### Optimizing for Large Clusters

LUMINO is designed to handle clusters of any size efficiently:

| Cluster Size | Recommendation | Tool Strategy |
|--------------|----------------|---------------|
| **Small** (< 50 pods) | Use default settings | All tools work optimally |
| **Medium** (50-500 pods) | Use namespace filtering | Leverage adaptive tools with auto-sampling |
| **Large** (500+ pods) | Specify time windows and namespaces | Use conservative and streaming tools |
| **Very Large** (1000+ pods) | Combine filters and pagination | Progressive analysis with targeted queries |

### Token Budget Management

LUMINO automatically manages AI context limits:

- **Adaptive Sampling** - Smart tools auto-sample data when volumes are high
- **Progressive Loading** - Stream analysis processes data in chunks
- **Token Budgets** - Configurable limits prevent context overflow
- **Hybrid Strategies** - Automatically selects best analysis approach

### Query Optimization Tips

**Use Namespace Filtering**
```text
✅ "Analyze logs for pods in namespace production"
❌ "Analyze all pod logs in the cluster"
```

**Specify Time Windows**
```text
✅ "Show events from the last 2 hours"
❌ "Show all events" (might return thousands)
```

**Leverage Smart Tools**
```text
✅ "smart_summarize_pod_logs" - Adaptive analysis
❌ Direct log dumps - No processing
```

**Use Progressive Analysis**
```text
✅ Start with "overview" → drill down to "detailed"
❌ Jump directly to "deep_dive" on large datasets
```

### Performance Metrics

| Operation | Typical Response Time | Scalability |
|-----------|----------------------|-------------|
| List namespaces | < 1s | O(1) |
| Get pod logs (1 pod) | 1-3s | O(log size) |
| Analyze pipeline run | 2-5s | O(task count) |
| Cluster-wide search | 5-15s | O(namespace count) |
| ML anomaly detection | 3-10s | O(data points) |
| Topology mapping | 5-20s | O(resource count) |

### Caching Strategy

LUMINO uses intelligent caching for frequently accessed data:

- **15-minute cache** - For web-fetched content
- **Session cache** - For hybrid log analysis
- **ML model persistence** - Predictive models and training data stored locally in `~/.lumino/` (see [ML Model Persistence](#ml-model-persistence))

### Concurrent Requests

The server handles multiple concurrent requests efficiently:

- **Thread-safe operations** - Safe parallel tool execution
- **Connection pooling** - Reuses Kubernetes API connections
- **Async HTTP** - Non-blocking Prometheus queries

### Resource Usage

**Server Resource Requirements**

| Deployment | CPU | Memory | Disk |
|------------|-----|--------|------|
| Local (stdio) | 100-500m | 256-512Mi | Minimal |
| Kubernetes | 200m-1 | 512Mi-1Gi | Minimal |
| High-load | 1-2 | 1-2Gi | Minimal |

**Note**: LUMINO requires minimal resources. ML models and training data are persisted locally in `~/.lumino/` (see [ML Model Persistence](#ml-model-persistence)). Most processing happens in the AI assistant.

## Troubleshooting

### Common Issues

**No Kubernetes cluster found**
```text
Error: Unable to load kubeconfig
```
Ensure you have a valid kubeconfig at `~/.kube/config` or are running inside a cluster.

**Permission denied for resources**
```text
Error: Forbidden - User cannot list resource
```
Check your RBAC permissions. The server needs read access to the resources you want to query.

**Tool timeout**
For large clusters, some tools may timeout. Use filtering options (namespace, labels) to reduce scope.

## Dependencies

- `mcp[cli]>=1.10.1` - Model Context Protocol SDK
- `kubernetes>=32.0.1` - Kubernetes Python client
- `pandas>=2.0.0` - Data analysis
- `scikit-learn>=1.6.1` - ML algorithms
- `prometheus-client>=0.22.0` - Prometheus integration
- `aiohttp>=3.12.2` - Async HTTP client

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting pull requests.

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp) framework
- Inspired by the needs of SRE teams managing complex Kubernetes environments
