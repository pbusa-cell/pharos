# AGENTS.md — Pharos MCP Server: Agentic AI Architecture

This file documents the `.agents/` system for AI clients other than Claude Code
(Cursor, Codex, OpenCode, and any future agentic runtimes).

For Claude Code-specific instructions, see `.agents/CLAUDE.md`.

---

## Overview

The `.agents/` directory co-locates all agentic AI artefacts with the Pharos MCP server tools
they operate on (per ADR-006). It provides:

- **Skills** — reusable, parameterised SRE investigation patterns
- **Programs** — multi-step orchestration scripts that chain skills and tools
- **Runbooks** — machine-readable YAML failure response guides
- **Tests** — evaluation harnesses and fixtures for validating agent behaviour

---

## Directory Layout

```
.agents/
├── CLAUDE.md           # Claude Code system instructions (skill triggers, tool index, safety rules)
├── AGENTS.md           # This file — architecture overview for all other clients
│
├── skills/             # Reusable investigation and remediation skills (Markdown)
│   └── README.md
│
├── programs/           # Multi-step agentic programs that orchestrate skills + tools
│   └── README.md
│
├── runbooks/           # Machine-readable YAML runbooks for known failure patterns
│   ├── README.md
│   ├── certificate-expiry.yaml
│   ├── crashloopbackoff.yaml
│   ├── imagepullbackoff.yaml
│   ├── oomkilled.yaml
│   └── tekton-timeout.yaml
│
└── tests/
    ├── fixtures/        # Static mock data + live-cluster repro manifests for offline/CRC evaluation
    └── evaluation/      # Scoring harnesses for measuring agent diagnostic accuracy
```

Note: the `config/` directory (`safety-guardrails.yaml`, `autonomy-levels.yaml`, `clusters.yaml`)
that existed in this system's original single-cluster home (`lumino-mcp-server`) is **not**
present here. Those were unfilled placeholders describing a single-cluster config model that
Pharos has already superseded with a real mechanism — multi-cluster `source=<cluster>` dispatch
and `connect_cluster` (see "Multi-Cluster Dispatch" below). Cluster-scoped autonomy/guardrail
config may be reintroduced later against that mechanism, but no such file exists today — do not
reference `.agents/config/*` in this repo.

---

## Multi-Cluster Dispatch

Pharos is a multi-cluster server: every tool call accepts a `source=<cluster>` parameter that
selects which registered cluster the call targets (default `source=""` resolves to the local/first
configured cluster — it is *not* an error to omit it, but omitting it means "whichever cluster
happens to be default," which is rarely what an investigation should rely on). Named clusters are
registered via the `connect_cluster` tool from kubeconfig contexts.

**Always name the target cluster explicitly** — pass `source=` on every Pharos tool call, and say
which cluster you're reading from in any findings. This is normative team doctrine, not a style
preference: see "Mandatory Investigation Sequence" below.

---

## MCP Tool Catalog

All tools are exposed by the Pharos MCP server (`src/server-mcp.py`) and are **strictly read-only**.
No tool performs writes, deletes, or mutations on any cluster resource.

The full, current, per-tool catalog — 49 tools under the default `konflux` profile, 37 under the
`kubernetes`/`standalone` profiles — lives in the repository root
[`README.md` § Available Tools](../README.md#available-tools). That table is machine-verified
against the live tool registry by `tests/test_profile_docs.py`, so it is the single source of
truth; this file intentionally does not duplicate it (a second hand-maintained copy drifts, as
happened to this file's predecessor in `lumino-mcp-server`, which listed 39 tools across 12
categories against Pharos's current 49/37).

Tool categories, at a glance: Kubernetes Core, Tekton Pipelines, Log Analysis, Event Analysis,
Failure Analysis & RCA, Resource Monitoring, Namespace Investigation, Certificate & Security,
OpenShift Specific, CI/CD Performance, Topology & Prediction, Simulation.

---

## Skills

Skills live in `.agents/skills/` as Markdown files. Each skill file defines:

- **Trigger phrases** — natural language patterns that indicate when to apply this skill
- **Inputs** — parameters the invoking agent must supply (namespace, pod name, cluster `source`, time range, etc.)
- **Steps** — ordered sequence of MCP tool calls with parameter templates
- **Output** — what the skill produces (findings summary, hypothesis list, etc.)

**Discovery:** list `.agents/skills/` and read the file whose trigger phrases match the user request.

No skills have been authored yet — this directory currently holds only a placeholder `README.md`.

---

## Runbooks

Runbooks live in `.agents/runbooks/` as YAML files, following the `spre.agents/v1` schema:

```yaml
apiVersion: spre.agents/v1
kind: Runbook
metadata:
  name: <runbook-name>
  description: <one-line description>
spec:
  trigger:
    patterns: [<log or event strings that indicate this failure>]
    events: [<Kubernetes event reasons that indicate this failure, e.g. CrashLoopBackOff>]
    exit_codes: [<container exit codes that indicate this failure, e.g. 137 for OOMKilled>]
  diagnostic_steps:
    - tool: <mcp_tool_name>
      args: {<param>: <value or {{ template }} variable>}
      extract: [<fields to pull from tool output>]
      on_failure: skip  # optional — skip this step and continue if the tool call fails
                         # (e.g. Prometheus not discoverable) instead of aborting the runbook
      fallback:          # optional — an alternate step to run if this one comes up empty
        condition: <when to use the fallback, e.g. "no pods found (garbage-collected)">
        tool: <mcp_tool_name>
        args: {<param>: <value>}
  analysis:
    compare: [<comparisons to make>]
    check: [<boolean conditions to evaluate>]
  remediation: [<human-actionable step — never auto-applied by the agent>]
  verification: [<steps to confirm the fix worked>]
  rollback: [<steps to undo if remediation fails>]
  escalation:
    condition: <when to escalate>
    target: <escalation destination>
```

`on_failure` and `fallback` matter operationally, not just structurally: `tekton-timeout.yaml`'s
`fallback` from `get_pipelinerun_logs` to `query_kubearchive` *is* the Mandatory Investigation
Sequence's log-retrieval chain (see above) expressed in one runbook's diagnostic step — an agent
that reads only this schema summary and skips the actual runbook YAML would miss that the chain
is encoded there, not just described in prose.

Five runbooks are currently defined: `certificate-expiry`, `crashloopbackoff`, `imagepullbackoff`,
`oomkilled`, `tekton-timeout`. Each runbook's `diagnostic_steps` reference real Pharos MCP tools; when executing
them, remember to add `source=<cluster>` to every tool call per "Multi-Cluster Dispatch" above —
the runbook YAML itself predates multi-cluster and does not encode `source` explicitly.

**Execution:** read the runbook YAML, execute each `diagnostic_steps` entry using the named
MCP tool (with `source=` added) and the given params, interpret the output per the `analysis`
field, then present the `remediation` steps to the human operator for approval.

---

## Safety Contract

All agents operating in this system must honour:

1. **Read-only** — no writes, deletes, or mutations to cluster state.
2. **Hypothesis framing** — findings are presented as hypotheses, not facts.
3. **Human approval for remediation** — no autonomous remediation without explicit operator sign-off.
4. **Evidence-backed claims** — every load-bearing claim in a report names the tool, parameters,
   and `source=` cluster that produced it, per Pharos's honesty contract
   (`docs/HONESTY-CONTRACT.md`) and the read-only guard enforced in CI (`tests/test_readonly_guard.py`).

The sections below (Mandatory Investigation Sequence through Completion Checklist) are the full,
normative expansion of this contract — the daily fleet health agent (SPRE-6650) and any other
in-cluster agent are expected to read and follow this file directly, so this is where the doctrine
must be enforceable, not just summarized.

---

## Mandatory Investigation Sequence

*Normative team doctrine — every investigation any agent in this system performs follows these
steps IN ORDER. No conclusions before earlier steps complete. Source: SPRE team SRE doctrine
(`trajectories/00-investigation-principles.md` in the design-record repo), adapted here for
headless/interactive execution against Pharos.*

**Step 0 — Context gathering (BLOCKING).** Before forming any hypothesis:
- Query Chai Bot (`chai_konflux_public` / `ask_persona`) for SOPs, known issues, and escalation
  contacts. Ask focused single questions naming components and Jira keys.
- Search `konflux-ci/architecture` for service design docs/ADRs covering the affected service.
- This may run in parallel with Step 1's data collection — but the verdict is blocked on Step 0,
  not just the data pulls.

**Step 1 — Cluster data collection.** Name the target cluster first; pass `source=` on every
Pharos call (see "Multi-Cluster Dispatch" above). Release-pipeline failures always mean checking
at least two sources: the workload cluster AND `internal-services` on `kflux-c-prd-i01`
(InternalRequest pipelines: signing, advisories, FBC — API on port 443, not the usual 6443).

**Log retrieval chain** — "logs unavailable" is only permitted after ALL of, in order:
1. `get_pipelinerun_logs` / `analyze_failed_pipeline` (live)
2. `query_kubearchive(..., include_logs=True, source=...)` (archived)
3. Tekton Results / archive route via raw API

**Step 2 — Competing hypotheses.** Always include "this is not an issue" as one hypothesis.
Validate each against ≥3 independent sources (see "Evidence Standards" below). Correlation is a
lead, not a conclusion.

**Step 3 — Confidence-scored verdict.**
- **90%+**: ≥3 independent sources align, nothing contradicts.
- **70–89%**: 2 sources align; NAME the gaps.
- **<70%**: do not conclude — report what was checked, what is missing, and the fastest path to close.
- Every verdict includes: a false-positive check (does any data contradict? config artifact vs.
  runtime?), owner/escalation contacts (from Step 0), and the completion checklist below.

---

## Evidence Standards

- **Independence:** two Pharos tools reading the same underlying API count as ONE source. A
  Pharos summary plus a raw resource read (`get_kubernetes_resource`, or `kubectl`/`oc` when
  interactive) counts as TWO. Metrics, logs, events, resource state, and SOP/architecture context
  are distinct evidence paths.
- **Statistical hygiene:** use percentiles, never averages — averages hide bimodal failure modes.
  Rates need denominators. State time windows explicitly and compare like windows. A single
  post-change data point is an anecdote, not evidence.
- **Empty ≠ healthy:** a tool returning `[]`/empty can mean "no data exists" or "access/routing
  failed" (e.g. a 403). Distinguish the two by repeating the same call against a known-good target.
- **RBAC-limited views are partial evidence** — say so explicitly in the confidence score.
  Fallback modes on prod clusters are routine, not a red flag on their own.
- **Auditability:** every load-bearing claim names its instrument — tool + parameters + `source=`
  — so a reader can re-run it and get the same answer.

---

## Action Safety Chain

Diagnostics are read-only. **Any mutating action requires the full chain, no skipping any link:**

**pre-check → duplicate check → execute (smallest blast radius) → verify (observe, don't infer)
→ revert plan known BEFORE executing → record.**

This binds the agent's own actions, not just how a report gets written. Claude Code in this repo
has `kubectl`/`oc` available — "read-only" is a practice the agent must hold itself to, not a
technical restriction — so this chain is what actually stands between an investigation and an
unintended mutation.

- **Applies to report recommendations too:** a report that recommends a mutating action for a
  human operator to take must state the full chain for that operator to follow.
- **Multi-cluster blast radius:** an action described as looping over clusters needs an explicit
  cluster allowlist in the recommendation — never "all sources" implicitly.
- **Credentials:** never echo tokens; never widen RBAC, disable a webhook, or loosen validation as
  a shortcut.
- **Simulation first:** for scaling/config-change recommendations, run
  `what_if_scenario_simulator(source=...)` and include its risk assessment in the writeup.

---

## Konflux Operational Facts

- **Failed PR-check PipelineRuns are pruned within ~30 minutes.** Capture evidence at detection
  time, or go straight to KubeArchive if the window has passed.
- Kueue admission-gates tenant builds (`kueue.x-k8s.io/queue-name`); a `PipelineRunPending` under
  a threshold age is load telemetry, not an incident on its own.
- Exactly-at-timeout failures with otherwise-fast normal runs usually mean "never started," not
  "too slow" — check for admission/scheduling delay before assuming a performance regression.
- Routing sanity check per cluster: node count from the Kubernetes API should equal
  `count(kube_node_info)` from `query_metrics(source=...)` (canonical alias for `prometheus_query`
  — same function, either name works) — a mismatch means the metrics source is routed to the
  wrong cluster, not that nodes are actually missing.

---

## Completion Checklist

Every investigation report produced in this system must show:

- [ ] Chai Bot queried for SOPs / known issues (Step 0)
- [ ] Architecture repo searched for the affected service (Step 0)
- [ ] Cluster `source=` named for every piece of evidence
- [ ] Escalation contacts identified
- [ ] Confidence scored per conclusion (gaps named for 70–89%)

---

## Supported Clients

| Client | Entry point |
|--------|------------|
| Claude Code | `.agents/CLAUDE.md` (auto-discovered) |
| Cursor | `.agents/AGENTS.md` (add to context manually or via `.cursorrules`) |
| Codex / OpenAI Agents | `.agents/AGENTS.md` (pass as system context) |
| OpenCode | `.agents/AGENTS.md` (reference in project config) |
