# Pharos Stage — Team MCP Onboarding

How to connect a local MCP client (Claude Code) to the **stage** Pharos Route and run
read-only investigations against production clusters. Tracks SPRE-6652.

## Endpoint

| | |
|---|---|
| **Route** | `https://pharos-spre-automations.apps.rosa.kflux-c-stg-i01.qfla.p3.openshiftapps.com/mcp` |
| **Cluster** | `kflux-c-stg-i01` (internal-staging inner-services), namespace `spre-automations` |
| **Transport** | Streamable HTTP, stateless |
| **Auth** | Bearer token (`LUMINO_HTTP_TOKEN`). Fail-closed — no token ⇒ `401`. |

## Get the bearer token

The token is **not** readable from the cluster Secret (`spre-automations` grants viewer RBAC
without secret access). Fetch it from the AppSRE Vault:

| | |
|---|---|
| **Vault UI** | https://vault.devshift.net/ui/vault/secrets/stonesoup/kv/list/staging/spre/ |
| **Mount** | `stonesoup` |
| **Key** | `staging/spre/pharos-token` → field `LUMINO_HTTP_TOKEN` |

Requires the `spre-staging-vault` role — add it to your app-interface user file if you don't
have it yet (one-line `$ref`, see app-interface MR !210885 for the pattern).

**Browser:** open the Vault UI link above, log in with OIDC, open `pharos-token`, copy
`LUMINO_HTTP_TOKEN`.

**CLI:**
```bash
export VAULT_ADDR=https://vault.devshift.net
vault login -method=oidc                       # SSO
export PHAROS_STAGE_TOKEN=$(vault kv get -mount=stonesoup -field=LUMINO_HTTP_TOKEN staging/spre/pharos-token)
```

> Never paste the token into a file, commit, or Jira comment. Keep it in the
> `PHAROS_STAGE_TOKEN` env var only.

## MCP config block

Add to your project `.mcp.json` (or `~/.claude.json`). The token stays in the env var —
Claude Code expands `${PHAROS_STAGE_TOKEN}` at launch, so nothing secret lands in the file:

```json
{
  "mcpServers": {
    "pharos-stage": {
      "type": "http",
      "url": "https://pharos-spre-automations.apps.rosa.kflux-c-stg-i01.qfla.p3.openshiftapps.com/mcp",
      "headers": { "Authorization": "Bearer ${PHAROS_STAGE_TOKEN}" }
    }
  }
}
```

Restart Claude Code; tools appear as `mcp__pharos-stage__*`.

## How to test it

### Option A — scripted check (fastest)

```bash
cd <pharos repo>
export PHAROS_STAGE_TOKEN='<token from Vault>'
./scripts/validate-stage.sh                            # in-cluster source only
./scripts/validate-stage.sh <cluster-a> <cluster-b>    # once prod sources are registered
```

A good run ends with:
```
== fail-closed check (no token) ==
  PASS (401)
== tools/list ==
  200 OK
== tools against source=<in-cluster> ==
  list_sources          200 OK
  list_namespaces       200 OK
  ... (12 tools total)
== summary: 12/12 tool calls OK across 1 source(s) ==
```
`12/12 OK` means the endpoint works. It prints `ACCEPTANCE PARTIAL` until two prod `source=`
names are passed — expected while the prod blocker (below) stands.

### Option B — interactive, via Claude Code

1. Add the [MCP config block](#mcp-config-block) above to your `.mcp.json`.
2. In the shell you launch Claude Code from: `export PHAROS_STAGE_TOKEN='<token>'`
3. Restart Claude Code, then ask, e.g.:
   - "List the namespaces on stage" → `mcp__pharos-stage__list_namespaces`
   - "Check cluster certificate health on stage"
   - "Show recent events in the spre-automations namespace"

> Don't invoke the whole-cluster scan tools (`live_system_topology_mapper`, `topology_mapper`,
> `resource_bottleneck_forecaster`, `predictive_log_analyzer`) — they crash the pod (SPRE-7074).

**Stage result (2026-10-13):** fail-closed ✓, auth ✓, `tools/list` ✓ (37 tools, profile
`konflux`), **12/12 tools OK** against the in-cluster source. `list_sources` shows one source
(`kubernetes`, connected) — no prod sources registered yet (see below).

## ⚠️ Known limitations (2026-10-13)

1. **`source=` multi-cluster dispatch is not yet functional.** `pharos-config` has an empty
   `cluster_registry` and no mounted credentials, because the read-only prod ServiceAccounts
   (**SPRE-6614**, Backlog) do not exist yet and their tokens (**SPRE-6648**, in Review) are not
   delivered. Until both land, validation targets only the in-cluster (stage) source, and the
   "≥10 tools across ≥2 prod clusters" criterion cannot be met.

2. **Pod OOMKilled under whole-cluster scan tools (SPRE-7074).** The pod's memory limit is
   512Mi; tools that fan out across all namespaces in parallel (`live_system_topology_mapper`,
   `topology_mapper`, `resource_bottleneck_forecaster`, `predictive_log_analyzer`) crash it
   (exit 137) and the Route returns 503 until restart. `validate-stage.sh` excludes these from
   its default set so the run is pod-safe. Avoid them until SPRE-7074 is fixed.

## Per-engineer checklist

Tracked in SPRE-6652. Each engineer: connect, run `validate-stage.sh`, tick below, file bugs
for any failing tool.

| Engineer | Connected | ≥10 tools | ≥2 prod clusters | Bugs filed |
|---|---|---|---|---|
| Prathamesh | ✅ | ✅ (12/12 stage) | ☐ (blocked) | SPRE-7074 |
| Georgi | ☐ | ☐ | ☐ (blocked) | — |
| Sachin | ☐ | ☐ | ☐ (blocked) | — |
| Ayush | ☐ | ☐ | ☐ (blocked) | — |
| Diksha | ☐ | ☐ | ☐ (blocked) | — |
| Radha | ☐ | ☐ | ☐ (blocked) | — |
