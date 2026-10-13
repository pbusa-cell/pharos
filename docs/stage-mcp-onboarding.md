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
| **Vault** | `https://vault.ci.ext.devshift.net` |
| **Mount** | `stonesoup` |
| **Key** | `staging/spre/pharos-token` → field `LUMINO_HTTP_TOKEN` |

```bash
export VAULT_ADDR=https://vault.ci.ext.devshift.net
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

## Validate

With `PHAROS_STAGE_TOKEN` set, run the scripted check:

```bash
./scripts/validate-stage.sh                     # defaults to in-cluster source only
./scripts/validate-stage.sh <cluster-a> <cluster-b>   # once prod sources are registered
```

It confirms reachability, fail-closed auth, `tools/list`, and exercises ≥10 read-only tools.
Pass two registered `source=` names to satisfy the ≥2-prod-cluster acceptance criterion.

## ⚠️ Known limitation (2026-10-13)

`source=` **multi-cluster dispatch is not yet functional.** `pharos-config` has an empty
`cluster_registry` and no mounted credentials, because the read-only prod ServiceAccounts
(**SPRE-6614**, Backlog) do not exist yet and their tokens (**SPRE-6648**, in Review) are not
delivered. Until both land, validation can only target the in-cluster (stage) source, and the
"≥10 tools across ≥2 prod clusters" criterion cannot be met. See the SPRE-6652 comment thread.

## Per-engineer checklist

Tracked in SPRE-6652. Each engineer: connect, run `validate-stage.sh`, tick below, file bugs
for any failing tool.

| Engineer | Connected | ≥10 tools | ≥2 prod clusters | Bugs filed |
|---|---|---|---|---|
| Prathamesh | ☐ | ☐ | ☐ (blocked) | — |
| Georgi | ☐ | ☐ | ☐ (blocked) | — |
| Sachin | ☐ | ☐ | ☐ (blocked) | — |
| Ayush | ☐ | ☐ | ☐ (blocked) | — |
| Diksha | ☐ | ☐ | ☐ (blocked) | — |
| Radha | ☐ | ☐ | ☐ (blocked) | — |
