# validate-stage.sh — scripted stage endpoint check

Automated validation of the stage Pharos Route for SPRE-6652. Confirms reachability,
fail-closed auth, `tools/list`, and that ≥10 read-only tools execute. For the human
connect-and-use flow, see [../docs/stage-mcp-onboarding.md](../docs/stage-mcp-onboarding.md).

## Run

```bash
export PHAROS_STAGE_TOKEN='<token from Vault>'   # vault.devshift.net stonesoup/staging/spre/pharos-token
./scripts/validate-stage.sh                            # in-cluster source only
./scripts/validate-stage.sh <cluster-a> <cluster-b>    # once prod sources are registered
```

Optional overrides: `PHAROS_URL`, `PHAROS_NS` (default `openshift-apiserver`),
`PHAROS_SMALL_NS` (default `spre-automations`).

## Expected output

```
== fail-closed check (no token) ==
  PASS (401)
== tools/list ==
  200 OK
== tools against source=<in-cluster> ==
  list_sources          200 OK
  list_namespaces       200 OK
  ... (12 tools total)
  source=<in-cluster>: 12/12 OK
== summary: 1/1 source(s) cleared >=10 tools OK ==
```

`12/12 OK` ⇒ the endpoint works. The script prints `ACCEPTANCE PARTIAL` until two prod
`source=` names are passed and each clears ≥10 OK — expected while the prod blocker stands
(SPRE-7090, blocked by SPRE-6648 and KFLUXINFRA-4683).

## Notes

- The default tool set deliberately excludes the whole-cluster scan tools
  (`live_system_topology_mapper`, `topology_mapper`, `resource_bottleneck_forecaster`,
  `predictive_log_analyzer`) — they OOM-crash the 512Mi pod (**SPRE-7074**).
- Tool names are specific to this deployment's profile (`konflux`); verify against
  `tools/list` if the profile changes.
