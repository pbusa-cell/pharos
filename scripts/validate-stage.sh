#!/usr/bin/env bash
# SPRE-6652 — scripted validation of the stage Pharos Route.
# Connects over streamable HTTP with the bearer token and exercises >=10 read-only
# tools. Pass up to two registered source= cluster names to satisfy the
# ">=10 tools across >=2 prod clusters" criterion; with none it uses the in-cluster source.
#
# Usage:  PHAROS_STAGE_TOKEN=... ./validate-stage.sh [cluster-a] [cluster-b]
set -uo pipefail

URL="${PHAROS_URL:-https://pharos-spre-automations.apps.rosa.kflux-c-stg-i01.qfla.p3.openshiftapps.com/mcp}"
: "${PHAROS_STAGE_TOKEN:?set PHAROS_STAGE_TOKEN (see docs/stage-mcp-onboarding.md)}"
SOURCES=("$@"); [ ${#SOURCES[@]} -eq 0 ] && SOURCES=("")   # "" = default in-cluster source

ns="${PHAROS_NS:-openshift-apiserver}"   # a namespace that exists on every OCP cluster
# tool:json-args  (args merged with {"source": <cluster>} when a source is given)
TOOLS=(
  'list_namespaces:{}'
  'get_openshift_cluster_operator_status:{}'
  'check_cluster_certificate_health:{}'
  'get_machine_config_pool_status:{}'
  'conservative_namespace_overview:{"namespace":"'"$ns"'"}'
  'list_pods_in_namespace:{"namespace":"'"$ns"'"}'
  'smart_get_namespace_events:{"namespace":"'"$ns"'"}'
  'list_recent_pipeline_runs:{}'
  'live_system_topology_mapper:{}'
  'prometheus_query:{"query":"up"}'
  'detect_anomalies:{}'
  'check_resource_constraints:{}'
)

call() { # method, params-json -> body on stdout, sets HTTP in global
  local method="$1" params="$2"
  curl -s -w '\n%{http_code}' -X POST "$URL" \
    -H "Authorization: Bearer $PHAROS_STAGE_TOKEN" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    --max-time 60 \
    -d '{"jsonrpc":"2.0","id":1,"method":"'"$method"'","params":'"$params"'}'
}

ok_json() { # stdin: curl body incl trailing status line -> prints "HTTP <code>" + jsonrpc ok?
  python3 - "$@" <<'PY'
import sys,json
raw=sys.stdin.read().rsplit("\n",1)
body,code=raw[0], (raw[1] if len(raw)>1 else "")
# strip SSE "data: " framing if present
lines=[l[6:] if l.startswith("data: ") else l for l in body.strip().splitlines()]
txt="\n".join(l for l in lines if l.strip())
err=""
try:
    d=json.loads(txt)
    if "error" in d: err=str(d["error"].get("message",d["error"]))[:80]
except Exception as e:
    err=f"unparseable ({e})"
print(code, "OK" if (code=="200" and not err) else f"FAIL {err}")
PY
}

echo "Endpoint: $URL"
echo "== fail-closed check (no token) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' --max-time 20)
[ "$code" = "401" ] && echo "  PASS (401)" || { echo "  FAIL: expected 401, got $code"; }

echo "== tools/list =="
read -r tlcode tlstat < <(call tools/list '{}' | ok_json)
echo "  $tlcode $tlstat"

pass=0; total=0
for src in "${SOURCES[@]}"; do
  label="${src:-<in-cluster>}"
  echo "== tools against source=$label =="
  for entry in "${TOOLS[@]}"; do
    name="${entry%%:*}"; args="${entry#*:}"
    [ -n "$src" ] && args=$(python3 -c "import json,sys;a=json.loads(sys.argv[1]);a['source']=sys.argv[2];print(json.dumps(a))" "$args" "$src")
    params='{"name":"'"$name"'","arguments":'"$args"'}'
    read -r c s < <(call tools/call "$params" | ok_json)
    printf "  %-40s %s %s\n" "$name" "$c" "$s"
    total=$((total+1)); [ "$s" = "OK" ] && pass=$((pass+1))
  done
done

echo "== summary: $pass/$total tool calls OK across ${#SOURCES[@]} source(s) =="
# acceptance: >=10 distinct tools OK and >=2 real sources
[ "$pass" -ge 10 ] && [ "${#SOURCES[@]}" -ge 2 ] && [ -n "${SOURCES[0]}" ] \
  && echo "ACCEPTANCE MET" || echo "ACCEPTANCE PARTIAL (need >=10 OK across >=2 named prod sources)"
