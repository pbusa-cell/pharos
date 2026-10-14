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
sns="${PHAROS_SMALL_NS:-spre-automations}"  # small ns for per-namespace scans (memory-safe)
# tool:json-args  (names verified against this deployment's tools/list;
#  args merged with {"source": <cluster>} when a source is given)
TOOLS=(
  'list_sources:{}'
  'list_namespaces:{}'
  'list_pods_in_namespace:{"namespace":"'"$ns"'"}'
  'check_cluster_certificate_health:{}'
  'investigate_tls_certificate_issues:{}'
  'conservative_namespace_overview:{"namespace":"'"$sns"'"}'
  'smart_get_namespace_events:{"namespace":"'"$ns"'"}'
  'check_resource_constraints:{"namespace":"'"$sns"'"}'
  'detect_anomalies:{"namespace":"'"$sns"'"}'
  'adaptive_namespace_investigation:{"namespace":"'"$sns"'"}'
  'progressive_event_analysis:{"namespace":"'"$sns"'"}'
  'prometheus_query:{"query":"up"}'
)
# NOTE: topology/forecaster/predictive tools omitted from the default set — they
# scan 100+ namespaces in parallel and OOM-crashed the 512Mi stage pod (OOMKilled,
# exit 137, observed 2026-10-13). Run those individually with a namespace filter.

call() { # method, params-json -> body on stdout, sets HTTP in global
  local method="$1" params="$2"
  curl -s -w '\n%{http_code}' -X POST "$URL" \
    -H "Authorization: Bearer $PHAROS_STAGE_TOKEN" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    --max-time 60 \
    -d '{"jsonrpc":"2.0","id":1,"method":"'"$method"'","params":'"$params"'}'
}

# Parser in a temp file so the curl output stays on stdin (a `python3 - <<EOF`
# heredoc would hijack stdin and read the script instead of the piped response).
PARSER=$(mktemp)
trap 'rm -f "$PARSER"' EXIT
cat > "$PARSER" <<'PY'
import sys,json
raw=sys.stdin.read().rsplit("\n",1)
body,code=raw[0], (raw[1] if len(raw)>1 else "")
# SSE framing: keep only "data: " lines, drop "event:" and blanks
lines=[l[6:] for l in body.strip().splitlines() if l.startswith("data: ")]
txt="\n".join(lines) or body.strip()
err=""
try:
    d=json.loads(txt)
    if "error" in d: err=str(d["error"].get("message",d["error"]))[:80]
    elif d.get("result",{}).get("isError"): err="tool isError=true"
except Exception as e:
    err=f"unparseable ({e})"
print(code, "OK" if (code=="200" and not err) else f"FAIL {err}")
PY
ok_json() { python3 "$PARSER"; }  # stdin: curl body + trailing status line

echo "Endpoint: $URL"
echo "== fail-closed check (no token) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' --max-time 20)
fail=0   # any required check that fails flips this; script exits non-zero
[ "$code" = "401" ] && echo "  PASS (401)" || { echo "  FAIL: expected 401, got $code"; fail=1; }

echo "== tools/list =="
read -r tlcode tlstat < <(call tools/list '{}' | ok_json)
echo "  $tlcode $tlstat"
[ "$tlstat" = "OK" ] || fail=1

min=0   # count of sources clearing >=10 OK; must equal #sources for acceptance
for src in "${SOURCES[@]}"; do
  label="${src:-<in-cluster>}"
  echo "== tools against source=$label =="
  pass=0; total=0
  for entry in "${TOOLS[@]}"; do
    name="${entry%%:*}"; args="${entry#*:}"
    [ -n "$src" ] && args=$(python3 -c "import json,sys;a=json.loads(sys.argv[1]);a['source']=sys.argv[2];print(json.dumps(a))" "$args" "$src")
    params='{"name":"'"$name"'","arguments":'"$args"'}'
    read -r c s < <(call tools/call "$params" | ok_json)
    printf "  %-40s %s %s\n" "$name" "$c" "$s"
    total=$((total+1)); [ "$s" = "OK" ] && pass=$((pass+1)) || fail=1
  done
  echo "  source=$label: $pass/$total OK"
  [ "$pass" -ge 10 ] && min=$((min+1))
done

echo "== summary: $min/${#SOURCES[@]} source(s) cleared >=10 tools OK =="
# acceptance: EVERY source clears >=10 OK, and >=2 real (named) prod sources
if [ "$min" -eq "${#SOURCES[@]}" ] && [ "${#SOURCES[@]}" -ge 2 ] && [ -n "${SOURCES[0]}" ]; then
  echo "ACCEPTANCE MET"
else
  echo "ACCEPTANCE PARTIAL (need >=10 OK per source across >=2 named prod sources)"
fi

exit "$fail"
