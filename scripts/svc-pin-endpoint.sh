#!/usr/bin/env bash
# copyright: 2025, the k8shell authors. 
#
# The script pins a ClusterIP Service to a single backend IP by:
#  1) removing the Service .spec.selector
#  2) deleting all EndpointSlices for the Service
#  3) creating/updating a manual Endpoints with the Service's port name(s)
#
# This is useful for pinning a Service to an IP where k8shell workspace is running. The workspace can be used
# to replace the backend service (e.g. for debugging or testing).
#
# Requires: kubectl, jq
#
# Usage example:
#   svc-pin-endpoint.sh --namespace myns --service mysvc --ip 10.0.0.1

set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --namespace <ns> --service <name> --ip <a.b.c.d> [--only-port <svcPortName>] [--kubeconfig <path>]

Pins a ClusterIP Service to a single backend IP by:
  1) removing the Service .spec.selector
  2) deleting all EndpointSlices for the Service
  3) creating/updating a manual Endpoints with the Service's port name(s)

Requires: kubectl, jq
EOF
  exit 2
}

NS="" SVC="" IP="" ONLY_PORT="" KUBECONFIG_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace) NS="$2"; shift 2;;
    --service)   SVC="$2"; shift 2;;
    --ip)        IP="$2"; shift 2;;
    --only-port) ONLY_PORT="$2"; shift 2;;
    --kubeconfig) KUBECONFIG_ARG="--kubeconfig=$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

[[ -z "$NS" || -z "$SVC" || -z "$IP" ]] && usage
if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Invalid IPv4: $IP" >&2; exit 1
fi

# 1) Fetch Service JSON
SVC_JSON="$(kubectl $KUBECONFIG_ARG -n "$NS" get svc "$SVC" -o json)" || { echo "Service not found"; exit 1; }

# 1a) Build Endpoints ports from Service ports (match by name; number may be the Service port)
# Create a TSV: name\tport\tprotocol
PORTS_TSV="$(echo "$SVC_JSON" | jq -r --arg ONLY "$ONLY_PORT" '
  .spec.ports[]
  | select(($ONLY == "") or (.name == $ONLY))
  | "\(.name // "")\t\(.port)\t\(.protocol // "TCP")"
')"

if [[ -z "$PORTS_TSV" ]]; then
  echo "No matching Service ports (only-port=$ONLY_PORT)" >&2
  exit 1
fi

# 2) Remove selector (so endpoints controller stops managing)
HAS_SELECTOR="$(echo "$SVC_JSON" | jq '.spec.selector != null and (.spec.selector | length > 0)')"
if [[ "$HAS_SELECTOR" == "true" ]]; then
  echo "Removing selector from Service/$SVC ..."
  kubectl $KUBECONFIG_ARG -n "$NS" patch svc "$SVC" --type=json -p '[{"op":"remove","path":"/spec/selector"}]'
else
  echo "Service/$SVC already has no selector"
fi

# 3) Delete EndpointSlices for this Service
echo "Deleting EndpointSlices for Service/$SVC ..."
kubectl $KUBECONFIG_ARG -n "$NS" delete endpointslice -l "kubernetes.io/service-name=$SVC" --ignore-not-found

# 4) Create/Update legacy Endpoints -> $IP with ports copied from Service
TMP_EP="$(mktemp)"
{
  cat <<EOF
apiVersion: v1
kind: Endpoints
metadata:
  name: $SVC
  namespace: $NS
subsets:
- addresses:
  - ip: $IP
  ports:
EOF
  # render YAML list of ports
  while IFS=$'\t' read -r NAME PORT PROTO; do
    [[ -z "$NAME" ]] && { echo "Service port has no name; name is required to match Service" >&2; exit 1; }
    cat <<EOF
  - name: $NAME
    port: $PORT
    protocol: $PROTO
EOF
  done <<< "$PORTS_TSV"
} > "$TMP_EP"

echo "Applying manual Endpoints pointing to $IP ..."
kubectl $KUBECONFIG_ARG apply -f "$TMP_EP"
rm -f "$TMP_EP"

# 5) Wait (briefly) for EndpointSlice mirroring (if enabled)
echo "Waiting for EndpointSlice mirroring (up to 20s) ..."
for i in {1..10}; do
  if kubectl $KUBECONFIG_ARG -n "$NS" get endpointslice -l "kubernetes.io/service-name=$SVC" -o json \
    | jq -e --arg IP "$IP" '[.items[].endpoints[]?.addresses[]?] | index($IP) != null' >/dev/null; then
    echo "Mirrored EndpointSlice contains $IP"
    exit 0
  fi
  sleep 2
done

echo "No mirrored EndpointSlice found (cluster may not mirror Endpoints). Service will still work via Endpoints." >&2
exit 0