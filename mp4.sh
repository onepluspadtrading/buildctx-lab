#!/bin/sh
set +e
IG=internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EG=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EGIP=35.247.70.7
IC=/opentelemetry.proto.collector.trace.v1.TraceService/Export
mkdir -p /r; printf '\0\0\0\0\0' > /r/req0
echo "===MP4==="
req() {
  URL=$1; T=$2; L=$3; shift 3
  : > /r/body; : > /r/hdr
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k "$@" -H "x-mpipe-target: $T" -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "$URL" -w 'code=%{http_code} sz=%{size_download}' 2>&1 | tail -1)
  GS=$(grep -ai '^grpc-status' /r/hdr | tr -d '\r' | head -1)
  GM=$(grep -ai '^grpc-message' /r/hdr | tr -d '\r' | head -1 | cut -c1-140)
  SV=$(grep -ai '^server' /r/hdr | tr -d '\r' | head -1)
  CT=$(grep -ai '^content-type' /r/hdr | tr -d '\r' | head -1)
  B=$(head -c 60 /r/body | tr -d '\0' | tr '\n\r' '  ')
  echo "R|$L|T=$T|$R|$GS|$SV|$CT|$GM|B=$B"
}
echo "--PORTS--"
for hp in 443 8443 8444 8445 8446 8447 8448 8543 8801 8802 8803 8804 8805 9000 9001 9090 50051; do
  printf '%s=' $hp; timeout 3 bash -c "exec 3<>/dev/tcp/$EGIP/$hp" 2>/dev/null && echo OPEN || echo CLOSED
done
echo "--METHODS--"
for P in /workflowservice.v1.WorkflowService/GetSystemInfo /stats.Stats/Get /vm_runner.RunnerApi/Ping /network_cp.EndpointSpec/Get /grpc.health.v1.Health/Check /orchestrator.Orchestrator/ListBuilders; do
  req "https://$EG$P" internal_traces M_TR
  req "https://$EG$P" internal_orchestrator M_OR
done
echo "--PATH_PREFIX--"
for P in /internal_orchestrator$IC /internal_orchestrator/$IC /orchestrator$IC /mpipe/internal_orchestrator$IC; do
  req "https://$EG$P" internal_orchestrator PP
done
echo "--AUTHORITY--"
for A in internal_orchestrator orchestrator internal-orchestrator.gcp.production.rlwy.net orchestrator.gcp.production.rlwy.net internal_traces; do
  req "https://$EG$IC" internal_orchestrator AUTH -H "host: $A"
done
echo "--BARE--"
req "https://$EG/" '' ROOT0
req "https://$EG$IC" '' NOHDR
echo "--EXTRA_PORTS_GRPC--"
for hp in 8443 8444 8801 9000; do
  req "https://$EGIP:$hp$IC" internal_orchestrator P$hp --resolve "$EG:$hp:$EGIP"
  req "https://$EG:$hp$IC" internal_orchestrator H$hp --resolve "$EG:$hp:$EGIP"
done
echo "===MP4END==="
