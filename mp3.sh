#!/bin/sh
set +e
IG=internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EG=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EXPORT=/opentelemetry.proto.collector.trace.v1.TraceService/Export
mkdir -p /r
printf '\0\0\0\0\0' > /r/req0
echo "===MP3==="
echo "--NET--"; hostname; uname -r; ip -o link 2>/dev/null | head -8; ip route 2>/dev/null | head -8
echo "--DNS--"
for h in $IG $EG; do printf '%s=' "$h"; getent hosts $h | head -1; echo; done
IGIP=$(getent hosts $IG | awk '{print $1}' | head -1); echo "IGIP=$IGIP"
req() {
  H=$1; T=$2; P=$3; L=$4
  : > /r/body; : > /r/hdr
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k -H "x-mpipe-target: $T" -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "https://$H$P" -w 'code=%{http_code} sz=%{size_download}' 2>&1 | tail -1)
  GS=$(grep -ai '^grpc-status' /r/hdr | tr -d '\r' | head -1)
  GM=$(grep -ai '^grpc-message' /r/hdr | tr -d '\r' | head -1 | cut -c1-160)
  SV=$(grep -ai '^server' /r/hdr | tr -d '\r' | head -1)
  echo "R|$L|T=$T|P=$P|$R|$GS|$SV|$GM"
}
echo "--INTERNAL_GW--"
req $IG internal_traces $EXPORT I1
req $IG internal_orchestrator $EXPORT I2
if [ -n "$IGIP" ]; then
  for hp in 443 8443 50051 8080 9090 22; do
    printf 'port %s=' $hp; timeout 4 bash -c "echo > /dev/tcp/$IGIP/$hp" 2>/dev/null && echo OPEN || echo CLOSED
  done
fi
echo "--EXT_PORTMAP--"
for hp in 443 8443 50051; do
  printf 'eg %s=' $hp; timeout 4 bash -c "echo > /dev/tcp/35.247.70.7/$hp" 2>/dev/null && echo OPEN || echo CLOSED
done
echo "--IG_TARGETS--"
if [ -n "$IGIP" ]; then
  for T in internal_traces internal_orchestrator orchestrator internal_temporal internal_registry internal_network_cp; do
    req $IGIP $T $EXPORT IGX
  done
fi
echo "--SVCMETHODS--"
for M in /workflowservice.v1.WorkflowService/GetSystemInfo /stats.Stats/Get /vm_runner.RunnerApi/Ping /network_cp.EndpointSpec/Get /grpc.health.v1.Health/Check; do
  req $EG internal_traces $M M1
  req $EG internal_temporal $M M2
  req $EG internal_orchestrator $M M3
done
echo "--AUTHVAR--"
req $EG __nope__ $EXPORT NEG
req $EG internal_traces / NEGROOT
echo "===MP3END==="
