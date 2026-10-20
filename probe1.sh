#!/bin/sh
G=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
C="--cert /pki/client.crt --key /pki/client.key -k --connect-timeout 2 -m 4"
echo "===P1==="
echo "--TLSCHAIN--"
openssl s_client -connect $G:443 -servername $G -cert /pki/client.crt -key /pki/client.key </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null | head -4
echo "--SNI_ALPN--"
openssl s_client -connect $G:443 -servername $G -alpn h2,http/1.1 -cert /pki/client.crt -key /pki/client.key </dev/null 2>/dev/null | grep -aE "ALPN|Verification|Verify return" | head -3
echo "--CTRL_NOHEADER--"
curl -sS -o /tmp/o -D /tmp/h -w 'code=%{http_code} size=%{size_download} ct=%{content_type}\n' $C https://$G/ 2>&1
head -c 120 /tmp/o | tr -d '\0'
grep -aiE '^(HTTP|server|x-|content-type|grpc|www-auth)' /tmp/h | head -6
echo "--CTRL_GARBAGE--"
curl -sS -o /tmp/o -D /tmp/h -w 'code=%{http_code} size=%{size_download}\n' $C -H 'x-mpipe-target: _nope_' https://$G/ 2>&1
head -c 120 /tmp/o | tr -d '\0'
grep -aiE '^(HTTP|server|x-|grpc)' /tmp/h | head -6
echo "--MATRIX1--"
for T in orchestrator orchestrator.gcp.production.rlwy.net orchestrator.metal.production.rlwy.net internal_orchestrator internal-orchestrator internalorchestrator backboard backboard.gcp.production.rlwy.net registry registry.gcp.production.rlwy.net registry.metal.production.rlwy.net registrymetal stacklet stacklet.gcp.production.rlwy.net stacklet.metal.production.rlwy.net stacklet.certs.railway.app certs certs.gcp.production.rlwy.net nats nats.gcp.production.rlwy.net storage-agent network-cp railyard station csc builder internal_builder buildkit traces internal_traces otel otlp mpipe hikari api gateway sandbox edge web; do
  R=$(curl -sS -o /tmp/o -D /tmp/h -w '%{http_code} %{size_download} %{content_type}' $C -H "x-mpipe-target: $T" https://$G/ 2>/dev/null)
  S=$(grep -aiE '^server:' /tmp/h | head -1 | tr -d '\r')
  B=$(head -c 60 /tmp/o 2>/dev/null | tr -d '\0' | tr '\n\r' '  ')
  echo "$T|$R|$S|$B"
done
echo "--HOSTHDR--"
for T in orchestrator.gcp.production.rlwy.net orchestrator.metal.production.rlwy.net orchestrator registry stacklet.gcp.production.rlwy.net stacklet; do
  R=$(curl -sS -o /tmp/o -D /tmp/h -w '%{http_code} %{size_download}' $C -H "Host: $T" https://$G/ 2>/dev/null)
  B=$(head -c 60 /tmp/o 2>/dev/null | tr -d '\0' | tr '\n\r' '  ')
  echo "H:$T|$R|$B"
done
echo "--SNIPROBE--"
IP=$(getent hosts $G | awk '{print $1}' | head -1)
echo "gwip=$IP"
for N in orchestrator.gcp.production.rlwy.net stacklet.gcp.production.rlwy.net stacklet.certs.railway.app registry.gcp.production.rlwy.net registry.metal.production.rlwy.net nats.gcp.production.rlwy.net; do
  R=$(curl -sS -o /tmp/o -D /tmp/h -w '%{http_code} %{size_download}' $C --resolve "$N:443:$IP" https://$N/ 2>/dev/null)
  B=$(head -c 60 /tmp/o 2>/dev/null | tr -d '\0' | tr '\n\r' '  ')
  echo "SNI:$N|$R|$B"
done
echo "--GRPC--"
for T in NONE orchestrator orchestrator.gcp.production.rlwy.net stacklet stacklet.certs.railway.app internal_traces; do
  for M in /grpc.health.v1.Health/Check /grpc.reflection.v1.ServerReflection/ServerReflectionInfo /orchestrator.v1.Orchestrator/Ping; do
    if [ "$T" = NONE ]; then HDR=""; else HDR="x-mpipe-target: $T"; fi
    R=$(curl -sS --http2 -o /tmp/go -D /tmp/gh -w '%{http_code} %{size_download}' $C ${HDR:+-H "$HDR"} -H 'content-type: application/grpc' -H 'te: trailers' --data-binary '\000\000\000\000\000' https://$G$M 2>/dev/null)
    GH=$(grep -aiE '^(HTTP|grpc-status|grpc-message|content-type|server)' /tmp/gh | tr '\n' ' ' | tr -d '\r')
    echo "G:$T$M|$R|$GH"
  done
done
echo "--OPTS--"
for T in orchestrator stacklet registry; do
  R=$(curl -sS -o /tmp/o -D /tmp/h -X OPTIONS -w '%{http_code} %{size_download}' $C -H "x-mpipe-target: $T" https://$G/ 2>/dev/null)
  echo "O:$T|$R|$(grep -aiE '^(allow|access-control|server)' /tmp/h | tr '\n' ' ' | tr -d '\r')"
done
echo "===P1END==="
