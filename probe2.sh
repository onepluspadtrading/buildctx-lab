#!/bin/sh
echo "===P2==="
echo "--ID--"; hostname; cat /etc/hostname 2>/dev/null; uname -r; id
echo "--ROUTE--"; ip route 2>/dev/null || cat /proc/net/route
echo "--DNS--"
for n in external-mtls-service-gateway-us-west1.gcp.production.rlwy.net external-mtls-service-gateway-us-west1.metal.production.rlwy.net external-mtls-service-gateway-us-east4.gcp.production.rlwy.net external-mtls-service-gateway-asia-southeast1.gcp.production.rlwy.net external-mtls-service-gateway-us-central1.gcp.production.rlwy.net external-mtls-service-gateway.gcp.production.rlwy.net orchestrator.gcp.production.rlwy.net orchestrator.metal.production.rlwy.net registry.gcp.production.rlwy.net stacklet.gcp.production.rlwy.net stacklet.metal.production.rlwy.net nats.gcp.production.rlwy.net builder-lhmgif.railway.internal; do printf "%s=" $n; getent hosts $n | awk '{print $1}' | head -1; echo; done
echo "--EGRESS--"
for u in https://example.com https://registry-1.docker.io/v2/ https://backboard.railway.com/graphql/v2; do printf "%s " $u; curl -s -m 6 -o /dev/null -w "%{http_code} %{remote_ip}\n" $u; done
echo "--TCPGW--"
for ip in 35.247.70.7 34.107.141.139 69.46.46.46; do printf "%s:443 " $ip; timeout 5 nc -z -w 4 $ip 443 >/dev/null 2>&1 && echo OPEN || echo TO; done
echo "--TCPORCH--"
for ip in 10.10.10.42 10.10.10.1; do printf "%s:443 " $ip; timeout 5 nc -z -w 4 $ip 443 >/dev/null 2>&1 && echo OPEN || echo TO; done
echo "--GW_TLS--"
G=external-mtls-service-gateway-us-west1.gcp.production.rlwy.net
timeout 6 openssl s_client -connect $G:443 -servername $G </dev/null 2>&1 | head -5
echo "===P2END==="
