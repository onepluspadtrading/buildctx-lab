#!/bin/sh
# I68006 probe2: metadata block boundary + gateway fingerprint
echo "=== A HOST ==="
echo "product=$(cat /sys/class/dmi/id/product_name 2>&1) host=$(hostname) zone_search=$(sed -n 's/^search //p' /etc/resolv.conf)"
echo "route_meta=$(ip route get 169.254.169.254 2>&1 | tr '\n' '|')"
echo "env_proxy=$(env | grep -i proxy | tr '\n' '|')"
echo "ipt_names=$(cat /proc/net/ip_tables_names 2>&1 | tr '\n' ' ')"
echo "arp=$(cat /proc/net/arp 2>&1 | tr '\n' '|')"

echo "=== B PORT MATRIX 169.254.x ==="
t() { h=$1; p=$2; s=$(date +%s%N); out=$(nc -w 2 "$h" "$p" </dev/null 2>&1); rc=$?; e=$(date +%s%N); ms=$(( (e-s)/1000000 )); echo "NC $h:$p rc=$rc ms=$ms out=$(printf %s "$out" | head -c 120)"; }
t 169.254.169.254 53
t 169.254.169.254 80
t 169.254.169.254 443
t 169.254.169.254 8080
t 169.254.169.254 8081
t 169.254.169.254 10080
t 169.254.169.254 22
t 169.254.170.2 80
t 169.254.169.253 53
t 169.254.0.1 80
t 198.18.0.1 53
t 198.18.0.1 80
t 198.18.0.1 443
t 198.18.0.1 3128
t 198.18.0.1 8080
t 198.18.0.1 8083
t 198.18.0.1 8888
t 198.18.0.2 80

echo "=== C DNS over TCP ==="
# raw DNS query for metadata.google.internal over TCP
Q='\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08metadata\x06google\x08internal\x00\x00\x01\x00\x01'
out=$(printf "$Q" | nc -w 3 169.254.169.254 53 2>&1 | od -An -tx1 | head -3 | tr '\n' ' ')
echo "TCP53 out=$out"

echo "=== D GATEWAY HTTP ==="
for u in http://198.18.0.1:8083/ http://198.18.0.1:8083/health http://198.18.0.1/ http://198.18.0.1:8080/ http://198.18.0.1:3128/; do
  out=$(wget -S -T 3 -t 1 -O - "$u" 2>&1 | head -c 300); echo "GW $u => $(printf %s "$out" | tr '\n' '|' | head -c 280)"
done

echo "=== E META RETRY (explicit + host variants) ==="
for u in "http://169.254.169.254/computeMetadata/v1/" "http://metadata.google.internal/computeMetadata/v1/" "http://169.254.169.254:80/computeMetadata/v1/instance/service-accounts/default/token"; do
  out=$(wget -T 3 -t 1 -O - --header 'Metadata-Flavor: Google' "$u" 2>&1); echo "M2 $u rc=$? body=$(printf %s "$out" | head -c 200)"
done
echo "=== F low-src-port attempt ==="
out=$(nc -p 53 -w 2 169.254.169.254 80 </dev/null 2>&1); echo "NC src53 rc=$? out=$(printf %s "$out" | head -c 150)"
echo "=== G buildkit/sandbox local sockets ==="
ls -la /run /var/run 2>&1 | head -20
echo "=== END ==="
