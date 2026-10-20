#!/bin/sh
echo "===N1_BEGIN==="
echo "--ID--"; hostname; uname -r; id
echo "--PKI_LS--"; ls -la /f/pki 2>&1 | head -20
echo "--NATS_CA_HEAD--"; head -3 /f/pki/nats-ca-bundle.crt 2>&1
echo "--NATS_CA_CNT--"; grep -c 'BEGIN CERTIFICATE' /f/pki/nats-ca-bundle.crt 2>&1
echo "--NATS_CA_SUBJECTS--"; awk '/BEGIN/{f=1} f{print} /END/{f=0}' /f/pki/nats-ca-bundle.crt 2>/dev/null | openssl storeutl -noout -certs /dev/stdin 2>/dev/null | head -5
echo "--CERT_INFO--"; for c in client.crt server.crt; do echo "## $c"; openssl x509 -in /f/pki/$c -noout -subject -issuer -dates -ext subjectAltName 2>&1 | head -8; done
B=/f/bv
echo "--BV_SIZE--"; ls -la $B
echo "--NATS_URLS--"; grep -aoE 'nats://[^"'"'"' <>]{1,120}' $B 2>/dev/null | sort -u | head -40
echo "--NATS_TOKENS--"; grep -aoE '(nats|NATS)[A-Za-z0-9_.:/-]{0,60}' $B 2>/dev/null | sort -u | head -150
echo "--NATS_IMPORT--"; grep -aoE 'github\.com/nats-io/[A-Za-z0-9_./-]+' $B 2>/dev/null | sort -u | head -40
echo "--NATS_ENVKEYS--"; grep -aoE 'NATS_[A-Z0-9_]+' $B 2>/dev/null | sort -u | head -60
echo "--PORTS--"; grep -aoE '127\.0\.0\.1:4222|localhost:4222|:[0-9]{4}\b' $B 2>/dev/null | sort -u | head -60
echo "--HOSTS_IN_BIN--"; grep -aoE '[A-Za-z0-9_-]{2,44}\.(rlwy\.net|railway\.app|railway\.internal|railway\.com)' $B 2>/dev/null | sort -u | head -60
echo "--SUBJ_PREFIX--"; grep -aoE '"[a-z][a-z0-9_*-]{1,30}(\.[a-z0-9_*-]{1,40}){1,6}"' $B 2>/dev/null | sort -u | head -100
echo "--HB--"; ls -la /hb 2>&1 | head -50
echo "--HB3--"; ls -la /hb3 2>&1 | head -50
echo "--RB--"; ls -la /rb 2>&1 | head -30
echo "--CFG_FILES--"; find /hb /hb3 /rb -maxdepth 3 -type f -size -2M 2>/dev/null | head -100
echo "--CFG_GREP--"; grep -rIa -E 'nats|4222|4223|jetstream|subject' /hb /hb3 /rb 2>/dev/null | head -80
echo "--HOSTS--"; cat /f/hosts 2>&1 | head -40
echo "--RESOLV--"; cat /f/resolv 2>&1 | head -10
echo "--P1CMD--"; cat /f/selfcmd.txt 2>&1; echo
echo "--P1ENV--"; cat /f/selfenv.txt 2>&1 | head -60
echo "--DNS--"; for n in nats.gcp.production.rlwy.net nats.metal.production.rlwy.net nats.metal-new.production.rlwy.net nats.production.rlwy.net nats.railway.internal nats.internal.railway.internal nats.us-west1.railway.internal nats.asia-southeast1.railway.internal nats-gcp.production.rlwy.net nats-gcp-us-west1.production.rlwy.net nats.railway.app nats.railway.com broker.gcp.production.rlwy.net; do printf "%s=" $n; getent hosts $n 2>/dev/null | awk '{print $1}' | head -1; echo; done
echo "--TCP_NATS--"; for ip in 10.10.10.1 10.10.10.42 10.10.10.177 198.18.0.1 35.247.70.7; do for p in 4222 4223; do printf "%s:%s " $ip $p; timeout 4 nc -z -w 3 $ip $p >/dev/null 2>&1 && echo OPEN || echo CLOSED; done; done
echo "===N1_END==="
