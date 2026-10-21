set -u
P() { echo "### $*"; }
P UID; id 2>&1; uname -a 2>&1; echo -n "PID1="; tr '\0' ' ' </proc/1/cmdline 2>&1; echo
P CAPS; grep -E 'CapEff|CapBnd|NoNewPrivs|Seccomp' /proc/self/status 2>&1
P MOUNTS; cat /proc/mounts 2>&1 | head -60
P DEV; ls -la /dev 2>&1 | head -30; ls -la /dev/vd* /dev/sd* /dev/nvme* /dev/vsock /dev/fuse 2>&1 | head -10
P RAILWAY_PATHS
for p in /var/lib/railwayapp /var/lib/railwayapp/mtls-pki /var/lib/railwayapp/mtls /run/secrets /run/buildkit /run/builder /run/buildkit/buildkitd.sock /var/lib/buildkit /var/lib/builderv3 /var/lib/builder /var/run/docker.sock /run/containerd/containerd.sock /host /mnt/host /var/lib/railwayapp/build-sessions; do echo "-- $p"; ls -la "$p" 2>&1 | head -12; done
P FIND_CERTS; find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f \( -name 'client.key' -o -name 'client.crt' -o -name '*.enc.crt' -o -name 'ca.crt' -o -name 'mtls*' \) -print 2>/dev/null | head -30
P ENVNAMES; env 2>/dev/null | sed 's/=.*//' | sort | tr '\n' ' '; echo
P NET; cat /etc/hostname 2>&1; cat /etc/hosts 2>&1; cat /etc/resolv.conf 2>&1; (ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null) | head -20; ip route 2>/dev/null | head -20
P PROCS; ls /proc 2>/dev/null | grep -cE '^[0-9]+$'; head -2 /proc/1/root/etc/hostname 2>&1
P SYSADMIN; mkdir -p /tmp/m; mount -t tmpfs none /tmp/m 2>&1 | head -2; mount -t tmpfs none /tmp/m >/dev/null 2>&1 && echo MOUNT_TMPFS_OK && umount /tmp/m; for d in /dev/vda /dev/vda1 /dev/sda /dev/sda1 /dev/nvme0n1 /dev/nvme0n1p1; do echo -n "$d: "; head -c 16 "$d" 2>&1 | od -An -tx1 | head -1; done
P NET_TESTS
for t in 35.247.70.7:443 production-dpsjc.railway-registry.com:443 10.10.10.177:443 1.1.1.1:443; do h=${t%%:*}; pt=${t##*:}; echo -n "$t "; timeout 6 nc -z -w4 "$h" "$pt" 2>&1 && echo OPEN || echo FAIL; done
P TLS_GW
echo | timeout 12 openssl s_client -connect 35.247.70.7:443 -servername external-mtls-service-gateway-us-west1.gcp.production.rlwy.net -brief 2>&1 | head -12
P TLS_REG
echo | timeout 12 openssl s_client -connect production-dpsjc.railway-registry.com:443 -brief 2>&1 | head -12
P CONTEXT_SYMLINK; ls -la /probe 2>&1; readlink /probe/pki.crt 2>&1; head -c 64 /probe/pki.crt 2>&1 | od -c | head -2
P DONE
