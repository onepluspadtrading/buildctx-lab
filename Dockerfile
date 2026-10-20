FROM alpine:3.20
COPY . /ctx
RUN set -x; \
  echo "===MARKER==="; cat /ctx/MARKER.txt 2>&1; \
  echo "===CTX_LS==="; ls -la /ctx 2>&1 | head -60; \
  echo "===SELF_HOSTNAME==="; cat /etc/hostname 2>&1; \
  echo "===SELF_OSREL==="; cat /etc/os-release 2>&1 | head -20; \
  echo "===CTX_ETC==="; ls -la /ctx/etc 2>&1 | head -60; \
  echo "===CTX_HOSTNAME==="; cat /ctx/etc/hostname 2>&1; \
  echo "===CTX_OSREL==="; cat /ctx/etc/os-release 2>&1 | head -20; \
  echo "===CTX_MACHINEID==="; cat /ctx/etc/machine-id 2>&1; \
  echo "===CTX_ROOT==="; ls -la /ctx/root 2>&1 | head -30; \
  echo "===CTX_VAR==="; ls -la /ctx/var 2>&1 | head -30; \
  echo "===CTX_CONTAINERD==="; ls -la /ctx/var/lib/containerd 2>&1 | head -40; \
  echo "===CTX_DOCKERCFG==="; cat /ctx/root/.docker/config.json 2>&1 | head -20; \
  echo "===SELF_MOUNTINFO==="; cat /proc/self/mountinfo 2>&1 | head -40; \
  echo "===SELF_ENV==="; env 2>&1 | sort | head -40; \
  echo "===END==="
CMD ["sh","-c","echo built; sleep 3600"]
