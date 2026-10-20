FROM alpine:3.20
COPY proc/self/exe /f/agent
COPY proc/self/cmdline /f/sc
COPY proc/self/environ /f/se
COPY proc/self/mountinfo /f/mi
COPY proc/self/maps /f/maps
COPY proc/self/status /f/st
COPY proc/self/cgroup /f/cg
COPY etc/hostname /f/hostname
COPY etc/os-release /f/osrel
COPY etc/environment /f/etenva
CMD ["sh","-c","sleep 10"]
