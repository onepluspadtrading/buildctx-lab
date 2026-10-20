FROM alpine:3.20 AS base
ONBUILD RUN --mount=type=bind,source=.,target=/ctx sh -c 'set +e; echo --L1--; ls -la /ctx 2>&1 | head -60; echo --L2--; for d in /ctx/*; do echo "== $d"; ls -la "$d" 2>&1 | head -8; done | head -200; echo --LEND--'
FROM base
RUN true
CMD ["true"]
