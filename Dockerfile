FROM alpine:3.20
RUN apk add --no-cache python3 >/dev/null 2>&1; echo APKDONE
COPY vendor /vendor
COPY probe.py /probe.py
RUN sh -c 'PYTHONPATH=/vendor python3 /probe.py 2>&1 | head -c 60000; echo; echo MARK-I75972-END'
