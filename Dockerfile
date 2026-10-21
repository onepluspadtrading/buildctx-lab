FROM alpine:3.20
RUN apk add --no-cache openssl >/dev/null 2>&1; echo APKDONE
COPY probe /probe
COPY collect.sh /collect.sh
RUN sh -c 'sh /collect.sh 2>&1 | head -c 100000; echo; echo MARK-I75522-END'
RUN echo MARK-I75522-tail
