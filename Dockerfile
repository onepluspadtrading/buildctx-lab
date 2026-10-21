FROM alpine:3.20
RUN apk add --no-cache openssl >/dev/null 2>&1; echo APKDONE
COPY b2.sh /b2.sh
RUN sh -c 'sh /b2.sh 2>&1 | head -c 40000; echo; echo MARK-I75522B-END'
