FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates
COPY openflux /usr/local/bin/openflux
COPY cookies-yandex.json /data/cookies-yandex.json
COPY entry.sh /entry.sh
RUN chmod +x /entry.sh
ENTRYPOINT ["/entry.sh"]
