#!/bin/sh
# $1 = socks port inside container
exec openflux \
  --role client \
  --inbound socks5 \
  --transport yandex \
  --url "https://disk.yandex.ru/i/yO8AV2VT66KlxA" \
  --cookie-store /data/cookies-yandex.json \
  --socks5 "0.0.0.0:${1:-1080}" \
  --debug
