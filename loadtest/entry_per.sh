#!/bin/sh
# 1) mint a private browser identity (cookies)  2) start the flux client
python3 /mint.py || { echo "MINT_FAILED rc=$?"; exit 1; }
exec openflux \
  --role client \
  --inbound socks5 \
  --transport yandex \
  --url "https://disk.yandex.ru/i/yO8AV2VT66KlxA" \
  --cookie-store /data/cookies-yandex.json \
  --socks5 "0.0.0.0:${1:-1080}" \
  --debug
