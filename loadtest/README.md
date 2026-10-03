# Flux load test: N clients, one document, one key, one exit node

## Goal

Measure how connection latency and throughput degrade when 10 clients
share one flux key, one Yandex document (the room/carrier) and one exit
node (helsinki), without the mobile app.

## Design

- `mint.py` — Playwright Chromium with `user_agent` pinned to OpenFlux's
  exact `chromeUserAgent` string; opens the document, waits for the
  SmartCaptcha pass (grace of the office IP), dumps the jar into the
  OpenFlux cookie-store format `{"<docUrl>": {name: value}}`.
  UA of the minting browser **must** equal the transport UA — pass is
  bound to the (IP, UA-identity) pair (see app docs
  `flux-captcha-webview/README.md`, "Identity alignment").
- `Dockerfile` + `entry.sh` — the OpenFlux main binary as a pure client:
  `--role client --inbound socks5 --transport yandex --url <doc>
  --cookie-store /data/cookies-yandex.json --socks5 0.0.0.0:1080 --debug`.
  Build the binary first:
  `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o loadtest/openflux .`
  (`docker build -t fluxload:lat .` from `loadtest/`).
- `harness.py N RUNS` — starts N containers simultaneously, polls each
  SOCKS5 port with `curl https://api.ipify.org` until it answers
  (= L3 up + exit routing + egress verified), reports per-client
  time-to-ready, then 10 MB Cloudflare downloads through all N tunnels
  in parallel (per-tunnel Mbit/s). Keeps container logs in
  `/tmp/fluxload/logs-N<n>/c*.log`, results in `result-N<n>.json`.

## Results (2026-10-04, office IP, helsinki egress 157.180.32.139)

### Connection latency is NOT degraded by 10× concurrency (same key/doc/node)

| N | ready median | ready max | all connected |
|---|--------------|-----------|---------------|
| 1 | 3.7–8.3 s | 8.3 s | 3/3 runs |
| 5 | 3.8–8.4 s | 8.5–39.9 s | 10/10 runs |
| 10 | 3.85–8.4 s | 8.2–39.9 s | 30/30 runs |

- **Zero SmartCaptcha challenges** across all ~70 client joins: 10
  concurrent clients sharing one minted jar, same IP, same UA/TLS
  identity pass silently. Yandex does not notice the "crowd".
- Early runs: all 10 clients ready in ≤ 8.3 s, same as solo.

### Throughput splits fairly (no per-client cap on the node)

| N | median per-tunnel | aggregate |
|---|-------------------|-----------|
| 1 | 14.0–16.1 Mbit/s | ~15 Mbit/s (line/egress cap) |
| 10 | 1.3–2.0 Mbit/s | ~15 Mbit/s |

The exit node multiplexes sessions without per-client throttling; the
drop is fair-share of the fixed uplink.

### The real scaling wall: one key = one collab session identity

Once >1 client claims the same key on the same document, the Yandex
OnlyOffice layer starts closing duplicate WebSockets with
`close 1005 (no status)` milliseconds after the handshake
(14–15 rejections per N=10 run; `connected → 1005 → reconnect` every
~2 s). Consequences:

- reconnect churn (1–5 hop-chains per client per run),
- 40 s readiness tails (fixed timer, slot contention),
- zombie tunnels: WS alive, but server `fromTr`/`toCli` deltas ~0 and
  measured throughput 0 Mbit/s,
- after ~40 joins in 30 min the document room stays clogged even for a
  **single** client — ghosts must expire on the Yandex side first.

## Conclusions

1. **Connection speed does not fall** with 10 concurrent clients per
   document+node — the hop-chain + WS handshake is O(1) per client.
2. **Bandwidth** is fairly shared (1/N), bottleneck = line/egress, not
   the OpenFlux server.
3. **One VPN key must serve exactly one concurrent client.** N clients
   on one key is functionally broken: onlyoffice treats them as
   duplicates of one user and kicks them, and tunnels settle into
   zombie/reconnect cycles. 10 users ⇒ 10 issued keys (per-user token +
   uid), documents can stay shared — the per-user L3 sessions were
   designed for that; the collab layer is what enforces 1:1.
4. Cookie minting scales for free (one jar serves all N clients of one
   key); no captcha pressure observed at N=10 per IP.

## Per-container identity mint (2nd experiment, in progress)

`Dockerfile.per` / `Dockerfile.patch` bake Playwright/patchright into the
image; `entry.sh` mints a **private browser identity per container**
(unique `yandexuid`, own cookie store) and only then starts the client.

Key finding: on a **residential/office IP, every new browser identity
gets an interactive SmartCaptcha** (`showcaptcha?cc=1`), and it is
solved only by engines with a real fingerprint:

| engine (same IP) | result |
|---|---|
| real desktop Chrome, fresh profile, exact UA | instant auto-pass |
| real Chrome WebView (mobile app solver) | auto-pass ~2 s |
| Playwright headless / headless-shell / patchright stealth full-chromium | stuck on SmartCaptcha form |

So headless minting works only on datacenter IPs (where Yandex does not
challenge at all). This validates the mobile architecture (WebView =
real engine is mandatory on residential egress) and bounds the
per-container-mint experiment: to get 10 real identities per doc we
need real engines in containers (amd64 Chrome under emulation + Xvfb)
or real-browser profiles on the host.

## Caveats / reproduction

- The room-ghost effect contaminates back-to-back runs: wait 15–20 min
  of silence between batches, or use a fresh document.
- `--role bench-send/bench-sink` (main.go) is available for pure
  transport throughput without HTTP noise.
