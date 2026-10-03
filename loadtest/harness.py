#!/usr/bin/env python3
"""Flux load test: N clients, one doc, one key, one exit node.
Measures per-client time-to-ready (curl-over-socks succeeds) and parallel throughput."""
import json, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 3
BASE_PORT = 11000
DOC = "lt"
IMAGE = __import__("os").environ.get("FLUX_IMAGE", "fluxload:lat")

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def cleanup():
    sh(f'docker ps -aq --filter name=^{DOC} | xargs -r docker rm -f')

def launch(i):
    port = BASE_PORT + i
    sh(f'docker rm -f {DOC}{i} >/dev/null 2>&1')
    r = sh(f'docker run -d --name {DOC}{i} -p 127.0.0.1:{port}:1080 {IMAGE} 1080')
    return port, time.monotonic()

def probe(port):
    r = subprocess.run(["curl", "-s", "--max-time", "4",
                        "--socks5-hostname", f"127.0.0.1:{port}",
                        "https://api.ipify.org?format=json"],
                       capture_output=True, text=True)
    try:
        return json.loads(r.stdout).get("ip", "")
    except Exception:
        return ""

def wait_ready(i, port, deadline=120.0, t0=None):
    t0 = t0 or time.monotonic()
    while time.monotonic() - t0 < deadline:
        ip = probe(port)
        if ip:
            return i, time.monotonic() - t0, ip
        time.sleep(0.5)
    return i, None, ""

def bench(port, mb=10):
    url = f"https://speed.cloudflare.com/__down?bytes={mb*1000000}"
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", "90",
                        "--socks5-hostname", f"127.0.0.1:{port}",
                        "-w", "%{speed_download} %{http_code}", url],
                       capture_output=True, text=True)
    try:
        spd, code = r.stdout.split()
        return round(float(spd) * 8 / 1e6, 2), code  # Mbit/s
    except Exception:
        return 0.0, "ERR"

def run_once(n):
    cleanup()
    time.sleep(3)
    with ThreadPoolExecutor(max_workers=n) as ex:
        started = list(ex.map(launch, range(n)))  # staggered by daemon start cost
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=n) as ex:
        res = list(ex.map(lambda a: wait_ready(a[0], a[1], t0=t0), enumerate([p for p, _ in started])))
    ready = {i: (t, ip) for i, t, ip in res}
    # mint phase (per-container, from MINT_DONE t=)
    mints = {}
    for i in sorted(ready):
        log = sh(f'docker logs {DOC}{i} 2>&1 | grep -oE "MINT_DONE t=[0-9.]+s landed=\S+ cookies=[0-9]+ uid=\S+"')
        mints[i] = log.stdout.strip()
    # throughput: all parallel
    with ThreadPoolExecutor(max_workers=n) as ex:
        sp = list(ex.map(lambda i: bench(BASE_PORT + i), sorted(ready)))
    out = []
    for i in sorted(ready):
        t, ip = ready[i]
        mbps, code = sp[i]
        log = sh(f'docker logs {DOC}{i} 2>&1 | grep -icE "showcaptcha|smartcaptcha|429|reconnect|disconnected|deadline exceeded|EOF|refused"')
        out.append({"mint": mints.get(i, ""), "i": i, "ready_s": round(t, 2) if t else None, "ip": ip,
                    "mbps": mbps, "http": code, "warn_lines": log.stdout.strip()})
    import os
    os.makedirs(f"/tmp/fluxload/logs-N{n}", exist_ok=True)
    for i in range(n):
        sh(f'docker logs {DOC}{i} > /tmp/fluxload/logs-N{n}/c{i}.log 2>&1')
    return out

if __name__ == "__main__":
    allruns = []
    for r in range(RUNS):
        o = run_once(N)
        ok = [x["ready_s"] for x in o if x["ready_s"]]
        allruns.append({"run": r, "results": o,
                        "connected": len(ok),
                        "t_med": sorted(ok)[len(ok)//2] if ok else None,
                        "t_max": max(ok) if ok else None,
                        "t_spread": (max(ok) - min(ok)) if ok else None,
                        "mbps_med": sorted(x["mbps"] for x in o)[len(o)//2] if o else None})
        print(f"[N={N} run={r}] connected={len(ok)}/{N} med={allruns[-1]['t_med']}s "
              f"max={allruns[-1]['t_max']}s spread={allruns[-1]['t_spread']}s "
              f"mbps_med={allruns[-1]['mbps_med']}", flush=True)
    cleanup()
    with open(f"/tmp/fluxload/result-N{N}.json", "w") as f:
        json.dump(allruns, f, indent=1)
