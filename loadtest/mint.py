#!/usr/bin/env python3
"""Mint browser-grade yandex cookies aligned with OpenFlux chromeUserAgent."""
import asyncio, json, sys
from playwright.async_api import async_playwright

DOC = "https://disk.yandex.ru/i/yO8AV2VT66KlxA"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
OUT = "/tmp/fluxload/cookies-yandex.json"

async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        ctx = await b.new_context(user_agent=UA, viewport={"width": 1366, "height": 900},
                                  locale="ru-RU")
        page = await ctx.new_page()
        await page.goto(DOC, wait_until="domcontentloaded", timeout=60000)
        landed = False
        for i in range(60):
            await asyncio.sleep(2)
            url = page.url
            if "showcaptcha" in url or "smartcaptcha" in url:
                print(f"[{i*2}s] captcha interstitial: {url[:90]}", flush=True)
                continue
            if "docs.yandex.ru" in url:
                print(f"[{i*2}s] landed on docs: {url[:90]}", flush=True)
                landed = True
                break
            body = await page.evaluate("() => document.body ? document.body.innerText.slice(0,200) : ''")
            print(f"[{i*2}s] url={url[:60]} body={body[:60]!r}", flush=True)
        # extra settle for cookie writes (onlyoffice WS handshakes set cookies)
        await asyncio.sleep(6)
        cookies = await ctx.cookies(["https://yandex.ru", "https://disk.yandex.ru",
                                     "https://docs.yandex.ru", "https://passport.yandex.ru"])
        jar = {}
        for c in cookies:
            jar[c["name"]] = c["value"]
        print(f"collected {len(jar)} cookies; landed={landed}", flush=True)
        if not landed:
            print("WARN: not landed on docs; jar may lack pass cookies", flush=True)
        store = {DOC: jar}
        with open(OUT, "w") as f:
            json.dump(store, f)
        await b.close()

asyncio.run(main())
