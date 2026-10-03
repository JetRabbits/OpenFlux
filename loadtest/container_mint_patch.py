#!/usr/bin/env python3
"""In-container cookie mint: fresh anonymous browser identity per container.
Writes OpenFlux cookie-store JSON, then prints MINT_DONE."""
import json, sys, time
from patchright.sync_api import sync_playwright

DOC = "https://disk.yandex.ru/i/yO8AV2VT66KlxA"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
OUT = "/data/cookies-yandex.json"
T0 = time.time()

with sync_playwright() as p:
    b = p.chromium.launch(channel="chromium", headless=True, args=["--no-sandbox"])
    ctx = b.new_context(user_agent=UA, viewport={"width": 1366, "height": 900},
                        locale="ru-RU")
    page = ctx.new_page()
    page.goto(DOC, wait_until="domcontentloaded", timeout=60000)
    landed = False
    clicked = False
    for i in range(75):  # up to 150s: pass may involve fast-captcha or smartcaptcha
        url = page.url
        if "docs.yandex.ru" in url and "showcaptcha" not in url:
            landed = True
            break
        if "showcaptcha?cc=1" in url and not clicked:
            # interactive SmartCaptcha: try the checkbox (in frame or inline)
            try:
                frame = page.frame_locator("#js_smartCaptchTarget")
                frame.locator("input[type=checkbox]").first.click(timeout=3000)
            except Exception:
                try:
                    page.locator("input[type=checkbox], #checkbox, .Checkbox2-input").first.click(timeout=3000)
                except Exception as e:
                    print(f"CAPTCHA_CLICK_FAIL t={time.time()-T0:.0f}s {type(e).__name__}", flush=True)
            clicked = True
            print(f"CAPTCHA_CLICKED t={time.time()-T0:.0f}s", flush=True)
        time.sleep(2)
    time.sleep(6)  # let onlyoffice handshake cookies settle
    cookies = ctx.cookies(["https://yandex.ru", "https://disk.yandex.ru",
                           "https://docs.yandex.ru", "https://passport.yandex.ru"])
    jar = {c["name"]: c["value"] for c in cookies}
    with open(OUT, "w") as f:
        json.dump({DOC: jar}, f)
    uid = jar.get("yandexuid", "?")
    print(f"MINT_DONE t={time.time()-T0:.1f}s landed={landed} cookies={len(jar)} uid={uid}", flush=True)
    b.close()

sys.exit(0 if landed and len(jar) >= 5 else 1)
