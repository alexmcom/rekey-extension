#!/usr/bin/env python3
"""
Rekey — real-site page capturer (feeds the F11 test battery)
============================================================
Opens a real browser (headless), visits real login / signup / reset pages,
lets the JavaScript render, and saves each page's RENDERED HTML into
  product/extension/fixtures/realsite/cap-<slug>.html
plus a stub <slug>.json the battery can read.

WHY a real browser: modern login pages build their forms with JavaScript, so a
plain download gets an empty shell. Playwright renders the page like Chrome does,
so the saved HTML is what the extension actually sees. That's the whole point:
test the engine against REAL structures, not hand-made mocks.

The captured pages are saved UNLABELLED. The battery (test-realsite-battery.js)
then flags any page that has a password box but where the engine found no login
and no new-password form — i.e. a likely real miss to fix. That's the bug finder.

ONE-TIME SETUP (paste each line in Terminal, press Enter, wait):
  pip3 install playwright --break-system-packages
  python3 -m playwright install chromium

RUN IT (paste, Enter):
  python3 "/Users/alex/Claude/Projects/New Business plan to make money/product/extension/capture-realsite.py"

Then tell Claude "captured" — it reads the pages and runs the battery.

Notes: this only visits PUBLIC pages and saves their HTML. It does NOT log in,
type anything, or touch your accounts. Edit SITES below to add pages you care about.
"""

import json
import os
import re
import sys
from datetime import date

# (url, kind) — kind is just a hint for the report. Add/remove freely.
# Spread across DIFFERENT structures on purpose: SPA logins, multi-step, signups,
# resets, and known-tricky ones (regfox/webconnex are our real cases).
SITES = [
    ("https://github.com/login", "login"),
    ("https://github.com/join", "signup"),
    ("https://gitlab.com/users/sign_in", "login"),
    ("https://bitbucket.org/account/signin/", "login"),
    ("https://auth.regfox.com/", "login"),
    ("https://www.reddit.com/login", "login"),
    ("https://www.dropbox.com/login", "login"),
    ("https://www.figma.com/login", "login"),
    ("https://app.hubspot.com/login", "login"),
    ("https://trello.com/login", "login"),
    ("https://www.notion.so/login", "login"),
    ("https://accounts.google.com/signin", "login-multistep"),
    ("https://login.yahoo.com/", "login-multistep"),
    ("https://signin.ebay.com/", "login"),
    ("https://www.paypal.com/signin", "login"),
    ("https://www.spotify.com/us/login/", "login"),
    ("https://vault.bitwarden.com/#/register", "signup"),
    ("https://account.proton.me/signup", "signup"),
    ("https://mailchimp.com/signup/", "signup"),
    ("https://www.canva.com/signup", "signup"),
]

TIMEOUT_MS = 20000
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "realsite")


def slug(url):
    s = re.sub(r"^https?://", "", url)
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return ("cap-" + s)[:70]


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright isn't installed yet. Run these two lines first:\n"
              "  pip3 install playwright --break-system-packages\n"
              "  python3 -m playwright install chromium")
        return 1

    os.makedirs(OUT_DIR, exist_ok=True)
    saved, flagged, failed = 0, 0, 0

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            viewport={"width": 1280, "height": 900},
        )
        for i, (url, kind) in enumerate(SITES, 1):
            name = slug(url)
            try:
                page = ctx.new_page()
                page.goto(url, timeout=TIMEOUT_MS, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=6000)
                except Exception:
                    pass
                page.wait_for_timeout(1200)  # let late JS forms settle
                html = page.content()
                has_pw = "type=\"password\"" in html or "type='password'" in html
                open(os.path.join(OUT_DIR, name + ".html"), "w", encoding="utf-8").write(html)
                open(os.path.join(OUT_DIR, name + ".json"), "w", encoding="utf-8").write(json.dumps({
                    "url": url, "kind": kind, "note": f"captured {date.today().isoformat()} (unlabelled)",
                    "expect": {}
                }, indent=2))
                saved += 1
                flag = "  ⚠ no password field found (maybe multi-step or blocked)" if not has_pw else ""
                if not has_pw:
                    flagged += 1
                print(f"[{i:>2}/{len(SITES)}] saved {name}{flag}")
                page.close()
            except Exception as e:
                failed += 1
                print(f"[{i:>2}/{len(SITES)}] FAILED {url}  ({type(e).__name__})")
        browser.close()

    print("\n" + "=" * 60)
    print(f"Saved {saved} pages to {OUT_DIR}")
    if flagged:
        print(f"{flagged} had no password field in the captured HTML (multi-step logins reveal the "
              f"password only after you enter an email, or the site blocked the bot). Fine to leave; "
              f"they still test signup/step-1 detection.")
    if failed:
        print(f"{failed} pages failed to load (timeouts / blocks) — normal, just re-run or edit SITES.")
    print("\nNext: tell Claude 'captured' — it runs test-realsite-battery.js and reviews the flags.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
