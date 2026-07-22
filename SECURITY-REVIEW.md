# Rekey — Security Review (self-audit)

_Scope: Rekey's own Chrome MV3 extension (`product/extension/`) and, at a high level, getrekey.com. Only Rekey-owned assets. Date: 2026-07-11._

This is a defensive review of Rekey before wider testing. It documents the threat model, what was checked, what was **fixed in this pass**, what is **accepted risk** (inherent to any password manager), and what is **queued** for later hardening.

## Threat model

A password manager's job is to hold secrets and only release them to the right place. The threats that matter:

1. **A malicious/random web page** trying to pull secrets out of the extension.
2. **A look-alike / phishing site** trying to get autofill to type your real password into it.
3. **Secrets written to disk in plaintext** (recoverable by other software or after uninstall).
4. **Weak crypto** (guessable master-password derivation, IV reuse, etc.).
5. **XSS in the extension's own privileged UI** (the popup can read the whole vault).
6. **The vault staying unlocked longer than intended.**

## What was checked, and the result

### ✅ Crypto is sound on the essentials
- **AES-256-GCM** for the vault, captures, and key-wrapping.
- **Fresh random 12-byte IV on every encrypt** (`encryptJSON`, `wrapKey`) — no IV reuse (the one catastrophic GCM mistake) — verified in code.
- **GCM auth tag doubles as the "wrong password" check** — a bad master password fails to unwrap the DEK and throws, rather than returning garbage.
- **Separate random 16-byte salts** for the master-password key and the recovery key.
- **DEK model:** the vault is encrypted with a random Data Encryption Key; that DEK is wrapped under both the master-password key and the recovery key. Changing the master password re-wraps the DEK (no vault re-encryption), and the recovery key keeps working.
- **HIBP breach check uses k-anonymity** — only the first 5 hex chars of the SHA-1 hash leave the device; the password (and even its full hash) never does.

### ✅ FIXED — PBKDF2 work factor raised 150k → 600k
`deriveKey` used **150,000** PBKDF2-HMAC-SHA256 iterations; current OWASP guidance is **600,000**. New vaults now use 600k (`PBKDF2_ITERS`). The iteration count is stored per-vault in `meta.iters`, so **existing vaults keep opening** (they read their stored count, defaulting to the legacy 150k). A brand-new vault gets the stronger setting. _Follow-up: offer existing users a one-click re-key to 600k (needs re-wrapping both master + recovery)._

### ✅ FIXED — masked secret is now HTML-escaped in the popup
The card rendered `mask(secret)` (first 2 + last 2 chars) into `innerHTML`. A crafted "password" imported from a malicious CSV could, in theory, smuggle markup through those characters. Now escaped (`esc(mask(...))`). Practical exploitability was low (only 4 attacker chars), but a password manager should never put raw secret bytes into HTML.

### ✅ FIXED — auto-lock is now enforced in the background, not just the popup
Auto-lock was only checked when the popup opened. While the popup stayed closed, the cached key lingered, so autofill/capture/rotation would keep serving secrets past the lock timeout. The background now gates every secret-touching handler through `sessionKey()`, which clears the key once `lockAfterMin` has elapsed since the last popup unlock.

### ✅ FIXED — explicit Content-Security-Policy on extension pages
Added `content_security_policy.extension_pages` (`script-src 'self'; object-src 'self'; base-uri 'none'; connect-src 'self' https://api.pwnedpasswords.com`). MV3 is already strict by default; this makes it explicit and pins network egress to the HIBP endpoint.

### ✅ Message-passing trust boundary holds
- **No `externally_connectable`** in the manifest, so **web pages cannot send messages to the background** — only Rekey's own content scripts and popup can. Verified.
- Content scripts run in an **isolated world**; secrets returned to them are **not readable by the page's own JavaScript**.
- **No `eval` / `new Function`** anywhere. Verified.
- **No secret is ever `console.log`ged** (only test files log pass/fail). Verified.

### ✅ Anti-phishing on autofill
`lookupLogin` only returns a saved login when `hostMatchesSite(pageHost, savedSite)` — the page's real `location.hostname`, which a page cannot spoof. So a login saved for `spotify.com` is never offered on `evil.com`. Autofill is **top-frame only** (a malicious iframe can't trigger it) and **only fills on an explicit user click** (never silent typing). The demo/sample account is also excluded from autofill and rotation.

## Accepted risks (inherent to a password manager)

- **Autofill writes the secret into the page's DOM.** Once you click *Fill*, the password is in the page's input value, which the page's JS can read. This is true of every password manager. Mitigations in place: exact-domain match, top-frame only, user-click gated. A same-origin XSS on a legitimate site could still read a filled value — that's the site's compromise, not Rekey's.
- **The DEK is extractable and cached in `chrome.storage.session`** while unlocked. This is needed so you don't re-enter the master password on every popup open. Session storage is memory-backed and cleared when the browser closes; auto-lock now also clears it. A local attacker with live access to the running browser's memory is out of scope (true of all such tools).
- **`rekey_fill_new` on a malicious "create password" page** would generate a strong password, fill it, and save a vault entry for that origin. No existing secret leaks; worst case is a junk entry the user can delete.
- **`web_accessible_resources`** expose a few JS files to all origins, letting a page detect Rekey is installed (fingerprinting). Low severity.

## Queued hardening (not blocking, tracked for later)

- One-click re-key of existing vaults to 600k iterations (and a path to Argon2id if/when available in the platform).
- Rate-limit / lock-out consideration if active login-verification is added (avoid tripping site lockouts).
- Tighten `web_accessible_resources` matches where possible.
- Site (getrekey.com) checks — **not performed live this pass**: HTTPS + HSTS, security headers (CSP, X-Content-Type-Options, Referrer-Policy), and the waitlist form's handling of input. To be done with the browser agent against the live site.

## Bottom line

No secret-exfiltration path was found from a malicious web page: the background is unreachable by pages, autofill is domain-locked and click-gated, and nothing is written to disk in plaintext. The concrete weaknesses found — PBKDF2 work factor, an unescaped masked value, background-side auto-lock, and an explicit CSP — were **fixed in this pass**. All 126 unit tests still pass. Remaining items are accepted-risk (documented) or queued hardening.
