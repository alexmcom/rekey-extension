# Rekey

**Finds your breached passwords and walks you through fixing each one, without ever locking you out.**

Rekey is a local-first, zero-knowledge browser extension (Chrome / Edge / Brave, Manifest V3). Most password managers only *tell* you a password was leaked. Rekey helps you fix it: it detects breached passwords, generates a strong replacement, takes you to the site's change page, and saves the new password once it's confirmed working — keeping the old one until then, so you can't get locked out.

This repository is public so you don't have to take our word for any of it. **A password manager should be auditable.** Read the code, run the tests, verify the claims below.

> Status: **beta.** This is early software. Use it alongside your existing password manager and with low-stakes accounts while it's being validated.

## What it does

- **Breach detection** against Have I Been Pwned, using k-anonymity (only the first 5 characters of a SHA-1 hash ever leave your device — never a password).
- **Guided fixing, no lockout** — on a breached account, Rekey takes you to the change page, hands you a strong new password, and only records it once the new one works. The old password is kept until then.
- **Autofill & capture** — fills saved logins and offers to save new ones.
- **Local-first, zero-knowledge vault** — AES-GCM encryption, PBKDF2 key derivation, encrypted entirely on your device with a master password only you know.
- **Optional end-to-end-encrypted sync** — the server only ever stores ciphertext it cannot read.
- **Recovery key** so you never lose your vault.

## Verify the privacy claims yourself

- **Passwords never leave your device unencrypted.** Crypto lives in `core.js` (`encryptJSON` / `decryptJSON`, PBKDF2 + AES-GCM). Tests in `test-core.js` and `test-browser.js` assert the stored blob never contains the plaintext.
- **The breach check is k-anonymized.** See where only a 5-char hash prefix is sent (`api.pwnedpasswords.com/range/...`) — the full password/hash never leaves the device.
- **No telemetry, no tracking.** There are no analytics or reporting calls. The only network endpoints are the breach range API and (if you opt in) the sync endpoint. Grep the source: there is no `eval`, no remote code, no third-party trackers.
- **No inbox access.** Rekey never requests or uses email access; it confirms changes on the site itself.
- **Anti-phishing autofill.** Saved logins are only offered on a domain that matches the saved site (`hostMatchesSite` in `recipes.js`).

## Permissions, and why

- `storage` — store your encrypted vault locally.
- `scripting` + `activeTab` — fill/submit a change-password form on the tab you choose, only on your click.
- `tabs` — open a site's change/reset page to help you update a breached password.
- `favicon` — show site icons from Chrome's local cache (no network).
- host permission `api.pwnedpasswords.com` — the k-anonymized breach check.
- content scripts on all sites — a password manager must work on any site you log into. No browsing data is collected or transmitted.

## Run it locally

```
# Load the extension
1. Clone or download this repo.
2. Go to chrome://extensions, enable Developer mode, click "Load unpacked", select this folder.

# Run the test suite (Node + jsdom)
npm install
node test-core.js
node test-autofill.js
node test-capture.js
node test-rotate.js
node test-sync.js
node test-learn.js
node test-realsite-battery.js
```

## Security

See [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) for the self-audit (crypto choices, threat model, accepted risks). Found something? Email **mccomas0@gmail.com** — please report privately before disclosing.

## License

[GNU AGPL-3.0-or-later](LICENSE). You may read, run, study, and modify the code. If you distribute or host a modified version, you must open-source it under the AGPL too — which keeps every version of Rekey open and prevents it from being taken into a closed product.
