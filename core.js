// core.js — pure logic (encryption + rotation/history). No chrome APIs here, so it
// runs in both the extension AND plain Node (which is how we unit-test it).
//
// Everything is encrypted at rest with AES-256-GCM, using a key derived from your
// master password (PBKDF2). The master password is never stored, so nobody, not even
// us, can read the vault without it. That is the "local-first, zero-knowledge" promise
// made real: passwords live encrypted on the device and never leave it.

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function randomSaltB64() { return b64(crypto.getRandomValues(new Uint8Array(16))); }

// PBKDF2 work factor. New vaults use this (OWASP 2023 guidance for PBKDF2-HMAC-SHA256).
// Older vaults store their own count in meta.iters and keep using it, so they still open.
export const PBKDF2_ITERS = 600000;
export const LEGACY_PBKDF2_ITERS = 150000; // what the first vaults were created with

export async function deriveKey(masterPassword, saltB64, iterations = PBKDF2_ITERS) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(masterPassword), 'PBKDF2', false, ['deriveKey']);
  // extractable:true so we can cache the derived key in session storage (cleared when
  // the browser closes) and avoid re-entering the master password on every popup open.
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: unb64(saltB64), iterations, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportKeyB64(key) { return b64(await crypto.subtle.exportKey('raw', key)); }
export async function importKeyB64(keyB64) {
  return crypto.subtle.importKey('raw', unb64(keyB64), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// ---- Recovery: the vault is encrypted with a random Data Encryption Key (DEK). The DEK
// is "wrapped" (encrypted) separately under the master-password key AND under a recovery
// key — so EITHER can unwrap the DEK and open the vault. Changing the master password just
// re-wraps the DEK (no vault re-encryption). Losing the master password → use the recovery key.
export async function newDek() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
export async function wrapKey(wrappingKey, dek) {
  const raw = await crypto.subtle.exportKey('raw', dek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, raw);
  return { iv: b64(iv), ct: b64(ct) };
}
export async function unwrapKey(wrappingKey, wrap) {
  // Throws (AES-GCM auth failure) if the wrapping key is wrong — that's our "wrong password" check.
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(wrap.iv) }, wrappingKey, unb64(wrap.ct));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
// A human-friendly, high-entropy recovery key: RK- + 5 groups of 5 unambiguous chars.
export function generateRecoveryKey() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
  const rnd = crypto.getRandomValues(new Uint32Array(25));
  let s = '';
  for (let i = 0; i < 25; i++) { s += A[rnd[i] % A.length]; if (i % 5 === 4 && i < 24) s += '-'; }
  return 'RK-' + s;
}
export function normalizeRecoveryKey(s) { return String(s || '').toUpperCase().replace(/\s+/g, ''); }

export async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
export async function decryptJSON(key, blob) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
  return JSON.parse(dec.decode(pt));
}

export function genPassword(len = 20) {
  if (len < 4) len = 4;
  const lower = 'abcdefghijkmnpqrstuvwxyz', upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ', digit = '23456789', sym = '!@#$%^&*';
  const all = lower + upper + digit + sym;
  const rand = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
  const pick = (set) => set[rand(set.length)];
  // Guarantee at least one of each class, then fill, then shuffle — always scores "strong".
  const chars = [pick(lower), pick(upper), pick(digit), pick(sym)];
  for (let i = 0; i < len - 4; i++) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) { const j = rand(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}
export function mask(secret) { return secret ? secret.slice(0, 2) + '••••••••' + secret.slice(-2) : ''; }
export function newId(prefix) { return prefix + '_' + Math.random().toString(36).slice(2, 9); }

// The no-lockout commit, modelled in DATA: the new secret only becomes "current"
// AFTER it is verified, and the old secret is archived into history (never silently lost).
export function commitRotation(account, newSecret, when = new Date().toISOString()) {
  const oldSecret = account.secret;
  // Keep the OLD password as prevSecret and mark the rotation 'pending' — it's only truly
  // proven once you actually sign in with the new one. reconcileCapturedLogin() (below)
  // confirms it or auto-reverts, so a change that didn't really take can't lock you out.
  const updated = { ...account, secret: newSecret, lastRotated: when, status: 'fresh', breachCount: 0, prevSecret: oldSecret, verify: 'pending' };
  const receipt = {
    id: newId('r'), accountId: account.id, site: account.site, when,
    // Honest history: a fresh rotation is NOT verified yet — it only becomes verified once a
    // real sign-in with the new password confirms it (markReceiptVerified, via reconcile).
    // Claiming "✓ verified" the instant we write the new password is the false-receipt trap
    // Alex hit: history said "Verified" for a change that hadn't actually been proven.
    action: 'rotated', oldMasked: mask(oldSecret), newMasked: mask(newSecret), verified: false,
  };
  return { updated, receipt, oldSecret };
}

// Flip the most recent unverified rotation receipt for an account to verified — called once a
// real login proves the new password took. Returns a NEW history array (or the same one if
// there's nothing to update). Keeps history honest: "✓ verified" means genuinely confirmed.
export function markReceiptVerified(history, accountId, when = new Date().toISOString()) {
  if (!Array.isArray(history)) return history;
  const idx = history.findIndex((r) => r && r.accountId === accountId && r.action === 'rotated' && !r.verified);
  if (idx === -1) return history;
  const copy = history.slice();
  copy[idx] = { ...copy[idx], verified: true, verifiedAt: when };
  return copy;
}

// Drop every history receipt belonging to an account (used when the account is deleted) so the
// history view can't show orphaned "verified" receipts for a login that no longer exists — the
// stale-history half of the F6 bug (delete an account, its rotation receipts lingered).
export function pruneHistoryForAccount(history, accountId) {
  if (!Array.isArray(history)) return history;
  return history.filter((r) => !r || r.accountId !== accountId);
}

// Self-healing verification. Capture only fires on a SUCCESSFUL login, so `capturedSecret`
// is a password that just worked. For an account whose rotation is still 'pending':
//   • matches the new secret  → the rotation took → mark verified.
//   • matches the old secret  → the change never took → restore the old password.
//   • something else works     → the user set a new password themselves → adopt it.
// Returns the updated account, or null if there's nothing to reconcile.
export function reconcileCapturedLogin(account, capturedSecret) {
  if (!account || account.verify !== 'pending') return null;
  const { prevSecret, ...rest } = account;
  if (capturedSecret === account.secret) return { ...rest, verify: 'ok' };
  if (prevSecret && capturedSecret === prevSecret) {
    return { ...rest, secret: prevSecret, verify: 'reverted' };
  }
  return { ...rest, secret: capturedSecret, verify: 'ok' };
}

// Manual one-click undo: put the previous password back (used when the user knows the new
// one didn't take). Clears the pending state.
export function revertRotation(account) {
  if (!account || !account.prevSecret) return account;
  const { prevSecret, ...rest } = account;
  return { ...rest, secret: prevSecret, verify: 'reverted' };
}

export function newAccount(site, username, secret) {
  return { id: newId('a'), site: site.trim(), username: username.trim(), secret, status: 'unknown', lastRotated: null, breachCount: 0, authType: 'password', provider: null, addedAt: new Date().toISOString() };
}

// ---- Suspect passwords (the F1 trap: a saved password the site actually rejects) ----
// When we autofill a SAVED password and the site immediately shows a sign-in error, that stored
// password is almost certainly wrong. We flag it 'suspect' so it's no longer offered for
// autofill (re-filling a known-bad password is worse than useless). It stays in the vault — the
// user might still want to see/edit it — but Rekey stops pushing it, and switches to offering to
// SAVE the correct one once a real sign-in succeeds.
export function markSuspect(account) {
  if (!account) return account;
  return { ...account, suspect: true };
}

// A password we just SAW work (captured on a successful login) is authoritative. Adopt it as the
// current secret and clear any suspect/pending flags. Returns the same object if nothing changed.
export function adoptWorkingSecret(account, secret) {
  if (!account || !secret) return account;
  if (account.secret === secret && !account.suspect && account.verify !== 'pending') return account;
  const { prevSecret, ...rest } = account;
  return { ...rest, secret, suspect: false, verify: 'ok' };
}

// Should this saved account be offered for autofill? Suspect and sample accounts are held back.
export function isOfferable(account) {
  return !!account && !account.suspect && !isSampleAccount(account);
}

// ---- Cross-domain auth linking (e.g. a site whose sign-in redirects to a shared auth host) ----
// A saved account can list extra `loginHosts` — hostnames where its login is ALSO used (like an
// auth provider the app hands off to). The USER confirms every link, so Rekey never crosses
// domains on its own. `hostMatch` is passed in (recipes.hostMatchesSite) to avoid a circular
// import. Matches the account's own site OR any of its confirmed loginHosts.
export function accountMatchesHost(account, host, hostMatch) {
  if (!account || typeof hostMatch !== 'function') return false;
  if (hostMatch(host, account.site)) return true;
  return (account.loginHosts || []).some((h) => hostMatch(host, h));
}

// Add a confirmed extra login host to an account (deduped). Returns a new account object.
export function linkLoginHost(account, host) {
  const h = String(host || '').replace(/^www\./, '').toLowerCase();
  if (!account || !h) return account;
  const cur = account.loginHosts || [];
  if (cur.includes(h)) return account;
  return { ...account, loginHosts: [...cur, h] };
}

// The registrable domain a referrer URL points at. Used ONLY as a hint to SUGGEST a link the
// user must confirm. The browser sets the referrer to the real referring origin (a page can't
// forge it to another site), so it's a safe hint — but we still never link without confirmation.
export function referrerDomain(referrer) {
  try { return registrableDomain(new URL(referrer).hostname); } catch (_) { return ''; }
}

// Suggest a saved account to LINK to `host`: only when NO saved account already matches `host`,
// but some account's domain matches the referrer that sent us to this (auth) page. Skips
// SSO/passkey/suspect/sample accounts. Returns the account to offer, or null. Pure + testable.
export function linkCandidate(accounts, host, referrer, hostMatch) {
  if (!accounts || !accounts.length || typeof hostMatch !== 'function') return null;
  if (accounts.some((a) => accountMatchesHost(a, host, hostMatch))) return null; // already matches
  const rd = referrerDomain(referrer);
  if (!rd || rd === registrableDomain(host)) return null; // no cross-domain hint
  return accounts.find((a) => a.secret && a.authType !== 'sso' && a.authType !== 'passkey'
    && !a.suspect && !isSampleAccount(a) && registrableDomain(a.site) === rd) || null;
}

// Rough password strength, 0 (very weak) → 4 (strong).
export function scorePassword(pw) {
  if (!pw) return { score: 0, label: 'none' };
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 14) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++;
  return { score: s, label: ['very weak', 'weak', 'fair', 'good', 'strong'][s] };
}

// How old the current password is (days), by last rotation or when it was added.
export function passwordAgeDays(a, now = Date.now()) {
  const t = a.lastRotated || a.addedAt;
  if (!t) return null;
  return Math.floor((now - new Date(t).getTime()) / 86400000);
}
export function isStale(a, days = 90, now = Date.now()) {
  const age = passwordAgeDays(a, now);
  return age != null && age >= days;
}

// The accounts a bulk "rotate all breached" should act on: breached AND rotatable
// (a real password exists). SSO/passkey accounts have no password to rotate, so they're excluded.
export function breachedRotatable(accounts) {
  return accounts.filter((a) => a.status === 'breached' && a.authType !== 'sso' && a.authType !== 'passkey' && a.secret);
}

// Filter accounts by a search query (site or username).
export function filterAccounts(accounts, q) {
  q = (q || '').trim().toLowerCase();
  if (!q) return accounts;
  return accounts.filter((a) => (a.site || '').toLowerCase().includes(q) || (a.username || '').toLowerCase().includes(q));
}

// Rank an account by risk so the scariest float to the top (lower = more urgent).
export function riskRank(a) {
  if (a.status === 'breached') return 0;
  if ((!a.authType || a.authType === 'password') && a.secret && scorePassword(a.secret).score <= 1) return 1;
  if ((!a.authType || a.authType === 'password') && isStale(a)) return 2;
  if (a.authType === 'sso' || a.authType === 'passkey') return 5;
  return 3;
}
export function sortByRisk(accounts) {
  return [...accounts].sort((x, y) => riskRank(x) - riskRank(y)); // stable: equal ranks keep order
}

// Auto-lock: has the unlocked session gone idle past the timeout?
export function isExpired(unlockedAt, minutes, now = Date.now()) {
  if (!unlockedAt || !minutes) return false;
  return now - unlockedAt > minutes * 60000;
}

// A one-glance health rollup of the vault.
export function computeHealth(accounts) {
  const reused = findReusedPasswords(accounts);
  let password = 0, breached = 0, weak = 0, stale = 0, sso = 0, passkey = 0;
  for (const a of accounts) {
    if (a.authType === 'sso') { sso++; continue; }
    if (a.authType === 'passkey') { passkey++; continue; }
    password++;
    if (a.status === 'breached') breached++;
    if (a.secret && scorePassword(a.secret).score <= 1) weak++;
    if (isStale(a)) stale++;
  }
  return { total: accounts.length, password, breached, reused: reused.size, weak, stale, sso, passkey };
}

// Where to go to actually secure an SSO account (its identity provider).
export function providerSecurityUrl(provider) {
  const map = {
    google: 'https://myaccount.google.com/security',
    apple: 'https://account.apple.com/',
    microsoft: 'https://account.microsoft.com/security',
    github: 'https://github.com/settings/security',
    facebook: 'https://www.facebook.com/settings?tab=security',
  };
  return map[String(provider || '').toLowerCase()] || '';
}

// Where to review/revoke the apps that a provider account is signed into.
export function providerConnectionsUrl(provider) {
  const map = {
    google: 'https://myaccount.google.com/connections',
    apple: 'https://account.apple.com/account/manage',
    microsoft: 'https://account.microsoft.com/privacy',
    github: 'https://github.com/settings/applications',
    facebook: 'https://www.facebook.com/settings?tab=applications',
  };
  return map[String(provider || '').toLowerCase()] || '';
}

// Which accounts share a password with another account (password-type only).
export function findReusedPasswords(accounts) {
  const bySecret = new Map();
  for (const a of accounts) {
    if (a.authType && a.authType !== 'password') continue;
    if (!a.secret) continue;
    if (!bySecret.has(a.secret)) bySecret.set(a.secret, []);
    bySecret.get(a.secret).push(a.id);
  }
  const reused = new Set();
  for (const ids of bySecret.values()) if (ids.length >= 2) ids.forEach((id) => reused.add(id));
  return reused;
}

// Group SSO/passkey accounts by provider, for the "keystone / blast radius" view.
export function keystoneGroups(accounts) {
  const groups = new Map();
  for (const a of accounts) {
    if (a.authType !== 'sso' && a.authType !== 'passkey') continue;
    const key = a.provider || (a.authType === 'passkey' ? 'Passkey' : 'SSO');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  return groups;
}

// ---- Backup / restore (the whole vault is already encrypted; the backup just bundles it) ----
export function makeBackup(meta, vaultBlob) {
  return { rekeyBackup: 1, exportedAt: new Date().toISOString(), meta, vault: vaultBlob };
}
export function readBackup(text) {
  let o;
  try { o = JSON.parse(text); } catch (_) { throw new Error('That file isn\'t a valid Rekey backup.'); }
  if (!o || o.rekeyBackup !== 1 || !o.meta || !o.vault) throw new Error('Not a Rekey backup file.');
  // Validate the crypto structure BEFORE the caller overwrites the current vault, so a
  // truncated/corrupted backup can't wipe a good vault and leave an unusable one.
  const m = o.meta, v = o.vault;
  if (!m.masterWrap || !m.masterWrap.iv || !m.masterWrap.ct || !m.salt) throw new Error('This backup is incomplete or corrupted (missing key data).');
  if (!v.iv || !v.ct) throw new Error('This backup is incomplete or corrupted (missing vault data).');
  return { meta: m, vault: v };
}

// New vaults start EMPTY — no fake demo account. The popup shows a friendly empty state
// guiding the user to add or import their first login.
export function seedVault() {
  return { accounts: [], history: [] };
}

// Is this the built-in DEMO account (or a legacy seed without the flag)? Sample accounts
// must never be autofilled onto a real site or "rotated" — they hold placeholder creds,
// and doing so confuses the vault (e.g. filling you@example.com on the real GitHub login).
export function isSampleAccount(a) {
  if (!a) return false;
  if (a.sample) return true;
  return a.username === 'you@example.com' && typeof a.secret === 'string' && a.secret.startsWith('ghp_demo');
}

// ---- Import (Chrome / Bitwarden / 1Password CSV export) ----
// A real CSV parser so passwords containing commas or quotes survive intact.
export function parseCsv(text) {
  const rows = []; let row = [], field = '', inQ = false;
  text = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => !(r.length === 1 && r[0] === ''));
}

function hostFromUrl(u) {
  try { return new URL(u).hostname.replace(/^www\./, ''); }
  catch (_) { return String(u).replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0]; }
}

// Maps a logins CSV (Chrome: name,url,username,password,note) to {site, username, secret}.
export function parseLoginsCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const idx = (names) => { for (const n of names) { const j = header.indexOf(n); if (j !== -1) return j; } return -1; };
  const iName = idx(['name', 'title']);
  const iUrl = idx(['url', 'website', 'login_uri', 'uri']);
  const iUser = idx(['username', 'user', 'login', 'email', 'login_username']);
  const iPass = idx(['password', 'login_password']);
  if (iPass === -1) return [];
  const out = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    const secret = (row[iPass] || '').trim();
    if (!secret) continue;
    const url = iUrl >= 0 ? (row[iUrl] || '').trim() : '';
    let site = iName >= 0 ? (row[iName] || '').trim() : '';
    if (!site || site.includes('://')) site = hostFromUrl(url || site);
    if (!site) site = url || 'unknown';
    out.push({ site, username: iUser >= 0 ? (row[iUser] || '').trim() : '', secret });
  }
  return out;
}

// ---- Breach detection (Have I Been Pwned "Pwned Passwords", k-anonymity) ----
// We SHA-1 the password, then send ONLY the first 5 hex chars of that hash to the API.
// The API returns every breached-hash suffix under that prefix; we match locally.
// The password itself, and 35/40 of its hash, never leave the device.
export async function sha1HexUpper(text) {
  const buf = await crypto.subtle.digest('SHA-1', enc.encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
export async function pwnedParts(password) {
  const hash = await sha1HexUpper(password);
  return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}
// A colored letter-badge for a site, used as the favicon fallback when Chrome has no
// cached icon. Deterministic: the same domain always gets the same letter + color.
export function monogramFor(domain) {
  const d = String(domain || '').replace(/^www\./, '').toLowerCase();
  const m = d.match(/[a-z0-9]/i);
  const letter = (m ? m[0] : '?').toUpperCase();
  let h = 0;
  for (let i = 0; i < d.length; i++) h = (h * 31 + d.charCodeAt(i)) % 360;
  return { letter, bg: `hsl(${h}, 52%, 42%)` };
}

// The registrable domain of a site string ("https://www.spotify.com/" and
// "accounts.spotify.com" both → "spotify.com"). Used to recognize that two saved
// entries are really the same account. (Simple last-two-labels rule; doesn't special-case
// multi-part TLDs like co.uk — fine for dedupe, worst case it just merges a bit less.)
// Two-label "effective TLDs" where the label to their LEFT is a distinct owner, so we must
// keep three labels (e.g. bbc.co.uk, user.github.io). Covers common country-code SLDs AND
// shared-hosting domains — NOT the full Public Suffix List, but the ones people actually hit.
// Getting this right matters for security: it's what stops one *.github.io (or one worker on
// *.workers.dev) from matching another owner's site during autofill.
const TWO_LABEL_SUFFIXES = new Set([
  // country-code second-level domains
  'co.uk','org.uk','me.uk','gov.uk','ac.uk','ltd.uk','plc.uk','net.uk','sch.uk','nhs.uk',
  'com.au','net.au','org.au','edu.au','gov.au','id.au',
  'co.nz','net.nz','org.nz','govt.nz','ac.nz',
  'co.za','org.za','net.za','gov.za',
  'com.br','net.br','org.br','gov.br',
  'co.jp','ne.jp','or.jp','go.jp','ac.jp',
  'co.in','net.in','org.in','gen.in','firm.in','ind.in',
  'com.mx','org.mx','gob.mx','com.ar','gob.ar',
  'com.sg','edu.sg','gov.sg','com.hk','org.hk','gov.hk','edu.hk',
  'com.tr','gov.tr','edu.tr','com.cn','net.cn','org.cn','gov.cn',
  'co.kr','or.kr','go.kr','com.tw','org.tw','gov.tw','co.il','org.il','gov.il',
  // shared-hosting / app platforms (each subdomain is a different owner → must NOT merge)
  'github.io','githubusercontent.com','gitlab.io','herokuapp.com','herokudns.com',
  'vercel.app','netlify.app','netlify.com','pages.dev','workers.dev','r2.dev',
  'web.app','firebaseapp.com','glitch.me','onrender.com','fly.dev','replit.dev','repl.co',
  'blogspot.com','wordpress.com','myshopify.com','azurewebsites.net','cloudfront.net',
  'amazonaws.com','s3.amazonaws.com','translate.goog','sites.google.com',
]);

export function registrableDomain(site) {
  const host = String(site || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split('?')[0].split(':')[0];
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join('.');
  // On a two-label public suffix (bbc.co.uk, user.github.io) keep three labels; else two.
  return TWO_LABEL_SUFFIXES.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
}

// Merge accounts that are really the same login (same registrable domain + same username)
// into one clean entry, so a manual save + an autofill/capture of the same site don't
// show up as two cards (and don't trigger a false "reused password" warning).
// Returns { accounts, removed }.
export function dedupeAccounts(accounts) {
  const statusRank = { breached: 4, safe: 3, fresh: 2, unknown: 1 };
  const groups = new Map();
  for (const a of accounts) {
    const key = registrableDomain(a.site) + '|' + String(a.username || '').toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  const merged = [];
  let removed = 0;
  for (const group of groups.values()) {
    if (group.length === 1) { merged.push(group[0]); continue; }
    // Never merge across different auth types (e.g. a real SSO entry vs a password one).
    const byType = new Map();
    for (const a of group) {
      const t = a.authType || 'password';
      if (!byType.has(t)) byType.set(t, []);
      byType.get(t).push(a);
    }
    for (const sub of byType.values()) {
      if (sub.length === 1) { merged.push(sub[0]); continue; }
      removed += sub.length - 1;
      merged.push(mergeGroup(sub, statusRank));
    }
  }
  return { accounts: merged, removed };
}

function mergeGroup(group, statusRank) {
  const time = (a) => new Date(a.lastRotated || a.addedAt || 0).getTime();
  const byNewest = [...group].sort((x, y) => time(y) - time(x));
  const base = { ...byNewest[0] };
  base.site = registrableDomain(group[0].site); // clean, e.g. "spotify.com"
  base.secret = (byNewest.find((g) => g.secret) || base).secret;
  for (const g of group) {
    if ((statusRank[g.status] || 0) > (statusRank[base.status] || 0)) {
      base.status = g.status; base.breachCount = g.breachCount;
    }
  }
  const added = group.map((g) => g.addedAt).filter(Boolean).sort();
  if (added.length) base.addedAt = added[0]; // earliest
  return base;
}

// rangeText is the API body: many lines of "SUFFIX:COUNT". Returns the breach count (0 = clean).
export function countFromRange(rangeText, suffix) {
  const target = suffix.toUpperCase();
  for (const line of rangeText.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i === -1) continue;
    if (line.slice(0, i).toUpperCase() === target) return parseInt(line.slice(i + 1), 10) || 0;
  }
  return 0;
}
