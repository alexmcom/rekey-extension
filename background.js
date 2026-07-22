// Rekey service worker (module).
// Buffers passively-captured logins from the content script and — because the session
// key IS the vault key this session — can also save a captured login straight into the
// vault when the user clicks "Save login" on the on-page prompt (no popup needed).
// Captures are ENCRYPTED with the session key before being held in session storage, so
// no plaintext password is ever written to disk. If the vault is locked, captures drop.
import { importKeyB64, encryptJSON, decryptJSON, newAccount, genPassword, commitRotation, isSampleAccount, reconcileCapturedLogin, markSuspect, adoptWorkingSecret, isOfferable, markReceiptVerified, accountMatchesHost, linkLoginHost, linkCandidate } from './core.js';
import { hostMatchesSite } from './recipes.js';

chrome.runtime.onInstalled.addListener(() => { console.log('Rekey dev preview installed.'); sessionKey().then((sk) => setLockBadge(!sk)); });

const local = {
  get: (k) => new Promise((r) => chrome.storage.local.get(k, (o) => r(o[k]))),
  set: (k, v) => new Promise((r) => chrome.storage.local.set({ [k]: v }, r)),
};
const sessGet = (k) => new Promise((r) => chrome.storage.session.get(k, (o) => r(o[k])));
const sessSet = (k, v) => new Promise((r) => chrome.storage.session.set({ [k]: v }, r));

// Lock badge on the toolbar icon: a 🔒 whenever the vault is locked, cleared when unlocked.
// A passive, always-visible reminder so people notice they need to unlock before autofill —
// the popup sets it on unlock/lock; the background sets it here on AUTO-lock.
function setLockBadge(locked) {
  try {
    chrome.action.setBadgeText({ text: locked ? '🔒' : '' });
    if (locked) chrome.action.setBadgeBackgroundColor({ color: '#db2777' });
  } catch (_) { /* action API unavailable */ }
}

// The cached vault key, but ONLY if the auto-lock window hasn't lapsed. The popup checks
// this on open; the background must check it too, or autofill/capture/rotation would keep
// serving secrets after the vault should have locked (while the popup stayed closed).
// Time-since-last-popup-unlock; background reads never refresh the clock.
async function sessionKey() {
  const sk = await sessGet('sk');
  if (!sk) return null;
  const unlockedAt = await sessGet('unlockedAt');
  const mins = (await local.get('lockAfterMin')) ?? 30;
  if (mins > 0 && unlockedAt && (Date.now() - unlockedAt) > mins * 60000) {
    await chrome.storage.session.remove('sk'); // lock it
    setLockBadge(true);                          // show the lock on the icon after auto-lock
    return null;
  }
  return sk;
}

// Refresh the idle clock on GENUINE user activity — a successful sign-in we captured, or an
// explicit "Generate & fill" — so an actively-used vault doesn't auto-lock out from under the
// user mid-session (the F10 complaint: it locked too eagerly, so people ended up signed in
// while locked and nothing got captured). Passive page-load reads (status/lookup) deliberately
// do NOT call this. Never un-expires a vault that's already locked.
async function touchSession() {
  const sk = await sessGet('sk');
  if (!sk) return;
  await sessSet('unlockedAt', Date.now());
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg) return undefined;

  // Lightweight lock-state check (no vault touched) — lets the content script proactively
  // prompt "unlock first" on a page where Rekey could help, before the user tries an action.
  if (msg.type === 'rekey_status') {
    sessionKey().then((sk) => sendResponse({ unlocked: !!sk })).catch(() => sendResponse({ unlocked: false }));
    return true;
  }

  if (msg.type === 'rekey_capture' && msg.password) {
    // Buffer if unlocked, and tell the content script whether to show the prompt.
    bufferCapture(msg).then((r) => sendResponse(r));
    return true; // async response
  }

  if (msg.type === 'rekey_save_capture' && msg.password) {
    saveCapture(msg).then((ok) => sendResponse({ ok })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg.type === 'rekey_forget_capture') {
    forgetCapture(msg).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg.type === 'rekey_forget_recent') {
    // A page loaded showing a login error → drop any buffered capture, AND if we recently
    // autofilled a SAVED password for this host, flag that stored password 'suspect' (F1).
    forgetRecent(msg.host)
      .then(() => markSuspectIfRecentlyFilled(msg.host))
      .then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  // The content script just autofilled a SAVED login. Remember it (host + username + time) so
  // that if a sign-in error shows up right after, we know which stored password to suspect.
  if (msg.type === 'rekey_filled_saved' && msg.host) {
    noteFilledSaved(msg.host, msg.username).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  // A page loaded with NO login error → confirm recently buffered captures (auto-save armed
  // sites, heal suspect/pending accounts) even when the login succeeded via a redirect.
  if (msg.type === 'rekey_confirm_recent') {
    confirmRecentCaptures().then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  // Autofill: return the saved login for this host so the content script can fill it.
  if (msg.type === 'rekey_lookup') {
    lookupLogin(msg.host, msg.referrer).then((r) => sendResponse(r)).catch(() => sendResponse({ found: false }));
    return true;
  }

  // Autofill on a reset/create page: generate a strong password. Saves immediately only for
  // an EXISTING account (a real reset); for a new site it returns saved:false and the content
  // script commits via rekey_save_signup after the signup is actually submitted.
  if (msg.type === 'rekey_fill_new') {
    fillNew(msg.host).then((r) => sendResponse(r)).catch(() => sendResponse({ ok: false }));
    return true;
  }

  // Commit a signup ONLY after the form was submitted and went through (no phantom accounts).
  if (msg.type === 'rekey_save_signup' && msg.password) {
    saveSignup(msg).then((ok) => sendResponse({ ok })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  // Proactive save: the user accepted the "save this site?" nudge on a login page. Arm the
  // host so the NEXT successful login here is saved automatically (never a failed one).
  if (msg.type === 'rekey_arm_save' && msg.host) {
    armSave(msg.host).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  // The user confirmed that this host is a sign-in page for an existing account (cross-domain
  // auth link). Remember it on that account so it fills/matches here from now on.
  if (msg.type === 'rekey_link_host' && msg.host && msg.accountId) {
    linkHost(msg.host, msg.accountId).then((ok) => sendResponse({ ok })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  return undefined;
});

// Remember a user-confirmed extra login host on an account (cross-domain auth linking).
async function linkHost(rawHost, accountId) {
  const sk = await sessionKey();
  if (!sk) return false;
  const key = await importKeyB64(sk);
  const blob = await local.get('vault');
  if (!blob) return false;
  const vault = await decryptJSON(key, blob);
  const idx = vault.accounts.findIndex((a) => a.id === accountId);
  if (idx < 0) return false;
  vault.accounts[idx] = linkLoginHost(vault.accounts[idx], (rawHost || '').replace(/^www\./, ''));
  await local.set('vault', await encryptJSON(key, vault));
  return true;
}

async function armSave(rawHost) {
  const host = (rawHost || '').replace(/^www\./, '').toLowerCase();
  const cur = (await sessGet('armedSaves')) || [];
  if (!cur.includes(host)) cur.push(host);
  await sessSet('armedSaves', cur);
}

// Only accounts with a real, fillable password for a domain that matches the page —
// never SSO/passkey, and never a different site (anti-phishing).
function fillableAccount(a, host) {
  const t = a.authType;
  if (t === 'sso' || t === 'passkey') return false;
  if (!a.secret) return false;
  if (isSampleAccount(a)) return false; // never autofill the demo placeholder onto a real site
  // Matches the account's own domain OR any user-confirmed cross-domain login host. With no
  // loginHosts (every existing account), this is identical to the old hostMatchesSite check.
  return accountMatchesHost(a, host, hostMatchesSite);
}

async function lookupLogin(rawHost, referrer) {
  const sk = await sessionKey();
  if (!sk) return { found: false, unlocked: false }; // locked
  const key = await importKeyB64(sk);
  const blob = await local.get('vault');
  if (!blob) return { found: false, unlocked: true };
  const vault = await decryptJSON(key, blob);
  const host = rawHost || '';
  // A 'suspect' saved password (one the site just rejected after we filled it) is held back:
  // we don't re-offer a known-bad password. The account still exists, so we fall through to the
  // "save this login" offer, letting the user's correct password get captured on next success.
  const acct = vault.accounts.find((a) => fillableAccount(a, host) && isOfferable(a));
  if (acct) return { found: true, unlocked: true, username: acct.username || '', secret: acct.secret };
  // No direct match. If the referrer that sent us here points at a saved account's domain, this
  // is likely that account's auth/sign-in page (e.g. app.com → auth.provider.com). SUGGEST a
  // link the user must confirm — never auto-link. No secret is sent until they confirm.
  const cand = linkCandidate(vault.accounts, host, referrer, hostMatchesSite);
  if (cand) return { found: false, unlocked: true, link: { accountId: cand.id, site: cand.site, username: cand.username || '' } };
  return { found: false, unlocked: true }; // unlocked but nothing offerable saved for this site yet
}

async function fillNew(rawHost) {
  const sk = await sessionKey();
  if (!sk) return { ok: false, locked: true }; // vault locked → tell the user to unlock (no silent fail)
  const key = await importKeyB64(sk);
  const blob = await local.get('vault');
  if (!blob) return { ok: false };
  const vault = await decryptJSON(key, blob);
  await touchSession(); // explicit user action (Generate & fill) → keep the vault awake (F10)
  const host = (rawHost || '').replace(/^www\./, '');
  const password = genPassword(20);
  const idx = vault.accounts.findIndex((a) => hostMatchesSite(host, a.site) && a.authType !== 'sso' && a.authType !== 'passkey' && !isSampleAccount(a));
  if (idx >= 0) {
    // You already have an account here → this is a real password RESET. Rotate + save now.
    const { updated, receipt } = commitRotation(vault.accounts[idx], password);
    vault.accounts[idx] = updated;
    if (Array.isArray(vault.history)) vault.history.unshift(receipt);
    await local.set('vault', await encryptJSON(key, vault));
    return { ok: true, password, saved: true };
  }
  // New site → this is likely a SIGNUP. Give a strong password to fill, but DON'T save yet:
  // the content script commits it (rekey_save_signup) only after the signup is submitted and
  // goes through — so merely filling a form (or a signup modal that popped up) never creates
  // a phantom account for a site you didn't actually register on.
  return { ok: true, password, saved: false };
}

// Commit a signup only after the form was actually submitted successfully (deduped).
async function saveSignup(msg) {
  const sk = await sessionKey();
  if (!sk) return false;
  const key = await importKeyB64(sk);
  const blob = await local.get('vault');
  if (!blob) return false;
  const vault = await decryptJSON(key, blob);
  const host = (msg.host || '').replace(/^www\./, '');
  const username = (msg.username || '');
  const dupe = vault.accounts.some((a) => hostMatchesSite(host, a.site) && (a.username || '').toLowerCase() === username.toLowerCase());
  if (!dupe) {
    const acct = newAccount(host, username, msg.password);
    acct.lastRotated = new Date().toISOString();
    acct.status = 'fresh';
    vault.accounts.push(acct);
    await local.set('vault', await encryptJSON(key, vault));
  }
  return true;
}

// Encrypt + hold a capture in session storage. Returns { unlocked, dupe } — dupe is true
// when this login is already saved, so the content script can skip the "Save?" prompt.
async function bufferCapture(msg) {
  try {
    const sk = await sessionKey();
    if (!sk) return { unlocked: false, dupe: false }; // locked → never buffer a plaintext password
    const key = await importKeyB64(sk);
    let dupe = false;
    try {
      const vblob = await local.get('vault');
      if (vblob) {
        const vault = await decryptJSON(key, vblob);
        const u = (msg.username || '').toLowerCase();
        const match = (a) => accountMatchesHost(a, msg.host || '', hostMatchesSite) && (a.username || '').toLowerCase() === u;
        // A CONFIRMED (non-tentative) capture proves msg.password just worked → apply it to the
        // vault now (reconcile a pending rotation, heal a suspect/stale password, or auto-save an
        // armed site). A TENTATIVE pre-navigation capture is left buffered: confirmRecentCaptures()
        // promotes it once the destination page loads without a login error — so a login that
        // REDIRECTS on success (e.g. auth.webconnex.com → /products) still auto-saves.
        if (!msg.tentative) {
          const changed = await applyConfirmedLogin(vault, { host: msg.host, username: msg.username, password: msg.password });
          if (changed) await local.set('vault', await encryptJSON(key, vault));
        }
        dupe = vault.accounts.some(match); // existing OR just auto-saved → skip the on-page "save?" prompt
      }
    } catch (_) { /* if we can't read the vault, just don't claim dupe */ }
    const blob = await encryptJSON(key, {
      host: msg.host || '', username: msg.username || '', password: msg.password, ts: Date.now(),
    });
    const cur = (await sessGet('pendingCaptures')) || [];
    cur.push(blob);
    while (cur.length > 25) cur.shift();
    await sessSet('pendingCaptures', cur);
    // A confirmed sign-in is real user activity → keep the vault awake (F10 anti-eager-lock).
    if (!msg.tentative) await touchSession();
    return { unlocked: true, dupe };
  } catch (_) { return { unlocked: false, dupe: false }; }
}

// Apply a CONFIRMED successful login (cred.password just worked) to the vault. Mutates `vault`:
//   • matching account, rotation pending → reconcile (confirm or auto-revert) + verify receipt.
//   • matching account, suspect/stale secret → adopt the password that just worked, clear suspect.
//   • no matching account, site ARMED for save → auto-save it (and disarm).
// Never auto-creates an account for an UN-armed new login (that stays a popup "save?" offer, so
// we don't create phantom accounts). Returns true if the vault changed. Shared by the confirmed
// live capture AND confirmRecentCaptures (promoting a redirect login's buffered capture).
async function applyConfirmedLogin(vault, cred) {
  const host = (cred.host || '').replace(/^www\./, '').toLowerCase();
  const u = (cred.username || '').toLowerCase();
  const match = (a) => accountMatchesHost(a, cred.host || '', hostMatchesSite) && (a.username || '').toLowerCase() === u;
  const idx = vault.accounts.findIndex((a) => match(a) && !isSampleAccount(a));
  if (idx >= 0) {
    if (vault.accounts[idx].verify === 'pending') {
      const fixed = reconcileCapturedLogin(vault.accounts[idx], cred.password);
      if (fixed) {
        vault.accounts[idx] = fixed;
        if (fixed.verify === 'ok') vault.history = markReceiptVerified(vault.history, fixed.id);
        return true;
      }
      return false;
    }
    if (vault.accounts[idx].suspect || vault.accounts[idx].secret !== cred.password) {
      const healed = adoptWorkingSecret(vault.accounts[idx], cred.password);
      if (healed !== vault.accounts[idx]) { vault.accounts[idx] = healed; return true; }
    }
    return false; // existing account already correct — nothing to do, and never auto-save a dupe
  }
  const armed = (await sessGet('armedSaves')) || [];
  if (armed.includes(host)) {
    vault.accounts.push(newAccount(cred.host || host, cred.username || '', cred.password));
    await sessSet('armedSaves', armed.filter((h) => h !== host));
    return true;
  }
  return false;
}

// A page loaded WITHOUT a login error → any login just submitted likely SUCCEEDED. Promote
// recently-buffered captures (armed auto-save, suspect heal, pending reconcile) even when the
// success arrived via a full-page redirect (so only a tentative capture was ever sent). The
// complement of forgetRecent(): errors drop buffered captures, clean loads confirm them.
async function confirmRecentCaptures() {
  const sk = await sessionKey();
  if (!sk) return;
  const key = await importKeyB64(sk);
  const cur = (await sessGet('pendingCaptures')) || [];
  if (!cur.length) return;
  const vblob = await local.get('vault');
  if (!vblob) return;
  let vault; try { vault = await decryptJSON(key, vblob); } catch (_) { return; }
  const now = Date.now();
  const kept = [];
  let changedAny = false;
  for (const blob of cur) {
    let c; try { c = await decryptJSON(key, blob); } catch (_) { continue; }
    if (now - (c.ts || 0) > 30000) { kept.push(blob); continue; } // too old to attribute to this nav
    const changed = await applyConfirmedLogin(vault, c);
    if (changed) changedAny = true;      // committed (saved/healed) → drop it from the buffer
    else kept.push(blob);                // unarmed new login → leave it for the popup "save?" banner
  }
  if (changedAny) {
    await local.set('vault', await encryptJSON(key, vault));
    await sessSet('pendingCaptures', kept);
    await touchSession();
  }
}

// Save a captured login straight into the vault (used by the on-page "Save login" button).
// Deduped by site|username so it can't create a duplicate the popup would also offer.
async function saveCapture(msg) {
  const sk = await sessionKey();
  if (!sk) return false; // locked — can't touch the vault
  const key = await importKeyB64(sk);
  const blob = await local.get('vault');
  if (!blob) return false;
  const vault = await decryptJSON(key, blob);
  const host = (msg.host || '').replace(/^www\./, '');
  const username = msg.username || '';
  const dupe = vault.accounts.some(
    (a) => (a.site + '|' + a.username).toLowerCase() === (host + '|' + username).toLowerCase(),
  );
  if (!dupe) {
    vault.accounts.push(newAccount(host, username, msg.password));
    await local.set('vault', await encryptJSON(key, vault));
  }
  // Either way, drop any buffered copy so the popup won't re-offer this login.
  await forgetCapture({ host, username });
  return true;
}

// Drop recently-buffered captures for a host (last ~25s) — used when a page loads
// showing a login error, meaning a login that just navigated here actually failed.
async function forgetRecent(rawHost) {
  const sk = await sessionKey();
  if (!sk) return;
  const key = await importKeyB64(sk);
  const cur = (await sessGet('pendingCaptures')) || [];
  const host = (rawHost || '').replace(/^www\./, '').toLowerCase();
  const now = Date.now();
  const kept = [];
  for (const blob of cur) {
    let c; try { c = await decryptJSON(key, blob); } catch (_) { continue; }
    const same = (c.host || '').replace(/^www\./, '').toLowerCase() === host;
    if (same && now - (c.ts || 0) < 25000) continue; // recent + this host → drop it
    kept.push(blob);
  }
  await sessSet('pendingCaptures', kept);
}

// Record that we just autofilled a SAVED login for this host, so a sign-in error moments later
// can pin the blame on that stored password. Kept in session storage (last ~10 entries).
async function noteFilledSaved(rawHost, username) {
  const host = (rawHost || '').replace(/^www\./, '').toLowerCase();
  if (!host) return;
  const cur = (await sessGet('filledSaved')) || [];
  cur.push({ host, username: (username || '').toLowerCase(), ts: Date.now() });
  while (cur.length > 10) cur.shift();
  await sessSet('filledSaved', cur);
}

// A login-error page loaded. If we filled a SAVED password for this host in the last ~30s, the
// stored password is almost certainly wrong → mark it 'suspect' so autofill stops offering it.
// This is the F1 fix: a known-bad saved password gets flagged instead of re-filled forever.
async function markSuspectIfRecentlyFilled(rawHost) {
  const host = (rawHost || '').replace(/^www\./, '').toLowerCase();
  if (!host) return;
  const cur = (await sessGet('filledSaved')) || [];
  const now = Date.now();
  const hit = cur.find((e) => e.host === host && now - (e.ts || 0) < 30000);
  if (!hit) return;
  const sk = await sessionKey();
  if (!sk) return; // locked — can't touch the vault
  const key = await importKeyB64(sk);
  const blob = await local.get('vault');
  if (!blob) return;
  const vault = await decryptJSON(key, blob);
  const idx = vault.accounts.findIndex((a) => hostMatchesSite(host, a.site)
    && (!hit.username || (a.username || '').toLowerCase() === hit.username) && a.secret && !isSampleAccount(a));
  if (idx >= 0 && !vault.accounts[idx].suspect) {
    vault.accounts[idx] = markSuspect(vault.accounts[idx]);
    await local.set('vault', await encryptJSON(key, vault));
  }
  // Clear the arm for this host so a later, unrelated error can't re-flag it.
  await sessSet('filledSaved', cur.filter((e) => e.host !== host));
}

// Remove any buffered capture matching this host/username (on Save or "Not now").
async function forgetCapture(msg) {
  const sk = await sessionKey();
  if (!sk) return;
  const key = await importKeyB64(sk);
  const cur = (await sessGet('pendingCaptures')) || [];
  const host = (msg.host || '').replace(/^www\./, '');
  const username = msg.username || '';
  const kept = [];
  for (const blob of cur) {
    let c; try { c = await decryptJSON(key, blob); } catch (_) { continue; }
    const same = (c.host || '').replace(/^www\./, '').toLowerCase() === host.toLowerCase()
      && (c.username || '').toLowerCase() === username.toLowerCase();
    if (!same) kept.push(blob);
  }
  await sessSet('pendingCaptures', kept);
}
