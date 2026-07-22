// rotate-dom.js — the REAL in-page rotation engine.
//
// rotateInPage() is injected into the target site's change-password page via
// chrome.scripting.executeScript, where it fills the fields, submits, and waits
// for the site to confirm the change. The SAME function is unit-tested in Node
// with jsdom (see test-rotate.js).
//
// CRITICAL: this function must be fully SELF-CONTAINED — it may only use its own
// arguments, page globals (document/location/window), and built-ins. It must NOT
// reference any module-scope variable or import, because executeScript serializes
// the function source and runs it in the page's isolated world.
//
// No-lockout guarantee: this function NEVER stores or discards anything. It only
// reports ok/failure. The caller keeps the old password until ok===true.
export async function rotateInPage(recipe, currentPw, newPw) {
  const q = (sel) => { try { return document.querySelector(sel); } catch (_) { return null; } };
  const findField = (selectors) => {
    const list = Array.isArray(selectors) ? selectors : [selectors];
    for (const s of list) { const el = q(s); if (el) return el; }
    return null;
  };
  const setValue = (el, val) => {
    const proto = (typeof HTMLTextAreaElement !== 'undefined' && el instanceof HTMLTextAreaElement)
      ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) desc.set.call(el, val); else el.value = val;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const bodyText = () => ((document.body && document.body.innerText) || '').toLowerCase();
  const arr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]); // fields may be a string OR a list
  const okSignal = () => {
    for (const u of arr(recipe.successUrlIncludes)) if (location.href.includes(u)) return true;
    for (const s of arr(recipe.successSelector)) if (q(s)) return true;
    for (const t of arr(recipe.successTextIncludes)) if (bodyText().includes(String(t).toLowerCase())) return true;
    return false;
  };
  const failSignal = () => {
    for (const s of arr(recipe.errorSelector)) if (q(s)) return true;
    for (const t of arr(recipe.errorTextIncludes)) if (bodyText().includes(String(t).toLowerCase())) return true;
    return false;
  };

  // 0. SSO check: if there's no password field anywhere but the page offers
  //    "Sign in with Google/Apple/…", there's nothing to rotate here — the real
  //    credential lives at the identity provider. Report that instead of failing.
  const detectProvider = () => {
    const hay = [];
    document.querySelectorAll('a,button,[role="button"],input[type="submit"]').forEach((el) => {
      hay.push((el.textContent || '').toLowerCase());
      const href = el.getAttribute && el.getAttribute('href');
      if (href) hay.push(String(href).toLowerCase());
      if (el.value) hay.push(String(el.value).toLowerCase());
    });
    const t = hay.join(' | ');
    const has = (...keys) => keys.some((k) => t.includes(k));
    if (has('accounts.google.com', 'sign in with google', 'continue with google', 'log in with google')) return 'Google';
    if (has('appleid.apple.com', 'sign in with apple', 'continue with apple')) return 'Apple';
    if (has('login.microsoftonline.com', 'sign in with microsoft', 'continue with microsoft')) return 'Microsoft';
    if (has('sign in with github', 'continue with github')) return 'GitHub';
    if (has('continue with facebook', 'log in with facebook', 'sign in with facebook')) return 'Facebook';
    return null;
  };
  const detectPasskey = () => {
    let hay = ((document.body && document.body.innerText) || '').toLowerCase();
    document.querySelectorAll('a,button,[role="button"]').forEach((el) => { hay += ' ' + (el.textContent || '').toLowerCase(); });
    return /passkey|touch id|face id|fingerprint|security key|windows hello|use your (fingerprint|face)/.test(hay);
  };
  const detectPasswordless = () => {
    const t = (((document.body && (document.body.innerText || document.body.textContent)) || '')).toLowerCase();
    return /enter the code we sent|we sent you a code|we emailed you a|check your email for|sign in with a link|log in with a link|magic link|one-time code|passwordless|without a password/.test(t);
  };
  // 0a. If we're STILL sitting on the /.well-known/change-password link (the site didn't
  //     redirect us to a real form) or the page is a 404, the site doesn't support the
  //     automatic change-password standard. Say so plainly instead of "form not found".
  const looksNotFound = () => {
    // Use textContent as a fallback (innerText is empty in jsdom, and some 404s hide text).
    const t = (((document.body && (document.body.innerText || document.body.textContent)) || '')).toLowerCase();
    // Catch contractions too: "that page can't be found" (WeTransfer), "couldn't be found",
    // "cannot be found", "could not be found", plus bare 404 / "page not found".
    return /\b404\b|(can['’]?t|cannot|could ?n['’]?t|could not) be found|page not found|couldn['’]?t find/.test(t)
      && !document.querySelector('input[type="password"]');
  };
  if (location.href.includes('/.well-known/change-password') || looksNotFound()) {
    return { ok: false, stage: 'notfound', message: "This site doesn't offer an automatic change-password page — open its account settings and change the password there. Rekey will save the new one." };
  }

  if (!document.querySelector('input[type="password"]')) {
    const provider = detectProvider();
    if (provider) return { ok: false, stage: 'sso', provider, message: 'This site uses "Sign in with ' + provider + '" — there is no separate password to change here.' };
    if (detectPasskey()) return { ok: false, stage: 'passkey', message: 'This site uses a passkey (biometric or security key) — there is no password to change here.' };
    if (detectPasswordless()) return { ok: false, stage: 'passwordless', message: 'This site signs you in with an email code or magic link — your main login is your email, not a password.' };
  }

  // 1. Locate the fields — but WAIT for them, since many change-password pages render the
  //    form a moment after load (SPA hydration, redirects, or a re-auth step). A single-shot
  //    check would wrongly report "form not found" on a page that's still drawing it.
  const locate = () => ({
    curEl: recipe.currentPasswordSelector ? findField(recipe.currentPasswordSelector) : null,
    newEl: findField(recipe.newPasswordSelector),
    confEl: recipe.confirmPasswordSelector ? findField(recipe.confirmPasswordSelector) : null,
    submitEl: findField(recipe.submitSelector),
  });
  // ADAPTIVE FALLBACK: when the recipe's selectors miss (a site that doesn't use the standard
  // autocomplete/name attributes), infer the fields straight from the page's password inputs —
  // by count and by nearby name/id/placeholder hints. This lets rotation adapt to messy real
  // forms WITHOUT the user having to "teach" the page. Mirrors learnRecipe's logic.
  const inferFields = () => {
    const pws = [...document.querySelectorAll('input[type="password"]')].filter((p) => !p.disabled && p.type !== 'hidden');
    if (!pws.length) return null;
    const hint = (p) => (((p.getAttribute('name') || '') + ' ' + (p.id || '') + ' ' + (p.getAttribute('placeholder') || '') + ' ' + (p.getAttribute('aria-label') || '')).toLowerCase());
    const byAc = (v) => pws.find((p) => p.getAttribute('autocomplete') === v);
    // A LONE password field is a login/re-auth — not a change form. Only infer when there are
    // 2+ password fields, or the field is explicitly marked new-password.
    if (pws.length < 2 && !byAc('new-password') && !pws.some((p) => /\bnew\b|create|change/.test(hint(p)))) return null;
    const byHint = (re) => pws.find((p) => re.test(hint(p)));
    let cur = byAc('current-password') || byHint(/current|old|existing/);
    let neu = byAc('new-password') || byHint(/\bnew\b|create/);
    let conf = byHint(/confirm|re-?type|re-?enter|repeat|again|verify/);
    const rest = pws.filter((p) => p !== cur && p !== neu && p !== conf);
    if (!neu) neu = rest.shift() || pws[pws.length - 1];
    if (!cur && pws.length >= 2 && pws[0] !== neu && pws[0] !== conf) cur = pws[0];
    if (!conf && rest.length) conf = rest.find((p) => p !== neu) || null;
    const form = neu && (neu.form || (neu.closest && neu.closest('form')));
    const submit = (form && (form.querySelector('button[type="submit"], input[type="submit"]') || form.querySelector('button')))
      || document.querySelector('button[type="submit"], input[type="submit"]');
    return { curEl: cur || null, newEl: neu || null, confEl: conf || null, submitEl: submit || null };
  };
  const enough = (f) => f.newEl && f.submitEl;
  let f = locate();
  const locateDeadline = Date.now() + (recipe.locateTimeoutMs || 7000);
  while (!enough(f) && Date.now() < locateDeadline) {
    const inf = inferFields();               // try inference each pass too
    if (inf && enough(inf)) { f = inf; break; }
    await sleep(250); f = locate();
  }
  if (!enough(f)) { const inf = inferFields(); if (inf && enough(inf)) f = inf; }
  const { curEl, newEl, confEl, submitEl } = f;
  if (!newEl) {
    // No new-password field ever appeared. If the page is really a sign-in wall (a lone
    // password + a username/email), say so — the site wants you to re-authenticate first.
    const lonePw = document.querySelector('input[type="password"]');
    const hasUser = document.querySelector('input[type="email"], input[autocomplete="username"]');
    if (lonePw && hasUser) return { ok: false, stage: 'locate', message: 'This page is asking you to sign in first — open the site, sign in, then rotate.' };
    return { ok: false, stage: 'locate', message: 'New-password field not found on the page.' };
  }
  if (!submitEl) return { ok: false, stage: 'locate', message: 'Submit button not found on the page.' };
  // Note: a current-password field is filled if present, but NOT required — some change forms
  // (already-authenticated settings pages) don't ask for it. If a site DOES require it and we
  // can't find it, the submit simply won't confirm and the no-lockout gate keeps the old one.

  // 2. Fill.
  if (curEl) setValue(curEl, currentPw);
  setValue(newEl, newPw);
  if (confEl) setValue(confEl, newPw);
  await sleep(150);

  // 3. Submit.
  submitEl.click();

  // 4. Wait for the site to confirm (or reject), or ask for a 2FA code.
  //    This is the no-lockout gate: the caller only commits if we return ok:true.
  const detectOtp = () => !!document.querySelector(
    'input[autocomplete="one-time-code"], input[name*="otp" i], input[id*="otp" i], input[name*="2fa" i], input[id*="2fa" i], input[name*="verification" i], input[id*="verification" i], input[name*="onetime" i], input[name*="one-time" i]');
  const timeout = recipe.timeoutMs || 8000;
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (okSignal()) return { ok: true, stage: 'done', message: 'Site confirmed the password change.' };
    if (failSignal()) return { ok: false, stage: 'verify', message: 'Site reported an error. Old password kept.' };
    if (detectOtp()) return { ok: false, stage: '2fa', message: 'This change needs a 2-factor code. Enter it on the page and finish the change.' };
    await sleep(200);
  }
  return { ok: false, stage: 'verify', message: 'No confirmation from the site (timed out). Old password kept.' };
}

// Re-check whether the change ultimately succeeded — used after the user completes a
// 2FA step on the page. Self-contained; injected via executeScript, unit-tested in jsdom.
export function checkSuccessOnPage(recipe) {
  const q = (s) => { try { return document.querySelector(s); } catch (_) { return null; } };
  const arr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
  const bodyText = () => ((document.body && document.body.innerText) || '').toLowerCase();
  for (const u of arr(recipe.successUrlIncludes)) if (location.href.includes(u)) return { ok: true };
  for (const s of arr(recipe.successSelector)) if (q(s)) return { ok: true };
  for (const t of arr(recipe.successTextIncludes)) if (bodyText().includes(String(t).toLowerCase())) return { ok: true };
  for (const s of arr(recipe.errorSelector)) if (q(s)) return { ok: false };
  for (const t of arr(recipe.errorTextIncludes)) if (bodyText().includes(String(t).toLowerCase())) return { ok: false };
  return { ok: false, uncertain: true };
}

// learnRecipe() inspects the change-password form currently on the page and derives a
// site-specific recipe (exact selectors). Injected via executeScript when the generic
// detector misses a site — lets rotation coverage grow without hand-written recipes.
// Self-contained (page globals only), and unit-tested in jsdom.
export function learnRecipe() {
  const cssEsc = (s) => (typeof CSS !== 'undefined' && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  const sel = (el) => {
    if (!el) return null;
    const tag = el.tagName.toLowerCase();
    if (el.id) return '#' + cssEsc(el.id);
    if (el.getAttribute('name')) return `${tag}[name="${el.getAttribute('name')}"]`;
    if (el.getAttribute('autocomplete')) return `${tag}[autocomplete="${el.getAttribute('autocomplete')}"]`;
    if (el.getAttribute('type')) return `${tag}[type="${el.getAttribute('type')}"]`;
    return tag;
  };
  const pw = [...document.querySelectorAll('input[type="password"]')];
  if (!pw.length) return { ok: false, message: 'No password fields found on this page.' };
  const byAc = (v) => document.querySelector(`input[type="password"][autocomplete="${v}"]`);
  const matchName = (re) => pw.find((e) => re.test((((e.getAttribute('name') || '') + ' ' + (e.id || '')).toLowerCase())));
  let cur = byAc('current-password') || matchName(/current|old/);
  let neu = byAc('new-password') || matchName(/new/);
  const conf = matchName(/confirm|retype|verify/);
  const remaining = pw.filter((e) => e !== cur && e !== neu && e !== conf);
  if (!neu) neu = remaining.shift() || pw[pw.length - 1];
  if (!cur && pw.length >= 2 && pw[0] !== neu) cur = pw[0];
  const form = neu && neu.closest('form');
  const submit = (form && form.querySelector('button[type="submit"],input[type="submit"]')) || document.querySelector('button[type="submit"],input[type="submit"]');
  const recipe = {
    currentPasswordSelector: cur ? sel(cur) : null,
    newPasswordSelector: neu ? sel(neu) : null,
    confirmPasswordSelector: conf ? sel(conf) : null,
    submitSelector: submit ? sel(submit) : null,
    successTextIncludes: ['password has been', 'password was changed', 'password updated', 'successfully'],
    // Remember the exact page this form lives on, so a later off-site rotation can navigate
    // straight here instead of guessing via /.well-known/change-password.
    changePasswordUrl: (typeof location !== 'undefined' && location.href) ? location.href : null,
    learnedAt: new Date().toISOString(),
  };
  if (!recipe.newPasswordSelector || !recipe.submitSelector) return { ok: false, message: 'Could not identify the new-password field or the submit button.' };
  return { ok: true, recipe };
}
