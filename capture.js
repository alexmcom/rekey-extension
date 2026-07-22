// capture.js — content script injected on every web page. Two jobs:
//  1) passive login capture (offers to save logins as you browse), and
//  2) on request, run a rotation IN THIS TAB — this is what powers bulk "rotate all
//     breached": the popup opens each site in a background tab and messages that tab,
//     and this script (already injected) does the fill+submit. No broad host permission
//     needed, because content scripts are granted via the manifest matches.
(async () => {
  try {
    const mod = await import(chrome.runtime.getURL('capture-core.js'));
    const inTopFrame = window.top === window; // only surface the prompt in the main page

    // If THIS page loads already showing a login error — OR we've bounced back to a login
    // form on an auth URL — a just-submitted login (that navigated here) actually failed.
    // Tell the background to drop any capture it buffered on the way out, so we never save
    // or offer a rejected password. Bounced-back detection catches sites (e.g. Amazon) that
    // reload the sign-in page on failure without a text error string we recognise.
    // Fail closed: a VISIBLE login form on the page we landed on means the credentials we just
    // sent were rejected. No longer gated on the URL looking auth-ish — a site that redirects to
    // a plain URL and words its error in a way we don't recognise would otherwise have let a
    // wrong password survive into the popup's "Save this login?" offer.
    const bouncedBackToLogin = mod.stillShowingLoginForm(document);
    if (mod.detectLoginError(document) || bouncedBackToLogin) {
      try { chrome.runtime.sendMessage({ type: 'rekey_forget_recent', host: hostOf() }); } catch (_) {}
    } else {
      // No login error on load → a login we just submitted likely SUCCEEDED. Tell the background
      // to confirm any recently-buffered capture: this auto-saves an armed "Save on sign-in" site
      // and heals suspect/pending accounts even when success arrived via a full-page REDIRECT
      // (where only a tentative capture was ever sent). Harmless no-op if nothing's buffered.
      try { chrome.runtime.sendMessage({ type: 'rekey_confirm_recent' }); } catch (_) {}
    }

    let last = null; // the most recent submitted login, awaiting an outcome

    mod.install((cred) => {
      last = cred;
      // Same-page (SPA) logins: poll the outcome instead of guessing after a fixed delay.
      // Only offer to save on a definite SUCCESS (login form gone). A visible error →
      // never offer. Still on the form with no error → keep waiting (up to ~7s) for the
      // server to answer, so a slow "Incorrect password" can't sneak a save through.
      const deadline = Date.now() + 7000;
      let settled = false;
      const tick = () => {
        if (settled) return;
        const outcome = mod.classifyOutcome(document);
        if (outcome === 'failure') { settled = true; return; } // rejected → save nothing
        if (outcome === 'success') {
          settled = true;
          try {
            chrome.runtime.sendMessage({ type: 'rekey_capture', ...cred }, (res) => {
              if (chrome.runtime.lastError) return; // background asleep — skip prompt
              if (inTopFrame && res && res.unlocked && !res.dupe) offerToSave(cred);
            });
          } catch (_) { /* not ready */ }
          return;
        }
        if (Date.now() > deadline) { settled = true; return; } // still on the form → don't offer
        setTimeout(tick, 350);
      };
      setTimeout(tick, 350);
    });

    // Full-navigation logins: the page unloads before the timer fires. Buffer the login
    // tentatively so it isn't lost — if we land on a failed-login page, the block above
    // (detectLoginError on load) will forget it.
    window.addEventListener('pagehide', () => {
      if (!last) return;
      try { chrome.runtime.sendMessage({ type: 'rekey_capture', ...last, tentative: true }); } catch (_) {}
    });

    // Autofill: offer to fill a saved login, or a fresh strong password on reset pages.
    if (inTopFrame) setupAutofill();
  } catch (_) { /* injection not allowed here */ }
})();

function hostOf() { return (location.hostname || '').replace(/^www\./, ''); }

// Watch the page for a login form (offer to fill the saved login) or a create/reset
// password form (offer to generate + fill a new strong one). Re-scans as the page
// changes (SPA route changes, late-rendered forms). Each kind is offered once per URL.
async function setupAutofill() {
  let af, prompt, cc;
  try {
    af = await import(chrome.runtime.getURL('autofill-core.js'));
    prompt = await import(chrome.runtime.getURL('capture-prompt.js'));
    cc = await import(chrome.runtime.getURL('capture-core.js'));
  } catch (_) { return; }

  let offered = new Set();
  let curUrl = location.href;
  let errorFired = false; // so we report an in-place sign-in error at most once per page/route

  // Is the vault unlocked right now? (No vault data is touched — just a yes/no.)
  const isUnlocked = () => new Promise((res) => {
    try { chrome.runtime.sendMessage({ type: 'rekey_status' }, (st) => res(!chrome.runtime.lastError && !!(st && st.unlocked))); }
    catch (_) { res(false); }
  });

  // The real "Generate & fill" prompt (only shown when the vault is unlocked).
  const showGeneratePrompt = (nu) => {
    prompt.showFillPrompt({
      title: 'Fill a new strong password?', site: hostOf(),
      sub: 'Rekey generates a strong one. On a new site it saves only once you finish signing up.',
      actionLabel: 'Generate & fill', doneText: '✓ Filled',
      onFill: () => new Promise((resolve) => {
        try {
          chrome.runtime.sendMessage({ type: 'rekey_fill_new', host: hostOf() }, (r) => {
            if (chrome.runtime.lastError) { resolve({ ok: false, message: "Rekey isn't responding — reload the page and try again." }); return; }
            if (!r || !r.ok) { resolve({ ok: false, locked: !!(r && r.locked) }); return; }
            const a = af.setFieldValue(nu.newPass, r.password);
            const b = nu.confirm ? af.setFieldValue(nu.confirm, r.password) : true;
            // New site (signup): commit only after the signup form is actually submitted.
            if (!r.saved) watchSignupSubmit(nu, r.password);
            resolve({ ok: a && b, message: (a && b) ? '' : "Couldn't fill the password field on this page." });
          });
        } catch (_) { resolve({ ok: false }); }
      }),
    });
  };

  // On a page where Rekey CAN generate a password: if unlocked, offer it directly; if locked,
  // proactively tell the user to unlock FIRST (before they try), then auto-switch to the real
  // prompt once they've unlocked in the Rekey popup. Master password never enters the page.
  const offerGenerate = async (nu) => {
    if (await isUnlocked()) { showGeneratePrompt(nu); return; }
    prompt.showFillPrompt({
      title: 'Unlock Rekey to generate a password here', site: hostOf(),
      sub: 'Click the 🔒 Rekey icon in your toolbar and unlock — this will switch to Generate & fill automatically.',
      actionLabel: 'Got it', doneText: ' ',
      onFill: () => ({ ok: true }),
    });
    const deadline = Date.now() + 120000;
    const poll = async () => {
      if (await isUnlocked()) { showGeneratePrompt(nu); return; } // replaces the nudge card
      if (Date.now() < deadline) setTimeout(poll, 2000);
    };
    setTimeout(poll, 2000);
  };

  // Show the saved-login prompt for a lookup result: fill it if saved, or offer to save if not.
  const showLoginOffer = (res, login) => {
    if (res.found) {
      // We have this login saved → offer to fill it.
      prompt.showFillPrompt({
        title: 'Fill your saved login?', site: hostOf(), sub: res.username || '',
        actionLabel: 'Fill', doneText: '✓ Filled',
        onFill: () => {
          // Re-find fields at click time: on SPA logins the password box can be replaced
          // after the initial scan, leaving a stale ref (email fills, password doesn't).
          const fresh = af.findLoginFields(document) || login;
          if (fresh.user && res.username) af.setFieldValue(fresh.user, res.username);
          const ok = fresh.pass ? af.setFieldValue(fresh.pass, res.secret) : false;
          // Arm the F1 guard: if this saved password is wrong, a sign-in error moments
          // from now will flag it 'suspect' so we stop re-filling a known-bad password.
          if (ok) { try { chrome.runtime.sendMessage({ type: 'rekey_filled_saved', host: hostOf(), username: res.username || '' }); } catch (_) {} }
          return { ok };
        },
      });
    } else if (res.link) {
      // Cross-domain: this looks like the sign-in page for a saved account (the referrer that
      // sent us here matches that account's domain). Ask the user to confirm the link — Rekey
      // NEVER links on its own. On confirm we remember this host, then fill the saved login.
      prompt.showFillPrompt({
        title: `Fill your ${res.link.site} login here?`, site: hostOf(),
        sub: `This looks like the sign-in page for ${res.link.site}${res.link.username ? ' (' + res.link.username + ')' : ''}. Link it so Rekey fills it here from now on.`,
        actionLabel: 'Fill & remember', doneText: '✓ Filled & linked',
        onFill: () => new Promise((resolve) => {
          try {
            // 1) remember the link, 2) re-look-up (now matches via loginHosts), 3) fill.
            chrome.runtime.sendMessage({ type: 'rekey_link_host', host: hostOf(), accountId: res.link.accountId }, () => {
              chrome.runtime.sendMessage({ type: 'rekey_lookup', host: hostOf() }, (r2) => {
                if (chrome.runtime.lastError || !r2 || !r2.found) { resolve({ ok: false, message: "Linked, but couldn't fill here — open Rekey and try again." }); return; }
                const fresh = af.findLoginFields(document) || login;
                if (fresh.user && r2.username) af.setFieldValue(fresh.user, r2.username);
                const ok = fresh.pass ? af.setFieldValue(fresh.pass, r2.secret) : false;
                if (ok) { try { chrome.runtime.sendMessage({ type: 'rekey_filled_saved', host: hostOf(), username: r2.username || '' }); } catch (_) {} }
                resolve({ ok, message: ok ? '' : "Couldn't fill the password field on this page." });
              });
            });
          } catch (_) { resolve({ ok: false }); }
        }),
      });
    } else {
      // Unlocked but this site isn't saved yet → proactively offer to save it, so users don't
      // have to remember. It's stored after a SUCCESSFUL sign-in only.
      prompt.showFillPrompt({
        title: 'Save this login to Rekey?', site: hostOf(),
        sub: "New site — Rekey will save it once you sign in successfully.",
        actionLabel: 'Save on sign-in', doneText: '✓ Rekey will save it after you sign in',
        onFill: () => { try { chrome.runtime.sendMessage({ type: 'rekey_arm_save', host: hostOf() }); } catch (_) {} },
      });
    }
  };

  // Look up this host's saved login and offer to fill/save it. If the vault is LOCKED we can't
  // read it, so proactively nudge the user to unlock first (they'd otherwise get no help on a
  // login page) — then, once unlocked, re-look-up and swap in the real fill/save offer. Mirrors
  // the signup-page unlock nudge so a locked vault is never a silent dead end.
  const lookupAndOffer = (login) => {
    chrome.runtime.sendMessage({ type: 'rekey_lookup', host: hostOf(), referrer: document.referrer }, (res) => {
      if (chrome.runtime.lastError || !res) return;
      if (res.unlocked) { showLoginOffer(res, login); return; }
      // Locked → nudge to unlock, then retry the lookup once the vault opens.
      prompt.showFillPrompt({
        title: 'Unlock Rekey to fill your saved login', site: hostOf(),
        sub: 'Click the 🔒 Rekey icon in your toolbar and unlock — this will switch to your saved login automatically.',
        actionLabel: 'Got it', doneText: ' ',
        onFill: () => ({ ok: true }),
      });
      const deadline = Date.now() + 120000;
      const poll = async () => {
        if (await isUnlocked()) { // vault opened → get the real answer and offer it
          try { chrome.runtime.sendMessage({ type: 'rekey_lookup', host: hostOf(), referrer: document.referrer }, (r2) => {
            if (!chrome.runtime.lastError && r2 && r2.unlocked) showLoginOffer(r2, login);
          }); } catch (_) {}
          return;
        }
        if (Date.now() < deadline) setTimeout(poll, 2000);
      };
      setTimeout(poll, 2000);
    });
  };

  const scan = () => {
    if (location.href !== curUrl) { curUrl = location.href; offered = new Set(); errorFired = false; } // new page → fresh offers

    // F1: a sign-in error is now showing — including an in-place SPA error that never reloads
    // the page (e.g. RegFox's "Invalid email or password"). Tell the background: it drops any
    // buffered capture AND, if we just filled a SAVED password here, flags it 'suspect' so we
    // stop re-filling a known-bad password. Fire once per page/route so we don't spam it.
    if (!errorFired && cc.detectLoginError(document)) {
      errorFired = true;
      try { chrome.runtime.sendMessage({ type: 'rekey_forget_recent', host: hostOf() }); } catch (_) {}
    }

    if (!offered.has('login')) {
      const login = af.findLoginFields(document);
      // Don't offer to fill (or save) while the page is showing a sign-in error: the saved
      // password may be exactly the one that just failed, so re-filling it is pointless or
      // misleading (the F1 trap). Wait for a clean form. We DON'T mark 'login' offered here,
      // so once the error clears the prompt can still appear.
      if (login && login.pass && !cc.detectLoginError(document)) {
        offered.add('login'); // only AUTO-offer once per page…
        try { lookupAndOffer(login); } catch (_) { /* not ready */ }
        // …but let the user re-summon it: focusing the (empty) password field re-offers the
        // fill. The card auto-dismisses after a bit, so without this a dismissed/timed-out
        // prompt would be a dead end with no way to get autofill back short of reloading.
        if (!login.pass.__rekeyLoginFocusBound) {
          login.pass.__rekeyLoginFocusBound = true;
          login.pass.addEventListener('focus', () => {
            const fresh = af.findLoginFields(document);
            if (fresh && fresh.pass && !fresh.pass.value && !cc.detectLoginError(document)) {
              try { lookupAndOffer(fresh); } catch (_) {}
            }
          });
        }
        return;
      }
    }

    if (!offered.has('newpw')) {
      const nu = af.findNewPasswordFields(document);
      // Only offer when the field is actually visible on screen — not a hidden/background
      // signup form that some sites keep pre-rendered in the DOM.
      if (nu && nu.newPass && af.isOnScreen(nu.newPass)) {
        offered.add('newpw');
        offerGenerate(nu); // unlocked → offer directly; locked → nudge to unlock first, then auto-swap
        // Let the user re-summon it: focusing the (still-empty) new-password field re-offers,
        // so dismissing the card or accidentally clicking away isn't a dead end.
        if (!nu.newPass.__rekeyFocusBound) {
          nu.newPass.__rekeyFocusBound = true;
          nu.newPass.addEventListener('focus', () => { if (!nu.newPass.value) offerGenerate(nu); });
        }
      }
    }
  };

  scan();
  try {
    let t = null;
    const obs = new MutationObserver(() => { clearTimeout(t); t = setTimeout(scan, 400); });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  } catch (_) { /* observer unsupported */ }
  setInterval(scan, 1500); // catch SPA route changes that don't mutate the DOM much
}

// After a "Generate & fill" on a NEW site, only save the account once the signup form is
// actually submitted AND it goes through (the form disappears / the page navigates). If the
// user never submits — e.g. a signup modal popped up and they ignored it — nothing is saved,
// so no phantom account. Grabs the username from the form at submit time (before navigation).
function watchSignupSubmit(nu, password) {
  const form = nu.newPass.form || (nu.newPass.closest && nu.newPass.closest('form'));
  const getUser = () => {
    const scope = form || document;
    let u = scope.querySelector('input[type="email"], input[autocomplete="email"], input[autocomplete="username"]');
    if (!u || !u.value) {
      // Untagged signup: pick the real identifier, never a company/website/name/phone field.
      const cands = [...scope.querySelectorAll('input[type="text"], input:not([type])')];
      const hint = (el) => (((el.getAttribute('name') || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('autocomplete') || '')).toLowerCase());
      const isBad = (el) => /company|organi[sz]ation|\borg\b|website|\burl\b|first.?name|last.?name|\bfname\b|\blname\b|full.?name|phone|\btel\b|address|zip|postal|city|country|coupon|promo/.test(hint(el));
      const looksId = (el) => /e-?mail|user|login|account/.test(hint(el)) || (el.value && String(el.value).includes('@'));
      u = cands.find((t) => t.value && looksId(t) && !isBad(t))
        || cands.filter((t) => t.value && !isBad(t)).pop()
        || u;
    }
    return u && u.value ? String(u.value).trim() : '';
  };
  let done = false, submitted = false, capturedUser = '';
  const commit = () => {
    if (done) return; done = true;
    try { chrome.runtime.sendMessage({ type: 'rekey_save_signup', host: hostOf(), username: capturedUser, password }); } catch (_) {}
  };
  const onSubmit = () => {
    submitted = true;
    capturedUser = getUser(); // capture now, before any navigation clears the fields
    const deadline = Date.now() + 7000;
    const tick = () => {
      if (done) return;
      const stillThere = document.body && document.body.contains(nu.newPass);
      if (!stillThere) { commit(); return; }         // signup form gone → it went through
      if (Date.now() > deadline) { done = true; return; } // still on the form → likely failed; don't save
      setTimeout(tick, 400);
    };
    setTimeout(tick, 600);
  };
  try { (form || document).addEventListener('submit', onSubmit, true); } catch (_) {}
  window.addEventListener('pagehide', () => { if (submitted) commit(); }, { once: true });
  setTimeout(() => { done = true; }, 180000); // stop watching after 3 min
}

// Show the in-page "Save this login?" toast and wire its buttons to the background,
// which owns the vault key this session and can persist the login without the popup.
async function offerToSave(cred) {
  try {
    const p = await import(chrome.runtime.getURL('capture-prompt.js'));
    p.showSavePrompt(cred, {
      onSave: () => { try { chrome.runtime.sendMessage({ type: 'rekey_save_capture', ...cred }); } catch (_) {} },
      onDismiss: () => { try { chrome.runtime.sendMessage({ type: 'rekey_forget_capture', host: cred.host, username: cred.username }); } catch (_) {} },
    });
  } catch (_) { /* prompt module unavailable */ }
}

// Handle rotate / learn requests from the extension (used by bulk rotation).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'rekey_rotate') {
    import(chrome.runtime.getURL('rotate-dom.js'))
      .then((m) => m.rotateInPage(msg.recipe, msg.currentSecret, msg.newSecret))
      .then((res) => sendResponse(res))
      .catch((e) => sendResponse({ ok: false, stage: 'error', message: String((e && e.message) || e) }));
    return true; // keep the channel open for the async response
  }
  if (msg && msg.type === 'rekey_learn') {
    import(chrome.runtime.getURL('rotate-dom.js'))
      .then((m) => sendResponse(m.learnRecipe()))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  return undefined;
});
