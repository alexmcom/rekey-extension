// Tests the REAL rotation engine against a simulated change-password page (jsdom).
// Run: npm install jsdom && node test-rotate.js
import { JSDOM } from 'jsdom';
import { rotateInPage, learnRecipe, checkSuccessOnPage } from './rotate-dom.js';
import { recipeForSite } from './recipes.js';

let pass = 0, fail = 0;
function ok(label, cond) { console.log((cond ? 'PASS ' : 'FAIL ') + label); cond ? pass++ : fail++; }

// A realistic change-password page whose "server" checks the current password,
// records the new one, and shows a success OR error banner — like a real site.
function makePage({ realCurrent = 'OLDPW' } = {}) {
  const dom = new JSDOM(`<!doctype html><html><body>
    <form id="f">
      <input id="current" type="password" autocomplete="current-password" />
      <input id="newpass" type="password" autocomplete="new-password" />
      <input id="confirm" type="password" autocomplete="new-password" />
      <button id="save" type="button">Change password</button>
    </form>
    <div id="banner"></div>
  </body></html>`, { url: 'https://example.test/settings/password', runScripts: 'outside-only' });

  const { window } = dom;
  const doc = window.document;
  const server = { changedTo: null };
  doc.getElementById('save').addEventListener('click', () => {
    const cur = doc.getElementById('current').value;
    const np = doc.getElementById('newpass').value;
    const cf = doc.getElementById('confirm').value;
    const banner = doc.getElementById('banner');
    if (cur !== realCurrent) { banner.className = 'error'; banner.textContent = 'Current password is incorrect'; return; }
    if (np !== cf || !np) { banner.className = 'error'; banner.textContent = 'Passwords do not match'; return; }
    server.changedTo = np;                       // the "server" accepts it
    banner.className = 'success'; banner.textContent = 'Your password has been updated';
  });

  // expose jsdom's DOM as the globals rotateInPage expects
  global.window = window; global.document = doc; global.location = window.location;
  global.Event = window.Event; global.HTMLInputElement = window.HTMLInputElement;
  global.HTMLTextAreaElement = window.HTMLTextAreaElement;
  return { dom, doc, server };
}

const RECIPE = {
  currentPasswordSelector: '#current',
  newPasswordSelector: '#newpass',
  confirmPasswordSelector: '#confirm',
  submitSelector: '#save',
  successSelector: '.success',
  errorSelector: '.error',
  timeoutMs: 2000,
  locateTimeoutMs: 800,
};

// 1. Happy path — correct current password, site confirms.
{
  const { doc, server } = makePage();
  const res = await rotateInPage(RECIPE, 'OLDPW', 'N3w!StrongPass_9f2');
  ok('happy path returns ok:true', res.ok === true);
  ok('current-password field was filled', doc.getElementById('current').value === 'OLDPW');
  ok('new + confirm fields were filled with the new password', doc.getElementById('newpass').value === 'N3w!StrongPass_9f2' && doc.getElementById('confirm').value === 'N3w!StrongPass_9f2');
  ok('the "server" actually received the new password', server.changedTo === 'N3w!StrongPass_9f2');
}

// 2. Wrong current password — site errors, engine reports failure (no-lockout: caller keeps old).
{
  const { server } = makePage({ realCurrent: 'DIFFERENT' });
  const res = await rotateInPage(RECIPE, 'OLDPW', 'whatever_123');
  ok('wrong current password returns ok:false', res.ok === false);
  ok('failure is detected at the verify stage', res.stage === 'verify');
  ok('no change was committed on the server (old password safe)', server.changedTo === null);
}

// 3. A page with NO password fields → locate failure before touching anything.
{
  const dom = new JSDOM(`<!doctype html><html><body><div>Nothing to see here</div></body></html>`, { url: 'https://nopw.test/x' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'OLDPW', 'x');
  ok('a page with no password fields → locate failure', res.ok === false && res.stage === 'locate');
}

// 3b. ADAPTIVE: a non-standard form (no autocomplete attrs, generic names, no current field,
//     button not type=submit) is handled by inference — even when the recipe selectors miss.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <form><input id="np" type="password" name="pass1"><input id="cp" type="password" name="pass2">
    <button id="go">Save</button></form><div id="banner"></div></body></html>`, { url: 'https://weird.test/settings', runScripts: 'outside-only' });
  const doc = dom.window.document;
  global.window = dom.window; global.document = doc; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const server = { changedTo: null };
  doc.getElementById('go').addEventListener('click', () => {
    const a = doc.getElementById('np').value, b = doc.getElementById('cp').value;
    if (a && a === b) { server.changedTo = a; doc.getElementById('banner').className = 'success'; doc.getElementById('banner').textContent = 'Your password has been updated'; }
  });
  // recipe selectors intentionally DON'T match this form → inference must save it
  const recipe = { newPasswordSelector: '#nope-new', submitSelector: '#nope-btn', successSelector: '.success', locateTimeoutMs: 800, timeoutMs: 1500 };
  const res = await rotateInPage(recipe, '', 'N3w!inferred_9');
  ok('adapts to a non-standard form via inference (no attrs / no current field)', res.ok === true && server.changedTo === 'N3w!inferred_9');
}

// 4. Silent page (no confirmation) — engine times out and keeps the old password.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <input id="current" type="password"><input id="newpass" type="password">
    <button id="save" type="button">Save</button></body></html>`, { url: 'https://silent.test/pw' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'OLDPW', 'x', 'x');
  ok('silent page times out with ok:false at verify stage', res.ok === false && res.stage === 'verify');
}

// 5. Late-rendered form — the engine WAITS for it instead of failing on the first look.
{
  const dom = new JSDOM(`<!doctype html><html><body><div id="app"></div><div id="banner"></div></body></html>`, { url: 'https://late.test/pw', runScripts: 'outside-only' });
  const doc = dom.window.document;
  global.window = dom.window; global.document = doc; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const server = { changedTo: null };
  dom.window.setTimeout(() => {
    doc.getElementById('app').innerHTML = `<form><input id="newpass" type="password" autocomplete="new-password"><input id="confirm" type="password" autocomplete="new-password"><button id="save" type="button">Save</button></form>`;
    doc.getElementById('save').addEventListener('click', () => {
      const np = doc.getElementById('newpass').value, cf = doc.getElementById('confirm').value;
      const b = doc.getElementById('banner');
      if (np && np === cf) { server.changedTo = np; b.className = 'success'; b.textContent = 'Your password has been updated'; }
    });
  }, 500);
  const recipe = { newPasswordSelector: '#newpass', confirmPasswordSelector: '#confirm', submitSelector: '#save', successSelector: '.success', locateTimeoutMs: 2500, timeoutMs: 2000 };
  const res = await rotateInPage(recipe, '', 'N3w!pass_9');
  ok('waits for a late-rendered form and rotates it', res.ok === true && server.changedTo === 'N3w!pass_9');
}

// 6. A sign-in wall (lone password + email, no new-password) → clear "sign in first" message.
{
  const dom = new JSDOM(`<!doctype html><html><body><form><input type="email" value="me@x.com"><input type="password" autocomplete="current-password"><button type="submit">Log in</button></form></body></html>`, { url: 'https://wall.test/login' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage({ newPasswordSelector: '#newpass', submitSelector: '#save', locateTimeoutMs: 400 }, 'x', 'y');
  ok('a re-auth/sign-in wall is reported as needing sign-in', res.ok === false && res.stage === 'locate' && /sign in/i.test(res.message));
}

// 7b. Unsupported /.well-known link (site 404s / never redirects) → clear 'notfound',
//     NOT a vague locate failure (so we don't tell the user to "teach" a dead page).
{
  const dom = new JSDOM(`<!doctype html><html><body><h1>404</h1><p>This page could not be found.</p></body></html>`, { url: 'https://spotify.com/.well-known/change-password' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'x', 'y');
  ok('unsupported change-password link → notfound (not locate)', res.ok === false && res.stage === 'notfound');
}

// 7b-i. A curated URL-only site entry (e.g. wetransfer.com carries only resetUrl) must STILL
//       return working field selectors — regression guard: recipeForSite/resolveRecipe must
//       merge the generic selectors under URL-only entries, not replace them.
{
  const r = recipeForSite('wetransfer.com');
  ok('curated URL-only site still has newPasswordSelector', Array.isArray(r.newPasswordSelector) && r.newPasswordSelector.length > 0);
  ok('curated URL-only site still has currentPasswordSelector', Array.isArray(r.currentPasswordSelector) && r.currentPasswordSelector.length > 0);
}

// 7b-ii. Custom 404 with a CONTRACTION ("can't be found", e.g. WeTransfer) at a NON-well-known
//        URL → still detected as notfound via looksNotFound. Regression guard: the old regex
//        only matched "cannot"/"could not" and missed "can't", so these 404s slipped through.
{
  const dom = new JSDOM(`<!doctype html><html><body><h1>Yikes, that page can't be found.</h1><p>Head back to wetransfer.com</p></body></html>`, { url: 'https://wetransfer.com/reset' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'x', 'y');
  ok("a custom 404 with a contraction (can't be found) → notfound", res.ok === false && res.stage === 'notfound');
}

// 7. learnRecipe records the exact change-password URL (so off-site rotation goes straight there).
{
  const dom = new JSDOM(`<!doctype html><html><body><form>
    <input id="c" type="password" autocomplete="current-password">
    <input id="n" type="password" autocomplete="new-password">
    <button type="submit">Change</button></form></body></html>`, { url: 'https://example.test/settings/password' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.CSS = dom.window.CSS;
  const lr = learnRecipe();
  ok('learnRecipe captures the page URL as changePasswordUrl', lr.ok && lr.recipe.changePasswordUrl === 'https://example.test/settings/password');
}

// 5. SSO page — no password field, but "Sign in with Google" present.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <h1>Choose an account</h1>
    <button id="g">Sign in with Google</button>
    <a href="https://accounts.google.com/o/oauth2/auth">Continue</a>
  </body></html>`, { url: 'https://app.example/login' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'x', 'y');
  ok('SSO page is detected (stage:sso)', res.stage === 'sso');
  ok('SSO provider identified as Google', res.provider === 'Google');
}

// 6. Passkey page — no password field, biometric sign-in.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <h1>Sign in</h1><p>Use your passkey to continue</p>
    <button>Continue with Touch ID</button>
  </body></html>`, { url: 'https://app.example/login' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'x', 'y');
  ok('passkey page is detected (stage:passkey)', res.stage === 'passkey');
}

// 7. learnRecipe derives exact selectors from a change-password form.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <form>
      <input id="oldpw" type="password" autocomplete="current-password">
      <input id="newpw" type="password" autocomplete="new-password" name="new_password">
      <input id="confirmpw" type="password" name="confirm_password">
      <button type="submit">Update</button>
    </form>
  </body></html>`, { url: 'https://learn.test/settings' });
  global.window = dom.window; global.document = dom.window.document;
  const r = learnRecipe();
  ok('learnRecipe succeeds on a standard form', r.ok === true);
  ok('learns the current-password selector', r.recipe.currentPasswordSelector === '#oldpw');
  ok('learns the new-password selector', r.recipe.newPasswordSelector === '#newpw');
  ok('learns the confirm selector', r.recipe.confirmPasswordSelector === '#confirmpw');
  ok('learns a submit selector', !!r.recipe.submitSelector);
}
{
  const dom = new JSDOM(`<!doctype html><html><body><p>no password here</p></body></html>`, { url: 'https://x.test/' });
  global.window = dom.window; global.document = dom.window.document;
  ok('learnRecipe fails cleanly when there are no password fields', learnRecipe().ok === false);
}

// 8. 2FA: an OTP field appears after submit → engine pauses with stage:2fa.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <form><input id="current" type="password"><input id="newpass" type="password"><input id="confirm" type="password">
    <button id="save" type="button">Save</button></form><div id="banner"></div></body></html>`, { url: 'https://2fa.test/pw' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  dom.window.document.getElementById('save').addEventListener('click', () => {
    const i = dom.window.document.createElement('input');
    i.setAttribute('autocomplete', 'one-time-code');
    dom.window.document.body.appendChild(i);
  });
  const res = await rotateInPage(RECIPE, 'OLDPW', 'N3w!pass_ok_9f2');
  ok('a 2FA code field after submit pauses with stage:2fa', res.stage === '2fa');
}

// 9. checkSuccessOnPage re-check (used after the user completes 2FA).
{
  const mk = (inner, url = 'https://s.test/x') => {
    const dom = new JSDOM(`<!doctype html><html><body>${inner}</body></html>`, { url });
    global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  };
  mk('<div class="success">done</div>');
  ok('checkSuccessOnPage sees success', checkSuccessOnPage(RECIPE).ok === true);
  mk('<div class="error">bad</div>');
  ok('checkSuccessOnPage sees error', checkSuccessOnPage(RECIPE).ok === false);
  mk('<div>nothing conclusive</div>');
  ok('checkSuccessOnPage reports uncertain when neither', checkSuccessOnPage(RECIPE).uncertain === true);
}

// 10. Passwordless / email-code login page — no password field, "enter the code" UI.
{
  const dom = new JSDOM(`<!doctype html><html><body>
    <h1>Enter the code we sent to d***r@g*l.com</h1>
    <input inputmode="numeric" maxlength="6"><button>Next</button>
    <a href="#">Log in with a password</a>
  </body></html>`, { url: 'https://accounts.spotify.com/login' });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.Event = dom.window.Event; global.HTMLInputElement = dom.window.HTMLInputElement; global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  const res = await rotateInPage(RECIPE, 'x', 'y');
  ok('email-code login page is detected (stage:passwordless)', res.stage === 'passwordless');
}

console.log('\n' + (fail === 0 ? '✅ ALL ROTATION TESTS PASSED' : '❌ ' + fail + ' FAILED') + '  (' + pass + '/' + (pass + fail) + ')');
process.exit(fail === 0 ? 0 : 1);
