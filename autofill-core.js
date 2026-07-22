// autofill-core.js — pure DOM helpers for filling forms. Loaded by the capture.js
// content script (dynamic import) AND unit-tested in Node/jsdom. No chrome APIs here.

// Is an input actually fillable (visible-ish, not hidden/disabled)? jsdom has no layout,
// so we stay lenient: reject only clearly-hidden/disabled fields.
function fillable(el) {
  if (!el || el.disabled || el.readOnly) return false;
  if (el.type === 'hidden') return false;
  const style = (el.getAttribute && (el.getAttribute('style') || '')) || '';
  if (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(style)) return false;
  return true;
}

// Does THIS form's own button clearly say "create account / sign up / register" (and not login)?
// Used to pick the login form over a register form when a page shows both.
function formLooksLikeSignup(form) {
  const t = [...form.querySelectorAll('button, input[type="submit"], input[type="button"]')]
    .map((b) => ((b.textContent || '') + ' ' + (b.value || ''))).join(' ').toLowerCase();
  return /sign[\s-]?up|create\s+account|register|\bjoin\b/.test(t) && !/sign[\s-]?in|log[\s-]?in/.test(t);
}

// Find a LOGIN form's username + password fields (for filling a saved login).
// Skips create/change-password forms (those have a new-password field).
export function findLoginFields(doc) {
  doc = doc || (typeof document !== 'undefined' ? document : null);
  if (!doc) return null;
  const pws = [...doc.querySelectorAll('input[type="password"]')].filter(fillable);
  if (!pws.length) return null;
  // Reject change/create forms at the FORM level, not the whole page: a single page can hold a
  // login form AND a separate register form (e.g. Hacker News, many older sites), which is still
  // fillable. Only a form with 2+ password fields, or a new-password field, is a change/create
  // form to skip. (The old page-wide "2+ passwords = change form" bail missed every such page.)
  const isChangeOrNew = (p) => {
    if (p.getAttribute('autocomplete') === 'new-password') return true;
    const form = p.form;
    if (form) {
      const fpws = [...form.querySelectorAll('input[type="password"]')].filter(fillable);
      if (fpws.length >= 2) return true;
      if (fpws.some((q) => q.getAttribute('autocomplete') === 'new-password')) return true;
    }
    return false;
  };
  const candidates = pws.filter((p) => !isChangeOrNew(p));
  if (!candidates.length) return null;
  // When a page has both, prefer the form that is NOT a signup (button says login, not "create
  // account"); otherwise take the first in DOM order (login usually precedes register).
  const loginPw = candidates.find((p) => !p.form || !formLooksLikeSignup(p.form)) || candidates[0];

  const scope = loginPw.form || doc;
  // Use ~= (whitespace-token match) not = : real sites set autocomplete to token lists like
  // "username webauthn" or "email username" (e.g. Wikipedia), which an exact match would miss.
  let user = scope.querySelector('input[autocomplete~="username"], input[autocomplete~="email"], input[type="email"]');
  if (!user || !fillable(user)) {
    const texts = [...scope.querySelectorAll('input[type="text"], input:not([type])')].filter(fillable);
    user = texts.length ? texts[texts.length - 1] : null;
  }
  return { user: user && fillable(user) ? user : null, pass: loginPw };
}

// Build a lowercase "hints" string from a field's attributes + its <label>, so we can
// recognise current/new/confirm password fields even on forms that DON'T set autocomplete.
function fieldHints(el) {
  if (!el || !el.getAttribute) return '';
  const parts = [
    el.getAttribute('name'), el.getAttribute('id'), el.getAttribute('placeholder'),
    el.getAttribute('aria-label'), el.getAttribute('autocomplete'),
  ];
  try {
    const id = el.getAttribute('id');
    const doc = el.ownerDocument;
    if (id && doc) {
      const esc = (typeof CSS !== 'undefined' && CSS.escape) ? CSS.escape(id) : id.replace(/"/g, '\\"');
      const lab = doc.querySelector('label[for="' + esc + '"]');
      if (lab) parts.push(lab.textContent || '');
    }
  } catch (_) { /* label lookup optional */ }
  return parts.filter(Boolean).join(' ').toLowerCase();
}

// A field is a CURRENT-password field if tagged as such, OR its name/id/placeholder/label
// says so. Recognising the untagged case is what stops F3 (typing a fresh password into
// the current-password box on a change form that omits autocomplete attributes).
function looksCurrentPw(el) {
  if (el.getAttribute('autocomplete') === 'current-password') return true;
  return /\b(current|old|existing|previous)\b/.test(fieldHints(el));
}

// Does this page/form look like a SIGN-UP (create account), not a login? A signup page and a
// login page can BOTH be one password box + an email, so we only treat a lone password as
// "generate a new one here" when there's a positive signup signal AND no login signal. This
// lets Rekey offer strong passwords on single-field signups without misfiring on logins.
function looksLikeSignup(doc, pw) {
  const SIGNUP_RE = /(sign[\s-]?up|create\s+(?:an?\s+|your\s+)?account|create\s+account|register|registration|get\s+started|join\s+(?:free|now|us|today)|new\s+account)/i;
  const LOGIN_RE = /(sign[\s-]?in|log[\s-]?in|welcome\s+back)/i;
  const scope = (pw && pw.form) || doc;
  // Strongest signal: the field's OWN form action button — signup word present, login absent.
  const btnText = [...scope.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]')]
    .map((b) => (((b.textContent || '') + ' ' + (b.value || '')))).join(' | ').toLowerCase();
  const signupBtn = SIGNUP_RE.test(btnText), loginBtn = LOGIN_RE.test(btnText);
  if (signupBtn && !loginBtn) return true;   // the form's own button clearly says "create account"
  if (loginBtn && !signupBtn) return false;  // clearly a login form — a signup-y URL must NOT override it
  // Ambiguous button (both words, or neither) → fall back to the page URL.
  try {
    const url = (((typeof location !== 'undefined' && location.href) || (doc && doc.location && doc.location.href) || '')).toLowerCase();
    if (/sign[\s-]?up|signup|register|\/join\b|create[\s-]?account/.test(url)) return true;
  } catch (_) { /* no location */ }
  return false;
}

// Find a CREATE / RESET password form's fields (to fill a fresh strong password).
// Only PURE "set a new password" forms — never a change form that also asks for the
// current password (that's the rotation engine's job). Bailing on change forms — even
// untagged ones — is the F3 fix: generate-&-fill must never touch a current-password box.
export function findNewPasswordFields(doc) {
  doc = doc || (typeof document !== 'undefined' ? document : null);
  if (!doc) return null;
  const pws = [...doc.querySelectorAll('input[type="password"]')].filter(fillable);
  if (!pws.length) return null;

  // Any current-password field (tagged OR inferred) → this is a change form → bail.
  if (pws.some(looksCurrentPw)) return null;
  // 3+ password fields is almost always current + new + confirm → also a change form.
  if (pws.length >= 3) return null;

  const hasNew = pws.some((p) => p.getAttribute('autocomplete') === 'new-password');
  // A single lone password with no "new-password" marker is normally a login/re-auth — EXCEPT
  // when the page is clearly a SIGN-UP (create account), where that one box IS a new password
  // worth generating. Login pages (button says "Sign in") stay excluded via looksLikeSignup.
  if (!hasNew && pws.length < 2 && !looksLikeSignup(doc, pws[0])) return null;

  // No current-password field is present, so the first (or explicitly-marked) field is
  // safely the new password and the other is confirm.
  const newPass = pws.find((p) => p.getAttribute('autocomplete') === 'new-password') || pws[0];
  const confirm = pws.find((p) => p !== newPass) || null;
  return { newPass, confirm };
}

// Is the element actually visible on screen right now (not a hidden/off-screen pre-rendered
// form)? Used to avoid offering "generate a password" on a signup modal that isn't shown.
// Lenient on failure (returns true) so we never suppress a legit prompt by mistake.
export function isOnScreen(el) {
  try {
    if (!el || !el.getBoundingClientRect) return true;
    const r = el.getBoundingClientRect();
    if (!r || (r.width === 0 && r.height === 0)) return false;
    const vw = (typeof window !== 'undefined' && window.innerWidth) || (el.ownerDocument && el.ownerDocument.documentElement.clientWidth) || 0;
    const vh = (typeof window !== 'undefined' && window.innerHeight) || (el.ownerDocument && el.ownerDocument.documentElement.clientHeight) || 0;
    if (!vw || !vh) return true; // no layout info (e.g. tests) → don't suppress
    return r.bottom > 0 && r.right > 0 && r.top < vh && r.left < vw;
  } catch (_) { return true; }
}

// Set a field's value so the site's framework (React/Vue/etc.) actually notices.
// Uses the native value setter, then fires input + change like a real keystroke.
export function setFieldValue(el, value) {
  if (!el) return false;
  try {
    const proto = (typeof HTMLTextAreaElement !== 'undefined' && el instanceof HTMLTextAreaElement)
      ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) desc.set.call(el, value); else el.value = value;
  } catch (_) { el.value = value; }
  try {
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  } catch (_) { /* events optional */ }
  return el.value === value;
}
