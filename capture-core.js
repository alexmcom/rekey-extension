// capture-core.js — passive login-capture logic (single source of truth).
// Loaded as a module by the capture.js content script (via dynamic import) AND
// unit-tested in Node/jsdom. Uses page globals (document/location) + its args.

// Pull the username + password out of a submitted login form.
export function extractLogin(form) {
  const pw = form.querySelector('input[type="password"]');
  if (!pw || !pw.value) return null;
  let user = form.querySelector('input[autocomplete="username"]')
    || form.querySelector('input[type="email"]')
    || form.querySelector('input[autocomplete="email"]');
  if (!user) {
    // Untagged form (e.g. a signup with Company/Website/Email all as plain text). Pick the real
    // login identifier: prefer an email-ish field, and NEVER a company/website/name/phone field
    // (that's the "2pacforsure org name saved as username" bug).
    const texts = [...form.querySelectorAll('input[type="text"], input:not([type])')];
    const hint = (el) => (((el.getAttribute('name') || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('autocomplete') || '')).toLowerCase());
    const isBad = (el) => /company|organi[sz]ation|\borg\b|website|\burl\b|first.?name|last.?name|\bfname\b|\blname\b|full.?name|phone|\btel\b|address|zip|postal|city|country|coupon|promo/.test(hint(el));
    const looksId = (el) => /e-?mail|user|login|account/.test(hint(el)) || (el.value && String(el.value).includes('@'));
    user = texts.find((t) => looksId(t) && !isBad(t))   // clear identifier, not an org field
      || texts.filter((t) => !isBad(t)).pop()           // else the last non-org text field
      || (texts.length ? texts[texts.length - 1] : null); // last resort
  }
  return { username: user && user.value ? String(user.value).trim() : '', password: pw.value };
}

// Don't mistake a change-password form (2+ password fields, or a new-password field)
// for a login — those are handled by the rotation flow, not capture.
export function looksLikeChangePassword(form) {
  if (form.querySelectorAll('input[type="password"]').length >= 2) return true;
  if (form.querySelector('input[autocomplete="new-password"]')) return true;
  return false;
}

// Did the login just VISIBLY fail? We only offer to save a password once we're
// confident it was accepted — never a rejected/typo'd one. A failure looks like:
// a password field is still on the page AND a visible message says the credentials
// were wrong. Pure + testable (pass a document/root); conservative on purpose so it
// suppresses saves only when it's genuinely sure the login was rejected.
const LOGIN_ERROR_RE = new RegExp(
  [
    'incorrect', 'wrong password',
    "wrong (?:e-?mail|username|credentials?)",
    "invalid (?:e-?mail|password|login|username|credentials?)",
    // "…password is incorrect", "these credentials do not match our records" (Laravel's default),
    // "username and password did not match". Covers don't/doesn't/do not/does not/did not.
    "(?:password|e-?mail|username|login|credentials?).{0,20}(?:is |are |was |were )?(?:incorrect|invalid|(?:do(?:es)?|did)(?:n'?t| not) match|not recogni[sz]ed)",
    "couldn'?t (?:log|sign) you in", "could not (?:log|sign) you in",
    "couldn'?t find (?:your )?account", 'account (?:was )?not found',
    "that password (?:is|was) (?:incorrect|wrong)",
    // Generic failure banners that carry no field name — common on redirect-style logins,
    // which is exactly where a rejected password could otherwise reach the popup save offer.
    "(?:authentication|authorization|login|log-?in|sign-?\\s?in) (?:has )?failed",
    "failed to (?:log|sign) (?:you )?in",
    "unable to (?:log|sign) (?:you )?in",
    'bad credentials', // Spring Security's default
    "(?:please )?check your (?:details|credentials|e-?mail|password|username|login details)",
    "(?:we )?(?:don'?t|do not|didn'?t) recogni[sz]e",
    "no account (?:found|exists|matches)",
    "(?:e-?mail|username) (?:and|or) password (?:you entered )?(?:is|are|was|were)? ?(?:not )?(?:correct|right)",
  ].join('|'),
  'i',
);

// Non-English sign-in failures. NOTE ON SCOPE: the security guarantee does NOT rest on this list —
// stillShowingLoginForm() (structural) and the SPA timeout both fail closed regardless of language,
// so an unrecognised error never lets a wrong password be saved. What these phrases add is the
// SUSPECT-PASSWORD signal: correctly flagging a *saved* password as wrong when it stops working on
// a non-English site. Kept to high-confidence phrasings that pair a credential noun with a failure
// word, so ordinary copy ("forgot your password?", "password must be 8 characters") can't match.
const LOGIN_ERROR_I18N_RE = new RegExp(
  [
    // Spanish
    "contrase(?:ñ|n)a (?:incorrecta|inv(?:á|a)lida|err(?:ó|o)nea)",
    "(?:usuario|correo) (?:o|y) contrase(?:ñ|n)a (?:incorrectos|inv(?:á|a)lidos|no coinciden)",
    "credenciales (?:incorrectas|inv(?:á|a)lidas)",
    "no (?:pudimos|se pudo) iniciar sesi(?:ó|o)n",
    // French
    "mot de passe (?:incorrect|invalide|erron(?:é|e))",
    "identifiant(?:s)? (?:ou mot de passe )?(?:incorrect|invalide)",
    "(?:é|e)chec de (?:la )?connexion",
    "impossible de vous connecter",
    // German
    "falsches passwort", "passwort .{0,15}(?:falsch|ung(?:ü|u)ltig)",
    "ung(?:ü|u)ltige (?:anmeldedaten|zugangsdaten)",
    "anmeldung fehlgeschlagen",
    "benutzername oder passwort .{0,15}falsch",
    // Portuguese
    "senha (?:incorreta|inv(?:á|a)lida)",
    "(?:usu(?:á|a)rio|e-?mail) (?:ou|e) senha (?:incorretos|inv(?:á|a)lidos)",
    "credenciais inv(?:á|a)lidas",
    "falha ao (?:entrar|fazer login)",
    // Italian
    "password (?:errata|non valida)",
    "credenziali non valide",
    "accesso non riuscito",
    // Dutch
    "(?:onjuist|ongeldig) wachtwoord", "wachtwoord is onjuist",
    "ongeldige inloggegevens", "inloggen mislukt",
    // Polish
    "(?:nieprawid(?:ł|l)owe|b(?:łę|le)dne) has(?:ł|l)o",
    "nieprawid(?:ł|l)owy login",
    // Russian
    "неверный пароль", "неправильный пароль",
    "неверный (?:логин|email|адрес).{0,20}парол",
    "не удалось войти",
    // Turkish
    "(?:parola|şifre|sifre) (?:hatal(?:ı|i)|yanl(?:ı|i)ş)",
    "hatal(?:ı|i) (?:parola|şifre|sifre)",
    "ge(?:ç|c)ersiz kullan(?:ı|i)c(?:ı|i)",
    // Japanese
    "パスワードが(?:正しくありません|違います|間違)",
    "ログインできません", "認証に失敗",
    // Chinese (simplified + traditional)
    "密码错误", "密碼錯誤",
    "(?:用户名|帳號|账号)(?:或|和)密(?:码|碼)错误",
    "登录失败", "登入失敗",
    // Korean
    "비밀번호가 (?:올바르지|일치하지) 않",
    "잘못된 비밀번호",
    "로그인에? 실패",
  ].join('|'),
  'i',
);

export function detectLoginError(doc) {
  doc = doc || (typeof document !== 'undefined' ? document : null);
  if (!doc) return false;
  // Only meaningful while we're still looking at a login form.
  if (!doc.querySelector('input[type="password"]')) return false;

  // Prefer explicit alert regions — that's where sites announce sign-in errors.
  const alerts = doc.querySelectorAll('[role="alert"], [aria-live="assertive"], [aria-live="polite"]');
  for (const el of alerts) {
    const t = (el.textContent || '').trim();
    if (t && (LOGIN_ERROR_RE.test(t) || LOGIN_ERROR_I18N_RE.test(t))) return true;
  }
  // Fallback: short visible-ish text blocks (skip giant containers to avoid whole-page matches).
  const nodes = doc.querySelectorAll('p, span, div, label, strong, small');
  for (let i = 0; i < nodes.length; i++) {
    const t = (nodes[i].textContent || '').trim();
    if (t.length > 0 && t.length < 160 && (LOGIN_ERROR_RE.test(t) || LOGIN_ERROR_I18N_RE.test(t))) return true;
  }
  return false;
}

// Is this input actually on screen (not hidden/disabled)? Mirrors autofill-core's `fillable`,
// kept local so capture-core stays dependency-free. Uses layout when the browser offers it
// (offsetParent is null for display:none subtrees) and falls back to attribute checks in jsdom.
function visibleInput(el, hasLayout) {
  if (!el || el.disabled || el.type === 'hidden') return false;
  if (hasLayout) {
    // Authoritative in a real browser: display:none subtrees have no offsetParent and no rects.
    // (getClientRects covers position:fixed, whose offsetParent is legitimately null.)
    return el.offsetParent !== null || (el.getClientRects && el.getClientRects().length > 0);
  }
  // No layout engine (jsdom, detached document): inspect the ancestor chain for the two ways
  // a hidden login modal is normally suppressed.
  for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
    if (n.hidden) return false;
    const style = (n.getAttribute && (n.getAttribute('style') || '')) || '';
    if (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(style)) return false;
  }
  return true;
}

// Does this document have a working layout engine? jsdom reports 0 for every offset metric,
// so `offsetParent === null` there means "no layout", not "hidden".
function docHasLayout(doc) {
  return !!(doc && doc.body && doc.body.offsetHeight > 0);
}

// Does this form's own button clearly say "create account / sign up / register" (and not login)?
function formLooksLikeSignup(form) {
  const t = [...form.querySelectorAll('button, input[type="submit"], input[type="button"]')]
    .map((b) => ((b.textContent || '') + ' ' + (b.value || ''))).join(' ').toLowerCase();
  return /sign[\s-]?up|create\s+account|register|\bjoin\b/.test(t) && !/sign[\s-]?in|log[\s-]?in/.test(t);
}

// Is a LOGIN form still on screen? Used to fail closed after a login navigates: if we submitted
// credentials and the page we land on is still asking for a password, that login was almost
// certainly rejected — regardless of whether the URL looks auth-ish or the site's error wording
// is one we recognise. That combination (redirect + unfamiliar error text + non-auth URL) was the
// one path by which a wrong password could still reach the popup's "Save this login?" offer.
//
// Deliberately excludes forms that legitimately appear AFTER a successful login:
//   • change-password / set-password forms (2+ password fields, or a new-password field)
//   • signup/registration forms
//   • hidden login modals kept in the DOM of a logged-in page
export function stillShowingLoginForm(doc) {
  doc = doc || (typeof document !== 'undefined' ? document : null);
  if (!doc) return false;
  const hasLayout = docHasLayout(doc);
  const pws = [...doc.querySelectorAll('input[type="password"]')].filter((p) => visibleInput(p, hasLayout));
  if (!pws.length) return false;
  return pws.some((pw) => {
    const form = (pw.closest && pw.closest('form')) || null;
    if (!form) return true; // form-less SPA login (e.g. Etsy) — still a visible password prompt
    if (looksLikeChangePassword(form)) return false;
    if (formLooksLikeSignup(form)) return false;
    return true;
  });
}

// Does this URL still look like a sign-in / auth page? A rejected login often reloads the
// login page or bounces to another auth step (e.g. Amazon's /ap/signin challenge) that has
// no password field yet — which would otherwise be misread as success. Used to fail closed.
export function looksLikeAuthUrl(url) {
  url = String(url || (typeof location !== 'undefined' ? location.href : '')).toLowerCase();
  return /(sign-?in|log-?in|signin|login|\/auth\b|authenticate|challenge|\/ap\/signin|sessions\/new|account\/login|u\/login)/.test(url);
}

// After a login is submitted, what happened? Poll this until it stops returning 'pending'.
//  - 'failure' : a wrong-credentials error is visible → never offer to save.
//  - 'success' : the login form is gone AND we've left the auth page → safe to offer.
//  - 'pending' : still on the login form (or a challenge/auth URL) with no error yet →
//                keep waiting. "No password field yet" is NOT success on an auth URL, so a
//                slow rejection or a re-auth challenge can't slip a wrong-password save through.
export function classifyOutcome(doc, url) {
  doc = doc || (typeof document !== 'undefined' ? document : null);
  if (!doc) return 'pending';
  if (detectLoginError(doc)) return 'failure';
  if (!doc.querySelector('input[type="password"]')) {
    // Password field gone. Only call it success once we've also left the auth page.
    // Fail closed: still on an auth/challenge URL → 'pending' (never save an unproven login).
    if (looksLikeAuthUrl(url)) return 'pending';
    return 'success';
  }
  return 'pending';
}

// Attach the submit listener. `send` gets {host, username, password} for each login.
export function install(send) {
  document.addEventListener('submit', (e) => {
    const f = e.target;
    if (!f || f.tagName !== 'FORM') return;
    if (looksLikeChangePassword(f)) return;
    const cred = extractLogin(f);
    if (cred && cred.password) {
      const host = (location.hostname || '').replace(/^www\./, '');
      send({ host, username: cred.username, password: cred.password });
    }
  }, true);
}
