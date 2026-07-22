// Tests passive-capture detection against realistic forms (jsdom).
// Run: node test-capture.js
import { JSDOM } from 'jsdom';
import { extractLogin, looksLikeChangePassword, install, detectLoginError, classifyOutcome, looksLikeAuthUrl, stillShowingLoginForm } from './capture-core.js';

let pass = 0, fail = 0;
const ok = (l, c) => { console.log((c ? 'PASS ' : 'FAIL ') + l); c ? pass++ : fail++; };

function setup(html, url = 'https://www.example.com/login') {
  const dom = new JSDOM(html, { url });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  return dom;
}

// 1. A normal login form.
{
  setup(`<form id="f"><input type="email" value="me@x.com"><input type="password" value="s3cret"><button type="submit">Log in</button></form>`);
  const c = extractLogin(document.getElementById('f'));
  ok('extracts username + password from a login form', c.username === 'me@x.com' && c.password === 's3cret');
  ok('login form is NOT flagged as change-password', looksLikeChangePassword(document.getElementById('f')) === false);
}

// 2. A change-password form should be ignored by capture.
{
  setup(`<form id="f"><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"></form>`);
  ok('change-password form IS flagged (so capture skips it)', looksLikeChangePassword(document.getElementById('f')) === true);
}

// 3. install() fires on submit, with the (www-stripped) host.
{
  setup(`<form id="f"><input type="text" value="alex"><input type="password" value="pw123"><button type="submit">Go</button></form>`);
  let got = null;
  install((c) => { got = c; });
  document.getElementById('f').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  ok('install() captures on submit with host stripped of www', got && got.password === 'pw123' && got.username === 'alex' && got.host === 'example.com');
}

// 4. An empty password submit captures nothing.
{
  setup(`<form id="f"><input type="text" value="alex"><input type="password" value=""><button type="submit">Go</button></form>`);
  ok('empty password yields no credential', extractLogin(document.getElementById('f')) === null);
}

// 5. A rejected login (Spotify-style inline error) is detected as a failure.
{
  setup(`<div role="alert">Incorrect email address or password.</div>
    <form id="f"><input type="email" value="me@x.com"><input type="password" value="wrongpw"><button type="submit">Log in</button></form>`);
  ok('detects a login failure (wrong password error + password field present)', detectLoginError(document) === true);
}

// 6. A successful login (form gone, no error) is NOT a failure.
{
  setup(`<h1>Welcome back!</h1><nav>Your Library</nav>`, 'https://open.spotify.com/');
  ok('no failure when the login form is gone (success)', detectLoginError(document) === false);
}

// 7. A login page sitting idle (no error yet) is NOT a failure.
{
  setup(`<form id="f"><input type="email"><input type="password"><button type="submit">Log in</button></form>`);
  ok('no failure on a fresh login form with no error message', detectLoginError(document) === false);
}

// 8. Unrelated page text containing "invalid" elsewhere doesn't trip it without a password field.
{
  setup(`<p>Your session was invalid, please continue.</p><a href="/">Home</a>`, 'https://example.com/');
  ok('no false failure when there is no password field on the page', detectLoginError(document) === false);
}

// 9. Outcome polling: the login form still present with no error yet is 'pending'
//    (NOT success) — this is the race fix so a slow rejection can't slip a save through.
{
  setup(`<form id="f"><input type="email" value="me@x.com"><input type="password" value="pw"><button type="submit">Log in</button></form>`);
  ok("still on the login form, no error → 'pending' (don't offer yet)", classifyOutcome(document) === 'pending');
}

// 10. A visible error → 'failure'.
{
  setup(`<div role="alert">Incorrect email address or password.</div>
    <form id="f"><input type="email"><input type="password" value="pw"><button>Log in</button></form>`);
  ok("wrong-password error → 'failure'", classifyOutcome(document) === 'failure');
}

// 11. Login form gone AND we've left the auth page → 'success'.
{
  setup(`<h1>Welcome back</h1><nav>Home</nav>`, 'https://open.spotify.com/');
  ok("login form gone on a non-auth URL → 'success'", classifyOutcome(document) === 'success');
}

// 12. F7 REGRESSION: password field gone but we're STILL on an auth/challenge URL (Amazon-style
//     re-auth after a failed sign-in). This must be 'pending', NOT 'success' — otherwise Rekey
//     prompts to save a password the site never accepted.
{
  setup(`<div><h1>Authentication required</h1><p>For your security, please continue.</p></div>`, 'https://www.amazon.com/ap/signin?ie=UTF8');
  ok("F7: no password field but still on an auth URL → 'pending' (don't offer to save)", classifyOutcome(document) === 'pending');
}

// 13. looksLikeAuthUrl recognises common sign-in URLs and clears real destinations.
{
  ok('auth URL: amazon /ap/signin', looksLikeAuthUrl('https://www.amazon.com/ap/signin') === true);
  ok('auth URL: spotify /login', looksLikeAuthUrl('https://accounts.spotify.com/login') === true);
  ok('non-auth URL: a logged-in home page', looksLikeAuthUrl('https://open.spotify.com/') === false);
  ok('non-auth URL: an account dashboard', looksLikeAuthUrl('https://www.amazon.com/gp/css/homepage.html') === false);
}

// 14. F1 REGRESSION (real Amazon repro): the exact "There was a problem / Your password is
//     incorrect" error, with the password field still present, is detected — this is what
//     now suppresses the "Fill your saved login?" prompt on a failed sign-in page.
{
  setup(`<div><h4>There was a problem</h4><p>Your password is incorrect</p></div>
    <form id="f"><input type="email" value="me@x.com"><input type="password"><button>Sign in</button></form>`,
    'https://www.amazon.ca/ap/signin');
  ok('F1: Amazon "Your password is incorrect" is detected as a login error', detectLoginError(document) === true);
}

// 15. #90 REGRESSION (RegFox-style): multi-field signup with Company + Website + Email + Password.
//     The username must be the EMAIL, never the organization/company name.
{
  setup(`<form id="f">
    <input type="text" name="organization" placeholder="Organization or company name" value="2pacforsure">
    <input type="text" name="website" placeholder="Website URL (optional)" value="">
    <input type="text" name="email" placeholder="Enter email address" value="burner@gmail.com">
    <input type="password" value="Str0ng!pw"><button type="submit">Create account</button></form>`);
  const c = extractLogin(document.getElementById('f'));
  ok('#90: captures the email, not the company name', c.username === 'burner@gmail.com');
}

// 16. Same, but the email field is a proper type=email — still the email, never the org.
{
  setup(`<form id="f">
    <input type="text" name="company" value="AcmeCo">
    <input type="email" value="me@x.com">
    <input type="password" value="pw"><button>Sign up</button></form>`);
  ok('captures type=email username over a company text field', extractLogin(document.getElementById('f')).username === 'me@x.com');
}

// ── Wrong-password-on-a-NEW-site guard (Jul 21) ───────────────────────────────
// Reported by Alex: "if I get the password wrong on a new site, does it still save it?"
// Two layers stop that: (a) a widened error-phrase list, (b) stillShowingLoginForm(), which
// fails closed when the page we land on is still asking for a password.

// 17. Real-world error wordings the old regex missed.
{
  const wordings = [
    'These credentials do not match our records',   // Laravel default
    'Authentication failed',
    'Login failed',
    'Sign-in failed',
    'Bad credentials',                              // Spring Security default
    'Unable to sign in',
    'Failed to log in',
    'Please check your details and try again',
    "We don't recognise that email address",
    'No account found with that email',
    'Your username and password did not match',
    'Your password is incorrect',                   // regression: previously matched
  ];
  let missed = [];
  for (const w of wordings) {
    setup(`<form><input type="text"><input type="password"></form><div role="alert">${w}</div>`);
    if (!detectLoginError(document)) missed.push(w);
  }
  ok('detects all real-world login-failure wordings (' + wordings.length + ')', missed.length === 0);
  if (missed.length) console.log('   missed: ' + JSON.stringify(missed));
}

// 18. Still-innocent text must NOT be read as a login failure (false-positive guard).
{
  const innocent = [
    'Password must be at least 8 characters',
    'Forgot your password?',
    'Show password',
    'Keep me signed in on this device',
    'Your account is protected by two-factor authentication',
  ];
  let falsePos = [];
  for (const w of innocent) {
    setup(`<form><input type="text"><input type="password"></form><div role="alert">${w}</div>`);
    if (detectLoginError(document)) falsePos.push(w);
  }
  ok('does NOT flag innocent password-related copy as a failure', falsePos.length === 0);
  if (falsePos.length) console.log('   false positives: ' + JSON.stringify(falsePos));
}

// 19. THE HOLE: redirect to a non-auth URL, error wording we don't know, login form still there.
{
  setup(`<div class="msg">Something went wrong. Give it another go.</div>
    <form><input type="text" name="user"><input type="password" name="pass"><button>Continue</button></form>`,
    'https://app.example.com/home');
  ok('unknown error wording is NOT matched by the phrase list (as expected)', detectLoginError(document) === false);
  ok('...but stillShowingLoginForm() catches it → capture is dropped', stillShowingLoginForm(document) === true);
  ok('...and the old auth-URL check would have MISSED it', looksLikeAuthUrl('https://app.example.com/home') === false);
}

// 20. A form-less SPA login prompt still counts as "rejected" (Etsy-style).
{
  setup(`<div><input type="text"><input type="password"><button>Sign in</button></div>`, 'https://app.example.com/');
  ok('form-less SPA login prompt counts as still-showing-login', stillShowingLoginForm(document) === true);
}

// 21. Pages that legitimately show a password field AFTER a successful login must NOT be
//     treated as failures — otherwise we'd drop good captures (armed saves, heals).
{
  setup(`<h1>Account settings</h1><form>
    <input type="password" autocomplete="current-password">
    <input type="password" autocomplete="new-password">
    <button>Update password</button></form>`, 'https://app.example.com/settings');
  ok('change-password settings page is NOT treated as a failed login', stillShowingLoginForm(document) === false);
}
{
  setup(`<form><input type="email"><input type="password"><button>Create account</button></form>`,
    'https://app.example.com/welcome');
  ok('signup form is NOT treated as a failed login', stillShowingLoginForm(document) === false);
}
{
  setup(`<div style="display:none"><form><input type="text"><input type="password"><button>Log in</button></form></div>
    <h1>Welcome back, Alex</h1>`, 'https://app.example.com/dashboard');
  ok('hidden login modal on a logged-in page is NOT treated as a failed login', stillShowingLoginForm(document) === false);
}
{
  setup(`<h1>Welcome back, Alex</h1><p>You have 3 new messages.</p>`, 'https://app.example.com/dashboard');
  ok('a clean logged-in page is NOT treated as a failed login', stillShowingLoginForm(document) === false);
}

// 22. A page with BOTH a login form and a register form (Hacker News pattern) still counts as
//     a failure — the login half is what we landed back on.
{
  setup(`<form><input type="text"><input type="password"><button>login</button></form>
    <form><input type="text"><input type="password"><button>create account</button></form>`,
    'https://news.example.com/');
  ok('login-beside-register page counts as still-showing-login', stillShowingLoginForm(document) === true);
}

// 23. Non-English sign-in failures (powers the suspect-password flag on international sites).
{
  const wordings = [
    ['es', 'Contraseña incorrecta'],
    ['es', 'Usuario o contraseña incorrectos'],
    ['es', 'Credenciales inválidas'],
    ['fr', 'Mot de passe incorrect'],
    ['fr', 'Échec de la connexion'],
    ['fr', 'Impossible de vous connecter'],
    ['de', 'Falsches Passwort'],
    ['de', 'Anmeldung fehlgeschlagen'],
    ['de', 'Benutzername oder Passwort ist falsch'],
    ['pt', 'Senha incorreta'],
    ['pt', 'Credenciais inválidas'],
    ['it', 'Password errata'],
    ['it', 'Credenziali non valide'],
    ['nl', 'Onjuist wachtwoord'],
    ['nl', 'Inloggen mislukt'],
    ['pl', 'Nieprawidłowe hasło'],
    ['ru', 'Неверный пароль'],
    ['ru', 'Не удалось войти'],
    ['tr', 'Parola hatalı'],
    ['ja', 'パスワードが正しくありません'],
    ['zh', '密码错误'],
    ['zh', '登录失败'],
    ['ko', '잘못된 비밀번호'],
  ];
  let missed = [];
  for (const [lang, w] of wordings) {
    setup(`<form><input type="text"><input type="password"></form><div role="alert">${w}</div>`);
    if (!detectLoginError(document)) missed.push(lang + ': ' + w);
  }
  ok('detects non-English login failures (' + wordings.length + ' across 12 languages)', missed.length === 0);
  if (missed.length) console.log('   missed: ' + JSON.stringify(missed, null, 1));
}

// 24. Innocent non-English copy must NOT trip the detector (false-positive guard).
{
  const innocent = [
    ['es', '¿Olvidaste tu contraseña?'],
    ['es', 'La contraseña debe tener al menos 8 caracteres'],
    ['fr', 'Mot de passe oublié ?'],
    ['fr', 'Afficher le mot de passe'],
    ['de', 'Passwort vergessen?'],
    ['de', 'Angemeldet bleiben'],
    ['pt', 'Esqueceu sua senha?'],
    ['it', 'Password dimenticata?'],
    ['nl', 'Wachtwoord vergeten?'],
    ['ru', 'Забыли пароль?'],
    ['ja', 'パスワードをお忘れですか'],
    ['zh', '忘记密码？'],
    ['ko', '비밀번호를 잊으셨나요?'],
  ];
  let falsePos = [];
  for (const [lang, w] of innocent) {
    setup(`<form><input type="text"><input type="password"></form><div role="alert">${w}</div>`);
    if (detectLoginError(document)) falsePos.push(lang + ': ' + w);
  }
  ok('does NOT flag innocent non-English copy as a failure', falsePos.length === 0);
  if (falsePos.length) console.log('   false positives: ' + JSON.stringify(falsePos, null, 1));
}

console.log('\n' + (fail === 0 ? '✅ ALL CAPTURE TESTS PASSED' : '❌ ' + fail + ' FAILED') + '  (' + pass + '/' + (pass + fail) + ')');
process.exit(fail === 0 ? 0 : 1);
