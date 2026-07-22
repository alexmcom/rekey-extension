// test-realsite-battery.js — the F11 "real-site" test battery.
//
// WHY THIS EXISTS: the jsdom unit tests use hand-made forms that pass while REAL
// sites fail (the dogfooding meta-lesson). This harness runs the engine's REAL
// detection functions against a corpus of page HTML under fixtures/realsite/, each
// paired with a .json of what the engine SHOULD conclude. Two ways to grow the corpus:
//   1) Regression fixtures hand-labelled from bugs we actually hit (checked in here).
//   2) REAL rendered pages captured on a Mac via capture-realsite.mjs (the real win).
//
// Run:  node test-realsite-battery.js
// A fixture is <name>.html + <name>.json in fixtures/realsite/.
//
// .json shape (every key optional — only the checks you list are run):
// {
//   "url": "https://auth.example.com/login",
//   "kind": "login | signup | change | reset | login-error | login-success | magiclink | sso | 2fa",
//   "note": "human description / which real bug this guards",
//   "expect": {
//     "findLoginFields":      { "user": true, "pass": true } | null,
//     "findNewPasswordFields": { "newPass": true, "confirm": true } | null,
//     "detectLoginError":     true | false,
//     "looksLikeChangePassword": true | false,
//     "classifyOutcome":      "success" | "failure" | "pending",
//     "extractLogin":         { "username": "me@x.com", "password": "hunter2" }
//   }
// }

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { extractLogin, looksLikeChangePassword, detectLoginError, classifyOutcome } from './capture-core.js';
import { findLoginFields, findNewPasswordFields } from './autofill-core.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'realsite');

let pass = 0, fail = 0, flags = 0;
const failures = [];
const byKind = {};

function ok(label, cond, detail) {
  if (cond) { pass++; }
  else { fail++; failures.push(label + (detail ? '  →  ' + detail : '')); }
  console.log((cond ? 'PASS ' : 'FAIL ') + label);
}

// The <form> extractLogin should operate on: the one holding the password, else the first form.
function primaryForm(doc) {
  const pw = doc.querySelector('input[type="password"]');
  return (pw && (pw.form || pw.closest('form'))) || doc.querySelector('form') || null;
}

function run() {
  if (!existsSync(DIR)) {
    console.log('No fixtures/realsite/ dir yet — capture some pages first (see capture-realsite.mjs).');
    process.exit(0);
  }
  const htmls = readdirSync(DIR).filter((f) => f.endsWith('.html')).sort();
  if (!htmls.length) { console.log('fixtures/realsite/ is empty. Capture pages with capture-realsite.mjs.'); process.exit(0); }

  for (const file of htmls) {
    const base = file.slice(0, -5);
    const jsonPath = join(DIR, base + '.json');
    const html = readFileSync(join(DIR, file), 'utf8');
    const meta = existsSync(jsonPath) ? JSON.parse(readFileSync(jsonPath, 'utf8')) : {};
    const url = meta.url || 'https://example.com/';
    const kind = meta.kind || 'unlabelled';
    byKind[kind] = (byKind[kind] || 0) + 1;

    const dom = new JSDOM(html, { url });
    const doc = dom.window.document;
    // The detectors read some globals as a fallback; point them at this fixture.
    global.document = doc;
    global.location = dom.window.location;

    console.log(`\n── ${file}  [${kind}]${meta.note ? '  — ' + meta.note : ''}`);
    const e = meta.expect || {};

    if ('findLoginFields' in e) {
      const r = findLoginFields(doc);
      if (e.findLoginFields === null) ok(`${base}: findLoginFields is null`, r == null, r && 'got fields');
      else {
        ok(`${base}: findLoginFields found a password field`, !!(r && r.pass));
        if (e.findLoginFields.user) ok(`${base}: findLoginFields found the username field`, !!(r && r.user));
        if (e.findLoginFields.userName) ok(`${base}: username field is the right one (${e.findLoginFields.userName})`,
          !!(r && r.user && (r.user.name === e.findLoginFields.userName || r.user.id === e.findLoginFields.userName)),
          r && r.user && `got ${r.user.name || r.user.id}`);
      }
    }
    if ('findNewPasswordFields' in e) {
      const r = findNewPasswordFields(doc);
      if (e.findNewPasswordFields === null) ok(`${base}: findNewPasswordFields is null (not a create/reset form)`, r == null, r && 'wrongly matched');
      else {
        ok(`${base}: findNewPasswordFields found a new-password field`, !!(r && r.newPass));
        if (e.findNewPasswordFields.confirm) ok(`${base}: found the confirm field`, !!(r && r.confirm));
      }
    }
    if ('detectLoginError' in e) {
      ok(`${base}: detectLoginError == ${e.detectLoginError}`, detectLoginError(doc) === e.detectLoginError);
    }
    if ('looksLikeChangePassword' in e) {
      const f = primaryForm(doc);
      ok(`${base}: looksLikeChangePassword == ${e.looksLikeChangePassword}`, !!f && looksLikeChangePassword(f) === e.looksLikeChangePassword);
    }
    if ('classifyOutcome' in e) {
      ok(`${base}: classifyOutcome == ${e.classifyOutcome}`, classifyOutcome(doc, url) === e.classifyOutcome);
    }
    if ('extractLogin' in e) {
      const f = primaryForm(doc);
      const r = f ? extractLogin(f) : null;
      ok(`${base}: extractLogin username == ${JSON.stringify(e.extractLogin.username)}`, !!r && r.username === e.extractLogin.username, r && `got ${JSON.stringify(r.username)}`);
      if (e.extractLogin.password) ok(`${base}: extractLogin captured the password`, !!r && r.password === e.extractLogin.password);
    }

    // Label-free smoke flag: a page that clearly has a password field but the engine
    // finds NEITHER a login nor a new-password form is almost certainly a real miss.
    if (!('findLoginFields' in e) && !('findNewPasswordFields' in e)) {
      const hasPw = !!doc.querySelector('input[type="password"]');
      if (hasPw && !findLoginFields(doc) && !findNewPasswordFields(doc)) {
        flags++;
        console.log(`FLAG ${base}: has a password field but engine detected no login AND no new-password form — likely a miss to review`);
      }
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`Coverage by page kind: ${JSON.stringify(byKind)}`);
  console.log(`Checks: ${pass} passed, ${fail} failed.  Label-free flags to review: ${flags}.`);
  if (failures.length) {
    console.log('\nFailures:');
    failures.forEach((f) => console.log('  ✗ ' + f));
  }
  console.log(fail ? '\n❌ REAL-SITE BATTERY: failures above — engine misses real structures.' : '\n✅ REAL-SITE BATTERY: all labelled checks passed.');
  process.exit(fail ? 1 : 0);
}

run();
