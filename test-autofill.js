// Tests autofill field detection + filling against realistic forms (jsdom).
// Run: node test-autofill.js
import { JSDOM } from 'jsdom';
import { findLoginFields, findNewPasswordFields, setFieldValue } from './autofill-core.js';

let pass = 0, fail = 0;
const ok = (l, c) => { console.log((c ? 'PASS ' : 'FAIL ') + l); c ? pass++ : fail++; };

function setup(html, url = 'https://accounts.spotify.com/login') {
  const dom = new JSDOM(html, { url });
  global.window = dom.window; global.document = dom.window.document; global.location = dom.window.location;
  global.HTMLInputElement = dom.window.HTMLInputElement;
  global.HTMLTextAreaElement = dom.window.HTMLTextAreaElement;
  global.Event = dom.window.Event;
  return dom;
}

// 1. A login form → returns the username + password inputs.
{
  setup(`<form><input type="email" id="u" autocomplete="username"><input type="password" id="p" autocomplete="current-password"><button>Log in</button></form>`);
  const f = findLoginFields(document);
  ok('finds login username + password fields', !!f && f.user && f.user.id === 'u' && f.pass && f.pass.id === 'p');
  ok('a login form is NOT treated as a new-password form', findNewPasswordFields(document) === null);
}

// 2. A create/reset form (2 password fields, no current-password) → new-password fields.
{
  setup(`<form>
    <input type="password" id="np" autocomplete="new-password">
    <input type="password" id="cp">
    <button>Create password</button></form>`, 'https://www.spotify.com/password-reset');
  const f = findNewPasswordFields(document);
  ok('finds new + confirm password fields on a reset page', !!f && f.newPass.id === 'np' && f.confirm && f.confirm.id === 'cp');
  ok('a reset form is NOT treated as a login', findLoginFields(document) === null);
}

// 3. A change-password form that asks for the CURRENT password → not our new-password flow.
{
  setup(`<form>
    <input type="password" autocomplete="current-password">
    <input type="password" autocomplete="new-password">
    <input type="password"></form>`, 'https://example.com/settings');
  ok('change-password (has current) is not offered a generated password', findNewPasswordFields(document) === null);
  ok('change-password (3 pw fields) is not treated as a login', findLoginFields(document) === null);
}

// 4. setFieldValue sets the value and fires input/change.
{
  setup(`<input type="password" id="p">`);
  const el = document.getElementById('p');
  let sawInput = false; el.addEventListener('input', () => { sawInput = true; });
  const okSet = setFieldValue(el, 'Str0ng!Pass#9');
  ok('setFieldValue sets the value', okSet && el.value === 'Str0ng!Pass#9');
  ok('setFieldValue fires an input event (framework-visible)', sawInput === true);
}

// 5. A page with no password field → nothing to fill.
{
  setup(`<div><input type="text"><a href="/">home</a></div>`, 'https://example.com/');
  ok('no login fields when there is no password input', findLoginFields(document) === null);
  ok('no new-password fields when there is no password input', findNewPasswordFields(document) === null);
}

// 6. F3 REGRESSION: an UNTAGGED change form (current/new/confirm with NO autocomplete
//    attributes, only name hints) must NOT be treated as a reset — otherwise generate-&-fill
//    types the fresh password into the CURRENT-password box. This is the real-site case that
//    the old marker-only check missed.
{
  setup(`<form>
    <input type="password" name="currentPassword" placeholder="Current password">
    <input type="password" name="newPassword" placeholder="New password">
    <input type="password" name="confirmPassword" placeholder="Confirm new password">
    <button>Update</button></form>`, 'https://example.com/account/security');
  ok('F3: untagged current/new/confirm change form is NOT offered a generated password', findNewPasswordFields(document) === null);
}

// 7. F3 REGRESSION: a 2-field change form where the current field is untagged but its
//    label/name says "old password" must also bail.
{
  setup(`<form>
    <label for="op">Old password</label><input type="password" id="op">
    <input type="password" id="np2" placeholder="New password">
    <button>Save</button></form>`, 'https://example.com/settings');
  ok('F3: 2-field form with an "old password" field is NOT treated as a reset', findNewPasswordFields(document) === null);
}

// 8. A genuine reset page (new + confirm, untagged, no "current") is STILL handled — the fix
//    must not over-bail and break real password-reset links.
{
  setup(`<form>
    <input type="password" name="password" placeholder="New password">
    <input type="password" name="password_confirmation" placeholder="Confirm password">
    <button>Reset password</button></form>`, 'https://example.com/password/reset?token=abc');
  const f = findNewPasswordFields(document);
  ok('untagged new + confirm reset form is still detected', !!f && f.newPass.name === 'password' && f.confirm && f.confirm.name === 'password_confirmation');
}

// 9. SIGNUP CONTEXT: a single-field signup form (one password box, "Create account" button,
//    no confirm, no new-password marker) SHOULD be offered a generated password.
{
  setup(`<form>
    <input type="email" name="email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Create account</button></form>`, 'https://sureshortlist.com/register');
  const f = findNewPasswordFields(document);
  ok('single-field signup (Create account) IS offered a generated password', !!f && f.newPass.name === 'password');
}

// 10. LOGIN GUARD: a near-identical single-field LOGIN form ("Sign in" button, neutral URL)
//     must STILL be left alone — we never offer to "generate a new password" on a login.
{
  setup(`<form>
    <input type="email" name="email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign in</button></form>`, 'https://example.com/account');
  ok('single-field login (Sign in) is NOT offered a generated password', findNewPasswordFields(document) === null);
}

console.log('\n' + (fail === 0 ? '✅ ALL AUTOFILL TESTS PASSED' : '❌ ' + fail + ' FAILED') + '  (' + pass + '/' + (pass + fail) + ')');
process.exit(fail === 0 ? 0 : 1);
