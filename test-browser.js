// In-browser self-test. Runs the REAL crypto + logic (Web Crypto, real DOM) and renders
// results. Open chrome-extension://<id>/test.html to verify the build in Chrome itself.
import {
  randomSaltB64, deriveKey, encryptJSON, decryptJSON, genPassword, mask, commitRotation,
  seedVault, exportKeyB64, importKeyB64, sha1HexUpper, pwnedParts, countFromRange,
  newAccount, parseLoginsCsv, providerSecurityUrl, providerConnectionsUrl,
  findReusedPasswords, keystoneGroups, makeBackup, readBackup,
} from './core.js';
import { extractLogin, looksLikeChangePassword } from './capture-core.js';

const out = document.getElementById('out');
let pass = 0, fail = 0;
function ok(label, cond) {
  const row = document.createElement('div');
  row.className = 'row';
  row.innerHTML = `<span class="${cond ? 'ok' : 'bad'}">${cond ? '✓' : '✗'}</span><span>${label}</span>`;
  out.appendChild(row);
  cond ? pass++ : fail++;
}

(async () => {
  // crypto round-trip (real Web Crypto)
  const salt = randomSaltB64();
  const key = await deriveKey('correct horse battery staple', salt);
  const wrong = await deriveKey('nope', salt);
  const v = seedVault();
  const blob = await encryptJSON(key, v);
  ok('AES-GCM encrypt → decrypt round-trips', JSON.stringify(await decryptJSON(key, blob)) === JSON.stringify(v));
  ok('ciphertext hides the plaintext password', !JSON.stringify(blob).includes('ghp_demo_old_password_123'));
  let denied = false; try { await decryptJSON(wrong, blob); } catch (_) { denied = true; }
  ok('wrong master password is rejected', denied);
  ok('session key export → import still decrypts', JSON.stringify(await decryptJSON(await importKeyB64(await exportKeyB64(key)), blob)) === JSON.stringify(v));

  // password + rotation
  ok('generates a 20-char password', genPassword(20).length === 20);
  ok('mask hides the middle', mask('abcdefghij').includes('••'));
  const { updated, oldSecret } = commitRotation(v.accounts[0], 'NEWPW');
  ok('rotation sets new secret, preserves old', updated.secret === 'NEWPW' && oldSecret === 'ghp_demo_old_password_123');

  // breach parse
  ok('SHA-1("password") is the known hash', (await sha1HexUpper('password')) === '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  const parts = await pwnedParts('password');
  ok('breach count parsed from range body', countFromRange(parts.suffix + ':42\r\nX:1', parts.suffix) === 42);

  // import + reuse + keystone + backup
  ok('CSV import keeps a comma password intact', parseLoginsCsv('name,url,username,password\nA,https://a.com,u,"p,w"')[0].secret === 'p,w');
  ok('reused-password detection flags shared passwords', findReusedPasswords([{ id: '1', secret: 'x', authType: 'password' }, { id: '2', secret: 'x', authType: 'password' }]).size === 2);
  ok('keystone groups SSO by provider', keystoneGroups([{ authType: 'sso', provider: 'Google' }, { authType: 'sso', provider: 'Google' }]).get('Google').length === 2);
  ok('provider security + connections URLs resolve', providerSecurityUrl('Google').includes('myaccount') && providerConnectionsUrl('Google').includes('connections'));
  ok('backup bundle round-trips', readBackup(JSON.stringify(makeBackup({ a: 1 }, { b: 2 }))).vault.b === 2);

  // capture extraction (real DOM)
  const form = document.createElement('form');
  form.innerHTML = '<input type="email" value="me@x.com"><input type="password" value="s3cret">';
  const cred = extractLogin(form);
  ok('capture extracts username + password from a form', cred.username === 'me@x.com' && cred.password === 's3cret');
  const cp = document.createElement('form');
  cp.innerHTML = '<input type="password"><input type="password" autocomplete="new-password">';
  ok('capture skips change-password forms', looksLikeChangePassword(cp) === true);

  const sum = document.getElementById('sum');
  sum.textContent = fail === 0 ? `✅ ALL ${pass} TESTS PASSED` : `❌ ${fail} FAILED (${pass}/${pass + fail})`;
  sum.className = 'sum ' + (fail === 0 ? 'ok' : 'bad');
})();
