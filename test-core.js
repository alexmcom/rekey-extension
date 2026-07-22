// Unit test for core.js — run with: node test-core.js
import { randomSaltB64, deriveKey, encryptJSON, decryptJSON, genPassword, mask, commitRotation, seedVault, exportKeyB64, importKeyB64, sha1HexUpper, pwnedParts, countFromRange, newAccount, parseLoginsCsv, providerSecurityUrl, providerConnectionsUrl, findReusedPasswords, keystoneGroups, makeBackup, readBackup, scorePassword, passwordAgeDays, isStale, computeHealth, isExpired, filterAccounts, sortByRisk, breachedRotatable, newDek, wrapKey, unwrapKey, generateRecoveryKey, monogramFor, registrableDomain, dedupeAccounts, isSampleAccount, reconcileCapturedLogin, revertRotation, markReceiptVerified, pruneHistoryForAccount, markSuspect, adoptWorkingSecret, isOfferable, accountMatchesHost, linkLoginHost, referrerDomain, linkCandidate } from './core.js';
import { hostMatchesSite } from './recipes.js';

let pass = 0, fail = 0;
function ok(label, cond) { console.log((cond ? 'PASS ' : 'FAIL ') + label); cond ? pass++ : fail++; }

const salt = randomSaltB64();
const key = await deriveKey('correct horse battery staple', salt);
const wrongKey = await deriveKey('wrong password', salt);

// 1. encrypt/decrypt round-trips
const vault = seedVault();
vault.accounts.push(newAccount('github.com', 'you@example.com', 'ghp_demo_old_password_123')); // a test account (seed is now empty)
const blob = await encryptJSON(key, vault);
const back = await decryptJSON(key, blob);
ok('encrypt then decrypt returns the same vault', JSON.stringify(back) === JSON.stringify(vault));

// 2. ciphertext is not plaintext (password not readable in storage)
ok('stored blob does not contain the plaintext password', !JSON.stringify(blob).includes('ghp_demo_old_password_123'));

// 3. wrong master password cannot decrypt
let denied = false;
try { await decryptJSON(wrongKey, blob); } catch (e) { denied = true; }
ok('wrong master password is rejected (zero-knowledge)', denied);

// 4. password generator
const pw = genPassword(20);
ok('generates a 20-char password', pw.length === 20);
ok('two generated passwords differ', genPassword() !== genPassword());
ok('generated passwords always score strong (all char classes)', [0, 0, 0].every(() => scorePassword(genPassword()).score === 4));

// 5. masking hides the middle
ok('mask hides the secret middle', mask('ghp_demo_old_password_123').includes('••••'));

// 6. no-lockout rotation commit
const acct = vault.accounts[0];
const newPw = genPassword();
const { updated, receipt, oldSecret } = commitRotation(acct, newPw);
ok('new secret becomes current', updated.secret === newPw);
ok('OLD secret is preserved (not silently lost)', oldSecret === 'ghp_demo_old_password_123');
ok('receipt records old + new (masked) and is NOT verified until a real sign-in confirms it', receipt.oldMasked && receipt.newMasked && receipt.verified === false);
ok('receipt does NOT leak the full new password', !JSON.stringify(receipt).includes(newPw));

// 7. session key cache round-trip (export -> import -> still decrypts)
const cached = await importKeyB64(await exportKeyB64(key));
const back2 = await decryptJSON(cached, blob);
ok('exported+reimported key still decrypts the vault', JSON.stringify(back2) === JSON.stringify(vault));

// 8. breach detection (HIBP k-anonymity) — known SHA-1 of "password"
const KNOWN = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
ok('SHA-1("password") matches the known hash', (await sha1HexUpper('password')) === KNOWN);
const parts = await pwnedParts('password');
ok('prefix is first 5 hex chars', parts.prefix === '5BAA6');
ok('suffix is the remaining 35 chars', parts.suffix === KNOWN.slice(5));
// simulate an API range body: our suffix present with a big count
const mockRange = '0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n' + parts.suffix + ':9876543\r\nFFFF...:2';
ok('counts breaches when suffix is present', countFromRange(mockRange, parts.suffix) === 9876543);
ok('returns 0 when suffix absent (clean password)', countFromRange(mockRange, 'DEADBEEF') === 0);
ok('a freshly generated password is (almost certainly) absent from mock', countFromRange(mockRange, (await pwnedParts(genPassword())).suffix) === 0);

// monogram fallback for favicons: stable letter + color, strips www, handles junk
{
  const g = monogramFor('github.com');
  ok('monogram letter is the first alnum char, uppercased', g.letter === 'G' && /^hsl\(/.test(g.bg));
  ok('monogram strips www and is deterministic', monogramFor('www.github.com').letter === 'G' && monogramFor('github.com').bg === monogramFor('github.com').bg);
  ok('monogram handles empty/odd input without throwing', monogramFor('').letter === '?' && monogramFor('123-abc.io').letter === '1');
}

// dedupe: same real account saved twice (manual + capture) merges into one clean entry
{
  ok('registrableDomain collapses subdomains + urls', registrableDomain('https://www.spotify.com/') === 'spotify.com' && registrableDomain('accounts.spotify.com') === 'spotify.com');
  // Public-suffix awareness: keep 3 labels on two-label suffixes so unrelated owners don't merge.
  ok('registrableDomain keeps bbc.co.uk (not co.uk)', registrableDomain('news.bbc.co.uk') === 'bbc.co.uk');
  ok('registrableDomain keeps user.github.io separate', registrableDomain('alice.github.io') === 'alice.github.io');
  ok('registrableDomain keeps a worker subdomain separate', registrableDomain('rekey-sync.mccomas0.workers.dev') === 'mccomas0.workers.dev');
  ok('registrableDomain collapses regfox subdomains', registrableDomain('auth.regfox.com') === 'regfox.com' && registrableDomain('signup.regfox.com') === 'regfox.com');

  // hostMatchesSite: subdomains of the same site match (the RegFox fix)…
  ok('auth.regfox.com matches a login saved on signup.regfox.com', hostMatchesSite('auth.regfox.com', 'signup.regfox.com') === true);
  ok('accounts.spotify.com matches open.spotify.com', hostMatchesSite('accounts.spotify.com', 'open.spotify.com') === true);
  // …but different owners on a shared host do NOT (the security boundary)
  ok('alice.github.io does NOT match bob.github.io', hostMatchesSite('alice.github.io', 'bob.github.io') === false);
  ok('two different workers.dev sites do NOT match', hostMatchesSite('a.workers.dev', 'b.workers.dev') === false);
  ok('two unrelated .co.uk sites do NOT match', hostMatchesSite('bbc.co.uk', 'hmrc.co.uk') === false);
  ok('genuinely different domains do NOT match', hostMatchesSite('regfox.com', 'webconnex.com') === false);

  const a1 = { ...newAccount('https://www.spotify.com/', 'me@x.com', 'P6xxx2v'), status: 'safe', breachCount: 0 };
  const a2 = { ...newAccount('accounts.spotify.com', 'me@x.com', 'P6xxx2v'), status: 'unknown' };
  const other = newAccount('github.com', 'me@x.com', 'diff');
  const { accounts, removed } = dedupeAccounts([a1, a2, other]);
  ok('merges the two Spotify entries into one', removed === 1 && accounts.length === 2);
  const merged = accounts.find((a) => registrableDomain(a.site) === 'spotify.com');
  ok('merged entry uses the clean registrable domain', merged.site === 'spotify.com');
  ok('merged entry keeps the more informative status (safe over unknown)', merged.status === 'safe');
  ok('a genuinely different account is left alone', accounts.some((a) => a.site === 'github.com'));

  // different usernames on the same domain are NOT merged (two real accounts)
  const b1 = newAccount('spotify.com', 'one@x.com', 'p1');
  const b2 = newAccount('spotify.com', 'two@x.com', 'p2');
  ok('same domain but different usernames stay separate', dedupeAccounts([b1, b2]).removed === 0);

  // an SSO entry is never merged into a password entry for the same site
  const s1 = { ...newAccount('spotify.com', 'me@x.com', ''), authType: 'sso', provider: 'Google', secret: '' };
  const s2 = newAccount('spotify.com', 'me@x.com', 'realpw');
  ok('SSO and password entries for the same login are not merged', dedupeAccounts([s1, s2]).removed === 0);
}

// the built-in sample account is recognized (flag OR legacy placeholder signature), real ones aren't
{
  ok('new vaults start empty (no fake demo account)', seedVault().accounts.length === 0);
  ok('an explicit sample-flagged account is detected', isSampleAccount({ sample: true }) === true);
  ok('legacy seed (no flag) is still detected by its placeholder signature', isSampleAccount({ username: 'you@example.com', secret: 'ghp_demo_old_password_123' }) === true);
  ok('a real account is not a sample', isSampleAccount(newAccount('github.com', 'alex@real.com', 'Str0ng!pw_9x')) === false);
  ok('an edited-away sample (flag cleared, real creds) is not a sample', isSampleAccount({ sample: false, username: 'alex@real.com', secret: 'Str0ng!pw_9x' }) === false);
}

// rotation self-healing: pending state, then confirm / auto-revert / adopt via a real login
{
  const base = newAccount('example.com', 'me@x.com', 'OLDpw');
  const { updated } = commitRotation(base, 'NEWpw');
  ok('rotation marks the account pending and keeps the old password', updated.verify === 'pending' && updated.prevSecret === 'OLDpw' && updated.secret === 'NEWpw');

  // next login uses the NEW password → verified, prevSecret dropped
  const confirmed = reconcileCapturedLogin(updated, 'NEWpw');
  ok('login with the new password marks it verified', confirmed.verify === 'ok' && confirmed.secret === 'NEWpw' && confirmed.prevSecret === undefined);

  // next login had to use the OLD password → rotation never took → auto-restore old
  const reverted = reconcileCapturedLogin(updated, 'OLDpw');
  ok('login with the old password auto-restores it', reverted.verify === 'reverted' && reverted.secret === 'OLDpw' && reverted.prevSecret === undefined);

  // a different password works → user changed it themselves → adopt it
  const adopted = reconcileCapturedLogin(updated, 'THEIRownPw');
  ok('login with a different password adopts it', adopted.verify === 'ok' && adopted.secret === 'THEIRownPw');

  // nothing to reconcile once it's already settled
  ok('a non-pending account is left alone', reconcileCapturedLogin(confirmed, 'anything') === null);

  // manual one-click restore
  const manual = revertRotation(updated);
  ok('manual restore puts the old password back', manual.secret === 'OLDpw' && manual.verify === 'reverted' && manual.prevSecret === undefined);
}

// F6: honest history — a rotation receipt is unverified until a real sign-in confirms it, and
// markReceiptVerified flips ONLY the pending receipt for that account.
{
  const acctH = newAccount('site.com', 'me@x.com', 'OLDpw');
  const { updated, receipt } = commitRotation(acctH, 'NEWpw');
  let history = [receipt];
  ok('fresh rotation receipt starts unverified', receipt.verified === false);
  history = markReceiptVerified(history, updated.id);
  ok('markReceiptVerified flips the account\'s pending receipt to verified', history[0].verified === true && !!history[0].verifiedAt);
  // a receipt for a DIFFERENT account isn't touched
  const other = { id: 'r_x', accountId: 'a_other', action: 'rotated', verified: false };
  const h2 = markReceiptVerified([other], updated.id);
  ok('markReceiptVerified leaves other accounts\' receipts alone', h2[0].verified === false);
  // already-verified receipts aren't re-touched (no second pending one to flip)
  ok('markReceiptVerified is a no-op when nothing is pending', markReceiptVerified(history, updated.id)[0].verifiedAt === history[0].verifiedAt);
}

// F6: deleting an account removes its history receipts (no orphaned "verified" entries linger).
{
  const keep = { id: 'r1', accountId: 'a_keep', action: 'rotated', verified: true };
  const drop = { id: 'r2', accountId: 'a_gone', action: 'rotated', verified: true };
  const pruned = pruneHistoryForAccount([keep, drop], 'a_gone');
  ok('pruneHistoryForAccount drops the deleted account\'s receipts', pruned.length === 1 && pruned[0].accountId === 'a_keep');
  ok('pruneHistoryForAccount keeps everything else', pruneHistoryForAccount([keep], 'a_gone').length === 1);
}

// F1: suspect passwords — a saved password the site just rejected is held back from autofill,
// then healed once the real (working) password is captured.
{
  const acctS = newAccount('bank.com', 'me@x.com', 'WRONGpw');
  ok('a fresh account is offerable', isOfferable(acctS) === true);
  const sus = markSuspect(acctS);
  ok('markSuspect flags the stored password', sus.suspect === true);
  ok('a suspect account is NOT offered for autofill', isOfferable(sus) === false);
  // capturing the real, working password heals it (adopts + clears suspect)
  const healed = adoptWorkingSecret(sus, 'REALpw');
  ok('adoptWorkingSecret adopts the working password and clears suspect', healed.secret === 'REALpw' && healed.suspect === false && healed.verify === 'ok');
  ok('a healed account is offerable again', isOfferable(healed) === true);
  // adopting the SAME already-correct password is a no-op (returns the same object)
  const noop = adoptWorkingSecret(healed, 'REALpw');
  ok('adoptWorkingSecret is a no-op when nothing changes', noop === healed);
  // sample accounts are never offered even when not suspect
  const sample = { ...newAccount('example.com', 'you@example.com', 'ghp_demo_x'), sample: true };
  ok('sample accounts are never offerable', isOfferable(sample) === false);
}

// Cross-domain auth linking (user-confirmed): loginHosts + referrer-hinted link suggestions.
{
  const acct = newAccount('regfox.com', 'me@x.com', 'pw');
  // accountMatchesHost with NO loginHosts must behave EXACTLY like the old site-only match.
  ok('accountMatchesHost matches the account\'s own domain', accountMatchesHost(acct, 'auth.regfox.com', hostMatchesSite) === true);
  ok('accountMatchesHost rejects an unrelated domain (no loginHosts)', accountMatchesHost(acct, 'auth.webconnex.com', hostMatchesSite) === false);

  const linked = linkLoginHost(acct, 'auth.webconnex.com');
  ok('linkLoginHost records the confirmed host', (linked.loginHosts || []).includes('auth.webconnex.com'));
  ok('linkLoginHost is deduped', (linkLoginHost(linked, 'auth.webconnex.com').loginHosts || []).length === 1);
  ok('accountMatchesHost now matches the linked host', accountMatchesHost(linked, 'auth.webconnex.com', hostMatchesSite) === true);
  ok('linked host still does NOT match a different unrelated site', accountMatchesHost(linked, 'evil.com', hostMatchesSite) === false);

  ok('referrerDomain extracts the registrable domain', referrerDomain('https://auth.regfox.com/signin?x=1') === 'regfox.com');
  ok('referrerDomain is empty for junk', referrerDomain('') === '' && referrerDomain('not a url') === '');

  // linkCandidate: suggest linking ONLY when nothing matches the host but the REFERRER does.
  const accounts = [acct, { ...newAccount('cirro.io', 'me@x.com', 'pw2') }];
  const cand = linkCandidate(accounts, 'auth.webconnex.com', 'https://auth.regfox.com/login', hostMatchesSite);
  ok('linkCandidate suggests the referrer-matched account', cand && cand.site === 'regfox.com');
  ok('linkCandidate returns null when the host already matches an account', linkCandidate(accounts, 'auth.regfox.com', 'https://auth.regfox.com/login', hostMatchesSite) === null);
  ok('linkCandidate returns null with no referrer', linkCandidate(accounts, 'auth.webconnex.com', '', hostMatchesSite) === null);
  ok('linkCandidate returns null when referrer domain matches nothing saved', linkCandidate(accounts, 'auth.webconnex.com', 'https://stranger.com/login', hostMatchesSite) === null);
  // never suggest linking an SSO / suspect / sample account
  const ssoAcct = { ...newAccount('regfox.com', 'me@x.com', 'pw'), authType: 'sso' };
  ok('linkCandidate skips SSO accounts', linkCandidate([ssoAcct], 'auth.webconnex.com', 'https://auth.regfox.com/login', hostMatchesSite) === null);
  ok('linkCandidate skips suspect accounts', linkCandidate([markSuspect(acct)], 'auth.webconnex.com', 'https://auth.regfox.com/login', hostMatchesSite) === null);
}

// 9. newAccount factory
const na = newAccount('  Github.com ', ' me@x.com ', 'pw');
ok('newAccount trims + defaults status/breachCount', na.site === 'Github.com' && na.username === 'me@x.com' && na.status === 'unknown' && na.breachCount === 0);

// 10. CSV import (Chrome format, incl. a password containing commas + quotes)
const csv = [
  'name,url,username,password,note',
  'GitHub,https://github.com/login,me@x.com,"p,ass""word",work',
  'Reddit,https://www.reddit.com/,red@x.com,hunter2,',
  ',https://news.ycombinator.com/,hn_user,plainpass,',        // no name -> host from url
  'Empty,https://empty.com,nouser,,',                          // no password -> skipped
].join('\n');
const logins = parseLoginsCsv(csv);
ok('imports the right number of logins (skips passwordless)', logins.length === 3);
ok('password with commas AND quotes survives intact', logins[0].secret === 'p,ass"word');
ok('site + username parsed', logins[0].site === 'GitHub' && logins[0].username === 'me@x.com');
ok('falls back to host when name is blank', logins[2].site === 'news.ycombinator.com');

// 11. SSO helpers
ok('newAccount defaults to authType password', newAccount('x.com', 'u', 'p').authType === 'password');
ok('provider security url resolves (Google)', providerSecurityUrl('Google').includes('myaccount.google.com'));
ok('unknown provider returns empty url', providerSecurityUrl('nope') === '');

// 12. keystone helpers
ok('provider connections url resolves (Google)', providerConnectionsUrl('Google').includes('myaccount.google.com/connections'));
const kg = keystoneGroups([
  { id: 'a1', authType: 'sso', provider: 'Google' },
  { id: 'a2', authType: 'sso', provider: 'Google' },
  { id: 'a3', authType: 'passkey', provider: 'Apple' },
  { id: 'a4', authType: 'password' },
]);
ok('keystoneGroups groups SSO by provider', kg.get('Google').length === 2);
ok('keystoneGroups includes passkey group', kg.get('Apple').length === 1);
ok('keystoneGroups excludes password accounts', !kg.has(undefined) && [...kg.values()].flat().length === 3);

// 13. reused-password detection
const reused = findReusedPasswords([
  { id: 'r1', secret: 'samePass', authType: 'password' },
  { id: 'r2', secret: 'samePass', authType: 'password' },
  { id: 'r3', secret: 'unique', authType: 'password' },
  { id: 'r4', secret: 'samePass', authType: 'sso' }, // SSO ignored
]);
ok('flags the two accounts sharing a password', reused.has('r1') && reused.has('r2'));
ok('does not flag the unique one', !reused.has('r3'));
ok('ignores non-password (SSO) accounts', !reused.has('r4'));

// 14. backup bundle round-trips
const bmeta = { v: 2, salt: 's', recoverySalt: 'rs', masterWrap: { iv: 'i', ct: 'c' }, recoveryWrap: { iv: 'ri', ct: 'rc' }, iters: 600000 };
const bvault = { iv: 'x', ct: 'y' };
const restored = readBackup(JSON.stringify(makeBackup(bmeta, bvault)));
ok('backup preserves meta + vault blobs', JSON.stringify(restored.meta) === JSON.stringify(bmeta) && JSON.stringify(restored.vault) === JSON.stringify(bvault));
let rejected = false; try { readBackup('{"foo":1}'); } catch (_) { rejected = true; }
ok('rejects a non-Rekey file', rejected);
let badJson = false; try { readBackup('not json at all'); } catch (_) { badJson = true; }
ok('rejects a non-JSON file without crashing', badJson);
let corrupt = false; try { readBackup(JSON.stringify({ rekeyBackup: 1, meta: { salt: 's' }, vault: { iv: 'x', ct: 'y' } })); } catch (_) { corrupt = true; }
ok('rejects a structurally-corrupt backup (missing masterWrap) before it can overwrite a vault', corrupt);

// 15. password strength
ok('a short simple password scores weak (<=1)', scorePassword('abc').score <= 1);
ok('a long mixed password scores strong (4)', scorePassword('Xy7$kL9mQ2w!vRt4').score === 4);

// 16. password age / staleness
const dayMs = 86400000;
const oldAcct = { lastRotated: null, addedAt: new Date(Date.now() - 100 * dayMs).toISOString() };
const newAcct = { lastRotated: new Date().toISOString(), addedAt: null };
ok('age computed from addedAt when never rotated', passwordAgeDays(oldAcct) === 100);
ok('100-day-old password is stale (>=90)', isStale(oldAcct) === true);
ok('freshly rotated password is not stale', isStale(newAcct) === false);

// 17. health rollup
const health = computeHealth([
  { id: 'h1', authType: 'password', secret: 'abc', status: 'breached', addedAt: new Date(Date.now() - 100 * dayMs).toISOString() },
  { id: 'h2', authType: 'password', secret: 'abc', status: 'safe', addedAt: new Date().toISOString() },
  { id: 'h3', authType: 'sso', provider: 'Google' },
  { id: 'h4', authType: 'passkey', provider: 'Apple' },
]);
ok('health counts password/sso/passkey', health.password === 2 && health.sso === 1 && health.passkey === 1);
ok('health counts breached + reused + weak + stale', health.breached === 1 && health.reused === 2 && health.weak === 2 && health.stale === 1);

// 18. auto-lock expiry
const t0 = Date.now();
ok('not expired within the window', isExpired(t0, 15, t0 + 5 * 60000) === false);
ok('expired past the window', isExpired(t0, 15, t0 + 20 * 60000) === true);
ok('never-lock (0/undefined) never expires', isExpired(t0, 0, t0 + 999 * 60000) === false);

// 19. search + risk sort
const accts = [
  { id: 's1', site: 'github.com', username: 'me@x.com', authType: 'password', secret: 'Xy7$kL9mQ2w!vRt4', status: 'safe', addedAt: new Date().toISOString() },
  { id: 's2', site: 'reddit.com', username: 'red', authType: 'password', secret: 'Strong9!Pass_x2y', status: 'breached', addedAt: new Date().toISOString() },
  { id: 's3', site: 'news.com', username: 'n', authType: 'password', secret: 'abc', status: 'safe', addedAt: new Date().toISOString() },
];
ok('search matches by site', filterAccounts(accts, 'github').length === 1);
ok('search matches by username', filterAccounts(accts, 'red').length === 1);
ok('empty query returns all', filterAccounts(accts, '').length === 3);
const sorted = sortByRisk(accts);
ok('breached account floats to the top', sorted[0].id === 's2');
ok('weak account ranks above the safe/strong one', sorted[1].id === 's3');

// 20. bulk "rotate all breached" targeting
const bulk = breachedRotatable([
  { id: 'b1', status: 'breached', authType: 'password', secret: 'x' },   // yes
  { id: 'b2', status: 'breached', authType: 'emaillink', secret: 'y' },  // yes (password fallback)
  { id: 'b3', status: 'breached', authType: 'sso', secret: '' },         // no (no password)
  { id: 'b4', status: 'breached', authType: 'passkey' },                 // no
  { id: 'b5', status: 'safe', authType: 'password', secret: 'z' },       // no (not breached)
]);
ok('bulk targets only breached + rotatable accounts', bulk.length === 2 && bulk.map((a) => a.id).join(',') === 'b1,b2');

// 21. Recovery: DEK wrapped by master password AND recovery key — either opens the vault.
{
  const dek = await newDek();
  const theVault = seedVault();
  const vaultBlob = await encryptJSON(dek, theVault);       // vault encrypted with the DEK

  const mSalt = randomSaltB64(), rSalt = randomSaltB64();
  const recKey = generateRecoveryKey();
  ok('recovery key has the RK- format', /^RK-[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$/.test(recKey));

  const masterWrap = await wrapKey(await deriveKey('my master pw', mSalt), dek);
  const recWrap = await wrapKey(await deriveKey(recKey, rSalt), dek);

  // unlock with master password
  const dekViaMaster = await unwrapKey(await deriveKey('my master pw', mSalt), masterWrap);
  ok('master password unwraps the DEK and opens the vault',
    JSON.stringify(await decryptJSON(dekViaMaster, vaultBlob)) === JSON.stringify(theVault));

  // wrong master password is rejected
  let denied = false;
  try { await unwrapKey(await deriveKey('WRONG', mSalt), masterWrap); } catch (_) { denied = true; }
  ok('wrong master password fails to unwrap', denied);

  // unlock with the RECOVERY key (forgot master password)
  const dekViaRec = await unwrapKey(await deriveKey(recKey, rSalt), recWrap);
  ok('recovery key unwraps the DEK and opens the vault',
    JSON.stringify(await decryptJSON(dekViaRec, vaultBlob)) === JSON.stringify(theVault));

  // change master password = re-wrap the DEK (vault untouched)
  const nSalt = randomSaltB64();
  const newMasterWrap = await wrapKey(await deriveKey('new master pw', nSalt), dek);
  const dekAfterChange = await unwrapKey(await deriveKey('new master pw', nSalt), newMasterWrap);
  ok('new master password opens the vault after a re-wrap (no vault re-encryption)',
    JSON.stringify(await decryptJSON(dekAfterChange, vaultBlob)) === JSON.stringify(theVault));
  ok('recovery key still works after master-password change',
    JSON.stringify(await decryptJSON(await unwrapKey(await deriveKey(recKey, rSalt), recWrap), vaultBlob)) === JSON.stringify(theVault));
}

console.log('\n' + (fail === 0 ? '✅ ALL CORE TESTS PASSED' : '❌ ' + fail + ' FAILED') + '  (' + pass + '/' + (pass + fail) + ')');
process.exit(fail === 0 ? 0 : 1);
