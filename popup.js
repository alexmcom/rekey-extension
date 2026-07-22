// Rekey popup. Real encrypted local vault + rotation history.
// Rotation itself is still SIMULATED (generates + stores a new password); wiring a
// real site is the next step. But storage, encryption, and history are all real now.
import {
  randomSaltB64, deriveKey, PBKDF2_ITERS, LEGACY_PBKDF2_ITERS, encryptJSON, decryptJSON, genPassword, mask,
  commitRotation, seedVault, exportKeyB64, importKeyB64,
  newAccount, pwnedParts, countFromRange, parseLoginsCsv, providerSecurityUrl,
  providerConnectionsUrl, findReusedPasswords, keystoneGroups, makeBackup, readBackup,
  scorePassword, isStale, computeHealth, isExpired, filterAccounts, sortByRisk, breachedRotatable,
  newDek, wrapKey, unwrapKey, generateRecoveryKey, normalizeRecoveryKey, monogramFor, dedupeAccounts, isSampleAccount, revertRotation,
  pruneHistoryForAccount, linkLoginHost,
} from './core.js';
import { rotateInPage, learnRecipe, checkSuccessOnPage } from './rotate-dom.js';
import { recipeForSite, hostMatchesSite, normalizeDomain, changePasswordUrlForSite, resetUrlForSite } from './recipes.js';
import { recordSuccess, recordFailure } from './learn-core.js';
import { syncApi, deriveAuthHash, mergeVaults } from './sync.js';

// ---- tiny chrome.storage helpers (promise-based) ----
const local = {
  get: (k) => new Promise((r) => chrome.storage.local.get(k, (o) => r(o[k]))),
  set: (k, v) => new Promise((r) => chrome.storage.local.set({ [k]: v }, r)),
};
const session = {
  get: (k) => new Promise((r) => chrome.storage.session.get(k, (o) => r(o[k]))),
  set: (k, v) => new Promise((r) => chrome.storage.session.set({ [k]: v }, r)),
  remove: (k) => new Promise((r) => chrome.storage.session.remove(k, r)),
};

// ---- app state (in memory while popup is open) ----
let key = null;      // AES key
let vault = null;    // { accounts, history }
let captureQueue = []; // pending passively-captured logins awaiting "Save?"
let searchQuery = '';
let learnedRecipes = {}; // site-specific recipes taught by the user, keyed by domain
let recoveryPending = false; // true until the user saves their recovery key (skippable at setup)

const $ = (id) => document.getElementById(id);
// Toolbar lock badge: 🔒 when the vault is locked, cleared when unlocked. A passive reminder
// so people don't forget to unlock before autofill (they will otherwise). Background sets it
// on auto-lock; the popup sets it on the unlock/lock actions the user takes here.
const setLockBadge = (locked) => { try { chrome.action.setBadgeText({ text: locked ? '🔒' : '' }); if (locked) chrome.action.setBadgeBackgroundColor({ color: '#db2777' }); } catch (_) {} };
const show = (el, on) => el.classList.toggle('hidden', !on);

// ---- boot ----
init();
async function init() {
  const meta = await local.get('meta');
  if (!meta) return showSetup();

  // Already unlocked this browser session? reuse the cached key — unless auto-lock expired.
  const sk = await session.get('sk');
  if (sk) {
    const unlockedAt = await session.get('unlockedAt');
    const mins = await getLockMinutes();
    if (isExpired(unlockedAt, mins)) {
      await session.remove('sk');
    } else {
      try {
        key = await importKeyB64(sk);
        vault = await decryptJSON(key, await local.get('vault'));
        await session.set('unlockedAt', Date.now()); // opening the popup counts as activity
        return openApp();
      } catch (_) { await session.remove('sk'); }
    }
  }
  showUnlock();
}

async function getLockMinutes() {
  const v = await local.get('lockAfterMin');
  return v == null ? 30 : v; // default 30 minutes; 0 = never (raised from 15 — F10: locked too eagerly)
}

const GATE_VIEWS = ['setupView', 'kitView', 'unlockView', 'recoveryView', 'resetMasterView'];
function showGate(view) {
  show($('app'), false); show($('gate'), true);
  GATE_VIEWS.forEach((v) => show($(v), v === view));
}

// ---- SETUP (first run) ----
function showSetup() {
  showGate('setupView');
  $('createBtn').onclick = createVault;
  $('mp1').oninput = updateMasterStrength;
  $('mp2').addEventListener('keydown', (e) => { if (e.key === 'Enter') createVault(); });
}
// Live feedback on the master password — it protects everything, so weak ones are blocked.
function updateMasterStrength() {
  const v = $('mp1').value, el = $('mpStrength');
  if (!v) { el.textContent = ''; return; }
  const s = scorePassword(v);
  const colors = ['#ff5a5f', '#ff5a5f', '#ffb020', '#2fd27a', '#2fd27a'];
  el.textContent = 'Master password strength: ' + s.label + (s.score < 2 ? ' — too weak, make it longer or add variety' : '');
  el.style.color = colors[s.score];
}
async function createVault() {
  const p1 = $('mp1').value, p2 = $('mp2').value;
  const err = $('setupErr');
  if (p1.length < 8) return (err.textContent = 'Use at least 8 characters.');
  if (scorePassword(p1).score < 2) return (err.textContent = 'That master password is too weak — it protects your whole vault. Make it longer (a passphrase works great) or add uppercase, numbers, and symbols.');
  if (p1 !== p2) return (err.textContent = 'The two passwords don\'t match.');
  err.textContent = '';

  // The vault is encrypted with a random DEK; the DEK is wrapped under BOTH the master
  // password key and a recovery key, so either can open it.
  const dek = await newDek();
  const salt = randomSaltB64(), recoverySalt = randomSaltB64();
  const recoveryKey = generateRecoveryKey();
  const iters = PBKDF2_ITERS;
  const masterWrap = await wrapKey(await deriveKey(p1, salt, iters), dek);
  const recoveryWrap = await wrapKey(await deriveKey(recoveryKey, recoverySalt, iters), dek);
  key = dek;
  vault = seedVault();
  await local.set('meta', { v: 2, salt, recoverySalt, masterWrap, recoveryWrap, iters });
  await saveVault();
  await session.set('sk', await exportKeyB64(dek));
  await session.set('unlockedAt', Date.now());
  showRecoveryKit(recoveryKey);
}

// ---- RECOVERY KIT — the safety net. Shown at setup, but SKIPPABLE: the user can enter
// their vault right away and is gently reminded to save it until they do. (Value first,
// safety homework second — instead of a wall before any payoff.) ----
async function showRecoveryKit(recoveryKey) {
  showGate('kitView');
  $('kitKey').textContent = recoveryKey;
  await session.set('pendingRecoveryKey', recoveryKey);
  await local.set('recoveryPending', true);
  $('kitCopy').onclick = async () => { try { await navigator.clipboard.writeText(recoveryKey); $('kitCopy').textContent = 'Copied ✓'; } catch (_) {} };
  $('kitDownload').onclick = async () => { await exportBackup(); $('kitDownload').textContent = '✓ Kit downloaded'; await clearRecoveryPending(); };
  $('kitAck').onchange = async () => { if ($('kitAck').checked) await clearRecoveryPending(); };
  $('kitDone').disabled = false; // don't block entry — they can save it later
  $('kitDone').onclick = () => openApp();
}
async function clearRecoveryPending() { recoveryPending = false; await local.set('recoveryPending', false); await session.remove('pendingRecoveryKey'); }
async function reopenRecoveryKit() {
  const rk = await session.get('pendingRecoveryKey');
  if (rk) showRecoveryKit(rk);
  else regenerateRecoveryKey(); // key no longer in memory (browser was closed) → issue a fresh one
}

// ---- UNLOCK (returning) ----
function showUnlock() {
  showGate('unlockView');
  $('unlockBtn').onclick = unlock;
  $('mpUnlock').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  $('forgotLink').onclick = showRecovery;
  $('mpUnlock').focus();
}
async function unlock() {
  const err = $('unlockErr');
  const meta = await local.get('meta');
  if (!meta || !meta.masterWrap) { err.textContent = 'Older vault format — please Remove and re-add the extension to upgrade.'; return; }
  try {
    const mp = $('mpUnlock').value;
    key = await unwrapKey(await deriveKey(mp, meta.salt, meta.iters || LEGACY_PBKDF2_ITERS), meta.masterWrap); // throws if wrong
    vault = await decryptJSON(key, await local.get('vault'));
    await session.set('sk', await exportKeyB64(key));
    await session.set('unlockedAt', Date.now());
    await cacheAuthIfSynced(mp); // so "Sync now" works this session without re-entering the master password
    openApp();
  } catch (_) {
    err.textContent = 'Wrong master password.';
    $('mpUnlock').select();
  }
}

// ---- UNLOCK WITH RECOVERY KEY (forgot master password) ----
function showRecovery() {
  showGate('recoveryView');
  $('recBtn').onclick = unlockWithRecovery;
  $('backToUnlock').onclick = showUnlock;
  $('recInput').focus();
}
async function unlockWithRecovery() {
  const err = $('recErr');
  const meta = await local.get('meta');
  try {
    const rk = normalizeRecoveryKey($('recInput').value);
    key = await unwrapKey(await deriveKey(rk, meta.recoverySalt, meta.iters || LEGACY_PBKDF2_ITERS), meta.recoveryWrap); // throws if wrong
    vault = await decryptJSON(key, await local.get('vault'));
    await session.set('sk', await exportKeyB64(key));
    await session.set('unlockedAt', Date.now());
    showResetMaster(); // force setting a new master password since the old one is lost
  } catch (_) {
    err.textContent = 'That recovery key is not valid.';
  }
}
function showResetMaster() {
  showGate('resetMasterView');
  $('rmBtn').onclick = async () => {
    const n1 = $('rm1').value, n2 = $('rm2').value, e = $('rmErr');
    if (n1.length < 8) return (e.textContent = 'Use at least 8 characters.');
    if (n1 !== n2) return (e.textContent = 'The two passwords don\'t match.');
    const meta = await local.get('meta');
    const newSalt = randomSaltB64();
    const newMasterWrap = await wrapKey(await deriveKey(n1, newSalt, meta.iters || LEGACY_PBKDF2_ITERS), key); // key is the DEK
    await local.set('meta', { ...meta, salt: newSalt, masterWrap: newMasterWrap });
    openApp();
  };
  $('rm1').focus();
}

async function saveVault() { await local.set('vault', await encryptJSON(key, vault)); }

// ---- MAIN APP ----
function openApp() {
  setLockBadge(false); // vault is open now — clear the lock badge
  show($('gate'), false); show($('app'), true);
  show($('lockBtn'), true);
  local.get('recoveryPending').then((v) => { recoveryPending = !!v; renderVault(); });
  autoScanUnchecked(); // quietly surface breaches without the user pressing "Scan"
  checkPendingManual(); // resume a guided password change the user started before the popup closed
  $('lockBtn').onclick = lock;
  $('tabVault').onclick = () => switchTab('vault');
  $('tabHistory').onclick = () => switchTab('history');
  $('scanBtn').onclick = scanAll;
  $('addToggle').onclick = toggleAddForm;
  // Settings & backup are tucked into a collapsible panel so the main screen stays calm —
  // just Scan, Add, and your accounts. Everything else is one click away under here.
  $('settingsToggle').onclick = () => {
    const p = $('settingsPanel');
    const opening = p.classList.contains('hidden');
    show(p, opening);
    // Flip the label + caret so it's obvious the panel closes again (▾ open / ▴ close).
    $('settingsToggle').textContent = opening ? '⚙ Close settings & backup ▴' : '⚙ Settings & backup ▾';
  };
  $('fGen').onclick = () => { $('fPass').value = genPassword(20); updateStrengthHint(); };
  $('fPass').oninput = updateStrengthHint;
  $('fSave').onclick = addAccount;
  $('importBtn').onclick = () => $('importFile').click();
  $('importFile').onchange = importFromFile;
  $('exportBtn').onclick = exportBackup;
  $('restoreBtn').onclick = () => $('restoreFile').click();
  $('restoreFile').onchange = restoreBackup;
  getLockMinutes().then((m) => { $('lockSel').value = String(m); });
  $('lockSel').onchange = () => local.set('lockAfterMin', parseInt($('lockSel').value, 10));
  $('searchInput').oninput = (e) => { searchQuery = e.target.value; renderVault(); };
  $('cmpBtn').onclick = () => { const p = $('cmpPanel'); const opening = p.classList.contains('hidden'); show(p, opening); if (opening) { $('cmpCur').value = ''; $('cmpNew1').value = ''; $('cmpNew2').value = ''; $('cmpErr').textContent = ''; $('cmpCur').focus(); } };
  $('cmpCancel').onclick = () => show($('cmpPanel'), false);
  $('cmpSave').onclick = changeMasterPassword;
  $('recKeyBtn').onclick = regenerateRecoveryKey;
  $('syncBtn').onclick = () => { const p = $('syncPanel'); const opening = p.classList.contains('hidden'); if (opening) renderSyncPanel(); show(p, opening); };
  local.get('learnedRecipes').then((r) => { learnedRecipes = r || {}; });
  switchTab('vault');
  processPendingCaptures();
}

async function changeMasterPassword() {
  const err = $('cmpErr');
  const cur = $('cmpCur').value, n1 = $('cmpNew1').value, n2 = $('cmpNew2').value;
  if (n1.length < 8) return (err.textContent = 'New password must be at least 8 characters.');
  if (scorePassword(n1).score < 2) return (err.textContent = 'Too weak — it protects your whole vault. Use a longer passphrase or add uppercase, numbers, and symbols.');
  if (n1 !== n2) return (err.textContent = 'The new passwords don\'t match.');
  const meta = await local.get('meta');
  try {
    await unwrapKey(await deriveKey(cur, meta.salt, meta.iters || LEGACY_PBKDF2_ITERS), meta.masterWrap); // verify current (throws if wrong)
  } catch (_) { return (err.textContent = 'Current master password is incorrect.'); }
  err.textContent = '';
  // Just re-wrap the DEK under the new password — no vault re-encryption, recovery key unaffected.
  const newSalt = randomSaltB64();
  const newMasterWrap = await wrapKey(await deriveKey(n1, newSalt, meta.iters || LEGACY_PBKDF2_ITERS), key);
  const newMeta = { ...meta, salt: newSalt, masterWrap: newMasterWrap };
  await local.set('meta', newMeta);
  // If synced, rotate the server auth token too (derived from the new master password) so
  // sync keeps working, and push the updated meta (new masterWrap) up.
  try {
    const cfg = await getSyncCfg();
    if (cfg && cfg.email) {
      // Derive the OLD auth token from the current password we just verified (reliable),
      // not from a session cache that might be missing — otherwise sync auth could desync.
      const oldAh = await deriveAuthHash(cur, cfg.email);
      const newAh = await deriveAuthHash(n1, cfg.email);
      await syncApi(cfg.url, '/change-auth', { email: cfg.email, authHash: oldAh, newAuthHash: newAh, meta: newMeta });
      await session.set('ah', newAh);
    }
  } catch (_) { /* sync auth rotation is best-effort; local change already succeeded */ }
  show($('cmpPanel'), false);
  $('scanStatus').innerHTML = '<span class="ok">✓ Master password changed.</span> Your recovery key still works. Export a fresh backup to keep it current.';
}

async function regenerateRecoveryKey() {
  if (!confirm('Generate a NEW recovery key?\n\nYour old recovery key will stop working. Save the new one somewhere safe.')) return;
  const meta = await local.get('meta');
  const recoveryKey = generateRecoveryKey();
  const recoverySalt = randomSaltB64();
  const recoveryWrap = await wrapKey(await deriveKey(recoveryKey, recoverySalt, meta.iters || LEGACY_PBKDF2_ITERS), key); // key = DEK
  await local.set('meta', { ...meta, recoverySalt, recoveryWrap });
  $('scanStatus').innerHTML = `<span class="ok">✓ New recovery key — save it now:</span><br><code style="color:#8fa6ff;word-break:break-all;font-size:13px">${esc(recoveryKey)}</code>`;
}

async function exportBackup() {
  const meta = await local.get('meta');
  const vaultBlob = await local.get('vault');
  if (!meta || !vaultBlob) return;
  const data = JSON.stringify(makeBackup(meta, vaultBlob), null, 2);
  const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url; a.download = 'rekey-backup-' + new Date().toISOString().slice(0, 10) + '.json';
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  $('scanStatus').innerHTML = '<span class="ok">✓ Backup saved.</span> Keep it somewhere safe — it\'s encrypted with your master password, so it\'s useless to anyone without it.';
}

async function restoreBackup(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!file) return;
  if (!confirm('Restoring REPLACES your current vault with the one in this backup — and you\'ll need the master password that backup was made with to open it. Make sure you have it. Continue?')) return;
  let parsed;
  try { parsed = readBackup(await file.text()); }
  catch (err) { $('scanStatus').innerHTML = `<span class="breachnote">${esc(err.message || 'Invalid file')}</span>`; return; }
  await local.set('meta', parsed.meta);
  await local.set('vault', parsed.vault);
  await session.remove('sk');
  key = null; vault = null; captureQueue = [];
  showUnlock();
  $('unlockErr').textContent = 'Vault restored. Enter the master password from that backup to unlock it.';
}

// ---- Passive capture: offer to save logins the content script caught while browsing ----
async function processPendingCaptures() {
  let pending;
  try { pending = (await chrome.storage.session.get('pendingCaptures')).pendingCaptures; } catch (_) { return; }
  if (!pending || !pending.length) return;
  await chrome.storage.session.remove('pendingCaptures');
  const seen = new Set(vault.accounts.map((a) => (a.site + '|' + a.username).toLowerCase()));
  const uniq = new Map();
  for (const blob of pending) {
    let c; try { c = await decryptJSON(key, blob); } catch (_) { continue; }
    const k = (c.host + '|' + (c.username || '')).toLowerCase();
    if (seen.has(k)) continue;         // already saved
    uniq.set(k, c);                    // newest capture for this login wins
  }
  captureQueue = [...uniq.values()];
  showNextCapture();
}

function showNextCapture() {
  const banner = $('captureBanner');
  if (!captureQueue.length) { show(banner, false); banner.innerHTML = ''; return; }
  const c = captureQueue[0];
  banner.innerHTML = `<div class="t">Save this login to Rekey?<br><b>${esc(c.host)}</b> · ${esc(c.username || '(no username)')}</div>
    <div class="rowbtns"><button class="btn" id="capSave">Save</button><button class="btn ghost" id="capSkip">Not now</button></div>`;
  show(banner, true);
  $('capSave').onclick = async () => {
    if (!vault.accounts.some((a) => (a.site + '|' + a.username).toLowerCase() === (c.host + '|' + (c.username || '')).toLowerCase())) {
      vault.accounts.push(newAccount(c.host, c.username || '', c.password));
      await saveVault();
      renderVault();
    }
    captureQueue.shift();
    showNextCapture();
  };
  $('capSkip').onclick = () => { captureQueue.shift(); showNextCapture(); };
}
async function lock() {
  await session.remove('sk');
  setLockBadge(true);
  key = null; vault = null;
  $('mpUnlock') && ($('mpUnlock').value = '');
  showUnlock();
}
function switchTab(which) {
  const v = which === 'vault';
  $('tabVault').classList.toggle('active', v);
  $('tabHistory').classList.toggle('active', !v);
  show($('vaultView'), v); show($('historyView'), !v);
  show($('toolbar'), v); show($('settingsToggleRow'), v);
  if (!v) { show($('settingsPanel'), false); show($('addForm'), false); show($('cmpPanel'), false); show($('syncPanel'), false); $('scanStatus').textContent = ''; show($('captureBanner'), false); show($('searchInput'), false); show($('bulkBar'), false); if (!bulkRunning) show($('bulkProgress'), false); }
  else if (captureQueue.length) showNextCapture();
  v ? renderVault() : renderHistory();
}

// ---- Import from a Chrome/Bitwarden/1Password CSV export ----
async function importFromFile(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = ''; // allow re-importing the same file later
  if (!file) return;
  const st = $('scanStatus');
  st.innerHTML = '<span class="step">Reading ' + esc(file.name) + '…</span>';
  let text;
  try { text = await file.text(); } catch (_) { st.innerHTML = '<span class="breachnote">Couldn\'t read that file.</span>'; return; }
  const logins = parseLoginsCsv(text);
  if (!logins.length) {
    st.innerHTML = '<span class="breachnote">No logins found. Export as CSV from Chrome (Password Manager → Settings → Export), then pick that file.</span>';
    return;
  }
  const seen = new Set(vault.accounts.map((a) => (a.site + '|' + a.username).toLowerCase()));
  let added = 0, skipped = 0;
  for (const l of logins) {
    const key = (l.site + '|' + l.username).toLowerCase();
    if (seen.has(key)) { skipped++; continue; }
    seen.add(key);
    vault.accounts.push(newAccount(l.site, l.username, l.secret));
    added++;
  }
  await saveVault();
  renderVault();
  st.innerHTML = `<span class="ok">✓ Imported ${added} account${added === 1 ? '' : 's'}.</span>` +
    (skipped ? ` <span class="user">(${skipped} already in your vault)</span>` : '') +
    ` Checking them for breaches…`;
  await autoScanUnchecked(); // auto-scan the new logins instead of making the user press "Scan"
  const b = computeHealth(vault.accounts).breached;
  st.innerHTML = b
    ? `<span class="breachnote">✓ Imported ${added}. ⚠ ${b} of your passwords were found in known breaches — rotate those.</span>`
    : `<span class="safenote">✓ Imported ${added}. None were found in known breaches.</span>`;
}

function updateStrengthHint() {
  const val = $('fPass').value;
  const s = scorePassword(val);
  const colors = ['#ff5a5f', '#ff5a5f', '#ffb020', '#2fd27a', '#2fd27a'];
  const el = $('fStrength');
  el.textContent = val ? 'Strength: ' + s.label : '';
  el.style.color = val ? colors[s.score] : '';
}

function toggleAddForm() {
  const f = $('addForm');
  const opening = f.classList.contains('hidden');
  show(f, opening);
  if (opening) { $('fSite').value = ''; $('fUser').value = ''; $('fPass').value = ''; $('fStrength').textContent = ''; $('addErr').textContent = ''; $('fSite').focus(); }
}

async function addAccount() {
  const site = $('fSite').value.trim();
  const user = $('fUser').value.trim();
  const pass = $('fPass').value;
  const err = $('addErr');
  if (!site) return (err.textContent = 'Enter a site.');
  if (!pass) return (err.textContent = 'Enter or generate a password.');
  err.textContent = '';
  const acct = newAccount(site, user, pass);
  vault.accounts.push(acct);
  await saveVault();
  show($('addForm'), false);
  renderVault();
  checkBreach(acct).then(() => { saveVault(); renderVault(); }).catch(() => {});
}

async function deleteAccount(id) {
  const acct = vault.accounts.find((a) => a.id === id);
  if (!confirm('Remove ' + (acct ? acct.site : 'this account') + ' from your vault?')) return;
  vault.accounts = vault.accounts.filter((a) => a.id !== id);
  // Drop this account's rotation receipts too — otherwise deleting a login leaves orphaned
  // "verified" receipts in history for an account that no longer exists (the stale-history
  // half of F6: delete Facebook, re-add it, and old receipts still claimed "Verified").
  vault.history = pruneHistoryForAccount(vault.history, id);
  // Tombstone the id so sync doesn't resurrect it from another device.
  vault.deleted = Array.from(new Set([...(vault.deleted || []), id]));
  await saveVault();
  renderVault();
}

// ---- Breach detection (HIBP k-anonymity). Only the first 5 hash chars leave the device. ----
async function checkBreach(acct) {
  const { prefix, suffix } = await pwnedParts(acct.secret);
  const res = await fetch('https://api.pwnedpasswords.com/range/' + prefix, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error('HIBP ' + res.status);
  const count = countFromRange(await res.text(), suffix);
  acct.breachCount = count;
  acct.status = count > 0 ? 'breached' : 'safe';
  return count;
}

// Quietly breach-check any never-checked passwords in the background (on unlock / after
// import), so a breached password surfaces on its own instead of waiting for the user to
// remember to press "Scan". Only touches 'unknown' accounts, so it's a one-time-per-account
// cost, and it stays silent if offline.
async function autoScanUnchecked() {
  const targets = vault.accounts.filter((a) => (!a.status || a.status === 'unknown') && a.authType !== 'sso' && a.authType !== 'passkey' && a.secret);
  if (!targets.length) return;
  let changed = false;
  for (const acct of targets) {
    if (!vault || !key) return; // vault was locked mid-scan — stop, don't save with a null key
    try { await checkBreach(acct); changed = true; } catch (_) { /* offline — leave as unknown, try next time */ }
  }
  if (changed && vault && key) { await saveVault(); renderVault(); updateBadge(); }
}

async function scanAll() {
  const st = $('scanStatus');
  const btn = $('scanBtn');
  btn.disabled = true;
  const targets = vault.accounts.filter((a) => a.authType !== 'sso' && a.authType !== 'passkey' && a.secret);
  if (!targets.length) {
    btn.disabled = false;
    st.innerHTML = vault.accounts.length
      ? '<span class="user">Nothing to scan — your saved logins all sign in via SSO/passkey (no password to check).</span>'
      : '<span class="user">No passwords to scan yet — add or import a login first.</span>';
    return;
  }
  let breached = 0, checked = 0, failed = 0;
  for (const acct of targets) {
    st.innerHTML = `<span class="step">Checking ${checked + 1} of ${targets.length}…</span>`;
    try { if ((await checkBreach(acct)) > 0) breached++; } catch (_) { failed++; }
    checked++;
  }
  await saveVault();
  renderVault();
  st.innerHTML = failed
    ? `<span class="breachnote">Checked ${checked - failed}/${checked}. ${failed} couldn't be checked (network?). ${breached} breached.</span>`
    : (breached
        ? `<span class="breachnote">⚠ ${breached} of ${checked} password(s) found in known breaches.</span>`
        : `<span class="safenote">✓ None of your ${checked} password(s) were found in known breaches.</span>`);
  btn.disabled = false;
}

function fmt(iso) {
  if (!iso) return 'never';
  const d = new Date(iso), now = new Date();
  const mins = Math.round((now - d) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + ' min ago';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
         ' ' + d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// The card header: a site favicon (from Chrome's local cache — no network call, so the
// vault's contents never leak) with a colored letter-badge underneath as the fallback,
// then the site + username. If the favicon image fails to load, wireFavicons() drops it
// and the badge shows through.
function siteHeader(a) {
  const domain = String(a.site || '').replace(/^www\./, '');
  const mono = monogramFor(domain);
  let favUrl = '';
  try {
    const u = new URL(chrome.runtime.getURL('/_favicon/'));
    u.searchParams.set('pageUrl', 'https://' + domain);
    u.searchParams.set('size', '32');
    favUrl = u.href;
  } catch (_) { /* no favicon API — badge only */ }
  const img = favUrl ? `<img class="favicon" src="${esc(favUrl)}" alt="">` : '';
  return `<div class="sitehead">
      <span class="fav" style="background:${mono.bg}"><span class="favmono">${esc(mono.letter)}</span>${img}</span>
      <div><div class="site">${esc(a.site)}</div><div class="user">${esc(a.username)}</div></div>
    </div>`;
}

// If a favicon image fails to load, drop it so the colored letter-badge shows instead.
// (Inline onerror handlers are blocked by the extension CSP, so we wire them here.)
function wireFavicons(root) {
  root.querySelectorAll('img.favicon').forEach((img) => {
    img.onerror = () => img.remove();
  });
}

// A gentle, dismissible reminder to save the recovery key (shown until they do), instead
// of a hard wall at setup. Wired after render.
function recoveryBanner() {
  return recoveryPending
    ? `<div class="breachnote" id="recRemind" style="cursor:pointer">🔑 Finish protecting your vault — save your recovery key so you can never get locked out. <u>Save it now</u></div>`
    : '';
}
function wireRecoveryBanner() { const b = $('recRemind'); if (b) b.onclick = reopenRecoveryKit; }

// ---- VAULT view ----
function renderVault() {
  const host = $('vaultView');
  // Self-heal: silently merge same-account duplicates (e.g. spotify.com + accounts.spotify.com).
  const dd = dedupeAccounts(vault.accounts);
  if (dd.removed > 0) { vault.accounts = dd.accounts; saveVault(); }
  show($('searchInput'), vault.accounts.length > 3);
  updateBadge();
  renderBulkBar();
  if (!vault.accounts.length) {
    host.innerHTML = recoveryBanner() + `<div class="empty">
      <div style="font-size:15px;font-weight:700;margin-bottom:8px">Welcome to Rekey 👋</div>
      <div style="color:#c4ccdb;margin-bottom:14px;line-height:1.5">Rekey <b style="color:#fff">finds passwords caught in data breaches and changes them for you</b> — keeping the old one working until the new one's confirmed. Add your logins so it can start watching your back.</div>
      Two ways to fill your vault:<br><br>
      ➕ Click <b>+ Add account</b> above to add one login.<br>
      ⬇️ Or <b>Import from Chrome / CSV</b> to bring them all in at once.<br><br>
      Then hit <b>Scan for breaches</b> to see which ones need fixing.
    </div>`;
    wireRecoveryBanner();
    return;
  }
  const reused = findReusedPasswords(vault.accounts);
  const display = sortByRisk(filterAccounts(vault.accounts, searchQuery));
  const listHtml = display.length
    ? display.map((a) => {
    if (a.authType === 'sso' || a.authType === 'passkey') return ssoCard(a);
    const st = a.status || 'unknown';
    const label = st === 'breached' ? 'breached' : st === 'safe' ? 'safe' : st === 'fresh' ? 'fresh' : 'not checked';
    const sample = isSampleAccount(a);
    let note = '';
    if (sample) note = '';
    else if (st === 'breached') note = `<div class="breachnote">⚠ Found in ${Number(a.breachCount).toLocaleString()} known breaches. Change it now.</div>`;
    else if (st === 'safe') note = `<div class="safenote">✓ Not found in known breaches.</div>`;
    const sampleNote = sample ? `<div class="ssoguide">👋 This is a <b>sample</b> account so you can see how Rekey works. It won’t autofill or rotate on real sites. Click <b>Edit</b> to make it your real login, or <b>Remove</b> it.</div>` : '';
    const reusedNote = (!sample && reused.has(a.id)) ? `<div class="reusednote">⚠ Reused password — the same password is on more than one account.</div>` : '';
    const weakNote = (!sample && a.secret && scorePassword(a.secret).score <= 1) ? `<div class="reusednote">⚠ Weak password — short or simple. Change it to a strong one.</div>` : '';
    const staleNote = (!sample && isStale(a)) ? `<div class="reusednote">⏰ Due for rotation (over 90 days old).</div>` : '';
    const linkNote = a.authType === 'emaillink' ? `<div class="ssoguide">Signs in via <b>email code / magic link</b>. Your main login is your email, but the password still works as a fallback, so rotating it still closes that door.</div>` : '';
    // Success stays quiet: a freshly rotated password just shows a subtle "restore" option
    // in case the user knows it didn't take. Only a real auto-revert gets a loud note.
    const verifyNote = (!sample && a.verify === 'pending' && a.prevSecret)
      ? `<div class="user" style="margin-top:4px">New password saved · <button class="link restore">restore old one</button> if it didn't work</div>`
      : (a.verify === 'reverted')
      ? `<div class="reusednote">↩ That rotation didn't take — your <b>previous</b> password was restored, so you're not locked out.</div>`
      : '';
    // F1: this stored password was rejected by the site right after we filled it. We hold it
    // back from autofill and heal it automatically once you sign in with the right one — but
    // surface it so you know, with an escape hatch if it was flagged by mistake.
    const suspectNote = (!sample && a.suspect)
      ? `<div class="reusednote">⚠ This saved password looks wrong — the site rejected it. Rekey won't autofill it until you sign in with the correct one. <button class="link clearsuspect">It's actually right</button></div>`
      : '';
    // Transparency for cross-domain auth linking: show every sign-in host you've linked to this
    // account, each with a one-click unlink — so a link is always visible and reversible.
    const loginHostsNote = (!sample && (a.loginHosts || []).length)
      ? `<div class="user" style="margin-top:4px">🔗 Also signs in at: ${a.loginHosts.map((h) => `${esc(h)} <button class="link unlink" data-host="${esc(h)}">unlink</button>`).join(', ')}</div>`
      : '';
    return `<div class="acct" data-id="${a.id}">
      <div class="row">
        ${siteHeader(a)}
        <span class="pill ${sample ? 'unknown' : st}">${sample ? 'sample' : label}</span>
      </div>
      <div class="secret">
        <span class="secret-val">${esc(mask(a.secret))}</span>
        <span style="display:flex;gap:10px"><button class="link copy">Copy</button><button class="link reveal">Reveal</button></span>
      </div>
      ${sampleNote}${note}${reusedNote}${weakNote}${staleNote}${linkNote}${verifyNote}${suspectNote}${loginHostsNote}
      <div class="user" style="margin-top:6px">Last rotated: ${fmt(a.lastRotated)}</div>
      <div class="actions">
        <button class="btn rotate">Change password</button>
      </div>
      <div class="status"></div>
      <div style="text-align:right;margin-top:8px">
        <span class="moreactions hidden"><button class="teach link">Fix autofill</button> &nbsp; <button class="marksso link">Sign-in type</button> &nbsp; <button class="addhost link">Link sign-in page</button> &nbsp;</span>
        <button class="moretoggle link">More ▾</button> &nbsp; <button class="edit link">Edit</button> &nbsp; <button class="remove">Remove</button>
      </div>
    </div>`;
  }).join('')
    : `<div class="empty">No accounts match "${esc(searchQuery)}".</div>`;
  host.innerHTML = recoveryBanner() + renderHealth() + renderKeystones() + listHtml;
  wireFavicons(host);
  wireRecoveryBanner();

  host.querySelectorAll('.acct').forEach((card) => {
    const id = card.dataset.id;
    const acct = vault.accounts.find((a) => a.id === id);
    if (!acct) return;
    if (acct.authType === 'sso' || acct.authType === 'passkey') {
      card.querySelector('.unsso').onclick = () => setAuthType(id, 'password', null);
      card.querySelector('.remove').onclick = () => deleteAccount(id);
      return;
    }
    const valEl = card.querySelector('.secret-val');
    const revBtn = card.querySelector('.reveal');
    let shown = false;
    revBtn.onclick = () => {
      shown = !shown;
      valEl.textContent = shown ? acct.secret : mask(acct.secret);
      revBtn.textContent = shown ? 'Hide' : 'Reveal';
    };
    const copyBtn = card.querySelector('.copy');
    copyBtn.onclick = async () => {
      try { await navigator.clipboard.writeText(acct.secret); copyBtn.textContent = 'Copied ✓'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200); }
      catch (_) { copyBtn.textContent = 'Copy failed'; }
    };
    card.querySelector('.rotate').onclick = () => rotate(acct, card);
    card.querySelector('.teach').onclick = () => teachPage(acct, card);
    card.querySelector('.edit').onclick = () => editAccount(id, card);
    card.querySelector('.marksso').onclick = () => markSsoPicker(id, card);
    card.querySelector('.remove').onclick = () => deleteAccount(id);
    const restoreBtn = card.querySelector('.restore');
    if (restoreBtn) restoreBtn.onclick = async () => {
      const i = vault.accounts.findIndex((x) => x.id === id);
      if (i >= 0) { vault.accounts[i] = revertRotation(vault.accounts[i]); await saveVault(); renderVault(); }
    };
    const clearSuspectBtn = card.querySelector('.clearsuspect');
    if (clearSuspectBtn) clearSuspectBtn.onclick = async () => {
      const i = vault.accounts.findIndex((x) => x.id === id);
      if (i >= 0) { const { suspect, ...rest } = vault.accounts[i]; vault.accounts[i] = rest; await saveVault(); renderVault(); }
    };
    card.querySelectorAll('.unlink').forEach((btn) => {
      btn.onclick = async () => {
        const i = vault.accounts.findIndex((x) => x.id === id);
        if (i < 0) return;
        const h = btn.getAttribute('data-host');
        vault.accounts[i] = { ...vault.accounts[i], loginHosts: (vault.accounts[i].loginHosts || []).filter((x) => x !== h) };
        await saveVault(); renderVault();
      };
    });
    const moreBtn = card.querySelector('.moretoggle');
    if (moreBtn) moreBtn.onclick = () => {
      const m = card.querySelector('.moreactions');
      const open = m.classList.contains('hidden');
      m.classList.toggle('hidden', !open);
      moreBtn.textContent = open ? 'Less ▴' : 'More ▾';
    };
    const addHostBtn = card.querySelector('.addhost');
    if (addHostBtn) addHostBtn.onclick = async () => {
      const acct = vault.accounts.find((x) => x.id === id);
      const raw = prompt(`Link another sign-in page to ${acct ? acct.site : 'this account'}.\n\nEnter a host where this same login is used (e.g. auth.webconnex.com). Rekey will offer this login there too.`);
      if (!raw) return;
      const host = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split('?')[0].split(':')[0];
      if (!host || !host.includes('.')) { alert("That doesn't look like a valid website host."); return; }
      const i = vault.accounts.findIndex((x) => x.id === id);
      if (i < 0) return;
      vault.accounts[i] = linkLoginHost(vault.accounts[i], host);
      await saveVault(); renderVault();
    };
  });
}

// Persist a breach count on the toolbar icon so it nudges you even when the popup is closed.
function updateBadge() {
  try {
    const n = computeHealth(vault.accounts).breached;
    chrome.action.setBadgeText({ text: n > 0 ? String(n) : '' });
    chrome.action.setBadgeBackgroundColor({ color: '#ff2e7e' });
  } catch (_) { /* action API not available */ }
}

// ---- Bulk "rotate all breached": open each site in a background tab and rotate it ----
let bulkRunning = false;
function renderBulkBar() {
  const bar = $('bulkBar');
  if (!bar) return;
  const n = breachedRotatable(vault.accounts).length;
  if (n === 0 || bulkRunning) { bar.innerHTML = ''; return; }
  bar.innerHTML = `<button class="bulkbtn" id="bulkBtn">⚡ Change all ${n} breached password${n === 1 ? '' : 's'}</button>`;
  $('bulkBtn').onclick = bulkRotate;
}

function waitForTabComplete(tabId, timeout = 20000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => { if (settled) return; settled = true; clearTimeout(timer); chrome.tabs.onUpdated.removeListener(listener); setTimeout(resolve, 900); };
    const listener = (id, info) => { if (id === tabId && info.status === 'complete') finish(); };
    const timer = setTimeout(finish, timeout);
    chrome.tabs.onUpdated.addListener(listener);
    chrome.tabs.get(tabId, (t) => { if (!chrome.runtime.lastError && t && t.status === 'complete') finish(); });
  });
}
function sendToTab(tabId, msg, timeout = 15000) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; resolve(null); } }, timeout);
    try {
      chrome.tabs.sendMessage(tabId, msg, (r) => { if (done) return; done = true; clearTimeout(timer); resolve(chrome.runtime.lastError ? null : r); });
    } catch (_) { if (!done) { done = true; clearTimeout(timer); resolve(null); } }
  });
}

// Plain-English reason a rotation attempt didn't go through (shared by single + bulk).
function rotateFailReason(res) {
  return !res ? 'no change-password form found'
    : res.stage === '2fa' ? 'needs a 2FA code'
    : res.stage === 'passwordless' ? 'email-code login'
    : res.stage === 'sso' ? 'signs in with ' + (res.provider || 'SSO')
    : res.stage === 'notfound' ? "no automatic change-password page — change it in the site's settings"
    : res.stage === 'locate' ? "couldn't find the form"
    : res.stage === 'verify' ? 'change not confirmed'
    : (res.message || 'skipped');
}

// --- Self-learning loop (learn-core.js): remember the recipe that WORKED on a site, and
// record failures so the engine flags "needs teaching" instead of silently retrying the same
// doomed approach. Best-effort — learning never blocks or breaks a rotation. Persisted to
// local storage so it survives across sessions (and, later, seeds shared community recipes). ---
async function persistLearned() { try { await local.set('learnedRecipes', learnedRecipes); } catch (_) {} }

async function learnFailure(host, stage) {
  learnedRecipes = recordFailure(learnedRecipes, host, stage || 'unknown');
  await persistLearned();
}

// After a CONFIRMED rotation, capture the exact working selectors + change-password URL from
// the tab (via learnRecipe) so the next rotation here is instant and reliable, and off-site
// rotation can jump straight to the form. Only records when real selectors are found.
async function learnFromTab(tabId, host, viaExecuteScript) {
  try {
    let learned = null;
    if (viaExecuteScript) {
      const [o] = await chrome.scripting.executeScript({ target: { tabId }, func: learnRecipe });
      learned = o && o.result;
    } else {
      learned = await sendToTab(tabId, { type: 'rekey_learn' });
    }
    if (learned && learned.ok && learned.recipe) {
      learnedRecipes = recordSuccess(learnedRecipes, host, learned.recipe);
      await persistLearned();
    }
  } catch (_) { /* learning is best-effort */ }
}

// A change-password URL we TRUST for this site: one we learned from a past successful
// rotation here, or a curated verified one. Never a /.well-known/ guess. Returns null when
// we have no known-good page — in that case we hand off instead of opening a made-up link
// that 404s (the WeTransfer "spiral" problem).
function trustedChangeUrl(acct) {
  const learned = learnedRecipes[normalizeDomain(acct.site)];
  return (learned && learned.changePasswordUrl) || changePasswordUrlForSite(acct.site) || null;
}

// Open the site's change-password page in a BACKGROUND tab, rotate for real, close it.
// Returns { ok:true, newPw } on a confirmed change, or { ok:false, reason }. NEVER commits
// to the vault — the caller commits only on ok, so a failed attempt can't lock you out.
// Only opens a URL we TRUST (learned or curated); if there's none, it returns without opening
// anything, so Rekey never sends you to a guessed link that 404s.
async function rotateViaBackgroundTab(acct, onStep) {
  const domain = normalizeDomain(acct.site);
  const learned = learnedRecipes[domain];
  const url = trustedChangeUrl(acct);
  if (!url) return { ok: false, stage: 'nourl', reason: 'no automatic change page for this site' };
  let tab = null;
  try {
    onStep && onStep('opening ' + domain + '…');
    tab = await new Promise((res) => chrome.tabs.create({ url, active: false }, res));
    await waitForTabComplete(tab.id);
    onStep && onStep('changing…');
    const newPw = genPassword(20);
    const recipe = learned || recipeForSite(acct.site);
    const res = await sendToTab(tab.id, { type: 'rekey_rotate', recipe, currentSecret: acct.secret, newSecret: newPw });
    if (res && res.ok) {
      await learnFromTab(tab.id, domain, false); // capture the working recipe before the tab closes
      return { ok: true, newPw };
    }
    if (res && res.stage) await learnFailure(domain, res.stage);
    return { ok: false, reason: rotateFailReason(res), stage: res && res.stage };
  } catch (_) {
    return { ok: false, reason: 'error opening the page' };
  } finally {
    if (tab) { try { chrome.tabs.remove(tab.id); } catch (_) { /* already closed */ } }
  }
}

async function bulkRotate() {
  const targets = breachedRotatable(vault.accounts);
  if (!targets.length) return;
  bulkRunning = true;
  renderBulkBar();
  const panel = $('bulkProgress');
  show(panel, true);
  const rows = targets.map((a) => `<div class="prow" data-id="${a.id}"><span>${esc(a.site)}</span><span class="run">waiting…</span></div>`).join('');
  panel.innerHTML = `<div class="phead">Rotating ${targets.length} breached account${targets.length === 1 ? '' : 's'}…</div>${rows}`;
  const setRow = (id, cls, text) => { const el = panel.querySelector(`.prow[data-id="${id}"] span:last-child`); if (el) { el.className = cls; el.textContent = text; } };

  let ok = 0; const attention = [];
  for (const acct of targets) {
    setRow(acct.id, 'run', 'opening…');
    const r = await rotateViaBackgroundTab(acct, (s) => setRow(acct.id, 'run', s));
    if (r.ok) { await commitRotated(acct, r.newPw); setRow(acct.id, 'ok', '✓ rotated'); ok++; }
    else { setRow(acct.id, 'bad', '⚠ ' + r.reason); attention.push(acct.site + ' — ' + r.reason); }
  }

  panel.querySelector('.phead').innerHTML = ok === targets.length
    ? `<span class="ok">✓ Rotated all ${ok}. Each old password was kept until the new one was confirmed.</span>`
    : `<span>Rotated ${ok} of ${targets.length}. ${attention.length} still need a hand (see above) — do those manually or use Teach this page.</span>`;
  bulkRunning = false;
  renderVault();
}

// One-glance health rollup at the top of the vault.
function renderHealth() {
  const h = computeHealth(vault.accounts);
  if (!h.total) return '';
  const chips = [`<span class="hc">${h.total} account${h.total === 1 ? '' : 's'}</span>`];
  if (h.breached) chips.push(`<span class="hc bad">${h.breached} breached</span>`);
  if (h.reused) chips.push(`<span class="hc warn">${h.reused} reused</span>`);
  if (h.weak) chips.push(`<span class="hc warn">${h.weak} weak</span>`);
  if (h.stale) chips.push(`<span class="hc warn">${h.stale} due to rotate</span>`);
  if (h.sso + h.passkey) chips.push(`<span class="hc muted">${h.sso + h.passkey} SSO/passkey</span>`);
  if (h.password > 0 && !h.breached && !h.reused && !h.weak && !h.stale) chips.push('<span class="hc ok">✓ all healthy</span>');
  return `<div class="health">${chips.join('')}</div>`;
}

// The keystone / blast-radius panel: what each provider login unlocks.
function renderKeystones() {
  const groups = keystoneGroups(vault.accounts);
  if (!groups.size) return '';
  let html = '';
  for (const [provider, accts] of groups) {
    const n = accts.length;
    const secUrl = providerSecurityUrl(provider);
    const conUrl = providerConnectionsUrl(provider);
    const secBtn = secUrl ? `<a class="btn" href="${esc(secUrl)}" target="_blank" rel="noopener">Secure ${esc(provider)}</a>` : '';
    const conBtn = conUrl ? `<a class="btn ghost" href="${esc(conUrl)}" target="_blank" rel="noopener">Connected apps</a>` : '';
    html += `<div class="keystone">
      <div class="kh">⚠ ${n} account${n === 1 ? '' : 's'} depend${n === 1 ? 's' : ''} on your ${esc(provider)} login</div>
      <div class="kb">That single login is the key to all of them — secure it and you protect every one at once.</div>
      <div class="rowbtns">${secBtn}${conBtn}</div>
      <div class="tip">Make sure 2-factor authentication is ON for your ${esc(provider)} account — it's the biggest thing protecting these.</div>
    </div>`;
  }
  return html;
}

function ssoCard(a) {
  const isPk = a.authType === 'passkey';
  const secUrl = providerSecurityUrl(a.provider);
  const conUrl = providerConnectionsUrl(a.provider);
  const pill = isPk ? `${a.provider ? esc(a.provider) + ' ' : ''}passkey` : `${esc(a.provider || 'SSO')} sign-in`;
  const guide = isPk
    ? `Signs in with a <b>passkey</b>${a.provider ? ' via <b>' + esc(a.provider) + '</b>' : ''}. There's no password to rotate. Keep the ${esc(a.provider || 'provider')} account and its recovery options locked down.`
    : `Signs in with <b>${esc(a.provider || 'an identity provider')}</b>. There's no separate password here to rotate. Secure the provider account and review which apps have access.`;
  const links = [];
  if (secUrl) links.push(`<a class="btn" href="${esc(secUrl)}" target="_blank" rel="noopener">Secure ${esc(a.provider)}</a>`);
  if (conUrl) links.push(`<a class="btn ghost" href="${esc(conUrl)}" target="_blank" rel="noopener">Connected apps</a>`);
  const linkRow = links.length ? `<div class="actions" style="display:flex;gap:8px">${links.join('')}</div>` : '';
  return `<div class="acct" data-id="${a.id}">
    <div class="row">
      ${siteHeader(a)}
      <span class="pill sso">${pill}</span>
    </div>
    <div class="ssoguide">${guide}</div>
    ${linkRow}
    <div style="text-align:right;margin-top:8px"><button class="unsso link">Not ${isPk ? 'passkey' : 'SSO'}?</button> &nbsp; <button class="remove">Remove</button></div>
  </div>`;
}

function editAccount(id, card) {
  const a = vault.accounts.find((x) => x.id === id);
  if (!a) return;
  card.innerHTML = `
    <div class="row"><div class="site">${esc(a.site)}</div></div>
    <label>Username</label>
    <input class="e-user" value="${esc(a.username)}" autocomplete="off">
    <label>Password</label>
    <input class="e-pass" value="${esc(a.secret)}" autocomplete="off">
    <div class="editrow">
      <button class="btn ghost e-gen">Generate</button>
      <button class="btn e-save">Save</button>
      <button class="btn ghost e-cancel">Cancel</button>
    </div>`;
  card.querySelector('.e-gen').onclick = () => { card.querySelector('.e-pass').value = genPassword(20); };
  card.querySelector('.e-cancel').onclick = () => renderVault();
  card.querySelector('.e-save').onclick = async () => {
    const i = vault.accounts.findIndex((x) => x.id === id);
    const newSecret = card.querySelector('.e-pass').value;
    const changed = newSecret !== a.secret;
    vault.accounts[i] = { ...a, username: card.querySelector('.e-user').value.trim(), secret: newSecret, sample: false };
    if (changed) { vault.accounts[i].status = 'unknown'; vault.accounts[i].breachCount = 0; }
    await saveVault();
    renderVault();
  };
}

async function setAuthType(id, type, provider) {
  const i = vault.accounts.findIndex((a) => a.id === id);
  if (i < 0) return;
  vault.accounts[i] = { ...vault.accounts[i], authType: type, provider: (type === 'sso' || type === 'passkey') ? provider : null };
  if (type === 'sso' || type === 'passkey') vault.accounts[i].status = 'unknown'; // email-link keeps its password + status
  await saveVault();
  renderVault();
}

function markSsoPicker(id, card) {
  if (card.querySelector('.ssopick')) return;
  const providers = ['Google', 'Apple', 'Microsoft', 'GitHub', 'Facebook'];
  const picker = document.createElement('div');
  picker.className = 'ssopick';
  picker.style.cssText = 'margin-top:8px;font-size:12px;color:#9aa3b2';
  picker.innerHTML = 'How does this account sign in?<br>'
    + providers.map((p) => `<button class="btn ghost pk" data-p="${p}" style="margin:5px 5px 0 0;padding:6px 9px;font-size:12px">${p}</button>`).join('')
    + `<button class="btn ghost pk" data-p="__passkey" style="margin:5px 5px 0 0;padding:6px 9px;font-size:12px">Passkey</button>`
    + `<button class="btn ghost pk" data-p="__emaillink" style="margin:5px 5px 0 0;padding:6px 9px;font-size:12px">Email code / link</button>`
    + `<button class="btn ghost pk" data-p="__password" style="margin:5px 5px 0 0;padding:6px 9px;font-size:12px">Just a password</button>`
    + `<button class="link" id="pkCancel" style="margin-left:4px">Cancel</button>`;
  card.appendChild(picker);
  picker.querySelectorAll('.pk').forEach((b) => {
    b.onclick = () => {
      const p = b.dataset.p;
      if (p === '__passkey') setAuthType(id, 'passkey', null);
      else if (p === '__emaillink') setAuthType(id, 'emaillink', null);
      else if (p === '__password') setAuthType(id, 'password', null);
      else setAuthType(id, 'sso', p);
    };
  });
  picker.querySelector('#pkCancel').onclick = () => picker.remove();
}

// Dispatcher: if you're actually ON this account's change-password page, do it FOR REAL;
// otherwise fall back to the local simulation (and tell you how to do it for real).
async function rotate(acct, card) {
  const status = card.querySelector('.status');
  const btn = card.querySelector('.rotate');
  if (isSampleAccount(acct)) {
    status.innerHTML = '<span class="breachnote">This is Rekey’s built-in <b>sample</b> account (placeholder login). Click <b>Edit</b> to enter your real credentials, or <b>Remove</b> it — then rotation will work for real.</span>';
    return;
  }
  btn.disabled = true;
  status.innerHTML = '<span class="step">Checking the current tab…</span>';
  const tab = await getActiveTabInfo();
  const host = tab.url ? safeHost(tab.url) : '';
  if (tab.id && host && hostMatchesSite(host, acct.site)) {
    return realRotate(acct, card, tab.id, host);
  }
  // Off-site: open the site's change-password page in a background tab and rotate FOR REAL.
  // If it can't be done automatically, we say so and leave the saved password untouched —
  // never a silent overwrite that would lock you out.
  // Only auto-open-and-rotate when we have a URL we TRUST (learned or curated). Otherwise go
  // straight to the honest hand-off — never open a guessed /.well-known/ link that 404s.
  if (trustedChangeUrl(acct)) {
    status.innerHTML = `<span class="step">Opening <b>${esc(normalizeDomain(acct.site))}</b>’s change-password page…</span>`;
    const r = await rotateViaBackgroundTab(acct, (s) => { status.innerHTML = `<span class="step">${esc(s)}</span>`; });
    if (r.ok) {
      await commitRotated(acct, r.newPw);
      status.innerHTML = '<span class="ok">✓ Rotated for real.</span> Your old password was kept until the new one was confirmed.';
      setTimeout(renderVault, 1600);
      return;
    }
    guidedHandoff(acct, card, r.reason);
    return;
  }
  guidedHandoff(acct, card);
}

// Shared commit: only called once the change is confirmed. Old password kept until here.
async function commitRotated(acct, newPw) {
  const { updated, receipt } = commitRotation(acct, newPw);
  const i = vault.accounts.findIndex((a) => a.id === acct.id);
  vault.accounts[i] = updated; // includes prevSecret + verify:'pending' for self-healing
  vault.history.unshift(receipt);
  await saveVault();
}

// Honest guided hand-off — the GENERIC path that works on ANY site that gates password
// changes behind its own account settings / re-auth (WeTransfer, GitHub, banks, most apps).
// Rekey doesn't guess a deep-link (those 404 or bounce a logged-in user). It opens the site
// where you're ALREADY SIGNED IN, copies a fresh strong password, and gives the same simple
// directions every site follows. No-lockout: the old password stays until the new one is
// confirmed on next sign-in (or you restore the old one).
function guidedHandoff(acct, card, reason) {
  const status = card.querySelector('.status');
  const btn = card.querySelector('.rotate');
  btn.disabled = false;
  const domain = normalizeDomain(acct.site);
  const reset = resetUrlForSite(acct.site); // optional: only used as a "locked out?" fallback
  const why = reason ? ` (${esc(reason)})` : '';
  const resetHtml = reset
    ? `<div style="margin-top:8px;font-size:12px"><a href="${esc(reset)}" target="_blank" rel="noopener">Can't sign in? Reset ${esc(domain)} by email instead.</a></div>`
    : '';
  status.innerHTML = `<span class="user"><b>${esc(domain)}</b> changes passwords in its own account settings${why}. Rekey copies a fresh password and opens the site so you can paste it in:</span>
    <ol style="margin:8px 0 0 18px;padding:0;font-size:12px;color:#9aa3b2;line-height:1.6">
      <li>Open your <b>account settings</b> (usually your profile, top-right).</li>
      <li>Find <b>Password</b> or <b>Security</b>, then choose change password.</li>
      <li>Paste the new password (already on your clipboard) and save.</li>
    </ol>
    <div style="margin-top:8px"><button class="btn" id="hoOpen">Open ${esc(domain)} + copy a new password</button></div>
    ${resetHtml}
    <div id="hoStep2" style="margin-top:6px"></div>`;
  $('hoOpen') && ($('hoOpen').onclick = async () => {
    const newPw = genPassword(20);
    try { await navigator.clipboard.writeText(newPw); } catch (_) {}
    // Opening an active tab CLOSES this popup — so remember the pending change (encrypted in
    // session) BEFORE opening. When the user reopens Rekey, checkPendingManual() prompts them
    // to save it. This is what makes the hand-off actually finishable.
    try { await stashPendingManual(acct, newPw); } catch (_) {}
    // Open where the user is ALREADY SIGNED IN so they can reach account settings without a
    // re-login: the tab they already have open on this site, else a curated/learned change
    // page, else the site's front door. NEVER a reset URL as primary (it bounces a logged-in
    // user to the homepage) and NEVER a /.well-known/ guess (that's the 404 spiral). The front
    // door always loads, so this works for every site.
    let url = null;
    try { const t = await getActiveTabInfo(); if (t && t.url && hostMatchesSite(safeHost(t.url), acct.site)) url = t.url; } catch (_) {}
    if (!url) url = trustedChangeUrl(acct) || ('https://' + domain + '/');
    try { chrome.tabs.create({ url, active: true }); } catch (_) {}
    const step2 = card.querySelector('#hoStep2');
    if (step2) {
      step2.innerHTML = `<span class="ok">✓ Opened ${esc(domain)} and copied a new password.</span> Do the 3 steps above, then reopen Rekey to confirm it saved.`;
    }
  });
}

// "Teach this page" — the MANUAL counterpart to auto-learning. For a site Rekey can't rotate
// automatically, the user navigates to its REAL change-password page and clicks this; Rekey
// reads the form (learnRecipe) and remembers the exact URL + fields, so every future rotation
// on this site goes straight there instead of guessing (and, once shared, for everyone too).
// No password is entered or changed here — it only records where the form is.
async function teachPage(acct, card) {
  const status = card.querySelector('.status');
  const site = normalizeDomain(acct.site);
  const tab = await getActiveTabInfo();
  const host = tab && tab.url ? safeHost(tab.url) : '';
  if (!tab || !tab.id || !host || !hostMatchesSite(host, acct.site)) {
    status.innerHTML = `<span class="user">Open <b>${esc(site)}</b>'s change-password page in this tab first, then click <b>Teach page</b>.</span>`;
    return;
  }
  status.innerHTML = '<span class="step">Reading this page…</span>';
  let learned;
  try {
    const [o] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: learnRecipe });
    learned = o && o.result;
  } catch (_) {
    status.innerHTML = "<span class=\"breachnote\">Couldn't read this page. Reload it and try again.</span>";
    return;
  }
  if (!learned || !learned.ok || !learned.recipe) {
    status.innerHTML = `<span class="user">No change-password form found here. Go to <b>${esc(site)}</b>'s actual change-password page (the one with <b>New password</b> + <b>Confirm</b> fields), then click <b>Teach page</b>.</span>`;
    return;
  }
  learnedRecipes = recordSuccess(learnedRecipes, acct.site, learned.recipe);
  try { await local.set('learnedRecipes', learnedRecipes); } catch (_) {}
  status.innerHTML = `<span class="ok">✓ Learned ${esc(site)}'s change-password page.</span> Next time you rotate, Rekey goes straight here instead of guessing.`;
}

// Remember a pending manual password change (encrypted with the session key) so it survives
// the popup closing when the site's tab opens.
async function stashPendingManual(acct, newPw) {
  if (!key) return;
  const blob = await encryptJSON(key, { accountId: acct.id, site: acct.site, newPw, ts: Date.now() });
  await session.set('pendingManual', blob);
}

// On reopen: if a manual change is pending, ask the user whether they finished it, and save
// the new password (pending-verify then confirms it on next sign-in, or restores the old one).
async function checkPendingManual() {
  if (!key || !vault) return;
  const blob = await session.get('pendingManual');
  if (!blob) return;
  let pm; try { pm = await decryptJSON(key, blob); } catch (_) { await session.remove('pendingManual'); return; }
  const acct = vault.accounts.find((a) => a.id === pm.accountId);
  if (!acct) { await session.remove('pendingManual'); return; }
  const st = $('scanStatus');
  st.innerHTML = `<div class="ssoguide">Did you finish changing your password on <b>${esc(normalizeDomain(pm.site))}</b>? (The new one is on your clipboard.)
    <div style="margin-top:6px"><button class="btn" id="pmSave">✓ Yes — save it to Rekey</button> &nbsp; <button class="link" id="pmNo">Not yet / cancel</button></div></div>`;
  $('pmSave').onclick = async () => {
    const a = vault.accounts.find((x) => x.id === pm.accountId);
    if (a) await commitRotated(a, pm.newPw);
    await session.remove('pendingManual');
    renderVault();
    st.innerHTML = '<span class="ok">✓ Saved.</span> Rekey will confirm it the next time you sign in (and restore the old one if it didn\'t take).';
  };
  $('pmNo').onclick = async () => { await session.remove('pendingManual'); st.textContent = ''; };
}

async function realRotate(acct, card, tabId, host) {
  const status = card.querySelector('.status');
  const btn = card.querySelector('.rotate');
  const newPw = genPassword(20);
  status.innerHTML = `<span class="step">Looking for the change-password form on ${esc(host)}…</span>`;
  let res;
  try {
    const recipe = learnedRecipes[normalizeDomain(host)] || recipeForSite(acct.site);
    const [out] = await chrome.scripting.executeScript({ target: { tabId }, func: rotateInPage, args: [recipe, acct.secret, newPw] });
    res = out && out.result;
  } catch (e) {
    status.innerHTML = `<span class="breachnote">Couldn't run on this page (${esc(String((e && e.message) || e))}). Old password kept.</span>`;
    btn.disabled = false; return;
  }
  if (!res) { status.innerHTML = '<span class="breachnote">No response from the page. Old password kept.</span>'; btn.disabled = false; return; }

  if (!res.ok && res.stage === 'sso') {
    const mark = confirm(`This looks like it signs in with ${res.provider || 'an identity provider'}.\n\nMark it as SSO so Rekey stops trying to rotate a password here and shows you how to secure it instead?`);
    if (mark) { await setAuthType(acct.id, 'sso', res.provider || 'SSO'); return; }
    status.innerHTML = '<span class="user">Left as-is.</span>'; btn.disabled = false; return;
  }
  if (!res.ok && res.stage === 'passkey') {
    const mark = confirm('This looks like it uses a passkey (Touch ID / Face ID / security key) — there is no password to rotate here.\n\nMark it as a passkey account so Rekey stops trying?');
    if (mark) { await setAuthType(acct.id, 'passkey', acct.provider || null); return; }
    status.innerHTML = '<span class="user">Left as-is.</span>'; btn.disabled = false; return;
  }
  if (!res.ok && res.stage === 'passwordless') {
    const mark = confirm('This page signs in with an email code or magic link — your main login is your email, not a password.\n\nMark this account that way so Rekey is honest about it? (You can still keep a rotatable password as a fallback.)');
    if (mark) { await setAuthType(acct.id, 'emaillink', null); return; }
    status.innerHTML = '<span class="user">Left as-is.</span>'; btn.disabled = false; return;
  }
  if (!res.ok && res.stage === '2fa') {
    // Pause: the site wants a 2FA code. User enters it on the page, finishes, then we re-check.
    status.innerHTML = `<span class="step">${esc(res.message)}</span><div style="margin-top:8px"><button class="btn" id="done2fa">I finished — check</button></div>`;
    const recipe = learnedRecipes[normalizeDomain(host)] || recipeForSite(acct.site);
    status.querySelector('#done2fa').onclick = async () => {
      status.innerHTML = '<span class="step">Checking…</span>';
      let chk;
      try { const [o] = await chrome.scripting.executeScript({ target: { tabId }, func: checkSuccessOnPage, args: [recipe] }); chk = o && o.result; } catch (_) { /* ignore */ }
      let done = chk && chk.ok;
      if (chk && chk.uncertain) done = confirm(`Did ${acct.site} confirm your password was changed?`);
      if (done) {
        await commitRotated(acct, newPw);
        await learnFromTab(tabId, host, true);
        status.innerHTML = `<span class="ok">✓ Rotated on ${esc(host)}.</span> New password saved after the 2-factor step.`;
        setTimeout(renderVault, 1700);
      } else {
        status.innerHTML = '<span class="breachnote">Not confirmed. Old password kept — nothing lost.</span>';
        btn.disabled = false;
      }
    };
    return;
  }
  let commit = res.ok;
  if (!res.ok && res.stage === 'verify') {
    // Generic auto-detect is imperfect, so let the human confirm (still no-lockout: old kept unless confirmed).
    commit = confirm(`Rekey filled and submitted the change on ${acct.site}.\n\nDid the page confirm your password was updated?\n\nOK = yes, save the new password.\nCancel = no, keep the old one.`);
  } else if (!res.ok && (res.stage === 'locate' || res.stage === 'notfound')) {
    // The page you're on isn't the change-password form (e.g. you're on the site's home
    // page). Instead of a dead-end, open the site's REAL change-password page in the
    // background and rotate there — works on any site that supports the
    // /.well-known/change-password standard or one you've taught. This is what makes
    // "Rotate" work from anywhere on a site, not only when you're already on the form.
    if (trustedChangeUrl(acct)) {
      status.innerHTML = `<span class="step">No change-password form on this page. Opening <b>${esc(normalizeDomain(host))}</b>’s password page…</span>`;
      const r = await rotateViaBackgroundTab(acct, (s) => { status.innerHTML = `<span class="step">${esc(s)}</span>`; });
      if (r.ok) {
        await commitRotated(acct, r.newPw);
        status.innerHTML = '<span class="ok">✓ Rotated for real.</span> Your old password was kept until the new one was confirmed.';
        setTimeout(renderVault, 1600);
        return;
      }
      guidedHandoff(acct, card, r.reason);
      return;
    }
    // No trusted page for this site: don't guess a link that 404s. Hand off honestly.
    guidedHandoff(acct, card);
    return;
  }

  if (commit) {
    await commitRotated(acct, newPw);
    await learnFromTab(tabId, host, true); // remember the working recipe for next time
    status.innerHTML = `<span class="ok">✓ Rotated on ${esc(host)}.</span> New password saved; the old one was kept until the change was confirmed.`;
    setTimeout(renderVault, 1700);
  } else {
    if (res && res.stage) await learnFailure(host, res.stage);
    status.innerHTML = `<span class="breachnote">${esc(res.message || 'Not confirmed.')} Old password kept — nothing lost.</span>`;
    btn.disabled = false;
  }
}

// Local simulation (no real site): still generates + stores a new password and logs a receipt.
function safeHost(url) { try { return new URL(url).hostname; } catch (_) { return ''; } }
async function getActiveTabInfo() {
  try {
    const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
    let url = t && t.url;
    if (!url && t && t.id) {
      try { const [r] = await chrome.scripting.executeScript({ target: { tabId: t.id }, func: () => location.href }); url = r && r.result; } catch (_) {}
    }
    return { id: t && t.id, url };
  } catch (_) { return { id: null, url: '' }; }
}

// ---- HISTORY view ----
function renderHistory() {
  const host = $('historyView');
  if (!vault.history.length) {
    host.innerHTML = '<div class="empty">No rotations yet.<br>Rotate an account and the receipt shows up here.</div>';
    return;
  }
  host.innerHTML = vault.history.map((r) => `
    <div class="rcpt">
      <div class="t">${esc(r.site)} · ${fmt(r.when)} · ${r.verified ? '✓ verified' : 'unverified'}</div>
      <div class="m">${esc(r.oldMasked)} → ${esc(r.newMasked)}</div>
    </div>`).join('');
}

// ---- Zero-knowledge sync (Cloudflare Worker). The server only ever holds ciphertext. ----
async function getSyncCfg() { return (await local.get('sync')) || null; }
async function setSyncCfg(cfg) { await local.set('sync', cfg); }

// The auth token is derived from the master password with a FIXED work factor (independent
// of the vault's encryption iters), so a new device can authenticate before it has the meta.
async function cacheAuthIfSynced(masterPassword) {
  try {
    const cfg = await getSyncCfg();
    if (cfg && cfg.email && masterPassword) await session.set('ah', await deriveAuthHash(masterPassword, cfg.email));
  } catch (_) { /* non-fatal */ }
}

// Rekey's hosted sync server. Normal users never see or type a URL — this is used by
// default. Self-hosters can override it under "Use my own server (advanced)".
const DEFAULT_SYNC_URL = 'https://rekey-sync.mccomas0.workers.dev';

async function renderSyncPanel() {
  const panel = $('syncPanel');
  const cfg = await getSyncCfg();
  if (cfg && cfg.email) {
    panel.innerHTML = `
      <div class="ssoguide">☁ Synced as <b>${esc(cfg.email)}</b>. Your vault is end-to-end encrypted — the server can't read it.${cfg.lastSyncAt ? '<br>Last sync: ' + esc(fmt(cfg.lastSyncAt)) : ''}</div>
      <div class="rowbtns">
        <button id="syncNowBtn" class="btn">Sync now</button>
        <button id="syncOutBtn" class="btn ghost">Sign out of sync</button>
      </div>
      <div id="syncStatus" class="status"></div>`;
    $('syncNowBtn').onclick = syncNow;
    $('syncOutBtn').onclick = signOutSync;
  } else {
    panel.innerHTML = `
      <div class="ssoguide">Sync your encrypted vault across devices. Nothing readable ever leaves your machine — the server only holds <b>ciphertext</b>. <b>If you lose BOTH your master password and your recovery key, your data can't be recovered.</b></div>
      <input id="syncEmail" placeholder="Your email" autocomplete="off" />
      <input id="syncPw" type="password" placeholder="Confirm your master password" autocomplete="off" />
      <label style="display:flex;gap:8px;font-size:12px;color:var(--muted);margin:4px 0"><input type="checkbox" id="syncAck" style="flex:none;width:auto"> I understand losing my master password AND recovery key means my data is unrecoverable.</label>
      <div class="rowbtns">
        <button id="syncCreateBtn" class="btn">Create sync account</button>
        <button id="syncRestoreBtn" class="btn ghost">Restore from sync</button>
      </div>
      <div style="margin-top:6px"><button id="syncAdvBtn" class="link">Use my own server (advanced)</button></div>
      <div id="syncAdvRow" class="hidden" style="margin-top:6px"><input id="syncUrl" placeholder="Sync server URL (https://…)" autocomplete="off" /></div>
      <div id="syncStatus" class="status"></div>`;
    $('syncCreateBtn').onclick = enableSync;
    $('syncRestoreBtn').onclick = signInSync;
    $('syncAdvBtn').onclick = () => { const r = $('syncAdvRow'); const open = r.classList.contains('hidden'); show(r, open); if (open && cfg && cfg.url && cfg.url !== DEFAULT_SYNC_URL) $('syncUrl').value = cfg.url; };
  }
}

function syncInputs() {
  const urlEl = $('syncUrl');
  const url = (urlEl && urlEl.value.trim()) || DEFAULT_SYNC_URL; // hosted by default
  return { url, email: $('syncEmail').value.trim().toLowerCase(), pw: $('syncPw').value };
}

// Create a brand-new sync account and push this vault (encrypted) up.
async function enableSync() {
  const st = $('syncStatus');
  const { url, email, pw } = syncInputs();
  if (!email || !pw) { st.textContent = 'Enter your email and confirm your master password.'; return; }
  if (!$('syncAck').checked) { st.textContent = 'Please tick the acknowledgment box first.'; return; }
  const meta = await local.get('meta');
  const iters = meta.iters || LEGACY_PBKDF2_ITERS;
  try { await unwrapKey(await deriveKey(pw, meta.salt, iters), meta.masterWrap); }
  catch (_) { st.textContent = 'That master password is incorrect.'; return; }
  st.textContent = 'Creating your sync account…';
  const ah = await deriveAuthHash(pw, email);
  const blob = await encryptJSON(key, vault);
  const r = await syncApi(url, '/signup', { email, authHash: ah, blob, meta });
  if (r.status === 409) { st.textContent = 'An account with that email already exists — use “Restore from sync” instead.'; return; }
  if (r.status !== 200 || !r.ok) { st.textContent = r.error || ('Couldn’t create the account (status ' + r.status + ').'); return; }
  await session.set('ah', ah);
  await setSyncCfg({ url, email, version: r.version, lastSyncAt: new Date().toISOString() });
  st.innerHTML = '<span class="ok">✓ Sync enabled.</span> Your encrypted vault is backed up. Use the same email + master password on another device to sync it.';
  setTimeout(renderSyncPanel, 1400);
}

// Pull an existing account onto THIS device (second device or after a reinstall).
async function signInSync() {
  const st = $('syncStatus');
  const { url, email, pw } = syncInputs();
  if (!email || !pw) { st.textContent = 'Enter your email and master password.'; return; }
  st.textContent = 'Signing in…';
  const ah = await deriveAuthHash(pw, email);
  const r = await syncApi(url, '/pull', { email, authHash: ah });
  if (r.status === 404) { st.textContent = 'No sync account found for that email.'; return; }
  if (r.status === 401) { st.textContent = 'Wrong master password for that account.'; return; }
  if (r.status !== 200 || !r.blob) { st.textContent = r.error || ('Sign-in failed (status ' + r.status + ').'); return; }
  try {
    const m = r.meta;
    const dek = await unwrapKey(await deriveKey(pw, m.salt, m.iters || LEGACY_PBKDF2_ITERS), m.masterWrap);
    const pulled = await decryptJSON(dek, r.blob);
    key = dek; vault = pulled;
    await local.set('meta', m);
    await local.set('vault', r.blob);
    await session.set('sk', await exportKeyB64(dek));
    await session.set('ah', ah);
    await session.set('unlockedAt', Date.now());
    await setSyncCfg({ url, email, version: r.version, lastSyncAt: new Date().toISOString() });
    openApp();
  } catch (_) {
    st.textContent = 'Could not decrypt the vault with that master password.';
  }
}

// Pull → merge → push. Conflict-safe (retries once after re-merging the server's copy).
async function syncNow() {
  const st = $('syncStatus');
  const cfg = await getSyncCfg();
  if (!cfg) return;
  const ah = await session.get('ah');
  if (!ah) { st.textContent = 'Lock and unlock with your master password, then sync.'; return; }
  st.textContent = 'Syncing…';
  // Routine sync pushes only the vault blob — NOT meta. The server's meta (salts + key wraps)
  // is authoritative and only changes on a master-password change (via /change-auth). Sending
  // stale local meta here could clobber a newer master password set on another device.
  const pull = await syncApi(cfg.url, '/pull', { email: cfg.email, authHash: ah });
  if (pull.status === 401) { st.textContent = 'Auth failed — re-unlock with your master password.'; return; }
  if (pull.status !== 200 || !pull.blob) { st.textContent = pull.error || ('Sync failed (status ' + pull.status + ').'); return; }
  try { vault = mergeVaults(vault, await decryptJSON(key, pull.blob)); } catch (_) { st.textContent = 'Could not read the server copy (key mismatch).'; return; }
  await saveVault();
  let push = await syncApi(cfg.url, '/push', { email: cfg.email, authHash: ah, blob: await encryptJSON(key, vault), baseVersion: pull.version });
  if (push.conflict) {
    try { vault = mergeVaults(vault, await decryptJSON(key, push.blob)); } catch (_) {}
    await saveVault();
    push = await syncApi(cfg.url, '/push', { email: cfg.email, authHash: ah, blob: await encryptJSON(key, vault), baseVersion: push.version });
  }
  if (push.status !== 200 || !push.ok) { st.textContent = push.error || 'Push failed — try again.'; return; }
  await setSyncCfg({ ...cfg, version: push.version, lastSyncAt: new Date().toISOString() });
  renderVault();
  st.innerHTML = '<span class="ok">✓ Synced.</span>';
}

async function signOutSync() {
  if (!confirm('Sign out of sync on this device?\n\nYour vault stays here locally. It just stops syncing until you sign in again.')) return;
  await new Promise((r) => chrome.storage.local.remove('sync', r));
  await session.remove('ah');
  renderSyncPanel();
}
