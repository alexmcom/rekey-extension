// Tests the pure sync logic (auth-hash derivation + vault merge). Run: node test-sync.js
import { deriveAuthHash, mergeVaults, vaultChanged } from './sync-core.js';

let pass = 0, fail = 0;
const ok = (l, c) => { console.log((c ? 'PASS ' : 'FAIL ') + l); c ? pass++ : fail++; };

// 1. Auth hash: deterministic, email-bound, and NOT equal to a plain encryption derivation.
{
  const h1 = await deriveAuthHash('correct horse', 'me@x.com', 1000);
  const h2 = await deriveAuthHash('correct horse', 'me@x.com', 1000);
  const h3 = await deriveAuthHash('correct horse', 'other@x.com', 1000);
  const h4 = await deriveAuthHash('wrong pw', 'me@x.com', 1000);
  ok('auth hash is deterministic for same inputs', h1 === h2);
  ok('auth hash is 64 hex chars (SHA-256)', /^[0-9a-f]{64}$/.test(h1));
  ok('different email → different hash (email-bound)', h1 !== h3);
  ok('different password → different hash', h1 !== h4);
}

// 2. Merge: newer account wins by timestamp.
{
  const local = { accounts: [{ id: 'a1', site: 'x.com', username: 'u', secret: 'NEW', addedAt: '2026-01-01', lastRotated: '2026-07-10' }], history: [] };
  const remote = { accounts: [{ id: 'a1', site: 'x.com', username: 'u', secret: 'OLD', addedAt: '2026-01-01', lastRotated: '2026-05-01' }], history: [] };
  const m = mergeVaults(local, remote);
  ok('newer account version wins on merge', m.accounts.length === 1 && m.accounts[0].secret === 'NEW');
}

// 3. Merge: accounts unique to each side are both kept.
{
  const local = { accounts: [{ id: 'a1', site: 'x.com', addedAt: '2026-01-01' }], history: [] };
  const remote = { accounts: [{ id: 'a2', site: 'y.com', addedAt: '2026-01-01' }], history: [] };
  const m = mergeVaults(local, remote);
  ok('accounts from both sides are unioned', m.accounts.length === 2 && m.accounts.some((a) => a.id === 'a1') && m.accounts.some((a) => a.id === 'a2'));
}

// 4. Deletion tombstone: a deleted account does NOT resurrect from the remote copy.
{
  const local = { accounts: [], deleted: ['a1'], history: [] };
  const remote = { accounts: [{ id: 'a1', site: 'x.com', addedAt: '2026-01-01' }], history: [] };
  const m = mergeVaults(local, remote);
  ok('tombstoned account stays deleted after merge', !m.accounts.some((a) => a.id === 'a1') && m.deleted.includes('a1'));
}

// 5. History is unioned by receipt id, newest first.
{
  const local = { accounts: [], history: [{ id: 'r1', when: '2026-07-01' }] };
  const remote = { accounts: [], history: [{ id: 'r2', when: '2026-07-09' }, { id: 'r1', when: '2026-07-01' }] };
  const m = mergeVaults(local, remote);
  ok('history unioned without dupes, newest first', m.history.length === 2 && m.history[0].id === 'r2');
}

// 6. vaultChanged detects a real change and ignores a no-op.
{
  const a = { accounts: [{ id: 'a1', secret: 'x', status: 'safe', username: 'u', site: 's', verify: 'ok' }], deleted: [] };
  const b = { accounts: [{ id: 'a1', secret: 'x', status: 'safe', username: 'u', site: 's', verify: 'ok' }], deleted: [] };
  const c = { accounts: [{ id: 'a1', secret: 'CHANGED', status: 'safe', username: 'u', site: 's', verify: 'ok' }], deleted: [] };
  ok('identical vaults are not flagged as changed', vaultChanged(a, b) === false);
  ok('a changed secret is detected', vaultChanged(a, c) === true);
}

console.log('\n' + (fail === 0 ? '✅ ALL SYNC TESTS PASSED' : '❌ ' + fail + ' FAILED') + '  (' + pass + '/' + (pass + fail) + ')');
process.exit(fail === 0 ? 0 : 1);
