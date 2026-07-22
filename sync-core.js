// sync-core.js — pure logic for zero-knowledge sync. No chrome APIs, so it runs in the
// extension AND in Node for unit tests. The server only ever stores CIPHERTEXT plus a
// salted hash of an auth token — it can never decrypt your vault.
//
// Two secrets come out of your master password, kept separate so one can't derive the other:
//   • the ENCRYPTION key (existing code) wraps the DEK — never leaves the device.
//   • the AUTH hash (here) proves who you are to the sync server — derived with a DIFFERENT
//     salt namespace and then hashed, so it can't decrypt anything even if the server sees it.

const te = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

// The token the client sends to the server to authenticate. Derived from the master password
// with an auth-only salt ("rekey-auth|<email>"), then SHA-256'd. Distinct from the encryption
// key (which uses the vault's own salt), so knowing this reveals nothing about the vault.
export async function deriveAuthHash(masterPassword, email, iterations = 600000) {
  const salt = te.encode('rekey-auth|' + String(email || '').trim().toLowerCase());
  const base = await crypto.subtle.importKey('raw', te.encode(masterPassword), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, 256);
  const digest = await crypto.subtle.digest('SHA-256', bits);
  return toHex(digest);
}

// Merge a local vault with the server's copy. Rules:
//   • accounts: keyed by stable id; the newer one wins (by lastRotated/addedAt).
//   • deletions: tombstoned ids (either side) are removed and the tombstone list is unioned,
//     so a deleted account doesn't resurrect on the next sync.
//   • history: union of receipts by id, newest first.
// Returns the merged vault (shape compatible with the local vault).
export function mergeVaults(localV, remoteV) {
  const L = localV || { accounts: [], history: [] };
  const R = remoteV || { accounts: [], history: [] };
  const ts = (a) => new Date(a.lastRotated || a.addedAt || 0).getTime();

  const deleted = new Set([...(L.deleted || []), ...(R.deleted || [])]);

  const byId = new Map();
  for (const a of (R.accounts || [])) byId.set(a.id, a);
  for (const a of (L.accounts || [])) {
    const ex = byId.get(a.id);
    if (!ex || ts(a) >= ts(ex)) byId.set(a.id, a);
  }
  const accounts = [...byId.values()].filter((a) => !deleted.has(a.id));

  const hById = new Map();
  for (const r of (R.history || [])) hById.set(r.id, r);
  for (const r of (L.history || [])) if (!hById.has(r.id)) hById.set(r.id, r);
  const history = [...hById.values()].sort((x, y) => new Date(y.when) - new Date(x.when));

  return { ...L, accounts, history, deleted: [...deleted] };
}

// Do two vault snapshots differ in a way worth pushing? (cheap identity check on the
// parts that matter, so we don't push no-op syncs).
export function vaultChanged(a, b) {
  const norm = (v) => JSON.stringify({
    accounts: (v.accounts || []).map((x) => [x.id, x.secret, x.status, x.username, x.site, x.verify]).sort(),
    deleted: [...(v.deleted || [])].sort(),
  });
  return norm(a || {}) !== norm(b || {});
}
