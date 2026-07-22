// sync.js — thin network layer for Rekey sync. Pure crypto/merge logic lives in
// sync-core.js (unit-tested); this just talks to the Worker. The popup owns the vault
// key, so encryption/decryption of the blob happens there — this file never sees plaintext.
export { deriveAuthHash, mergeVaults, vaultChanged } from './sync-core.js';

// POST a JSON body to the Worker and return { status, ...json }.
export async function syncApi(url, path, body) {
  const base = String(url || '').replace(/\/+$/, '');
  let res;
  try {
    res = await fetch(base + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return { status: 0, error: 'network — check the Worker URL and your connection' };
  }
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  return { status: res.status, ...data };
}
