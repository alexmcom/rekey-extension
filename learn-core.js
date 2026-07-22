// learn-core.js — the self-learning recipe store (pure logic; no chrome APIs).
//
// Rekey learns each site's working change-password recipe from experience:
//   • when a rotation SUCCEEDS, the exact recipe that worked is saved for that domain, so
//     the next rotation there uses the proven recipe instead of guessing again;
//   • when a rotation FAILS, the failure is recorded so the engine can (a) stop trusting a
//     recipe that has stopped working, and (b) surface the site as "needs teaching" instead
//     of silently doing nothing (the exact F11 complaint).
//
// The background persists the store object this returns (chrome.storage.local). This module
// is storage-agnostic and unit-tested in Node. SHARED/community recipes plug in later as an
// extra source in resolveRecipe() — same recipe format, just distributed across users.
import { normalizeDomain } from './recipes.js';

const FAIL_BEFORE_TEACH = 2; // consecutive failures with no prior success → flag for teaching

// Store shape: { [domain]: { recipe, successes, failures, lastStage, needsTeaching, updatedAt } }

// Record that `recipe` successfully changed the password on `site`. The proven recipe wins,
// and a success clears any prior failure streak.
export function recordSuccess(store, site, recipe) {
  store = store || {};
  const d = normalizeDomain(site);
  if (!d || !recipe) return store;
  const prev = store[d] || {};
  store[d] = {
    recipe,
    successes: (prev.successes || 0) + 1,
    failures: 0,
    lastStage: null,
    needsTeaching: false,
    updatedAt: new Date().toISOString(),
  };
  return store;
}

// Record a failed rotation on `site` at a given stage ('locate' | 'verify' | '2fa' | …).
export function recordFailure(store, site, stage) {
  store = store || {};
  const d = normalizeDomain(site);
  if (!d) return store;
  const prev = store[d] || {};
  const failures = (prev.failures || 0) + 1;
  store[d] = {
    ...prev,
    failures,
    lastStage: stage || 'unknown',
    // Only nag when we've NEVER gotten it right here AND keep failing — a one-off blip on a
    // site that normally works shouldn't flag it.
    needsTeaching: (prev.successes || 0) === 0 && failures >= FAIL_BEFORE_TEACH,
    updatedAt: new Date().toISOString(),
  };
  return store;
}

// The proven recipe for a site, but only if it's actually worth trusting (has succeeded here).
export function getLearned(store, site) {
  const d = normalizeDomain(site);
  const e = store && store[d];
  if (!e || !e.recipe) return null;
  return (e.successes || 0) > 0 ? e.recipe : null;
}

// Which recipe should rotation use for a site? Priority:
//   1. a curated / shared site-specific recipe (vetted → wins),
//   2. a locally-learned recipe that has actually succeeded here,
//   3. the generic autocomplete-based recipe (baseline that works on well-built sites).
export function resolveRecipe(site, { siteRecipes, genericRecipe, store } = {}) {
  const d = normalizeDomain(site);
  // Merge over generic so a curated URL-only entry still carries field selectors.
  if (siteRecipes && siteRecipes[d]) return { ...(genericRecipe || {}), ...siteRecipes[d], source: 'curated' };
  const learned = getLearned(store || {}, site);
  if (learned) return { ...learned, source: 'learned' };
  return { ...(genericRecipe || {}), generic: true, source: 'generic' };
}

// Sites that keep failing with no success — the UI surfaces these so the user can teach a
// recipe (or, later, so a proven recipe can be shared with everyone). This is the engine
// saying "I couldn't do this one" instead of silently doing nothing.
export function sitesNeedingTeaching(store) {
  const out = [];
  for (const d of Object.keys(store || {})) if (store[d] && store[d].needsTeaching) out.push(d);
  return out;
}
