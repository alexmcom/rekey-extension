import { registrableDomain } from './core.js';

// recipes.js — per-site "recipes" tell the engine where a site's password fields are.
//
// The GENERIC recipe uses the web conventions most well-built sites follow:
//   autocomplete="current-password" / autocomplete="new-password"
// plus common name/id fallbacks. It works on many sites with NO per-site code —
// the same mechanism Chrome/Safari use to find change-password forms.
//
// When the generic recipe isn't enough for an important site, we add a site-specific
// recipe below (exact selectors), keyed by domain. Site-specific wins over generic.

export const genericRecipe = {
  name: 'generic (autocomplete-based)',
  currentPasswordSelector: [
    'input[autocomplete="current-password"]',
    'input[type="password"][name*="current" i]',
    'input[type="password"][id*="current" i]',
    'input[type="password"][name*="old" i]',
    'input[type="password"][id*="old" i]',
  ],
  newPasswordSelector: [
    'input[autocomplete="new-password"]',
    'input[type="password"][name*="new" i]',
    'input[type="password"][id*="new" i]',
  ],
  confirmPasswordSelector: [
    'input[type="password"][name*="confirm" i]',
    'input[type="password"][id*="confirm" i]',
    'input[type="password"][name*="retype" i]',
    'input[type="password"][name*="verify" i]',
    'input[type="password"][id*="verify" i]',
  ],
  submitSelector: [
    'button[type="submit"]',
    'input[type="submit"]',
    'button[name*="save" i]',
    'button[id*="save" i]',
    'button[id*="submit" i]',
  ],
  successTextIncludes: [
    'password has been updated', 'password was changed', 'password changed',
    'password updated', 'successfully updated', 'successfully changed',
    'password has been reset', 'your password has been',
  ],
  errorTextIncludes: [
    'incorrect', 'does not match', "doesn't match", 'do not match',
    'too weak', 'wrong password', "isn't correct", 'not correct', 'invalid password',
  ],
  timeoutMs: 6000,
};

// Site-specific recipes, keyed by root domain. Two independent things can live here:
//   selectors          — exact field/submit selectors when the generic recipe misses.
//   changePasswordUrl  — a KNOWN-GOOD page where the password can be changed in-place.
//   resetUrl           — a KNOWN-GOOD "forgot password" page (public, no re-auth, emails a
//                        set-new-password link). This is the honest universal fallback.
// These URLs are CURATED and verified, never guessed. If a site isn't listed and we haven't
// learned its page from a past success, Rekey does NOT invent a /.well-known/ link (those
// 404 on most sites); it hands off to the site's front door instead. Grow this list only
// with URLs confirmed to load.
export const siteRecipes = {
  'wetransfer.com': { resetUrl: 'https://wetransfer.com/forgot-password' },
  'dropbox.com':    { resetUrl: 'https://www.dropbox.com/forgot' },
  'spotify.com':    { resetUrl: 'https://accounts.spotify.com/en/password-reset' },
};

export function recipeForSite(site) {
  const root = normalizeDomain(site);
  const s = siteRecipes[root];
  // Merge OVER the generic selectors, so a curated entry that only carries URLs (resetUrl /
  // changePasswordUrl and no selectors) still gets working field selectors. A curated entry
  // with its own selectors overrides the generic ones.
  if (s) return { ...genericRecipe, ...s };
  return { ...genericRecipe, generic: true };
}

// A curated in-place change-password URL for this site, or null. Never a guess.
export function changePasswordUrlForSite(site) {
  const r = siteRecipes[normalizeDomain(site)];
  return (r && r.changePasswordUrl) || null;
}

// A curated "forgot password" reset URL for this site, or null. Never a guess.
export function resetUrlForSite(site) {
  const r = siteRecipes[normalizeDomain(site)];
  return (r && r.resetUrl) || null;
}

export function normalizeDomain(s) {
  if (!s) return '';
  return String(s).toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
}

// Match a saved account's site against the active tab host. Same registrable domain counts,
// so a login saved on signup.regfox.com is offered on auth.regfox.com too (both = regfox.com).
// registrableDomain is public-suffix-aware, so this does NOT merge unrelated *.github.io or
// *.workers.dev sites — that safety is what keeps autofill from crossing owners.
export function hostMatchesSite(host, site) {
  const h = normalizeDomain(host);
  const s = normalizeDomain(site);
  if (!h || !s) return false;
  if (h === s || h.endsWith('.' + s) || s.endsWith('.' + h)) return true;
  const rh = registrableDomain(h), rs = registrableDomain(s);
  return !!rh && rh === rs;
}
