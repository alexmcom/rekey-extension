// Tests the self-learning recipe store (pure logic). Run: node test-learn.js
import { recordSuccess, recordFailure, getLearned, resolveRecipe, sitesNeedingTeaching } from './learn-core.js';
import { genericRecipe } from './recipes.js';

let pass = 0, fail = 0;
const ok = (l, c) => { console.log((c ? 'PASS ' : 'FAIL ') + l); c ? pass++ : fail++; };

const RX = { newPasswordSelector: '#np', submitSelector: '#go' };

// 1. A success stores the recipe and makes it retrievable (domain normalised, www stripped).
{
  let store = {};
  store = recordSuccess(store, 'https://www.github.com/settings/security', RX);
  ok('success stores a learned recipe', !!store['github.com'] && store['github.com'].successes === 1);
  ok('learned recipe is retrievable by bare host', getLearned(store, 'github.com') === RX);
}

// 2. Before any success there is no trusted learned recipe.
{
  let store = {};
  store = recordFailure(store, 'example.com', 'locate');
  ok('no learned recipe before a success (only failures so far)', getLearned(store, 'example.com') === null);
}

// 3. Two failures with no success → flagged as needs-teaching (engine surfaces it, not silent).
{
  let store = {};
  store = recordFailure(store, 'weird.com', 'locate');
  ok('one failure does NOT flag teaching yet', sitesNeedingTeaching(store).length === 0);
  store = recordFailure(store, 'weird.com', 'locate');
  ok('two failures with no success → needs teaching', sitesNeedingTeaching(store).includes('weird.com'));
}

// 4. A later success clears the failure streak and the needs-teaching flag.
{
  let store = {};
  store = recordFailure(store, 'flaky.com', 'verify');
  store = recordFailure(store, 'flaky.com', 'verify');
  ok('flaky.com is flagged before it ever works', sitesNeedingTeaching(store).includes('flaky.com'));
  store = recordSuccess(store, 'flaky.com', RX);
  ok('a success clears needs-teaching', sitesNeedingTeaching(store).length === 0);
  ok('a success resets the failure count', store['flaky.com'].failures === 0);
}

// 5. A one-off failure on a site that already worked does NOT nag.
{
  let store = {};
  store = recordSuccess(store, 'reliable.com', RX);
  store = recordFailure(store, 'reliable.com', 'verify');
  ok('a blip after prior success does not flag teaching', sitesNeedingTeaching(store).length === 0);
  ok('the proven recipe is still trusted after one blip', getLearned(store, 'reliable.com') === RX);
}

// 6. resolveRecipe priority: curated > learned > generic.
{
  const curated = { newPasswordSelector: '#curated' };
  const siteRecipes = { 'bank.com': curated };
  let store = {};
  store = recordSuccess(store, 'shop.com', RX);

  const r1 = resolveRecipe('bank.com', { siteRecipes, genericRecipe, store });
  ok('curated recipe wins for a curated site', r1.newPasswordSelector === '#curated' && r1.source === 'curated');

  const r2 = resolveRecipe('shop.com', { siteRecipes, genericRecipe, store });
  ok('learned recipe used when no curated recipe exists', r2.newPasswordSelector === '#np' && r2.source === 'learned');

  const r3 = resolveRecipe('unknown.com', { siteRecipes, genericRecipe, store });
  ok('generic recipe is the baseline fallback', r3.generic === true && r3.source === 'generic');
}

console.log('\n' + (fail === 0 ? '✅ ALL LEARN TESTS PASSED' : '❌ ' + fail + ' FAILED') + '  (' + pass + '/' + (pass + fail) + ')');
process.exit(fail === 0 ? 0 : 1);
