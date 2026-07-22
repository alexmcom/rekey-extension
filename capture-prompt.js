// capture-prompt.js — Rekey's on-page cards (Shadow DOM so the host page's CSS can't
// touch them). One generic renderer, plus thin wrappers for each use:
//   • showSavePrompt  — "Save this login to Rekey?" (after a successful login)
//   • showFillPrompt  — "Fill your saved login" / "Fill a new strong password"
// Pure DOM — no imports.

let host = null; // only one card on screen at a time

export function dismissPrompt() {
  if (host && host.parentNode) host.parentNode.removeChild(host);
  host = null;
}

// opts: { title, site, sub, actionLabel, onAction, onDismiss, doneText, timeoutMs }
export function showPrompt(opts) {
  dismissPrompt();
  host = document.createElement('div');
  host.id = 'rekey-prompt';
  host.style.cssText = 'all: initial; position: fixed; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'open' });

  const site = String(opts.site || '').replace(/^www\./, '');
  const sub = opts.sub || '';

  root.innerHTML = `
    <style>
      :host { all: initial; }
      .card { position: fixed; top: 16px; right: 16px; width: 320px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #14141b; color: #f5f5f7; border: 1px solid #2a2a35;
        border-radius: 14px; box-shadow: 0 12px 40px rgba(0,0,0,.45);
        padding: 16px; box-sizing: border-box; animation: rk-in .18s ease-out; }
      @keyframes rk-in { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: none; } }
      .brand { font-weight: 800; font-size: 13px; letter-spacing: .5px; margin-bottom: 8px; }
      .brand .k { color: #ec4899; }
      .q { font-size: 14px; line-height: 1.4; margin-bottom: 4px; }
      .site { font-weight: 700; word-break: break-all; }
      .sub { color: #a1a1aa; font-size: 12px; margin-bottom: 14px; word-break: break-all; }
      .row { display: flex; gap: 8px; }
      button { flex: 1; font-size: 13px; font-weight: 700; padding: 9px 10px;
        border-radius: 9px; cursor: pointer; border: 1px solid transparent; }
      .go { background: #ec4899; color: #fff; }
      .go:hover { background: #db2777; }
      .skip { background: transparent; color: #d4d4d8; border-color: #3a3a45; }
      .skip:hover { background: #1e1e28; }
      .close { position: absolute; top: 10px; right: 12px; background: none; border: none;
        color: #71717a; font-size: 16px; line-height: 1; cursor: pointer; padding: 2px 4px; flex: none; }
      .done { font-size: 13px; color: #34d399; font-weight: 700; padding: 2px 0; }
    </style>
    <div class="card" role="dialog" aria-label="Rekey">
      <button class="close" id="x" title="Dismiss">&times;</button>
      <div class="brand">RE<span class="k">KEY</span></div>
      <div class="body">
        <div class="q">${esc(opts.title || '')}</div>
        <div class="site">${esc(site)}</div>
        ${sub ? `<div class="sub">${esc(sub)}</div>` : '<div class="sub"></div>'}
        <div class="row">
          <button class="go" id="go">${esc(opts.actionLabel || 'OK')}</button>
          <button class="skip" id="skip">Not now</button>
        </div>
      </div>
    </div>`;

  const bodyEl = root.querySelector('.body');
  let dismissTimer = null;
  const finishDone = () => {
    bodyEl.innerHTML = `<div class="done">${esc(opts.doneText || '✓ Done')}</div>`;
    setTimeout(dismissPrompt, 1400);
  };
  // Honest failure state — NEVER pretend an action worked. If the vault is locked, say exactly
  // what to do and let the user retry in place (the prompt isn't lost) once they've unlocked.
  const finishFail = (res) => {
    if (dismissTimer) { clearTimeout(dismissTimer); dismissTimer = null; } // give them time to act
    const locked = !!(res && res.locked);
    const msg = locked
      ? '🔒 Rekey is locked. Click the Rekey icon in your toolbar and unlock, then Try again.'
      : ((res && res.message) || "Couldn't do that on this page. Open Rekey and try again.");
    bodyEl.innerHTML = `<div class="q" style="margin-bottom:12px">${esc(msg)}</div>
      <div class="row">
        ${locked ? '<button class="go" id="retry">Try again</button>' : ''}
        <button class="skip" id="closeF">Close</button>
      </div>`;
    const rb = root.getElementById('retry');
    if (rb) rb.onclick = run;
    root.getElementById('closeF').onclick = () => { try { opts.onDismiss && opts.onDismiss(); } catch (_) {} dismissPrompt(); };
  };
  // Run the action, then show success OR an honest failure. An action that returns nothing
  // (void) is treated as success — preserves the old behaviour for save/arm prompts.
  const run = async () => {
    let r;
    try { r = opts.onAction ? await opts.onAction() : undefined; } catch (_) { r = { ok: false }; }
    const res = (r && typeof r === 'object') ? r : { ok: true };
    if (res.ok) finishDone(); else finishFail(res);
  };
  root.getElementById('go').onclick = run;
  root.getElementById('skip').onclick = () => { try { opts.onDismiss && opts.onDismiss(); } catch (_) {} dismissPrompt(); };
  root.getElementById('x').onclick = () => { try { opts.onDismiss && opts.onDismiss(); } catch (_) {} dismissPrompt(); };

  document.documentElement.appendChild(host);
  const t = opts.timeoutMs || 20000;
  dismissTimer = setTimeout(() => { if (host) dismissPrompt(); }, t);
}

// "Save this login to Rekey?" after a successful login.
export function showSavePrompt(cred, handlers) {
  showPrompt({
    title: 'Save this login to Rekey?',
    site: cred.host,
    sub: cred.username || '(no username)',
    actionLabel: 'Save login',
    doneText: '✓ Saved to Rekey',
    onAction: handlers.onSave,
    onDismiss: handlers.onDismiss,
  });
}

// "Fill your saved login" / "Fill a new strong password".
export function showFillPrompt(opts) {
  showPrompt({
    title: opts.title,
    site: opts.site,
    sub: opts.sub,
    actionLabel: opts.actionLabel || 'Fill',
    doneText: opts.doneText || '✓ Filled',
    onAction: opts.onFill,
    onDismiss: opts.onDismiss,
  });
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
