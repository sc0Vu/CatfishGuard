/*
 * CatfishGuard content script (LinkedIn only).
 *
 * Extracts the visible text + links of the recruiter-relevant part of the page
 * (open conversation, profile, job post), scores it locally with HRScam, and
 * shows a non-blocking corner badge whose panel lists every signal that fired.
 *
 * Nothing leaves the browser: indicators are matched against the cached
 * blocklist by our own service worker, not by any server.
 */
(function () {
  'use strict';
  if (window.__catfishGuardLoaded) return;
  window.__catfishGuardLoaded = true;

  const A = self.HRScam;
  if (!A) return;

  const SCAN_DELAY_MS = 800;
  const NAV_POLL_MS = 1000;
  const MAX_TEXT = 100000;
  const MAX_LINKS = 500;
  // Never scan the user's own composer/draft, form fields, or our own UI.
  const EXCLUDE = [
    '[contenteditable="true"]', '[contenteditable=""]', 'textarea', 'input', 'select',
    'script', 'style', 'noscript', 'svg', '.msg-form', '.hrsc-root',
  ].join(',');

  const BAND_TEXT = {
    high: 'High risk signals',
    caution: 'Some risk signals',
    low: 'Few risk signals',
  };

  let enabled = true;
  let alive = true;
  let lastKey = '';
  let lastResult = null;
  let lastContext = null;
  let dismissedKey = null;
  let panelOpen = false;
  let scanTimer = null;
  let scanning = false;
  let lastHref = location.href;
  let ui = null;
  const hitCache = new Map();

  // -------------------------------------------------------------------------
  // safe chrome.* wrappers — the extension must never throw into the page
  // -------------------------------------------------------------------------
  function contextOk() {
    try { return !!(chrome.runtime && chrome.runtime.id); } catch (_) { return false; }
  }

  function send(msg) {
    return new Promise((resolve) => {
      if (!contextOk()) { shutdown(); resolve(null); return; }
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          if (chrome.runtime.lastError) resolve(null); else resolve(res || null);
        });
      } catch (_) { resolve(null); }
    });
  }

  async function readEnabled() {
    try {
      const { settings } = await chrome.storage.local.get('settings');
      return !(settings && settings.enabled === false);
    } catch (_) { return true; }
  }

  // -------------------------------------------------------------------------
  // extraction
  // -------------------------------------------------------------------------
  function pageContext() {
    const p = location.pathname;
    if (/^\/messaging\//.test(p)) return 'messaging';
    if (/^\/in\//.test(p)) return 'profile';
    if (/^\/jobs\//.test(p)) return 'job';
    return 'other';
  }

  function firstOf(selectors) {
    for (const s of selectors) {
      const el = document.querySelector(s);
      if (el) return el;
    }
    return null;
  }

  /** The parts of the page worth scoring. On the feed and elsewhere we only
   *  look at open message overlays — scoring the whole feed would just be noise. */
  function scanRoots() {
    const ctx = pageContext();
    const roots = [];
    let main = null;
    if (ctx === 'messaging') main = firstOf(['.msg-s-message-list', '.msg-thread', '.scaffold-layout__detail', 'main']);
    else if (ctx === 'profile') main = firstOf(['main']);
    else if (ctx === 'job') {
      main = firstOf(['.jobs-search__job-details--container', '.jobs-details', '.job-view-layout',
        '.jobs-description', 'main']);
    }
    if (main) roots.push(main);
    document.querySelectorAll('.msg-overlay-conversation-bubble').forEach((b) => {
      if (!b.classList.contains('msg-overlay-conversation-bubble--is-minimized')) roots.push(b);
    });
    // drop roots nested inside another root
    return { ctx, roots: roots.filter((r, i) => !roots.some((o, j) => j !== i && o !== r && o.contains(r))) };
  }

  function extract(roots) {
    const parts = [];
    let len = 0;
    const links = [];
    for (const root of roots) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
        acceptNode(n) {
          if (n.nodeType === 1) return n.matches(EXCLUDE) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_SKIP;
          return NodeFilter.FILTER_ACCEPT;
        },
      });
      let node;
      while ((node = walker.nextNode()) && len < MAX_TEXT) {
        const t = node.nodeValue;
        if (t && t.trim()) { parts.push(t); len += t.length + 1; }
      }
      const anchors = root.querySelectorAll('a[href]');
      for (let i = 0; i < anchors.length && links.length < MAX_LINKS; i++) {
        const a = anchors[i];
        if (a.closest(EXCLUDE)) continue;
        if (/^(https?|mailto):/i.test(a.href)) links.push(a.href);
      }
    }
    return { text: parts.join(' ').slice(0, MAX_TEXT), links };
  }

  function hash(s) {
    let h = 5381;
    for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
    return (h >>> 0).toString(36) + ':' + s.length;
  }

  async function blocklistHits(indicators) {
    const key = JSON.stringify(indicators);
    if (hitCache.has(key)) return hitCache.get(key);
    const res = await send({ type: 'cfg:match', indicators });
    const hits = res && Array.isArray(res.hits) ? res.hits : [];
    if (res) {
      if (hitCache.size > 100) hitCache.clear();
      hitCache.set(key, hits);
    }
    return hits;
  }

  // -------------------------------------------------------------------------
  // scanning
  // -------------------------------------------------------------------------
  async function scan(force) {
    if (!alive || scanning) return lastResult;
    scanning = true;
    try {
      if (!enabled) { removeUI(); lastResult = null; lastKey = ''; return null; }
      const { ctx, roots } = scanRoots();
      const { text, links } = extract(roots);
      if (!text.trim() && !links.length) {
        removeUI(); lastResult = null; lastKey = ''; lastContext = ctx;
        return null;
      }
      const key = hash(ctx + '\u0000' + text + '\u0000' + links.join('\n'));
      if (!force && key === lastKey && lastResult) return lastResult;
      const hits = await blocklistHits(A.extractIndicators(text, links));
      const result = A.analyze(text, links, { blocklistHits: hits });
      lastKey = key;
      lastResult = result;
      lastContext = ctx;
      render(result, key);
      return result;
    } catch (_) {
      return lastResult; // never throw into the page
    } finally {
      scanning = false;
    }
  }

  function scheduleScan() {
    if (scanTimer || !alive) return; // coalesce bursts of mutations
    scanTimer = setTimeout(() => { scanTimer = null; scan(false); }, SCAN_DELAY_MS);
  }

  // -------------------------------------------------------------------------
  // UI — injected, non-blocking, hrsc- prefixed, built with textContent only
  // -------------------------------------------------------------------------
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function removeUI() {
    if (ui && ui.parentNode) ui.parentNode.removeChild(ui);
    ui = null;
  }

  function render(result, key) {
    if (dismissedKey && dismissedKey === key) { removeUI(); return; }
    dismissedKey = null;
    if (!ui || !ui.isConnected) {
      ui = el('div', 'hrsc-root');
      ui.setAttribute('role', 'status');
      ui.setAttribute('aria-live', 'polite');
      (document.body || document.documentElement).appendChild(ui);
    }
    ui.textContent = '';
    ui.dataset.band = result.band;

    const badge = el('button', 'hrsc-badge hrsc-band-' + result.band);
    badge.type = 'button';
    badge.setAttribute('aria-expanded', String(panelOpen));
    badge.title = 'CatfishGuard: click to see which signals fired';
    badge.appendChild(el('span', 'hrsc-dot'));
    badge.appendChild(el('span', 'hrsc-badge-text', BAND_TEXT[result.band] + ' · ' + result.score));
    badge.addEventListener('click', () => { panelOpen = !panelOpen; render(result, key); });
    ui.appendChild(badge);

    if (!panelOpen) return;

    const panel = el('div', 'hrsc-panel');
    const head = el('div', 'hrsc-head');
    head.appendChild(el('div', 'hrsc-title', 'CatfishGuard · ' + BAND_TEXT[result.band]));
    const close = el('button', 'hrsc-x', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close panel');
    close.addEventListener('click', () => { panelOpen = false; render(result, key); });
    head.appendChild(close);
    panel.appendChild(head);

    panel.appendChild(el('p', 'hrsc-sub',
      'Score ' + result.score + '/100. These are risk signals and a prompt to look closer, not a verdict about this person.'));

    if (!result.reasons.length) {
      panel.appendChild(el('p', 'hrsc-empty', 'No risk signals matched on this page.'));
    } else {
      const list = el('ul', 'hrsc-reasons');
      for (const r of result.reasons) {
        const li = el('li', 'hrsc-reason hrsc-cat-' + r.category);
        const row = el('div', 'hrsc-reason-row');
        row.appendChild(el('span', 'hrsc-reason-label', r.label));
        row.appendChild(el('span', 'hrsc-points', (r.points > 0 ? '+' : '') + r.points));
        li.appendChild(row);
        const chips = el('div', 'hrsc-chips');
        for (const m of r.matches.slice(0, 12)) {
          chips.appendChild(el('span', 'hrsc-chip', m.count > 1 ? m.term + ' ×' + m.count : m.term));
        }
        if (r.matches.length > 12) chips.appendChild(el('span', 'hrsc-chip', '+' + (r.matches.length - 12) + ' more'));
        li.appendChild(chips);
        if (r.note) li.appendChild(el('div', 'hrsc-note', r.note));
        list.appendChild(li);
      }
      panel.appendChild(list);
    }

    panel.appendChild(el('p', 'hrsc-tip',
      'Before acting: verify the recruiter through the company’s own website, and never enter keys, codes, ' +
      'logins or ID documents on a page reached from a message.'));

    const foot = el('div', 'hrsc-foot');
    const hide = el('button', 'hrsc-link', 'Hide for this content');
    hide.type = 'button';
    hide.addEventListener('click', () => { dismissedKey = key; panelOpen = false; removeUI(); });
    foot.appendChild(hide);
    panel.appendChild(foot);
    ui.appendChild(panel);
  }

  // -------------------------------------------------------------------------
  // wiring
  // -------------------------------------------------------------------------
  let observer = null;
  let navTimer = null;

  function shutdown() {
    alive = false;
    try { if (observer) observer.disconnect(); } catch (_) { /* ignore */ }
    clearInterval(navTimer);
    clearTimeout(scanTimer);
    removeUI();
  }

  function onMutations(muts) {
    for (const m of muts) {
      const t = m.target.nodeType === 1 ? m.target : m.target.parentElement;
      if (!t || !t.closest || !t.closest('.hrsc-root')) { scheduleScan(); return; }
    }
  }

  try {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (!msg || !sender || sender.id !== chrome.runtime.id) return false;
      if (msg.type === 'cfg:getResult') {
        sendResponse({ result: lastResult, context: lastContext, enabled });
        return false;
      }
      if (msg.type === 'cfg:rescan') {
        hitCache.clear();
        dismissedKey = null;
        scan(true).then((r) => sendResponse({ result: r, context: lastContext, enabled }));
        return true;
      }
      return false;
    });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      if (changes.settings) {
        const s = changes.settings.newValue;
        enabled = !(s && s.enabled === false);
        lastKey = '';
        if (!enabled) removeUI();
        scheduleScan();
      }
      if (changes.blocklistMeta) { hitCache.clear(); lastKey = ''; scheduleScan(); }
    });
  } catch (_) { /* context gone */ }

  observer = new MutationObserver(onMutations);
  observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });

  // LinkedIn is an SPA: catch route changes the observer might not.
  navTimer = setInterval(() => {
    if (!contextOk()) { shutdown(); return; }
    if (location.href !== lastHref) {
      lastHref = location.href;
      panelOpen = false;
      dismissedKey = null;
      scheduleScan();
    }
  }, NAV_POLL_MS);

  readEnabled().then((on) => { enabled = on; scan(false); });
})();
