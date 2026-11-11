/*
 * CatfishGuard content script (LinkedIn only).
 *
 * Scores each "unit" separately — the open conversation, each open message
 * overlay, or the profile/job page — from its visible text + links, locally.
 *
 * UI, proportional to band and never blocking:
 *  - a thin banner pinned above each open conversation (caution/high only),
 *    dismissible per conversation; re-appears only if the band escalates;
 *  - dots in the conversation list for triage (caution/high only);
 *  - the corner badge + reason panel as the always-available fallback.
 *
 * In conversations, only messages from the other person are scored when the
 * DOM lets us tell senders apart, so the user's own words can't trip keywords.
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
  const MAX_LIST_ITEMS = 100;
  const MAX_DISMISSED = 500;

  // LinkedIn selectors in one place — when LinkedIn changes its DOM, fix here.
  const SEL = {
    threadList: '.msg-s-message-list',
    event: '.msg-s-event-listitem',
    inboundClass: 'msg-s-event-listitem--other',
    overlay: '.msg-overlay-conversation-bubble',
    overlayMinClass: 'msg-overlay-conversation-bubble--is-minimized',
    convoItem: '.msg-conversation-listitem, .msg-conversations-container__convo-item',
    convoSnippet: '.msg-conversation-card__message-snippet, .msg-conversation-card__message-snippet-body',
    convoLink: 'a[href*="/messaging/thread/"]',
    jobRoots: ['.jobs-search__job-details--container', '.jobs-details', '.job-view-layout', '.jobs-description', 'main'],
    messagingFallback: ['.msg-thread', '.scaffold-layout__detail', 'main'],
  };
  const WATCHED_CLASSES = [SEL.inboundClass, SEL.overlayMinClass];
  const OWN_UI = '.hrsc-root, .hrsc-banner-root, .hrsc-listdot';
  // Never scan the user's own composer/draft, form fields, or our own UI.
  const EXCLUDE = [
    '[contenteditable="true"]', '[contenteditable=""]', 'textarea', 'input', 'select',
    'script', 'style', 'noscript', 'svg', '.msg-form', OWN_UI,
  ].join(',');

  const BAND_RANK = { low: 0, caution: 1, high: 2 };
  const BAND_TEXT = { high: 'High risk signals', caution: 'Some risk signals', low: 'Few risk signals' };
  const SCOPE_TEXT = {
    inbound: 'Scored: messages from the other person only.',
    all: 'Scored: the whole conversation (could not tell who sent which message).',
    page: 'Scored: the main content of this page.',
  };

  let enabled = true;
  let alive = true;
  let scanning = false;
  let rescanQueued = false;
  let scanTimer = null;
  let lastHref = location.href;
  let lastContext = null;

  let scanned = [];              // [{uid, kind, key, result, scope, host, threadId, bubble}]
  const unitCache = new Map();   // uid -> {key, result}
  const hitCache = new Map();    // indicators json -> hits
  const overlayIds = new WeakMap();
  let overlaySeq = 0;
  const overlayDismissed = new WeakMap(); // bubble element -> band (memory only)
  const memDismissed = new Map();         // uid -> band (threads without an id)
  let dismissedThreads = {};               // hash(threadId) -> {band, at}; on-device only
  const sessionBands = new Map();          // threadId -> {band, why}; memory only, for list dots

  let corner = null;
  let panelOpen = false;
  let panelUid = null;
  let cornerDismissedKey = null;

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

  async function storageGet(keys) {
    try { return (await chrome.storage.local.get(keys)) || {}; } catch (_) { return {}; }
  }
  async function storageSet(obj) {
    try { await chrome.storage.local.set(obj); } catch (_) { /* ignore */ }
  }

  function cleanDismissed(v) {
    const out = {};
    if (!v || typeof v !== 'object') return out;
    for (const [k, d] of Object.entries(v).slice(0, MAX_DISMISSED)) {
      if (typeof k === 'string' && k.length < 40 && d && BAND_RANK[d.band] != null && Number.isFinite(d.at)) {
        out[k] = { band: d.band, at: d.at };
      }
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------
  function hash(s) {
    let h = 5381;
    for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
    return (h >>> 0).toString(36) + ':' + s.length;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function firstOf(selectors) {
    for (const s of selectors) {
      const e = document.querySelector(s);
      if (e) return e;
    }
    return null;
  }

  function pageContext() {
    const p = location.pathname;
    if (/^\/messaging\//.test(p)) return 'messaging';
    if (/^\/in\//.test(p)) return 'profile';
    if (/^\/jobs\//.test(p)) return 'job';
    return 'other';
  }

  function threadIdFromHref(href) {
    const m = String(href || '').match(/\/messaging\/thread\/([^/?#]+)/);
    return m ? m[1] : null;
  }

  function summary(result) {
    const labels = result.reasons.filter((r) => r.points > 0).slice(0, 2).map((r) => r.label);
    return labels.length ? labels.join('; ') : 'no signals';
  }

  // -------------------------------------------------------------------------
  // units + extraction
  // -------------------------------------------------------------------------
  function findUnits() {
    const ctx = pageContext();
    const out = [];
    const page = (root) => root && out.push({ uid: 'page:' + location.pathname, kind: 'page', root });

    if (ctx === 'messaging') {
      const list = document.querySelector(SEL.threadList);
      const threadId = threadIdFromHref(location.pathname);
      if (list) out.push({ uid: 'thread:' + (threadId || 'current'), kind: 'thread', root: list, host: list, threadId });
      else page(firstOf(SEL.messagingFallback));
    } else if (ctx === 'profile') {
      page(document.querySelector('main'));
    } else if (ctx === 'job') {
      page(firstOf(SEL.jobRoots));
    }
    document.querySelectorAll(SEL.overlay).forEach((b) => {
      if (b.classList.contains(SEL.overlayMinClass)) return;
      if (!overlayIds.has(b)) overlayIds.set(b, ++overlaySeq);
      const list = b.querySelector(SEL.threadList);
      out.push({ uid: 'overlay:' + overlayIds.get(b), kind: 'overlay', root: list || b, host: list, bubble: b });
    });
    // a unit nested inside another is already covered by the outer one
    const units = out.filter((u, i) => !out.some((o, j) => j !== i && o.root !== u.root && o.root.contains(u.root)));
    return { ctx, units };
  }

  /** Inbound-only nodes for a conversation, when the DOM marks senders. */
  function scopeNodes(unit) {
    if (unit.kind === 'page') return { scope: 'page', nodes: [unit.root] };
    const events = Array.from(unit.root.querySelectorAll(SEL.event));
    const inbound = events.filter((e) => e.classList.contains(SEL.inboundClass));
    if (inbound.length) return { scope: 'inbound', nodes: inbound };
    return { scope: 'all', nodes: [unit.root] };
  }

  function extract(nodes) {
    const parts = [];
    let len = 0;
    const links = [];
    for (const root of nodes) {
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

  async function scanUnit(u) {
    const { scope, nodes } = scopeNodes(u);
    const { text, links } = extract(nodes);
    if (!text.trim() && !links.length) return null;
    const key = hash(u.kind + '\u0000' + scope + '\u0000' + text + '\u0000' + links.join('\n'));
    const cached = unitCache.get(u.uid);
    let result;
    if (cached && cached.key === key) {
      result = cached.result;
    } else {
      const hits = await blocklistHits(A.extractIndicators(text, links));
      result = A.analyze(text, links, { blocklistHits: hits });
      if (unitCache.size > 50) unitCache.clear();
      unitCache.set(u.uid, { key, result });
    }
    if (u.threadId) sessionBands.set(u.threadId, { band: result.band, why: summary(result) });
    return Object.assign({}, u, { key, result, scope });
  }

  function worst() {
    let w = null;
    for (const u of scanned) {
      if (!w || BAND_RANK[u.result.band] > BAND_RANK[w.result.band] ||
        (u.result.band === w.result.band && u.result.score > w.result.score)) w = u;
    }
    return w;
  }

  // -------------------------------------------------------------------------
  // scanning
  // -------------------------------------------------------------------------
  async function scan(force) {
    if (!alive) return null;
    if (scanning) { rescanQueued = true; return worst(); }
    scanning = true;
    try {
      if (!enabled) { teardownUI(); scanned = []; return null; }
      if (force) { unitCache.clear(); hitCache.clear(); }
      const { ctx, units } = findUnits();
      lastContext = ctx;
      const next = [];
      for (const u of units) {
        const r = await scanUnit(u);
        if (r) next.push(r);
      }
      scanned = next;
      renderBanners();
      renderCorner();
      renderListDots();
      return worst();
    } catch (_) {
      return worst(); // never throw into the page
    } finally {
      scanning = false;
      if (rescanQueued) { rescanQueued = false; scheduleScan(); }
    }
  }

  function scheduleScan() {
    if (scanTimer || !alive) return; // coalesce bursts of mutations
    scanTimer = setTimeout(() => { scanTimer = null; scan(false); }, SCAN_DELAY_MS);
  }

  // -------------------------------------------------------------------------
  // conversation banner
  // -------------------------------------------------------------------------
  function dismissedBand(u) {
    if (u.kind === 'thread' && u.threadId) {
      const d = dismissedThreads[hash(u.threadId)];
      return d ? d.band : null;
    }
    if (u.kind === 'overlay' && u.bubble) return overlayDismissed.get(u.bubble) || null;
    return memDismissed.get(u.uid) || null;
  }

  function isDismissed(u) {
    const d = dismissedBand(u);
    return d != null && BAND_RANK[u.result.band] <= BAND_RANK[d]; // escalation re-shows
  }

  function dismiss(u) {
    const band = u.result.band;
    if (u.kind === 'thread' && u.threadId) {
      dismissedThreads[hash(u.threadId)] = { band, at: Date.now() };
      const keys = Object.keys(dismissedThreads);
      if (keys.length > MAX_DISMISSED) {
        keys.sort((a, b) => dismissedThreads[a].at - dismissedThreads[b].at)
          .slice(0, keys.length - MAX_DISMISSED).forEach((k) => delete dismissedThreads[k]);
      }
      storageSet({ dismissedThreads });
    } else if (u.kind === 'overlay' && u.bubble) {
      overlayDismissed.set(u.bubble, band);
    } else {
      memDismissed.set(u.uid, band);
    }
    renderBanners();
  }

  function existingBanner(host) {
    const p = host.previousElementSibling;
    return p && p.classList.contains('hrsc-banner-root') ? p : null;
  }

  function stop(e) { e.stopPropagation(); }

  function buildBanner(u) {
    const r = u.result;
    const root = el('div', 'hrsc-banner-root');
    root.setAttribute('role', 'status');
    root.addEventListener('click', stop);
    const bar = el('div', 'hrsc-banner hrsc-banner-' + r.band);
    bar.appendChild(el('span', 'hrsc-banner-dot'));
    const txt = el('span', 'hrsc-banner-text');
    txt.appendChild(el('strong', null, BAND_TEXT[r.band] + ' in this conversation'));
    txt.appendChild(el('span', 'hrsc-banner-why', ' · ' + summary(r)));
    bar.appendChild(txt);
    const why = el('button', 'hrsc-banner-btn', 'Why?');
    why.type = 'button';
    why.addEventListener('click', (e) => { stop(e); panelUid = u.uid; panelOpen = true; cornerDismissedKey = null; renderCorner(); });
    bar.appendChild(why);
    const x = el('button', 'hrsc-banner-btn hrsc-banner-x', 'Dismiss');
    x.type = 'button';
    x.setAttribute('aria-label', 'Dismiss for this conversation');
    x.addEventListener('click', (e) => { stop(e); dismiss(u); });
    bar.appendChild(x);
    root.appendChild(bar);
    return root;
  }

  function renderBanners() {
    const live = new Set();
    for (const u of scanned) {
      if (!u.host || !u.host.parentNode) continue;
      let b = existingBanner(u.host);
      if (u.result.band === 'low' || isDismissed(u)) { if (b) b.remove(); continue; }
      const sig = u.uid + '|' + u.key + '|' + u.result.band;
      if (b && b.dataset.sig === sig) { live.add(b); continue; }
      const nb = buildBanner(u);
      nb.dataset.sig = sig;
      if (b) b.replaceWith(nb); else u.host.parentNode.insertBefore(nb, u.host);
      live.add(nb);
    }
    document.querySelectorAll('.hrsc-banner-root').forEach((b) => { if (!live.has(b)) b.remove(); });
  }

  // -------------------------------------------------------------------------
  // conversation-list dots (triage)
  // -------------------------------------------------------------------------
  function snippetText(node) {
    let t = '';
    node.childNodes.forEach((c) => {
      if (c.nodeType === 3) t += c.nodeValue;
      else if (c.nodeType === 1 && !c.matches(OWN_UI)) t += c.textContent;
    });
    return t.trim();
  }

  function renderListDots() {
    const items = document.querySelectorAll(SEL.convoItem);
    for (let i = 0; i < items.length && i < MAX_LIST_ITEMS; i++) {
      const item = items[i];
      const snip = item.querySelector(SEL.convoSnippet);
      const link = item.querySelector(SEL.convoLink);
      const tid = link ? threadIdFromHref(link.getAttribute('href')) : null;
      let band = 'low';
      let why = '';
      const full = tid && sessionBands.get(tid);
      if (full) {
        band = full.band;
        why = 'opened conversation: ' + full.why;
      } else if (snip) {
        const t = snippetText(snip);
        // "You: …" previews are the user's own words — never score them.
        if (t && !/^you\s*:/i.test(t)) {
          const r = A.analyze(t, []);
          band = r.band;
          why = 'message preview: ' + summary(r);
        }
      }
      let dot = item.querySelector('.hrsc-listdot');
      if (band === 'low') { if (dot) dot.remove(); continue; }
      const sig = band + '|' + why;
      if (dot && dot.dataset.sig === sig) continue;
      if (!dot) {
        dot = el('span', 'hrsc-listdot');
        dot.setAttribute('role', 'img');
        const host = snip || item;
        host.insertBefore(dot, host.firstChild);
      }
      dot.className = 'hrsc-listdot hrsc-listdot-' + band;
      dot.dataset.sig = sig;
      const label = 'CatfishGuard: ' + BAND_TEXT[band].toLowerCase() + ' (' + why + ')';
      dot.title = label;
      dot.setAttribute('aria-label', label);
    }
  }

  // -------------------------------------------------------------------------
  // corner badge + panel (fallback, and where "Why?" opens)
  // -------------------------------------------------------------------------
  function removeCorner() {
    if (corner && corner.parentNode) corner.parentNode.removeChild(corner);
    corner = null;
  }

  function teardownUI() {
    removeCorner();
    document.querySelectorAll('.hrsc-banner-root, .hrsc-listdot').forEach((n) => n.remove());
  }

  function renderCorner() {
    const w = worst();
    if (!w) { removeCorner(); panelUid = null; return; }
    if (cornerDismissedKey && cornerDismissedKey === w.key && !panelOpen) { removeCorner(); return; }
    if (cornerDismissedKey && cornerDismissedKey !== w.key) cornerDismissedKey = null;
    const shown = (panelUid && scanned.find((u) => u.uid === panelUid)) || w;
    const r = shown.result;

    if (!corner || !corner.isConnected) {
      corner = el('div', 'hrsc-root');
      corner.setAttribute('role', 'status');
      corner.setAttribute('aria-live', 'polite');
      (document.body || document.documentElement).appendChild(corner);
    }
    corner.textContent = '';
    corner.dataset.band = w.result.band;

    const badge = el('button', 'hrsc-badge hrsc-band-' + w.result.band);
    badge.type = 'button';
    badge.setAttribute('aria-expanded', String(panelOpen));
    badge.title = 'CatfishGuard: click to see which signals fired';
    badge.appendChild(el('span', 'hrsc-dot'));
    badge.appendChild(el('span', 'hrsc-badge-text', BAND_TEXT[w.result.band] + ' · ' + w.result.score));
    badge.addEventListener('click', () => { panelOpen = !panelOpen; if (!panelOpen) panelUid = null; renderCorner(); });
    corner.appendChild(badge);

    if (!panelOpen) return;

    const panel = el('div', 'hrsc-panel');
    const head = el('div', 'hrsc-head');
    head.appendChild(el('div', 'hrsc-title', 'CatfishGuard · ' + BAND_TEXT[r.band]));
    const close = el('button', 'hrsc-x', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close panel');
    close.addEventListener('click', () => { panelOpen = false; panelUid = null; renderCorner(); });
    head.appendChild(close);
    panel.appendChild(head);

    panel.appendChild(el('p', 'hrsc-sub',
      'Score ' + r.score + '/100. These are risk signals and a prompt to look closer, not a verdict about this person.'));
    panel.appendChild(el('p', 'hrsc-scope', SCOPE_TEXT[shown.scope] +
      (scanned.length > 1 ? ' Showing the ' + (shown === w ? 'highest-scoring' : 'selected') + ' of ' + scanned.length + ' open items.' : '')));

    if (!r.reasons.length) {
      panel.appendChild(el('p', 'hrsc-empty', 'No risk signals matched.'));
    } else {
      const list = el('ul', 'hrsc-reasons');
      for (const x of r.reasons) {
        const li = el('li', 'hrsc-reason hrsc-cat-' + x.category);
        const row = el('div', 'hrsc-reason-row');
        row.appendChild(el('span', 'hrsc-reason-label', x.label));
        row.appendChild(el('span', 'hrsc-points', (x.points > 0 ? '+' : '') + x.points));
        li.appendChild(row);
        const chips = el('div', 'hrsc-chips');
        for (const m of x.matches.slice(0, 12)) {
          chips.appendChild(el('span', 'hrsc-chip', m.count > 1 ? m.term + ' ×' + m.count : m.term));
        }
        if (x.matches.length > 12) chips.appendChild(el('span', 'hrsc-chip', '+' + (x.matches.length - 12) + ' more'));
        li.appendChild(chips);
        if (x.note) li.appendChild(el('div', 'hrsc-note', x.note));
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
    hide.addEventListener('click', () => { cornerDismissedKey = w.key; panelOpen = false; panelUid = null; removeCorner(); });
    foot.appendChild(hide);
    panel.appendChild(foot);
    corner.appendChild(panel);
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
    try { teardownUI(); } catch (_) { /* ignore */ }
  }

  const isOwn = (n) => n.nodeType === 1 && n.matches(OWN_UI);

  /** Ignore mutations caused purely by our own UI, so rendering can't loop. */
  function onMutations(muts) {
    for (const m of muts) {
      const t = m.target.nodeType === 1 ? m.target : m.target.parentElement;
      if (t && t.closest && t.closest(OWN_UI)) continue;
      if (m.type === 'attributes') {
        // LinkedIn churns classes constantly (hover, focus…); only react when a
        // class we key on flips — e.g. an overlay is (un)minimised.
        if (!t) continue;
        const had = String(m.oldValue || '').split(/\s+/);
        const watched = WATCHED_CLASSES.some((c) => had.includes(c) !== t.classList.contains(c));
        if (!watched) continue;
      }
      if (m.type === 'childList') {
        const nodes = [...m.addedNodes, ...m.removedNodes];
        if (nodes.length && nodes.every(isOwn)) continue;
      }
      scheduleScan();
      return;
    }
  }

  function publicResult() {
    const w = worst();
    return { result: w ? w.result : null, scope: w ? w.scope : null, units: scanned.length, context: lastContext, enabled };
  }

  try {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (!msg || !sender || sender.id !== chrome.runtime.id) return false;
      if (msg.type === 'cfg:getResult') {
        sendResponse(publicResult());
        return false;
      }
      if (msg.type === 'cfg:rescan') {
        cornerDismissedKey = null;
        scan(true).then(() => sendResponse(publicResult()));
        return true;
      }
      return false;
    });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      if (changes.settings) {
        const s = changes.settings.newValue;
        enabled = !(s && s.enabled === false);
        unitCache.clear();
        if (!enabled) teardownUI();
        scheduleScan();
      }
      if (changes.blocklistMeta) { hitCache.clear(); unitCache.clear(); scheduleScan(); }
      if (changes.dismissedThreads) { dismissedThreads = cleanDismissed(changes.dismissedThreads.newValue); renderBanners(); }
    });
  } catch (_) { /* context gone */ }

  observer = new MutationObserver(onMutations);
  observer.observe(document.documentElement, {
    childList: true, subtree: true, characterData: true,
    attributes: true, attributeFilter: ['class'], attributeOldValue: true,
  });

  // LinkedIn is an SPA: catch route changes the observer might not.
  navTimer = setInterval(() => {
    if (!contextOk()) { shutdown(); return; }
    if (location.href !== lastHref) {
      lastHref = location.href;
      panelOpen = false;
      panelUid = null;
      cornerDismissedKey = null;
      scheduleScan();
    }
  }, NAV_POLL_MS);

  storageGet(['settings', 'dismissedThreads']).then(({ settings, dismissedThreads: d }) => {
    enabled = !(settings && settings.enabled === false);
    dismissedThreads = cleanDismissed(d);
    scan(false);
  });
})();
