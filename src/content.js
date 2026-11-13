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
  // Give LinkedIn time to render after a navigation before calling a missing
  // selector a layout change.
  const HEALTH_GRACE_MS = 5000;
  const MAX_FLAGGED = 50;

  // LinkedIn selectors in one place — when LinkedIn changes its DOM, fix here.
  const SEL = {
    threadList: '.msg-s-message-list',
    // The list sits in a flex *column-reverse* container (verified on live
    // LinkedIn, 2026-11): a banner placed next to the list would render at the
    // bottom, by the composer. Anchor the banner before this container instead.
    listContainer: '.msg-s-message-list-container',
    event: '.msg-s-event-listitem',
    inboundClass: 'msg-s-event-listitem--other',
    overlay: '.msg-overlay-conversation-bubble',
    overlayMinClass: 'msg-overlay-conversation-bubble--is-minimized', // unverified
    // Verified live (2026-11): the open chat popup's header button carries
    // aria-expanded="true" while expanded — a sturdier signal than the class.
    overlayExpandBtn: '.msg-overlay-conversation-bubble__expand-btn',
    // /messaging/ page rows are <li>; the bottom-corner messaging-list popup
    // (.msg-overlay-list-bubble) uses div rows with a "--v2" class (live, 2026-11).
    convoItem: '.msg-conversation-listitem, .msg-conversations-container__convo-item, .msg-overlay-list-bubble__convo-item--v2',
    convoSnippet: '.msg-conversation-card__message-snippet, .msg-conversation-card__message-snippet-body, ' +
      '.msg-overlay-list-bubble__message-snippet--v2',
    // Live list rows (2026-11) carry no thread link — the open row is marked by
    // this class instead. The href lookup stays as a cheap fallback.
    convoActive: '.msg-conversations-container__convo-item-link--active',
    // Row title (both the /messaging/ list and the corner list popup, live 2026-11)
    // and the sender name inside each message group. Rows have no thread id, so
    // a scored conversation is matched back to its row by these names.
    convoNames: '.msg-conversation-listitem__participant-names, .msg-conversation-card__participant-names',
    senderName: '.msg-s-message-group__name',
    // On the feed (live, 2026-11) LinkedIn renders its chat popups and the
    // messaging list inside the shadow root of this host, so document-level
    // queries never see them. Direct children of <body> with a shadow root are
    // also searched, in case the host is renamed.
    shadowHosts: '#interop-outlet',
    eventPhoto: 'img.msg-s-event-listitem__profile-picture', // inside each event (live, 2026-11)
    convoLink: 'a[href*="/messaging/thread/"]',
    threadProfileLink: '.msg-thread__link-to-profile',
    jobRoots: ['.jobs-search__job-details--container', '.jobs-details', '.job-view-layout', '.jobs-description', 'main'],
    messagingFallback: ['.msg-thread', '.scaffold-layout__detail', 'main'],
  };
  const WATCHED_CLASSES = [SEL.inboundClass, SEL.overlayMinClass];
  const OWN_UI = '.hrsc-root, .hrsc-banner-root, .hrsc-listdot, .hrsc-style';
  // Never scan the user's own composer/draft, form fields, or our own UI.
  const EXCLUDE = [
    '[contenteditable="true"]', '[contenteditable=""]', 'textarea', 'input', 'select',
    'script', 'style', 'noscript', 'svg', '.msg-form', OWN_UI,
    // LinkedIn chrome inside each message: hover menus (emoji reactions,
    // "Reply to this message") and screen-reader duplicates. Not message text.
    '.msg-s-event-listitem__actions-container', '.a11y-text',
  ].join(',');

  const BAND_RANK = { low: 0, caution: 1, high: 2 };
  const BAND_TEXT = { high: 'High risk signals', caution: 'Some risk signals', low: 'Few risk signals' };
  const BAND_SHORT = { high: 'High', caution: 'Caution', low: 'Low' };
  const SCOPE_TEXT = {
    inbound: 'Scored: messages from the other person only.',
    all: 'Scored: the whole conversation (could not tell who sent which message).',
    page: 'Scored: the main content of this page.',
  };

  let enabled = true;
  let photoSearch = true;
  let overrides = null; // the user's local rule tuning (validated inside the analyzer)
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
  // hash(sender names) -> {band, why}: lets a row keep its conversation's full
  // score after you leave it. Memory only (this tab), never stored, never sent;
  // only a hash of the visible name is kept, never the name itself.
  const nameBands = new Map();
  const MAX_NAME_BANDS = 200;
  // "Conversations with risk signals in this tab" (corner panel). Memory only:
  // gone on reload, never stored or sent. Holds the display name LinkedIn shows
  // so the user can find the conversation again; never labels the person.
  const flagged = new Map(); // namesKey -> {name, band, score, why, source}
  let health = [];           // parts of LinkedIn's page we expected but could not find
  let healthTimer = null;
  let navAt = Date.now();

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

  // -------------------------------------------------------------------------
  // document + LinkedIn's shadow roots
  // -------------------------------------------------------------------------
  function openShadow(el) {
    try {
      if (chrome.dom && chrome.dom.openOrClosedShadowRoot) return chrome.dom.openOrClosedShadowRoot(el) || null;
    } catch (_) { /* fall through */ }
    return el.shadowRoot || null;
  }

  function shadowHosts() {
    const hosts = new Set(document.querySelectorAll(SEL.shadowHosts));
    if (document.body) for (const c of document.body.children) if (openShadow(c)) hosts.add(c);
    return Array.from(hosts);
  }

  /** The document first, then every shadow root we can open. */
  function roots() {
    const out = [document];
    for (const h of shadowHosts()) { const r = openShadow(h); if (r) out.push(r); }
    return out;
  }

  function qsa(sel) {
    const out = [];
    for (const r of roots()) r.querySelectorAll(sel).forEach((e) => out.push(e));
    return out;
  }

  function qs(sel) {
    for (const r of roots()) { const e = r.querySelector(sel); if (e) return e; }
    return null;
  }

  function firstOf(selectors) {
    for (const s of selectors) {
      const e = qs(s);
      if (e) return e;
    }
    return null;
  }

  // Our stylesheet is injected into the document only; UI placed inside a
  // shadow root (banner in a chat popup, list dots) needs its own copy.
  let cssPromise = null;
  const rootSheets = new WeakMap(); // shadow root -> CSSStyleSheet | <style>
  const observedRoots = new WeakSet();

  function styleRoot(root) {
    const have = rootSheets.get(root);
    if (have) {
      // LinkedIn may reassign adoptedStyleSheets; put ours back if it went
      if (have instanceof CSSStyleSheet && !root.adoptedStyleSheets.includes(have)) {
        try { root.adoptedStyleSheets = root.adoptedStyleSheets.concat([have]); } catch (_) { /* ignore */ }
      }
      return;
    }
    rootSheets.set(root, true);
    if (!cssPromise) cssPromise = send({ type: 'cfg:css' }).then((r) => (r && typeof r.css === 'string' ? r.css : ''));
    cssPromise.then((css) => {
      if (!css) { rootSheets.delete(root); cssPromise = null; return; }
      try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(css);
        root.adoptedStyleSheets = root.adoptedStyleSheets.concat([sheet]);
        rootSheets.set(root, sheet);
      } catch (_) {
        try {
          const st = document.createElement('style');
          st.className = 'hrsc-style';
          st.textContent = css;
          root.appendChild(st);
          rootSheets.set(root, st);
        } catch (_e) { rootSheets.delete(root); }
      }
    });
  }

  /** Watch and style every shadow root we can reach (hosts can appear late). */
  function attachRoots() {
    for (const r of roots()) {
      if (r === document) continue;
      styleRoot(r);
      if (observer && !observedRoots.has(r)) {
        try { observer.observe(r, OBSERVE_OPTS); observedRoots.add(r); } catch (_) { /* ignore */ }
      }
    }
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

  /** Order-insensitive key for a set of display names ("A, B" == "B, A"). */
  function namesKey(names) {
    const set = new Set();
    for (const n of names) {
      for (const part of String(n).split(/\s*[,，、]\s*|\s+and\s+/)) {
        const t = part.replace(/\s+/g, ' ').trim().toLowerCase();
        if (t) set.add(t);
      }
    }
    return set.size ? hash(Array.from(set).sort().join('\u0000')) : null;
  }

  const cleanName = (t) => String(t || '').replace(/\s+/g, ' ').trim().slice(0, 120);

  /** {key, name} of the other people in a conversation unit, from inbound message groups. */
  function senderInfo(unit) {
    if (unit.kind === 'page') return null;
    const names = [];
    unit.root.querySelectorAll(SEL.event + '.' + SEL.inboundClass + ' ' + SEL.senderName)
      .forEach((n) => { const t = cleanName(n.textContent); if (t && !names.includes(t)) names.push(t); });
    const key = namesKey(names);
    return key ? { key, name: names.join(', ') } : null;
  }

  /** Track a conversation with risk signals. A full conversation score is
   *  authoritative; a list preview only adds or raises an entry. */
  function noteFlag(key, name, band, score, why, source) {
    const cur = flagged.get(key);
    if (band === 'low') {
      if (cur && (source === 'conversation' || cur.source === 'preview')) flagged.delete(key);
      return;
    }
    if (cur && cur.source === 'conversation' && source === 'preview') {
      // keep the conversation entry; a worse newer preview only raises it
      if (BAND_RANK[band] > BAND_RANK[cur.band]) Object.assign(cur, { band, score, why: 'newest message: ' + why });
      return;
    }
    if (!cur && flagged.size >= MAX_FLAGGED) {
      // drop the mildest entry to make room
      let drop = null;
      for (const [k, v] of flagged) if (!drop || BAND_RANK[v.band] < BAND_RANK[drop[1].band]) drop = [k, v];
      if (drop && BAND_RANK[drop[1].band] <= BAND_RANK[band]) flagged.delete(drop[0]); else return;
    }
    flagged.set(key, { name, band, score, why, source });
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
      const list = qs(SEL.threadList);
      const threadId = threadIdFromHref(location.pathname);
      // No id in the URL: key the unit by the other party's profile link so an
      // in-memory dismissal can't leak onto the next thread. Memory only.
      const prof = threadId ? null : qs(SEL.threadProfileLink);
      const key = threadId || (prof ? 'p' + hash(prof.getAttribute('href') || '') : 'current');
      if (list) out.push({ uid: 'thread:' + key, kind: 'thread', root: list, host: bannerAnchor(list), threadId });
      else page(firstOf(SEL.messagingFallback));
    } else if (ctx === 'profile') {
      page(qs('main'));
    } else if (ctx === 'job') {
      page(firstOf(SEL.jobRoots));
    }
    qsa(SEL.overlay).forEach((b) => {
      if (overlayMinimized(b)) return;
      // Only score a popup that shows a conversation; without a message list
      // all we'd read is header chrome ("Minimize your conversation with …").
      const list = b.querySelector(SEL.threadList);
      if (!list) return;
      if (!overlayIds.has(b)) overlayIds.set(b, ++overlaySeq);
      out.push({ uid: 'overlay:' + overlayIds.get(b), kind: 'overlay', root: list, host: bannerAnchor(list), bubble: b });
    });
    // a unit nested inside another is already covered by the outer one
    const units = out.filter((u, i) => !out.some((o, j) => j !== i && o.root !== u.root && o.root.contains(u.root)));
    return { ctx, units };
  }

  function overlayMinimized(b) {
    if (b.classList.contains(SEL.overlayMinClass)) return true;
    const btn = b.querySelector(SEL.overlayExpandBtn);
    return !!btn && btn.getAttribute('aria-expanded') === 'false';
  }

  function bannerAnchor(list) {
    return list.closest(SEL.listContainer) || list;
  }

  /** Inbound-only nodes for a conversation, when the DOM marks senders. */
  // -------------------------------------------------------------------------
  // reverse image search (roadmap #3): links only, nothing is sent unless the
  // user clicks; only LinkedIn's own image host is ever offered.
  // -------------------------------------------------------------------------
  const PHOTO_SEARCH = [
    { name: 'Google Lens', url: (src) => 'https://lens.google.com/uploadbyurl?url=' + encodeURIComponent(src) },
    { name: 'TinEye', url: (src) => 'https://tineye.com/search?url=' + encodeURIComponent(src) },
  ];

  function licdnPhoto(img) {
    if (!img || !img.getAttribute) return null;
    const src = img.currentSrc || img.src || '';
    let u;
    try { u = new URL(src); } catch (_) { return null; }
    if (u.protocol !== 'https:' || !/(^|\.)licdn\.com$/.test(u.hostname)) return null;
    return /profile-(?:display|framed)photo/.test(u.pathname) ? u.href : null;
  }

  /** The other person's photo for a conversation (verified live: the avatar
   *  inside a --other event), or the largest profile photo on a profile page. */
  function findPhoto(u, scope) {
    if (u.kind === 'page') {
      if (pageContext() !== 'profile') return null;
      let best = null;
      let bestArea = 0;
      u.root.querySelectorAll('img').forEach((img) => {
        const src = licdnPhoto(img);
        if (!src || img.closest(OWN_UI)) return;
        const r = img.getBoundingClientRect();
        const area = r.width * r.height;
        if (area > bestArea) { best = src; bestArea = area; }
      });
      return best;
    }
    if (scope !== 'inbound') return null; // can't tell whose face it is
    for (const ev of u.root.querySelectorAll(SEL.event + '.' + SEL.inboundClass)) {
      const src = licdnPhoto(ev.querySelector(SEL.eventPhoto));
      if (src) return src;
    }
    return null;
  }

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
      result = A.analyze(text, links, { blocklistHits: hits, overrides });
      if (unitCache.size > 50) unitCache.clear();
      unitCache.set(u.uid, { key, result });
    }
    if (u.threadId) sessionBands.set(u.threadId, { band: result.band, why: summary(result) });
    const who = senderInfo(u);
    if (who) {
      if (nameBands.size >= MAX_NAME_BANDS && !nameBands.has(who.key)) nameBands.clear();
      nameBands.set(who.key, { band: result.band, why: summary(result) });
      noteFlag(who.key, who.name, result.band, result.score, summary(result), 'conversation');
    }
    return Object.assign({}, u, { key, result, scope, photo: findPhoto(u, scope) });
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
      attachRoots();
      const { ctx, units } = findUnits();
      lastContext = ctx;
      const next = [];
      for (const u of units) {
        const r = await scanUnit(u);
        if (r) next.push(r);
      }
      scanned = next;
      health = checkHealth(ctx, scanned);
      renderBanners();
      renderListDots();
      renderCorner();
      return worst();
    } catch (_) {
      return worst(); // never throw into the page
    } finally {
      scanning = false;
      if (rescanQueued) { rescanQueued = false; scheduleScan(); }
    }
  }

  /**
   * What we expected to find on LinkedIn's page but could not. LinkedIn changes
   * its markup without notice; when that breaks a selector the extension would
   * otherwise go quiet, which looks exactly like "no risk signals". Say so.
   */
  function checkHealth(ctx, units) {
    const wait = HEALTH_GRACE_MS - (Date.now() - navAt);
    if (wait > 0) {
      // too soon after a navigation to judge; look again once it has settled
      if (!healthTimer) healthTimer = setTimeout(() => { healthTimer = null; scheduleScan(); }, wait + 100);
      return [];
    }
    const out = [];
    if (ctx === 'messaging') {
      const rows = qsa(SEL.convoItem);
      if (!rows.length) out.push('the conversation list');
      else if (!qs(SEL.convoNames)) out.push('names in the conversation list');
      if (threadIdFromHref(location.pathname) && !qs(SEL.threadList)) {
        out.push('the messages of the open conversation');
      }
    }
    for (const u of units) {
      if (u.kind === 'page') continue;
      const events = u.root.querySelectorAll(SEL.event);
      if (!events.length) {
        // an empty new chat has no messages; text without message markup is the break
        if (u.root.textContent.trim().length > 40) out.push('individual messages in a conversation');
        continue;
      }
      const inbound = u.root.querySelectorAll(SEL.event + '.' + SEL.inboundClass);
      if (inbound.length && !u.root.querySelector(SEL.senderName)) out.push('sender names in a conversation');
    }
    return Array.from(new Set(out));
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
    qsa('.hrsc-banner-root').forEach((b) => { if (!live.has(b)) b.remove(); });
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
    const items = qsa(SEL.convoItem);
    for (let i = 0; i < items.length && i < MAX_LIST_ITEMS; i++) {
      const item = items[i];
      const snip = item.querySelector(SEL.convoSnippet);
      const link = item.querySelector(SEL.convoLink);
      const tid = link ? threadIdFromHref(link.getAttribute('href')) : null;
      let band = 'low';
      let why = '';
      let full = tid && sessionBands.get(tid);
      if (!full && item.querySelector(SEL.convoActive)) {
        const open = scanned.find((u) => u.kind === 'thread');
        if (open) full = { band: open.result.band, why: summary(open.result) };
      }
      const nm = item.querySelector(SEL.convoNames);
      const rowName = nm ? cleanName(nm.textContent) : '';
      const nk = rowName ? namesKey([rowName]) : null;
      // A conversation scored earlier in this tab, matched by the row's names.
      if (!full && nk) full = nameBands.get(nk);
      let preview = null;
      if (snip) {
        const t = snippetText(snip);
        // "You: …" previews are the user's own words — never score them.
        if (t && !/^you\s*:/i.test(t)) preview = A.analyze(t, [], { overrides });
      }
      if (full) {
        band = full.band;
        why = 'opened conversation: ' + full.why;
      }
      // A newer preview can only raise the dot (new messages since it was opened).
      if (preview && (!full || BAND_RANK[preview.band] > BAND_RANK[band])) {
        band = preview.band;
        why = 'message preview: ' + summary(preview);
      }
      if (nk && preview) noteFlag(nk, rowName, preview.band, preview.score, summary(preview), 'preview');
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
    qsa('.hrsc-banner-root, .hrsc-listdot').forEach((n) => n.remove());
  }

  function renderCorner() {
    const w = worst();
    // A layout problem keeps the corner up even when nothing could be scored:
    // silence would look exactly like "no risk signals".
    const cKey = w ? w.key + (health.length ? '|h' : '') : (health.length ? 'health:' + health.join('|') : null);
    if (!cKey) { removeCorner(); panelUid = null; return; }
    if (cornerDismissedKey && cornerDismissedKey === cKey && !panelOpen) { removeCorner(); return; }
    if (cornerDismissedKey && cornerDismissedKey !== cKey) cornerDismissedKey = null;
    const shown = w && ((panelUid && scanned.find((u) => u.uid === panelUid)) || w);
    const r = shown ? shown.result : null;
    const band = w ? w.result.band : 'low';

    if (!corner || !corner.isConnected) {
      corner = el('div', 'hrsc-root');
      corner.setAttribute('role', 'status');
      corner.setAttribute('aria-live', 'polite');
      (document.body || document.documentElement).appendChild(corner);
    }
    corner.textContent = '';
    corner.dataset.band = band;

    const badge = el('button', 'hrsc-badge hrsc-band-' + band);
    badge.type = 'button';
    badge.setAttribute('aria-expanded', String(panelOpen));
    badge.title = health.length
      ? 'CatfishGuard: LinkedIn\u2019s page layout may have changed; click for details'
      : 'CatfishGuard: click to see which signals fired';
    badge.appendChild(el('span', 'hrsc-dot'));
    badge.appendChild(el('span', 'hrsc-badge-text',
      w ? BAND_TEXT[band] + ' · ' + w.result.score : 'Can\u2019t read this page'));
    if (health.length) badge.appendChild(el('span', 'hrsc-warnmark', '!'));
    badge.addEventListener('click', () => { panelOpen = !panelOpen; if (!panelOpen) panelUid = null; renderCorner(); });
    corner.appendChild(badge);

    if (!panelOpen) return;

    const panel = el('div', 'hrsc-panel');
    const head = el('div', 'hrsc-head');
    head.appendChild(el('div', 'hrsc-title', r ? 'CatfishGuard · ' + BAND_TEXT[r.band] : 'CatfishGuard'));
    const close = el('button', 'hrsc-x', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close panel');
    close.addEventListener('click', () => { panelOpen = false; panelUid = null; renderCorner(); });
    head.appendChild(close);
    panel.appendChild(head);

    if (health.length) {
      const box = el('div', 'hrsc-health');
      box.appendChild(el('div', 'hrsc-health-title', 'LinkedIn\u2019s page layout may have changed'));
      box.appendChild(el('div', 'hrsc-note', 'CatfishGuard can\u2019t find: ' + health.join('; ') +
        '. Scores, banners and dots may be missing or incomplete until the extension is updated. ' +
        'Seeing nothing here does not mean a conversation is safe.'));
      panel.appendChild(box);
    }
    if (r) renderResult(panel, shown, r, w);
    renderFlagged(panel);

    panel.appendChild(el('p', 'hrsc-tip',
      'Before acting: verify the recruiter through the company’s own website, and never enter keys, codes, ' +
      'logins or ID documents on a page reached from a message.'));

    const foot = el('div', 'hrsc-foot');
    const hide = el('button', 'hrsc-link', 'Hide for this content');
    hide.type = 'button';
    hide.addEventListener('click', () => { cornerDismissedKey = cKey; panelOpen = false; panelUid = null; removeCorner(); });
    foot.appendChild(hide);
    panel.appendChild(foot);
    corner.appendChild(panel);
  }

  function renderResult(panel, shown, r, w) {
    panel.appendChild(el('p', 'hrsc-sub',
      'Score ' + r.score + '/100. These are risk signals and a prompt to look closer, not a verdict about this person.'));
    panel.appendChild(el('p', 'hrsc-scope', SCOPE_TEXT[shown.scope] +
      (scanned.length > 1 ? ' Showing the ' + (shown === w ? 'highest-scoring' : 'selected') + ' of ' + scanned.length + ' open items.' : '')));
    if (r.custom) panel.appendChild(el('p', 'hrsc-scope', 'Custom rules active (from your CatfishGuard settings).'));

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

    if (photoSearch && shown.photo) {
      const box = el('div', 'hrsc-photo');
      const thumb = el('img', 'hrsc-photo-thumb');
      thumb.src = shown.photo;
      thumb.alt = '';
      thumb.referrerPolicy = 'no-referrer';
      box.appendChild(thumb);
      const body = el('div', 'hrsc-photo-body');
      const row = el('div', 'hrsc-photo-row', 'Check this photo elsewhere: ');
      PHOTO_SEARCH.forEach((s, i) => {
        if (i) row.appendChild(document.createTextNode(' · '));
        const a = el('a', 'hrsc-link hrsc-photo-link', s.name);
        a.href = s.url(shown.photo);
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.referrerPolicy = 'no-referrer';
        a.title = 'Opens ' + s.name + ' in a new tab and shares only this photo\u2019s link with it';
        row.appendChild(a);
      });
      body.appendChild(row);
      body.appendChild(el('div', 'hrsc-note',
        'Only shared if you click. No match proves nothing (AI-generated faces match nothing); ' +
        'the same face under a different name is worth a closer look.'));
      box.appendChild(body);
      panel.appendChild(box);
    }
  }

  /** Find the list row for a flagged conversation by its displayed names. */
  function rowForKey(key) {
    for (const item of qsa(SEL.convoItem)) {
      const nm = item.querySelector(SEL.convoNames);
      if (nm && namesKey([cleanName(nm.textContent)]) === key) return item;
    }
    return null;
  }

  function renderFlagged(panel) {
    if (!flagged.size) return;
    const entries = Array.from(flagged.entries())
      .sort((a, b) => BAND_RANK[b[1].band] - BAND_RANK[a[1].band] || b[1].score - a[1].score);
    const box = el('div', 'hrsc-flagged');
    box.appendChild(el('div', 'hrsc-flagged-title', 'Conversations with risk signals in this tab (' + entries.length + ')'));
    const ul = el('ul', 'hrsc-flagged-list');
    for (const [key, f] of entries) {
      const li = el('li', 'hrsc-flagged-item');
      li.appendChild(el('span', 'hrsc-listdot hrsc-listdot-' + f.band));
      const body = el('div', 'hrsc-flagged-body');
      const row = el('div', 'hrsc-reason-row');
      row.appendChild(el('span', 'hrsc-flagged-name', f.name));
      row.appendChild(el('span', 'hrsc-points', BAND_SHORT[f.band] +
        (f.source === 'conversation' ? ' · ' + f.score : ' · preview')));
      body.appendChild(row);
      body.appendChild(el('div', 'hrsc-note', f.why));
      const item = rowForKey(key);
      if (item) {
        const go = el('button', 'hrsc-link', 'Show in list');
        go.type = 'button';
        go.addEventListener('click', () => {
          try { item.scrollIntoView({ block: 'center', behavior: 'smooth' }); } catch (_) { /* ignore */ }
        });
        body.appendChild(go);
      }
      li.appendChild(body);
      ul.appendChild(li);
    }
    box.appendChild(ul);
    box.appendChild(el('div', 'hrsc-note', 'Kept only until this tab is reloaded; never saved or sent. ' +
      'Each entry lists risk signals in what was said, not a judgement about the person.'));
    panel.appendChild(box);
  }

  // -------------------------------------------------------------------------
  // wiring
  // -------------------------------------------------------------------------
  let observer = null;
  let navTimer = null;
  const OBSERVE_OPTS = {
    childList: true, subtree: true, characterData: true,
    attributes: true, attributeFilter: ['class', 'aria-expanded'], attributeOldValue: true,
  };

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
        if (m.attributeName === 'aria-expanded') {
          if (t.matches(SEL.overlayExpandBtn)) { scheduleScan(); return; }
          continue;
        }
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
    return { result: w ? w.result : null, scope: w ? w.scope : null, units: scanned.length, context: lastContext, enabled,
      health: health.slice(), flagged: flagged.size };
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
        photoSearch = !(s && s.photoSearch === false);
        renderCorner();
        unitCache.clear();
        if (!enabled) teardownUI();
        scheduleScan();
      }
      if (changes.blocklistMeta) { hitCache.clear(); unitCache.clear(); scheduleScan(); }
      if (changes.overrides) {
        const v = changes.overrides.newValue;
        overrides = v && typeof v === 'object' ? v : null;
        unitCache.clear();
        scheduleScan();
      }
      if (changes.dismissedThreads) { dismissedThreads = cleanDismissed(changes.dismissedThreads.newValue); renderBanners(); }
    });
  } catch (_) { /* context gone */ }

  observer = new MutationObserver(onMutations);
  observer.observe(document.documentElement, OBSERVE_OPTS);
  attachRoots();

  // LinkedIn is an SPA: catch route changes the observer might not.
  navTimer = setInterval(() => {
    if (!contextOk()) { shutdown(); return; }
    if (location.href !== lastHref) {
      lastHref = location.href;
      navAt = Date.now();
      panelOpen = false;
      panelUid = null;
      cornerDismissedKey = null;
      scheduleScan();
    }
  }, NAV_POLL_MS);

  storageGet(['settings', 'dismissedThreads', 'overrides']).then(({ settings, dismissedThreads: d, overrides: ov }) => {
    overrides = ov && typeof ov === 'object' ? ov : null;
    enabled = !(settings && settings.enabled === false);
    photoSearch = !(settings && settings.photoSearch === false);
    dismissedThreads = cleanDismissed(d);
    scan(false);
  });
})();
