/*
 * CatfishGuard service worker.
 *
 * Owns the infrastructure blocklist: fetches the user-configured public list
 * (GitHub raw / gist only), validates it as hostile input, caches it in
 * chrome.storage.local (6h TTL), merges it over the bundled seed, and answers
 * "do any of these indicators match?" for the content script.
 *
 * The ONLY network request this extension makes is the GET below. It carries
 * no page content and no user data.
 */
'use strict';

importScripts('analyzer.js');
const A = self.HRScam;

const DEFAULT_SETTINGS = Object.freeze({ enabled: true, blocklistUrl: '', photoSearch: true });
const TTL_MS = 6 * 60 * 60 * 1000;
const FAIL_BACKOFF_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 20000;
const MAX_BYTES = 16 * 1024 * 1024;
const ALLOWED_HOSTS = ['raw.githubusercontent.com', 'gist.githubusercontent.com']; // = host_permissions
const PRESETS = Object.freeze([
  {
    id: 'metamask',
    name: 'MetaMask eth-phishing-detect',
    url: 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json',
  },
]);

// ---------------------------------------------------------------------------
// storage helpers — never throw
// ---------------------------------------------------------------------------
async function storageGet(keys) {
  try { return (await chrome.storage.local.get(keys)) || {}; } catch (_) { return {}; }
}
async function storageSet(obj) {
  try { await chrome.storage.local.set(obj); return true; } catch (_) { return false; }
}
async function storageRemove(keys) {
  try { await chrome.storage.local.remove(keys); } catch (_) { /* ignore */ }
}

async function getSettings() {
  const { settings } = await storageGet('settings');
  const s = Object.assign({}, DEFAULT_SETTINGS, settings && typeof settings === 'object' ? settings : {});
  return {
    enabled: s.enabled !== false,
    blocklistUrl: typeof s.blocklistUrl === 'string' ? s.blocklistUrl : '',
    photoSearch: s.photoSearch !== false,
  };
}

function validateBlocklistUrl(input) {
  const str = String(input == null ? '' : input).trim();
  if (!str) return { ok: true, url: '' };
  if (str.length > 2048) return { ok: false, error: 'URL is too long' };
  let u;
  try { u = new URL(str); } catch (_) { return { ok: false, error: 'Not a valid URL' }; }
  if (u.protocol !== 'https:') return { ok: false, error: 'Must be an https:// URL' };
  if (!ALLOWED_HOSTS.includes(u.hostname)) {
    return { ok: false, error: 'Must be hosted on raw.githubusercontent.com or gist.githubusercontent.com' };
  }
  if (u.username || u.password) return { ok: false, error: 'URL must not contain credentials' };
  u.hash = '';
  return { ok: true, url: u.toString() };
}

// ---------------------------------------------------------------------------
// seed + cache -> matcher
// ---------------------------------------------------------------------------
let seedPromise = null;
function loadSeed() {
  if (!seedPromise) {
    seedPromise = (async () => {
      try {
        const res = await fetch(chrome.runtime.getURL('data/blocklist.seed.json'));
        const r = A.normalizeBlocklist(await res.json());
        return r.ok ? r.list : A.mergeBlocklists();
      } catch (_) {
        return A.mergeBlocklists();
      }
    })();
  }
  return seedPromise;
}

let memoryList = null;        // used when the list is too big for storage
let matcherPromise = null;

function invalidateMatcher() { matcherPromise = null; }

function getMatcher() {
  if (!matcherPromise) {
    matcherPromise = (async () => {
      const seed = await loadSeed();
      const settings = await getSettings();
      let remote = null;
      if (settings.blocklistUrl) {
        if (memoryList && memoryList.url === settings.blocklistUrl) remote = memoryList.list;
        else {
          const { blocklistCache } = await storageGet('blocklistCache');
          if (blocklistCache && blocklistCache.url === settings.blocklistUrl) remote = blocklistCache.list;
        }
      }
      // Re-validated on merge: the cache is storage we wrote, but treat it as untrusted too.
      return A.createMatcher(A.mergeBlocklists(seed, remote));
    })().catch(() => A.createMatcher(null));
  }
  return matcherPromise;
}

// ---------------------------------------------------------------------------
// fetch + validate the remote list
// ---------------------------------------------------------------------------
let inflight = null;
let inflightForced = false;

async function readCapped(res) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > MAX_BYTES) throw new Error('list is larger than 16 MB');
  if (!res.body || !res.body.getReader) {
    const t = await res.text();
    if (t.length > MAX_BYTES) throw new Error('list is larger than 16 MB');
    return t;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BYTES) { try { reader.cancel(); } catch (_) { /* ignore */ } throw new Error('list is larger than 16 MB'); }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
  return new TextDecoder('utf-8').decode(buf);
}

async function fetchList(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',          // never get bounced to a host we didn't approve
      referrerPolicy: 'no-referrer',
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const text = await readCapped(res);
    let json;
    try { json = JSON.parse(text); } catch (_) { throw new Error('not valid JSON'); }
    const r = A.normalizeBlocklist(json);
    if (!r.ok) throw new Error(r.error);
    return r.list;
  } catch (e) {
    if (e && e.name === 'AbortError') throw new Error('timed out');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** Refresh the remote list if stale (or always, with force). Never throws. */
function refresh(force) {
  if (inflight) {
    // Coalesce with a running refresh — unless this one is forced and the running
    // one isn't (it may return early as "still fresh"): then run again after it.
    if (inflightForced || !force) return inflight;
    return inflight.then(() => refresh(true));
  }
  inflightForced = !!force;
  inflight = (async () => {
    const settings = await getSettings();
    const { blocklistMeta } = await storageGet('blocklistMeta');
    const meta = blocklistMeta && typeof blocklistMeta === 'object' ? blocklistMeta : {};
    const now = Date.now();

    if (!settings.blocklistUrl) {
      memoryList = null;
      await storageRemove(['blocklistCache']);
      const m = { url: '', fetchedAt: 0, lastAttempt: 0, error: null, counts: null, sources: [] };
      await storageSet({ blocklistMeta: m });
      invalidateMatcher();
      return m;
    }

    const sameUrl = meta.url === settings.blocklistUrl;
    if (!force && sameUrl) {
      if (meta.fetchedAt && now - meta.fetchedAt < TTL_MS) return meta;
      if (meta.error && meta.lastAttempt && now - meta.lastAttempt < FAIL_BACKOFF_MS) return meta;
    }

    const next = {
      url: settings.blocklistUrl,
      fetchedAt: sameUrl ? meta.fetchedAt || 0 : 0,
      counts: sameUrl ? meta.counts || null : null,
      sources: sameUrl ? meta.sources || [] : [],
      rejected: sameUrl ? meta.rejected || 0 : 0,
      lastAttempt: now,
      error: null,
      storedInMemoryOnly: false,
    };
    try {
      const list = await fetchList(settings.blocklistUrl);
      const stored = await storageSet({ blocklistCache: { url: settings.blocklistUrl, fetchedAt: now, list } });
      memoryList = stored ? null : { url: settings.blocklistUrl, list };
      if (!stored) await storageRemove(['blocklistCache']);
      Object.assign(next, {
        fetchedAt: now,
        counts: A.countsOf(list),
        sources: list.sources,
        rejected: list.rejected,
        storedInMemoryOnly: !stored,
      });
    } catch (e) {
      // keep whatever cache we had; just record why the update failed
      next.error = String((e && e.message) || e).slice(0, 200);
      if (!sameUrl) { memoryList = null; await storageRemove(['blocklistCache']); }
    }
    await storageSet({ blocklistMeta: next });
    invalidateMatcher();
    return next;
  })().catch((e) => ({ error: String((e && e.message) || e) })).finally(() => { inflight = null; });
  return inflight;
}

// ---------------------------------------------------------------------------
// messaging
// ---------------------------------------------------------------------------
async function handle(msg) {
  switch (msg && msg.type) {
    case 'cfg:match': {
      refresh(false); // stale-while-revalidate; don't block the answer
      const m = await getMatcher();
      return { hits: m.match(msg.indicators) };
    }
    case 'cfg:getState': {
      const { blocklistMeta } = await storageGet('blocklistMeta');
      return { settings: await getSettings(), meta: blocklistMeta || null, presets: PRESETS };
    }
    case 'cfg:saveSettings': {
      const cur = await getSettings();
      const inS = (msg.settings && typeof msg.settings === 'object') ? msg.settings : {};
      const next = Object.assign({}, cur);
      if ('enabled' in inS) next.enabled = inS.enabled !== false;
      if ('photoSearch' in inS) next.photoSearch = inS.photoSearch !== false;
      if ('blocklistUrl' in inS) {
        const v = validateBlocklistUrl(inS.blocklistUrl);
        if (!v.ok) return { ok: false, error: v.error };
        next.blocklistUrl = v.url;
      }
      await storageSet({ settings: next });
      let meta = null;
      if (next.blocklistUrl !== cur.blocklistUrl) { invalidateMatcher(); meta = await refresh(true); }
      return { ok: true, settings: next, meta };
    }
    case 'cfg:refresh':
      return { ok: true, meta: await refresh(true) };
    default:
      return { error: 'unknown message' };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id) return false;
  handle(msg).then(sendResponse, (e) => sendResponse({ error: String((e && e.message) || e) }));
  return true;
});

chrome.runtime.onInstalled.addListener(async () => {
  const { settings } = await storageGet('settings');
  if (!settings) await storageSet({ settings: Object.assign({}, DEFAULT_SETTINGS) });
  refresh(false);
});

chrome.runtime.onStartup.addListener(() => { refresh(false); });

// exposed for tests (the vm sandbox reads these)
self.__cfg = { handle, refresh, validateBlocklistUrl, getMatcher, PRESETS };
