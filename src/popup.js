/* CatfishGuard popup: settings + last result for the active tab. */
'use strict';

const $ = (id) => document.getElementById(id);
const BAND_TEXT = { high: 'High risk signals', caution: 'Some risk signals', low: 'Few risk signals' };
let presets = [];

function sendBg(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (res) => resolve(chrome.runtime.lastError ? null : res || null));
    } catch (_) { resolve(null); }
  });
}

async function activeTabId() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab ? tab.id : null;
  } catch (_) { return null; }
}

async function sendTab(msg) {
  const id = await activeTabId();
  if (id == null) return null;
  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(id, msg, (res) => resolve(chrome.runtime.lastError ? null : res || null));
    } catch (_) { resolve(null); }
  });
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function showResult(res) {
  const box = $('result');
  box.textContent = '';
  box.className = '';
  if (!res) {
    box.className = 'muted';
    box.textContent = 'Not a LinkedIn page (or the page needs a reload after installing).';
    return;
  }
  if (!res.enabled) { box.className = 'muted'; box.textContent = 'Scanning is turned off.'; return; }
  if (Array.isArray(res.health) && res.health.length) {
    box.appendChild(el('p', 'small warn', 'LinkedIn\u2019s page layout may have changed. CatfishGuard can\u2019t find: ' +
      res.health.map(String).join('; ') + '. Results may be missing; seeing nothing doesn\u2019t mean it\u2019s safe.'));
  }
  const r = res.result;
  if (!r) {
    box.appendChild(el('p', 'muted', 'Nothing to score here. Open a conversation, profile or job post.'));
    return;
  }
  const head = el('div');
  head.appendChild(el('span', 'band band-' + r.band, BAND_TEXT[r.band]));
  head.appendChild(document.createTextNode(' · score ' + r.score + '/100'));
  box.appendChild(head);
  const SCOPE = {
    inbound: 'Scored messages from the other person only.',
    all: 'Scored the whole conversation (senders could not be told apart).',
    page: 'Scored the main content of this page.',
  };
  if (SCOPE[res.scope]) box.appendChild(el('p', 'small muted', SCOPE[res.scope] +
    (res.units > 1 ? ' Showing the highest of ' + res.units + ' open items.' : '')));
  if (r.custom) box.appendChild(el('p', 'small muted', 'Custom rules active.'));
  const fired = r.reasons.filter((x) => x.points !== 0 || x.category === 'counter');
  if (!fired.length) {
    box.appendChild(el('p', 'small muted', 'No risk signals matched.'));
    return;
  }
  const ul = el('ul', 'small');
  for (const x of fired) {
    const terms = x.matches.slice(0, 4).map((m) => m.term).join(', ');
    ul.appendChild(el('li', null, x.label + ' (' + (x.points > 0 ? '+' : '') + x.points + '): ' + terms +
      (x.matches.length > 4 ? ', …' : '')));
  }
  box.appendChild(ul);
}

function fmtAgo(ts) {
  if (!ts) return 'never';
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return new Date(ts).toLocaleString();
}

function showMeta(meta, settings) {
  const p = $('listStatus');
  p.className = 'small muted';
  if (!settings || !settings.blocklistUrl) {
    p.textContent = 'No list configured. Only the bundled seed is used; no network requests are made.';
    return;
  }
  if (!meta) { p.textContent = 'Not fetched yet.'; return; }
  const c = meta.counts;
  const n = c ? c.domains + c.urls + c.handles + c.wallets + c.emails : 0;
  let t = meta.fetchedAt
    ? n.toLocaleString() + ' indicators' + (c && c.fuzzy ? ' + ' + c.fuzzy + ' lookalike brands' : '') +
      ' · updated ' + fmtAgo(meta.fetchedAt)
    : 'Not fetched yet.';
  if (meta.rejected) t += ' · ' + meta.rejected.toLocaleString() + ' invalid entries ignored';
  if (meta.storedInMemoryOnly) t += ' · too large to cache, kept in memory';
  p.textContent = t;
  if (meta.error) {
    p.appendChild(document.createElement('br'));
    p.appendChild(el('span', 'err', 'Last update failed: ' + meta.error));
  }
}

async function loadState() {
  const st = await sendBg({ type: 'cfg:getState' });
  if (!st) return;
  presets = st.presets || [];
  $('enabled').checked = st.settings.enabled;
  $('photoSearch').checked = st.settings.photoSearch;
  $('url').value = st.settings.blocklistUrl;
  showMeta(st.meta, st.settings);
}

async function save(url) {
  $('save').disabled = true;
  $('listStatus').className = 'small muted';
  $('listStatus').textContent = url ? 'Fetching…' : 'Saving…';
  const res = await sendBg({ type: 'cfg:saveSettings', settings: { blocklistUrl: url } });
  $('save').disabled = false;
  if (!res || !res.ok) {
    $('listStatus').className = 'small err';
    $('listStatus').textContent = (res && res.error) || 'Could not save.';
    return;
  }
  $('url').value = res.settings.blocklistUrl;
  await loadState();
}

$('save').addEventListener('click', () => save($('url').value));
$('url').addEventListener('keydown', (e) => { if (e.key === 'Enter') save($('url').value); });
$('preset').addEventListener('click', () => {
  const p = presets.find((x) => x.id === 'metamask');
  if (p) { $('url').value = p.url; save(p.url); }
});
$('refresh').addEventListener('click', async () => {
  $('refresh').disabled = true;
  $('listStatus').textContent = 'Fetching…';
  await sendBg({ type: 'cfg:refresh' });
  $('refresh').disabled = false;
  await loadState();
});
$('enabled').addEventListener('change', async () => {
  await sendBg({ type: 'cfg:saveSettings', settings: { enabled: $('enabled').checked } });
  setTimeout(async () => showResult(await sendTab({ type: 'cfg:getResult' })), 1200);
});
$('photoSearch').addEventListener('change', () => {
  sendBg({ type: 'cfg:saveSettings', settings: { photoSearch: $('photoSearch').checked } });
});
$('customize').addEventListener('click', () => {
  try { chrome.runtime.openOptionsPage(); } catch (_) { /* ignore */ }
});
$('rescan').addEventListener('click', async () => {
  $('result').textContent = 'Scanning…';
  showResult(await sendTab({ type: 'cfg:rescan' }));
});

loadState();
sendTab({ type: 'cfg:getResult' }).then(showResult);
