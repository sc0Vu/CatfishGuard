'use strict';
// Service-worker tests: run src/background.js in a vm with a stubbed chrome.*
// and fetch, and check the network/caching/validation contract.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { SRC, plain } = require('./helpers');

const EXT_ID = 'cfg-test-id';
const LIST_URL = 'https://raw.githubusercontent.com/example/lists/main/blocklist.json';

function makeEnv() {
  const store = {};
  const fetches = [];
  const listeners = {};
  let responder = () => jsonResponse({ schema: 'catfishguard-blocklist', domains: ['evil.xyz'] });

  const chrome = {
    runtime: {
      id: EXT_ID,
      getURL: (p) => 'chrome-extension://' + EXT_ID + '/' + p,
      onMessage: { addListener: (fn) => { listeners.message = fn; } },
      onInstalled: { addListener: (fn) => { listeners.installed = fn; } },
      onStartup: { addListener: (fn) => { listeners.startup = fn; } },
    },
    storage: {
      local: {
        async get(keys) {
          const ks = Array.isArray(keys) ? keys : [keys];
          const out = {};
          for (const k of ks) if (k in store) out[k] = JSON.parse(JSON.stringify(store[k]));
          return out;
        },
        async set(obj) { for (const [k, v] of Object.entries(obj)) store[k] = JSON.parse(JSON.stringify(v)); },
        async remove(keys) { for (const k of [].concat(keys)) delete store[k]; },
      },
    },
  };

  async function fakeFetch(url, opts) {
    if (url.startsWith('chrome-extension://')) {
      const p = path.join(SRC, '..', url.split('/' + EXT_ID + '/')[1]);
      return jsonResponse(JSON.parse(fs.readFileSync(p, 'utf8')));
    }
    fetches.push({ url, opts });
    return responder(url, opts);
  }

  const sandbox = {
    URL, TextDecoder, AbortController, setTimeout, clearTimeout, console, Date,
    chrome, fetch: fakeFetch,
  };
  sandbox.self = sandbox;
  sandbox.importScripts = (f) => {
    vm.runInContext(fs.readFileSync(path.join(SRC, f), 'utf8'), sandbox, { filename: f });
  };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(SRC, 'background.js'), 'utf8'), sandbox, { filename: 'background.js' });

  function send(msg, senderId = EXT_ID) {
    return new Promise((resolve) => {
      const async = listeners.message(msg, { id: senderId }, resolve);
      if (!async) resolve('__not_handled__');
    });
  }

  return {
    store, fetches, send, cfg: sandbox.__cfg,
    respond(fn) { responder = fn; },
  };
}

function jsonResponse(obj, init = {}) {
  return textResponse(JSON.stringify(obj), init);
}
function textResponse(text, { status = 200, headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (h) => headers[h.toLowerCase()] ?? null },
    body: null,
    text: async () => text,
    json: async () => JSON.parse(text),
  };
}

test('URL validation: https + GitHub raw/gist only', () => {
  const { cfg } = makeEnv();
  assert.equal(cfg.validateBlocklistUrl('').ok, true);
  assert.equal(cfg.validateBlocklistUrl(LIST_URL).ok, true);
  assert.equal(cfg.validateBlocklistUrl('https://gist.githubusercontent.com/u/abc/raw/list.json').ok, true);
  for (const bad of ['http://raw.githubusercontent.com/a/b', 'https://evil.com/list.json',
    'https://raw.githubusercontent.com.evil.com/x', 'https://user:pw@raw.githubusercontent.com/x',
    'ftp://raw.githubusercontent.com/x', 'not a url', 'javascript:alert(1)']) {
    assert.equal(cfg.validateBlocklistUrl(bad).ok, false, bad);
  }
});

test('no URL configured -> no network request at all', async () => {
  const env = makeEnv();
  const res = await env.send({ type: 'cfg:match', indicators: { domains: ['evil.xyz'] } });
  await env.cfg.refresh(false);
  assert.deepEqual(plain(res.hits), []);
  assert.equal(env.fetches.length, 0);
});

test('saving a URL fetches once, with no credentials/referrer, and matching works', async () => {
  const env = makeEnv();
  const res = await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });
  assert.equal(res.ok, true);
  assert.equal(env.fetches.length, 1);
  const { opts } = env.fetches[0];
  assert.equal(opts.method, 'GET');
  assert.equal(opts.credentials, 'omit');
  assert.equal(opts.redirect, 'error');
  assert.equal(opts.referrerPolicy, 'no-referrer');
  assert.equal(opts.body, undefined);
  assert.equal(res.meta.counts.domains, 1);
  assert.equal(env.store.blocklistCache.list.domains[0], 'evil.xyz');

  const m = await env.send({ type: 'cfg:match', indicators: { domains: ['apply.evil.xyz', 'linkedin.com'] } });
  assert.deepEqual(plain(m.hits), [{ kind: 'domain', value: 'apply.evil.xyz', entry: 'evil.xyz' }]);
});

test('invalid URL is refused and nothing is fetched', async () => {
  const env = makeEnv();
  const res = await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: 'https://evil.com/x.json' } });
  assert.equal(res.ok, false);
  assert.equal(env.fetches.length, 0);
});

test('6h TTL: fresh cache is not refetched; stale cache is', async () => {
  const env = makeEnv();
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });
  await env.cfg.refresh(false);
  assert.equal(env.fetches.length, 1);
  env.store.blocklistMeta.fetchedAt = Date.now() - 7 * 3600 * 1000;
  await env.cfg.refresh(false);
  assert.equal(env.fetches.length, 2);
});

test('hostile responses are rejected and the previous cache is kept', async () => {
  const env = makeEnv();
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });

  const cases = [
    [() => textResponse('<html>not json</html>'), /not valid JSON/],
    [() => jsonResponse([1, 2, 3]), /not a JSON object/],
    [() => jsonResponse({ hello: 'world' }), /unrecognised schema/],
    [() => textResponse('{}', { status: 500 }), /HTTP 500/],
    [() => textResponse('{}', { headers: { 'content-length': String(64 * 1024 * 1024) } }), /larger than 16 MB/],
    [() => { throw new TypeError('Failed to fetch'); }, /Failed to fetch/],
  ];
  for (const [responder, err] of cases) {
    env.respond(responder);
    const r = await env.send({ type: 'cfg:refresh' });
    assert.match(r.meta.error, err);
    const m = await env.send({ type: 'cfg:match', indicators: { domains: ['evil.xyz'] } });
    assert.equal(m.hits.length, 1, 'previous list still active after ' + err);
  }
});

test('failure backoff: a failed fetch is not retried on every page load', async () => {
  const env = makeEnv();
  env.respond(() => textResponse('{}', { status: 503 }));
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });
  const n = env.fetches.length;
  await env.cfg.refresh(false);
  await env.cfg.refresh(false);
  assert.equal(env.fetches.length, n);
});

test('clearing the URL drops the cache and stops matching remote entries', async () => {
  const env = makeEnv();
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: '' } });
  assert.equal(env.store.blocklistCache, undefined);
  const m = await env.send({ type: 'cfg:match', indicators: { domains: ['evil.xyz'] } });
  assert.equal(m.hits.length, 0);
});

test('eth-phishing-detect lists work through the worker', async () => {
  const env = makeEnv();
  env.respond(() => jsonResponse({ version: 2, tolerance: 1, fuzzylist: ['metamask.io'], whitelist: [], blacklist: ['opensea.support'] }));
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });
  const m = await env.send({ type: 'cfg:match', indicators: { domains: ['opensea.support', 'metamask.com'] } });
  assert.deepEqual(plain(m.hits).map((h) => h.kind), ['domain', 'lookalike']);
});

test('messages from other extensions are ignored; enable toggle persists', async () => {
  const env = makeEnv();
  assert.equal(await env.send({ type: 'cfg:getState' }, 'someone-else'), '__not_handled__');
  await env.send({ type: 'cfg:saveSettings', settings: { enabled: false } });
  const st = await env.send({ type: 'cfg:getState' });
  assert.equal(st.settings.enabled, false);
  assert.equal(st.settings.blocklistUrl, '');
  assert.equal(env.fetches.length, 0);
});

test('a corrupted cache in storage is re-validated, not trusted', async () => {
  const env = makeEnv();
  await env.send({ type: 'cfg:saveSettings', settings: { blocklistUrl: LIST_URL } });
  // Corrupt what is on disk, then make the next update fail: the worker rebuilds
  // its matcher from the (corrupted) cache and must survive it.
  env.store.blocklistCache.list = { domains: ['evil.xyz', 42, '<img src=x>'], fuzzy: 'boom', tolerance: 1e9 };
  env.respond(() => textResponse('nope'));
  const r = await env.send({ type: 'cfg:refresh' });
  assert.match(r.meta.error, /not valid JSON/);
  const m = await env.send({ type: 'cfg:match', indicators: { domains: ['evil.xyz', 'x.com'] } });
  assert.deepEqual(plain(m.hits).map((h) => h.value), ['evil.xyz']);
});
