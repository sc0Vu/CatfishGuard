#!/usr/bin/env node
'use strict';
/*
 * End-to-end test in real Chrome.
 *
 * - Serves fake https://www.linkedin.com and https://raw.githubusercontent.com
 *   from a local HTTPS server (self-signed cert + --host-resolver-rules).
 * - Loads the unpacked extension via CDP Extensions.loadUnpacked (branded
 *   Chrome no longer honours --load-extension).
 * - Drives fixture pages and asserts on the injected badge/panel, plus logs
 *   every request so we can prove nothing but the blocklist GET goes out.
 *
 * Usage: node test/e2e/run.js   (env CHROME=/path/to/chrome to override)
 * Needs: Chrome 126+, openssl on PATH.
 */
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const assert = require('assert/strict');

const ROOT = path.resolve(__dirname, '..', '..');
const FIX = path.join(__dirname, 'fixtures');
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const SHOT_DIR = process.env.CFG_SHOTS || null;
const LIST_PATH = '/catfishguard-test/lists/main/blocklist.json';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cfg-e2e-'));
const requests = [];

// --------------------------------------------------------------------------
// local HTTPS "linkedin" + "github raw"
// --------------------------------------------------------------------------
function makeCert() {
  const key = path.join(tmp, 'key.pem');
  const cert = path.join(tmp, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=cfg-e2e',
    '-addext', 'subjectAltName=DNS:www.linkedin.com,DNS:raw.githubusercontent.com,DNS:media.licdn.com',
    '-keyout', key, '-out', cert], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

let blocklistBody = JSON.stringify({ schema: 'catfishguard-blocklist', domains: ['careers-acme.xyz'], handles: [] });

function startServer() {
  const server = https.createServer(makeCert(), (req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push({ host: req.headers.host, method: req.method, url: req.url, headers: req.headers, body });
      const host = (req.headers.host || '').split(':')[0];
      if (host === 'raw.githubusercontent.com' && req.url === LIST_PATH) {
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        return res.end(blocklistBody);
      }
      if (host === 'media.licdn.com') { // profile photos the page itself loads
        res.writeHead(200, { 'content-type': 'image/png' });
        return res.end(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64'));
      }
      if (host === 'www.linkedin.com') {
        const name = req.url.startsWith('/messaging/thread/2-zh') ? 'messaging-zh.html'
          : req.url.startsWith('/messaging/') ? 'messaging.html'
          : req.url.startsWith('/in/') ? 'profile-legit.html'
          : req.url.startsWith('/feed/zh-popup') ? 'feed-overlay-zh.html'
            : req.url.startsWith('/feed') ? 'feed.html' : null;
        if (name) {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'set-cookie': 'li_at=SECRET; Path=/; Secure' });
          return res.end(fs.readFileSync(path.join(FIX, name)));
        }
      }
      res.writeHead(404); res.end('nf');
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
}

// --------------------------------------------------------------------------
// minimal CDP client over --remote-debugging-pipe
// --------------------------------------------------------------------------
function launchChrome(port) {
  const proc = spawn(CHROME, [
    '--headless=new', '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
    '--user-data-dir=' + path.join(tmp, 'profile'), '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-features=OptimizationHints,MediaRouter,Translate',
    '--host-resolver-rules=MAP www.linkedin.com 127.0.0.1:' + port + ',MAP raw.githubusercontent.com 127.0.0.1:' + port + ',MAP media.licdn.com 127.0.0.1:' + port +
      ',EXCLUDE localhost',
    '--ignore-certificate-errors', '--window-size=1280,900', 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  const out = proc.stdio[3];
  const inp = proc.stdio[4];
  let buf = '';
  let id = 0;
  const pending = new Map();
  const eventWaiters = [];
  inp.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let i;
    while ((i = buf.indexOf('\0')) >= 0) {
      const msg = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message + ' ' + (msg.error.data || ''))) : resolve(msg.result);
      } else if (msg.method) {
        for (const w of eventWaiters.slice()) if (w.test(msg)) { eventWaiters.splice(eventWaiters.indexOf(w), 1); w.resolve(msg); }
      }
    }
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const m = { id: ++id, method, params };
    if (sessionId) m.sessionId = sessionId;
    pending.set(m.id, { resolve, reject });
    out.write(JSON.stringify(m) + '\0');
  });
  const waitEvent = (test, ms = 10000) => new Promise((resolve, reject) => {
    const w = { test, resolve };
    eventWaiters.push(w);
    setTimeout(() => reject(new Error('timeout waiting for event')), ms);
  });
  return { proc, send, waitEvent };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const server = await startServer();
  const port = server.address().port;
  const { proc, send, waitEvent } = launchChrome(port);
  const results = [];
  const check = async (name, fn) => {
    try { await fn(); results.push(['ok', name]); console.log('ok   ' + name); }
    catch (e) { results.push(['FAIL', name, e]); console.log('FAIL ' + name + '\n     ' + e.message.split('\n').join('\n     ')); }
  };

  try {
    const { id: extId } = await send('Extensions.loadUnpacked', { path: ROOT });
    console.log('loaded extension ' + extId);

    async function openPage(url) {
      const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
      await send('Page.enable', {}, sessionId);
      await send('Runtime.enable', {}, sessionId);
      const loaded = waitEvent((m) => m.method === 'Page.loadEventFired' && m.sessionId === sessionId);
      await send('Page.navigate', { url }, sessionId);
      await loaded;
      const evaluate = async (expr) => {
        const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }, sessionId);
        if (r.exceptionDetails) throw new Error('page eval: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
        return r.result.value;
      };
      const waitFor = async (expr, ms = 8000) => {
        const t0 = Date.now();
        for (;;) {
          const v = await evaluate(expr);
          if (v) return v;
          if (Date.now() - t0 > ms) throw new Error('timed out waiting for: ' + expr);
          await sleep(150);
        }
      };
      const shot = async (name) => {
        if (!SHOT_DIR) return;
        const { data } = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
        fs.mkdirSync(SHOT_DIR, { recursive: true });
        fs.writeFileSync(path.join(SHOT_DIR, name + '.png'), Buffer.from(data, 'base64'));
      };
      const close = () => send('Target.closeTarget', { targetId });
      return { evaluate, waitFor, shot, close, sessionId };
    }

    const badge = `(() => { const b = document.querySelector('.hrsc-root .hrsc-badge'); return b && b.textContent; })()`;
    const panelText = `(() => { const p = document.querySelector('.hrsc-panel'); return p && p.innerText; })()`;
    const scoreOf = (t) => Number((t || '').split('·').pop().trim());

    // ---------------------------------------------------------------- scans
    const banner = `(() => { const b = document.querySelector('.hrsc-banner-root'); return b && b.innerText; })()`;
    const dots = `(() => [...document.querySelectorAll('.msg-conversation-listitem')].map((li) => {
      const d = li.querySelector('.hrsc-listdot'); return d ? d.className.replace('hrsc-listdot ', '') : '-'; }).join(','))()`;
    const inbound = (html) => `(() => {
      const li = document.createElement('li');
      li.className = 'msg-s-event-listitem msg-s-event-listitem--other';
      li.innerHTML = '<div class="msg-s-event-listitem__body">' + ${JSON.stringify(html)} + '</div>';
      document.querySelector('.msg-s-message-list ul').appendChild(li);
    })()`;
    const own = (html) => inbound(html).replace(' msg-s-event-listitem--other', '');

    let msgPage;
    await check('thread: hand-derived score 68, scored from inbound messages only', async () => {
      msgPage = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      const t = await msgPage.waitFor(badge);
      // inbound only: web3 5 + toogood ($900/day, no experience needed) 20 + offplatform 30 + urgent 8
      // + linkrisk 5 (the redirect-wrapped link lands on a cheap .xyz domain) = 68.
      // The user's own reply (passport copy, seed phrase, registration fee) must add nothing.
      assert.equal(scoreOf(t), 68, t);
      assert.match(t, /High risk signals/);
    });

    await check('panel lists the reasons, states the scope, never says "scammer"', async () => {
      await msgPage.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const p = await msgPage.waitFor(panelText);
      for (const s of ['Pushes the conversation off LinkedIn', 'telegram', '$900/day', 'not a verdict',
        'messages from the other person only']) {
        assert.ok(p.includes(s), 'panel missing "' + s + '":\n' + p);
      }
      assert.doesNotMatch(p, /scammer/i);
      assert.doesNotMatch(p, /passport|seed phrase|private key|registration fee/i, "user's own words leaked into the score");
      await msgPage.evaluate(`document.querySelector('.hrsc-x').click()`);
    });

    await check('banner is pinned above the open conversation, assertive on high', async () => {
      const b = await msgPage.waitFor(banner);
      assert.match(b, /High risk signals in this conversation/);
      assert.match(b, /Pushes the conversation off LinkedIn/);
      const pos = await msgPage.evaluate(`(() => {
        const r = document.querySelector('.hrsc-banner-root');
        const list = document.querySelector('.msg-s-message-list');
        return { before: r.nextElementSibling.classList.contains('msg-s-message-list-container'),
          inside: !!r.closest('.msg-s-message-list-container'),
          above: r.getBoundingClientRect().bottom <= list.getBoundingClientRect().top + 1 };
      })()`);
      // live LinkedIn reverses the list container's flex column, so the banner must sit outside it
      assert.deepEqual(pos, { before: true, inside: false, above: true });
      await msgPage.shot('1-thread-banner');
    });

    await check('conversation list dots: open thread high, risky preview caution, legit/own none', async () => {
      // 2-abc: full score of the open thread (high) · 3-def preview: whatsapp + add me on 30, registration fee 15 = 45
      // 4-ghi: counter only -> low (no dot) · 5-jkl: "You: …" preview is the user's own -> never scored
      const d = await msgPage.waitFor(`(() => { const d = ${dots}; return d.startsWith('hrsc-listdot-high') ? d : null; })()`);
      // 5th row is LinkedIn's empty off-screen placeholder -> no dot, no crash
      assert.equal(d, 'hrsc-listdot-high,hrsc-listdot-caution,-,-,-');
      const activeTitle = await msgPage.evaluate(`document.querySelector('.hrsc-listdot').title`);
      assert.match(activeTitle, /opened conversation/, 'open row should use the full thread score, not its preview');
      const title = await msgPage.evaluate(`document.querySelectorAll('.hrsc-listdot')[1].title`);
      assert.match(title, /some risk signals \(message preview: /);
    });

    await check('a scored conversation keeps its dot after you leave it (matched by sender name, memory only)', async () => {
      const p = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await p.waitFor(`(() => { const d = ${dots}; return d.startsWith('hrsc-listdot-high') ? d : null; })()`);
      // Leave the conversation: no open row, no message list. Jane's preview alone scores low.
      await p.evaluate(`(() => {
        document.querySelector('.msg-conversations-container__convo-item-link--active')
          .classList.remove('msg-conversations-container__convo-item-link--active');
        document.querySelector('.msg-s-message-list-container').remove();
      })()`);
      const d = await p.waitFor(`(() => document.querySelector('.msg-s-message-list') ? null :
        document.querySelector('.hrsc-root .hrsc-badge') && ${dots})()`);
      assert.equal(d, 'hrsc-listdot-high,hrsc-listdot-caution,-,-,-');
      assert.match(await p.evaluate(`document.querySelector('.hrsc-listdot').title`), /opened conversation/);
      // The corner panel lists conversations with risk signals seen in this tab.
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const list = await p.waitFor(`(() => { const f = document.querySelector('.hrsc-flagged'); return f && f.innerText; })()`);
      // Jane: the full conversation (68, high) first; Sam: risky list preview only (caution)
      assert.match(list, /Conversations with risk signals in this tab \(2\)/);
      assert.match(list, /Jane \(fixture\)\s+High · 68[\s\S]*Sam \(fixture\)\s+Caution · preview/);
      assert.doesNotMatch(list, /Priya|Alex/, 'low-scoring and own-preview rows are not listed');
      assert.doesNotMatch(list, /scammer|suspicious/i);
      await p.evaluate(`document.querySelector('.hrsc-flagged').scrollIntoView()`);
      await p.shot('2b-flagged-list');
      await p.close();
    });

    await check('layout check: quiet on a healthy page, warns when LinkedIn markup goes missing', async () => {
      const p = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await p.waitFor(badge);
      await sleep(5600); // past the post-navigation grace period
      assert.equal(await p.evaluate(`!!document.querySelector('.hrsc-warnmark')`), false, 'false layout alarm on the fixture');
      // Simulate a LinkedIn redesign: list rows and sender names re-rendered under new class names.
      await p.evaluate(`(() => {
        const rename = (sel, from, to) => document.querySelectorAll(sel).forEach((n) => {
          n.outerHTML = n.outerHTML.split(from).join(to); });
        rename('.msg-conversation-listitem', 'msg-conversation', 'renamed-conversation');
        rename('.msg-s-message-group__name', 'msg-s-message-group__name', 'renamed-name');
      })()`);
      await p.waitFor(`!!document.querySelector('.hrsc-warnmark')`);
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const h = await p.waitFor(`(() => { const b = document.querySelector('.hrsc-health'); return b && b.innerText; })()`);
      assert.match(h, /page layout may have changed/);
      assert.match(h, /the conversation list; sender names in a conversation/);
      assert.match(h, /does not mean a conversation is safe/);
      await p.shot('4-layout-warning');
      await p.close();
    });

    await check('live-structure zh thread: inbound-only, CJK terms, fake-interview pattern -> 38 (caution)', async () => {
      const zh = await openPage('https://www.linkedin.com/messaging/thread/2-zh/');
      const t = await zh.waitFor(badge);
      // inbound only: crypto 区块链 5 + pressure 会议中等你 8 + devlure github 账号 10 + pattern 15 = 38.
      // The user's own replies (incl. the company link they posted) add nothing.
      assert.equal(scoreOf(t), 38, t);
      await zh.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const p = await zh.waitFor(panelText);
      assert.match(p, /区块链/);
      assert.match(p, /会议中等你/);
      assert.match(p, /messages from the other person only/);
      assert.match(p, /Matches a known fake-interview pattern/);
      const b = await zh.waitFor(banner);
      assert.match(b, /Some risk signals in this conversation/);
      await zh.shot('0-live-zh-caution');
      await zh.close();
    });

    await check('brand impersonation in a live thread: lookalike link + claimed employer mismatch', async () => {
      const p = await openPage('https://www.linkedin.com/messaging/thread/6-imp/');
      await p.waitFor(badge);
      await p.evaluate(`(() => {
        document.querySelector('.msg-s-message-list ul').innerHTML =
          '<li class="msg-s-event-listitem msg-s-event-listitem--other"><p class="msg-s-event-listitem__body">' +
          'Hi! I\\'m a recruiter at Coinbase. Please apply here: ' +
          '<a href="https://coinbase-careers.com/apply">coinbase-careers.com/apply</a></p></li>';
      })()`);
      // impersonation: contains "Coinbase" 35 + claims Coinbase but links elsewhere 15 = 50 (caution)
      const t = await p.waitFor(`(() => { const t = ${badge}; return t && /· 50$/.test(t) ? t : null; })()`);
      assert.equal(scoreOf(t), 50);
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const text = await p.waitFor(panelText);
      assert.match(text, /Links or claims that imitate a known brand/);
      assert.match(text, /coinbase-careers\.com contains "Coinbase"/);
      assert.match(text, /claims to recruit for Coinbase/);
      await p.shot('7-impersonation');
      await p.close();
    });

    const PHOTO = (tag, size) => 'https://media.licdn.com/dms/image/v2/' + tag + '/profile-displayphoto-' + size + '/0/1?e=1&v=beta&t=x';
    const photoLinks = `[...document.querySelectorAll('.hrsc-photo-link')].map((a) => ({ text: a.textContent, href: a.href, rel: a.rel, target: a.target, rp: a.referrerPolicy }))`;

    await check("reverse image search: offers the other person's LinkedIn photo as links only, no referrer", async () => {
      const p = await openPage('https://www.linkedin.com/messaging/thread/2-zh/');
      await p.waitFor(badge);
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const links = await p.waitFor(`(() => { const l = ${photoLinks}; return l.length ? l : null; })()`);
      const src = PHOTO('FIXTURE-RECRUITER', 'scale_100_100'); // theirs, not FIXTURE-ME
      assert.deepEqual(links.map((l) => l.href), [
        'https://lens.google.com/uploadbyurl?url=' + encodeURIComponent(src),
        'https://tineye.com/search?url=' + encodeURIComponent(src),
      ]);
      for (const l of links) {
        assert.equal(l.target, '_blank');
        assert.match(l.rel, /noopener/); assert.match(l.rel, /noreferrer/);
        assert.equal(l.rp, 'no-referrer');
      }
      assert.match(await p.evaluate(panelText), /Only shared if you click/);
      await p.shot('8-photo-search');
      await p.close();
    });

    await check('profile page: the largest LinkedIn profile photo (top card) is offered', async () => {
      const p = await openPage('https://www.linkedin.com/in/jane-doe-fixture/');
      await p.waitFor(badge);
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const links = await p.waitFor(`(() => { const l = ${photoLinks}; return l.length ? l : null; })()`);
      assert.ok(links[0].href.includes(encodeURIComponent(PHOTO('FIXTURE-TOPCARD', 'shrink_400_400'))), links[0].href);
      await p.close();
    });

    await check('non-LinkedIn images are never offered; the setting hides the action', async () => {
      const en = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await en.waitFor(badge);
      await en.evaluate(`document.querySelector('.hrsc-badge').click()`);
      await en.waitFor(panelText);
      assert.equal(await en.evaluate(`document.querySelectorAll('.hrsc-photo').length`), 0, 'data: avatar must not be offered');
      await en.close();

      const zh = await openPage('https://www.linkedin.com/messaging/thread/2-zh/');
      await zh.waitFor(badge);
      await zh.evaluate(`document.querySelector('.hrsc-badge').click()`);
      await zh.waitFor(`document.querySelectorAll('.hrsc-photo').length === 1`);
      const pop = await openPage('chrome-extension://' + extId + '/src/popup.html');
      await pop.evaluate(`chrome.runtime.sendMessage({type:'cfg:saveSettings', settings:{photoSearch:false}})`);
      await zh.waitFor(`document.querySelector('.hrsc-panel') && document.querySelectorAll('.hrsc-photo').length === 0`);
      await pop.evaluate(`chrome.runtime.sendMessage({type:'cfg:saveSettings', settings:{photoSearch:true}})`);
      await zh.waitFor(`document.querySelectorAll('.hrsc-photo').length === 1`);
      await pop.close();
      await zh.close();
    });

    await check('options page: categories, live preview, save with validation, live effect on LinkedIn, reset', async () => {
      const opt = await openPage('chrome-extension://' + extId + '/src/options.html');
      const rows = await opt.waitFor(`document.querySelectorAll('#cats tr').length`);
      assert.equal(rows, await opt.evaluate(`Object.keys(HRScam.RULES).length`));
      assert.equal(await opt.evaluate(`document.getElementById('off-credentials').disabled`), true, 'credentials is locked');

      const setField = (id, v) => opt.evaluate(`(() => { const e = document.getElementById(${JSON.stringify(id)});
        e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input', { bubbles: true })); })()`);
      // preview compares built-in vs unsaved settings: "urgent" = 8, muted = 0
      await setField('sample', 'Please reply, this is urgent');
      await setField('mute', 'urgent');
      await opt.waitFor(`document.getElementById('pv-stock').textContent === '8 (low)' &&
        document.getElementById('pv-custom').textContent === '0 (low)'`);
      await setField('mute', '');

      await setField('brands', 'nexachain = nexachain.example');
      await setField('trusted', '???');
      await opt.evaluate(`document.getElementById('save').click()`);
      const warn = await opt.waitFor(`(() => { const t = document.getElementById('warnings').textContent; return t || null; })()`);
      assert.match(warn, /not a valid domain/);
      assert.match(await opt.evaluate(`document.getElementById('status').textContent`), /^Saved/);
      const stored = await opt.evaluate(`chrome.storage.local.get('overrides').then((r) => r.overrides)`);
      assert.deepEqual(stored.brands, [{ name: 'nexachain', domains: ['nexachain.example'] }]);
      assert.deepEqual(stored.trustedDomains, []);
      await opt.shot('9-options');

      // the open LinkedIn thread picks it up: 38 + claimed nexachain without a link to nexachain.example (15) = 53
      const zh = await openPage('https://www.linkedin.com/messaging/thread/2-zh/');
      const t = await zh.waitFor(`(() => { const t = ${badge}; return t && /· 53$/.test(t) ? t : null; })()`);
      assert.equal(scoreOf(t), 53);
      await zh.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const p = await zh.waitFor(panelText);
      assert.match(p, /Custom rules active/);
      assert.match(p, /claims to recruit for nexachain/);

      // reset (two clicks) -> storage cleared -> open tab goes back to the built-in 38 by itself
      await opt.evaluate(`document.getElementById('reset').click()`);
      await opt.evaluate(`document.getElementById('reset').click()`);
      await opt.waitFor(`chrome.storage.local.get('overrides').then((r) => r.overrides === undefined)`);
      await zh.waitFor(`(() => { const t = ${badge}; return t && /· 38$/.test(t) ? t : null; })()`);
      await zh.close();
      await opt.close();
    });

    await check('popup links to the rules page', async () => {
      const pop = await openPage('chrome-extension://' + extId + '/src/popup.html');
      assert.equal(await pop.evaluate(`!!document.getElementById('customize')`), true);
      await pop.close();
    });

    await check('idle page is quiet: injected banner/dots cause no render loop', async () => {
      await sleep(1500); // let the previous step's own re-render settle
      const seen = await msgPage.evaluate(`new Promise((resolve) => {
        const seen = [];
        const mo = new MutationObserver((ms) => ms.forEach((m) => seen.push(m.type + ' on ' +
          (m.target.className || m.target.nodeName) + ' +' + [...m.addedNodes].map((n) => n.className || n.nodeName))));
        mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, characterData: true });
        setTimeout(() => { mo.disconnect(); resolve(seen); }, 4000);
      })`);
      assert.equal(seen.length, 0, seen.length + ' DOM mutations while idle:\n' + seen.slice(0, 10).join('\n'));
    });

    await check("banner 'Why?' opens the reason panel", async () => {
      await msgPage.evaluate(`[...document.querySelectorAll('.hrsc-banner-btn')].find((b) => b.textContent === 'Why?').click()`);
      const p = await msgPage.waitFor(panelText);
      assert.match(p, /Pushes the conversation off LinkedIn/);
      await msgPage.evaluate(`document.querySelector('.hrsc-x').click()`);
    });

    await check("user's own draft and own new messages never move the score", async () => {
      await msgPage.evaluate(own('Also, should I send my seed phrase and bank details on WhatsApp?'));
      await sleep(1800);
      assert.equal(scoreOf(await msgPage.evaluate(badge)), 68);
    });

    await check('badge is non-blocking: page under it stays clickable', async () => {
      const r = await msgPage.evaluate(`(() => {
        const root = document.querySelector('.hrsc-root');
        const cs = getComputedStyle(root);
        return { pe: cs.pointerEvents, pos: cs.position, modal: !!document.querySelector('dialog[open]') };
      })()`);
      assert.equal(r.pe, 'none');
      assert.equal(r.pos, 'fixed');
      assert.equal(r.modal, false);
    });

    await check('new inbound message triggers a re-scan (MutationObserver)', async () => {
      await msgPage.evaluate(inbound('To get started, please connect your wallet.'));
      const t = await msgPage.waitFor(`(() => { const t = ${badge}; return t && /· 100$/.test(t) ? t : null; })()`);
      // 68 + credentials 40 = 108 -> clamped 100
      assert.equal(scoreOf(t), 100);
    });

    await check('dismissing the banner persists per conversation across reloads', async () => {
      await msgPage.evaluate(`document.querySelector('.hrsc-banner-x').click()`);
      await msgPage.waitFor(`!document.querySelector('.hrsc-banner-root')`);
      await sleep(1200);
      assert.equal(await msgPage.evaluate(`!!document.querySelector('.hrsc-banner-root')`), false, 'stays dismissed');
      assert.ok(await msgPage.evaluate(badge), 'corner badge remains as the fallback');
      const p2 = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await p2.waitFor(badge);
      await sleep(1000);
      assert.equal(await p2.evaluate(`!!document.querySelector('.hrsc-banner-root')`), false, 'dismissal survives reload');
      await p2.close();
    });

    await check('URL without thread id: a dismissal does not leak onto the next conversation', async () => {
      const p = await openPage('https://www.linkedin.com/messaging/');
      await p.waitFor(banner);
      await p.evaluate(`document.querySelector('.hrsc-banner-x').click()`);
      await p.waitFor(`!document.querySelector('.hrsc-banner-root')`);
      // LinkedIn swaps the open thread in place: new person in the title bar, new messages
      await p.evaluate(`(() => {
        document.querySelector('.msg-thread__link-to-profile').setAttribute('href', 'https://www.linkedin.com/in/ACoAAFixtureOther');
        const ul = document.querySelector('.msg-s-message-list ul');
        ul.innerHTML = '<li class="msg-s-event-listitem msg-s-event-listitem--other"><div>Contact me on Telegram, then send your seed phrase.</div></li>';
      })()`);
      const b = await p.waitFor(banner);
      assert.match(b, /High risk signals/);
      await p.close();
    });

    await check('a dismissed caution banner re-appears if the conversation escalates to high', async () => {
      await msgPage.evaluate(`(() => {
        history.pushState({}, '', '/messaging/thread/3-def/');
        document.querySelector('.msg-s-message-list ul').innerHTML = '';
      })()`);
      await msgPage.evaluate(inbound('Add me on WhatsApp, the registration fee is refundable.'));
      const b = await msgPage.waitFor(`(() => { const b = ${banner}; return b && /Some risk signals/.test(b) ? b : null; })()`);
      assert.match(b, /Some risk signals in this conversation/);
      await msgPage.shot('2-thread-caution');
      await msgPage.evaluate(`document.querySelector('.hrsc-banner-x').click()`);
      await msgPage.waitFor(`!document.querySelector('.hrsc-banner-root')`);
      await msgPage.evaluate(inbound('Then send a photo of your passport.'));
      const b2 = await msgPage.waitFor(`(() => { const b = ${banner}; return b && /High risk/.test(b) ? b : null; })()`);
      assert.match(b2, /High risk signals in this conversation/);
    });

    await check('no sender markers -> falls back to scoring the whole conversation, and says so', async () => {
      await msgPage.evaluate(`document.querySelectorAll('.msg-s-event-listitem--other').forEach((e) => e.classList.remove('msg-s-event-listitem--other'))`);
      await sleep(1500);
      await msgPage.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const p = await msgPage.waitFor(`(() => { const t = ${panelText}; return t && /could not tell/.test(t) ? t : null; })()`);
      assert.match(p, /whole conversation/);
      await msgPage.evaluate(`document.querySelector('.hrsc-x').click()`);
    });

    await check('"Hide for this content" removes the corner UI until content changes', async () => {
      await msgPage.evaluate(`document.querySelector('.hrsc-badge').click()`);
      await msgPage.evaluate(`document.querySelector('.hrsc-foot .hrsc-link').click()`);
      await sleep(1500);
      assert.equal(await msgPage.evaluate(`!!document.querySelector('.hrsc-root')`), false);
    });

    await check('SPA navigation to a legit recruiter profile re-scores to low; no banner, no dots', async () => {
      await msgPage.evaluate(`(() => {
        history.pushState({}, '', '/in/jane-doe-recruiter/');
        document.querySelector('main').innerHTML = '<section><h1>Jane Doe</h1><p>Technical recruiter at Acme. ' +
          'We are hiring for our blockchain infrastructure team. Our interview process is described on our careers page: ' +
          '<a href="https://boards.greenhouse.io/acme/jobs/42">boards.greenhouse.io/acme/jobs/42</a></p></section>';
      })()`);
      const t = await msgPage.waitFor(`(() => { const t = ${badge}; return t && /Few risk/.test(t) ? t : null; })()`);
      // blockchain 5, counter (interview process, greenhouse.io, our careers page) capped -20 -> 0
      assert.equal(scoreOf(t), 0, t);
      assert.equal(await msgPage.evaluate(`document.querySelectorAll('.hrsc-banner-root, .hrsc-listdot').length`), 0);
      await msgPage.shot('3-profile-low');
    });

    await check('live-structure chat popup on the feed (zh): 53 caution, own link ignored, row + panel list', async () => {
      const p = await openPage('https://www.linkedin.com/feed/zh-popup/');
      const t = await p.waitFor(`(() => { const t = ${badge}; return t && /· 53$/.test(t.trim()) ? t : null; })()`);
      // inbound only: crypto 区块链 5 + pressure 会议中等你 8 + devlure github 账号 10 + pattern 15
      // + impersonation 15 (claims peaq; the recruiter only links calendly). The user's own
      // peaq.xyz link and its unrolled preview card must not answer the claim (else 38),
      // and the feed post behind the popup ("urgent", "telegram") is never scored.
      assert.match(t, /Some risk signals/);
      const b = await p.waitFor(`(() => { const b = document.querySelector('.msg-overlay-conversation-bubble .hrsc-banner-root'); return b && b.innerText; })()`);
      assert.match(b, /Some risk signals in this conversation/);
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const panel = await p.waitFor(panelText);
      assert.match(panel, /claims to recruit for peaq/);
      assert.match(panel, /messages from the other person only/);
      assert.doesNotMatch(panel, /telegram|urgent/i, 'feed post or own messages leaked into the score');
      const list = await p.waitFor(`(() => { const f = document.querySelector('.hrsc-flagged'); return f && f.innerText; })()`);
      assert.match(list, /Recruiter \(fixture\)\s+Caution · 53/);
      const dot = await p.evaluate(`(() => { const d = document.querySelector('.msg-overlay-list-bubble .hrsc-listdot'); return d && d.className + ' | ' + d.title; })()`);
      assert.match(dot, /hrsc-listdot-caution \| .*opened conversation/);
      await sleep(5600);
      assert.equal(await p.evaluate(`!!document.querySelector('.hrsc-warnmark')`), false, 'false layout alarm on live markup');
      await p.shot('5-feed-popup-zh');
      await p.close();
    });

    await check('feed is not scored; an open message overlay is, with its own banner', async () => {
      const feed = await openPage('https://www.linkedin.com/feed/');
      await sleep(2000);
      assert.equal(await feed.evaluate(`!!document.querySelector('.hrsc-root')`), false, 'feed posts should not be scored');
      // messaging-list popup: risky preview (45, caution) gets a dot; own "You: …" and the attachment row don't
      const popupDots = await feed.waitFor(`(() => { const d = [...document.querySelectorAll('.msg-overlay-list-bubble__convo-item--v2')]
        .map((r) => { const x = r.querySelector('.hrsc-listdot'); return x ? x.className.replace('hrsc-listdot ', '') : '-'; }).join(',');
        return d.includes('hrsc') ? d : null; })()`);
      assert.equal(popupDots, 'hrsc-listdot-caution,-,-');
      // Open chat popup, inner structure mirrored from live LinkedIn (2026-11).
      await feed.evaluate(`(() => {
        const b = document.createElement('div');
        b.className = 'msg-overlay-conversation-bubble';
        b.style.cssText = 'position:fixed;right:420px;bottom:0;width:340px;background:#fff;border:1px solid #ccc';
        b.innerHTML = '<div class="relative display-flex flex-column flex-grow-1">' +
          '<header class="msg-overlay-conversation-bubble-header"><h2 class="msg-overlay-bubble-header__title"><a href="/in/ACoAAFixtureSam/">Sam (fixture)</a></h2>' +
          '<button aria-expanded="true" class="msg-overlay-bubble-header__control msg-overlay-conversation-bubble__expand-btn">' +
          '<span class="artdeco-button__text">Minimize your conversation with Me and Sam — act now</span></button></header>' +
          '<div class="msg-overlay-conversation-bubble__content-wrapper relative display-flex flex-column">' +
          '<div class="msg-s-message-list-container msg-s-message-list-container--column-reversed" style="display:flex;flex-direction:column-reverse">' +
          '<div class="msg-s-message-list"><ul class="msg-s-message-list-content">' +
          '<li class="msg-s-message-list__event"><div class="msg-s-event-listitem msg-s-event-listitem--other">' +
          '<div class="msg-s-message-group__meta"><span class="msg-s-message-group__name">Sam (fixture)</span></div>' +
          '<div class="msg-s-event-listitem__actions-container"><button title="Reply to this message"><span class="artdeco-button__text">Reply urgently</span></button></div>' +
          '<p class="msg-s-event-listitem__body">Quick question: are you open to a role? Add me on WhatsApp, registration fee is refundable.</p></div></li>' +
          '<li class="msg-s-message-list__event"><div class="msg-s-event-listitem"><p class="msg-s-event-listitem__body">Sure, but is there a fee? I use telegram too.</p></div></li>' +
          '</ul></div></div>' +
          '<form class="msg-form"><div class="msg-form__contenteditable" contenteditable="true" role="textbox"><p>my draft: seed phrase?</p></div></form>' +
          '</div></div>';
        document.body.appendChild(b);
      })()`);
      const t = await feed.waitFor(badge);
      // inbound only: offplatform (whatsapp, add me on) 30 + money (registration fee) 15 = 45 caution
      assert.equal(scoreOf(t), 45, t);
      // live signal: minimise button flips aria-expanded -> popup no longer scored; flip back -> scored again
      await feed.evaluate(`document.querySelector('.msg-overlay-conversation-bubble__expand-btn').setAttribute('aria-expanded', 'false')`);
      await feed.waitFor(`!document.querySelector('.hrsc-root')`);
      await feed.evaluate(`document.querySelector('.msg-overlay-conversation-bubble__expand-btn').setAttribute('aria-expanded', 'true')`);
      await feed.waitFor(badge);
      // a popup whose message list is gone (collapsed render) is not scored from header chrome
      const extra = await feed.evaluate(`(() => {
        const b = document.createElement('div');
        b.className = 'msg-overlay-conversation-bubble';
        b.innerHTML = '<header class="msg-overlay-conversation-bubble-header"><h2>Other (fixture)</h2></header>';
        document.body.appendChild(b);
        return true;
      })()`);
      assert.ok(extra);
      await sleep(1500);
      const units = await feed.evaluate(`(() => { const p = document.querySelectorAll('.hrsc-banner-root'); return p.length; })()`);
      assert.equal(units, 1, 'only the popup with a message list gets a banner');
      // minimise -> its banner goes and nothing is scored; un-minimise (pure class flip) -> back
      await feed.evaluate(`document.querySelector('.msg-overlay-conversation-bubble').classList.add('msg-overlay-conversation-bubble--is-minimized')`);
      await feed.waitFor(`!document.querySelector('.hrsc-root')`);
      await feed.evaluate(`document.querySelector('.msg-overlay-conversation-bubble').classList.remove('msg-overlay-conversation-bubble--is-minimized')`);
      await feed.waitFor(badge);
      const inBubble = await feed.waitFor(`(() => { const b = document.querySelector('.msg-overlay-conversation-bubble .hrsc-banner-root'); return b && b.innerText; })()`);
      assert.match(inBubble, /Some risk signals in this conversation/);
      await feed.shot('4-overlay-caution');
      await feed.close();
    });

    // ------------------------------------------------------------ blocklist
    let popup;
    await check('popup rejects a non-GitHub blocklist URL', async () => {
      popup = await openPage('chrome-extension://' + extId + '/src/popup.html');
      const r = await popup.evaluate(`chrome.runtime.sendMessage({type:'cfg:saveSettings', settings:{blocklistUrl:'https://evil.example/list.json'}})`);
      assert.equal(r.ok, false);
    });

    await check('popup saves a GitHub raw URL; worker fetches and caches it', async () => {
      const r = await popup.evaluate(`chrome.runtime.sendMessage({type:'cfg:saveSettings', settings:{blocklistUrl:'https://raw.githubusercontent.com${LIST_PATH}'}})`);
      assert.equal(r.ok, true, JSON.stringify(r));
      assert.equal(r.meta.error, null, JSON.stringify(r.meta));
      assert.equal(r.meta.counts.domains, 1);
      await popup.evaluate('location.reload()');
      await sleep(800);
      const status = await popup.waitFor(`(() => { const t = document.getElementById('listStatus').textContent; return /indicators/.test(t) ? t : null; })()`);
      assert.match(status, /1 indicators/);
      await popup.shot('6-popup');
    });

    await check('blocklisted domain behind a LinkedIn redirect link -> blocklist reason', async () => {
      const p = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await p.waitFor(`(() => { const t = ${badge}; return t && scoreOfOk(t); function scoreOfOk(t){ return Number(t.split('·').pop()) >= 63; } })()`);
      await p.evaluate(`document.querySelector('.hrsc-badge').click()`);
      const text = await p.waitFor(`(() => { const t = ${panelText}; return t && /scam-infrastructure/.test(t) ? t : null; })()`);
      assert.match(text, /domain careers-acme\.xyz/);
      await p.shot('5-blocklist-hit');
      await p.close();
    });

    await check('hostile blocklist (garbage) is rejected; previous list stays active', async () => {
      blocklistBody = '{"schema":"catfishguard-blocklist","domains":"<script>alert(1)</script>", "x": ' + '['.repeat(5000);
      const r = await popup.evaluate(`chrome.runtime.sendMessage({type:'cfg:refresh'})`);
      assert.match(r.meta.error, /not valid JSON/);
      const m = await popup.evaluate(`chrome.runtime.sendMessage({type:'cfg:match', indicators:{domains:['careers-acme.xyz']}})`);
      assert.equal(m.hits.length, 1);
    });

    await check('popup shows the active-tab result via the content script', async () => {
      // open popup UI in a tab and ask the LinkedIn tab directly
      const li = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await li.waitFor(badge);
      const r = await popup.evaluate(`(async () => {
        // no "tabs" permission -> tab URLs are hidden (good); ask each tab, keep the one that answers
        const out = [];
        for (const t of await chrome.tabs.query({})) {
          try {
            const r = await chrome.tabs.sendMessage(t.id, { type: 'cfg:getResult' });
            if (r) out.push(r);
          } catch (_) { /* no content script in that tab */ }
        }
        return out;
      })()`);
      const msg = r.find((x) => x.context === 'messaging');
      assert.ok(msg, 'messaging tab answered: ' + JSON.stringify(r.map((x) => x.context)));
      assert.equal(msg.enabled, true);
      assert.ok(msg.result.score >= 60, JSON.stringify(msg.result).slice(0, 200));
      assert.ok(msg.result.reasons.some((x) => x.category === 'blocklist'));
      await li.close();
    });

    await check('disabling in settings removes the UI', async () => {
      const li = await openPage('https://www.linkedin.com/messaging/thread/2-abc/');
      await li.waitFor(badge);
      await popup.evaluate(`chrome.runtime.sendMessage({type:'cfg:saveSettings', settings:{enabled:false}})`);
      await li.waitFor(`!document.querySelector('.hrsc-root')`);
      await popup.evaluate(`chrome.runtime.sendMessage({type:'cfg:saveSettings', settings:{enabled:true}})`);
      await li.waitFor(badge);
      await li.close();
    });

    // ------------------------------------------------------------- privacy
    await check('only outbound non-page request is the blocklist GET, with no cookies or page data', async () => {
      // media.licdn.com = profile photos the LinkedIn page itself loads (not the extension)
      const offPage = requests.filter((r) => !/^(www\.linkedin\.com|media\.licdn\.com)/.test(r.host || ''));
      assert.ok(offPage.length >= 1, 'expected blocklist fetches');
      for (const r of requests.filter((x) => /^media\.licdn\.com/.test(x.host || ''))) {
        assert.equal(r.method, 'GET');
        assert.match(r.url, /^\/dms\/image\/v2\/FIXTURE-/);
      }
      for (const r of offPage) {
        assert.equal(r.host.split(':')[0], 'raw.githubusercontent.com', JSON.stringify(r));
        assert.equal(r.method, 'GET');
        assert.equal(r.url, LIST_PATH);
        assert.equal(r.body, '');
        assert.equal(r.headers.cookie, undefined);
        assert.equal(r.headers.referer, undefined);
      }
      const liNonGet = requests.filter((r) => r.host.startsWith('www.linkedin.com') && r.method !== 'GET');
      assert.equal(liNonGet.length, 0, 'extension must not post to linkedin either');
    });
  } finally {
    try { proc.kill('SIGKILL'); } catch (_) { /* ignore */ }
    server.close();
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* ignore */ }
  }

  const failed = results.filter((r) => r[0] === 'FAIL');
  console.log(`\n${results.length - failed.length}/${results.length} e2e checks passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
