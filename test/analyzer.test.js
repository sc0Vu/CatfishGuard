'use strict';
// Expected scores are derived by hand from the RULES weights/caps:
//   credentials 40/term cap 60 (critical -> floor 60) · offplatform 15 cap 30
//   money 15 cap 40 · crypto 5 cap 20, +20 at 3+ distinct · toogood 10 cap 30
//   pressure 8 cap 24 · counter -10 cap -20 (only if nothing critical/blocklist)
//   blocklist hit +60, floor 60. Bands: 0-29 low, 30-59 caution, 60+ high.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadAnalyzer, plain } = require('./helpers');

const A = loadAnalyzer();
const cat = (r, id) => r.reasons.find((x) => x.category === id);

test('empty input scores zero', () => {
  const r = A.analyze('', []);
  assert.equal(r.score, 0);
  assert.equal(r.band, 'low');
  assert.equal(r.reasons.length, 0);
  assert.equal(A.analyze(null, null).score, 0);
});

test('bands: 0-29 low, 30-59 caution, 60-100 high', () => {
  assert.equal(A.bandFor(0), 'low');
  assert.equal(A.bandFor(29), 'low');
  assert.equal(A.bandFor(30), 'caution');
  assert.equal(A.bandFor(59), 'caution');
  assert.equal(A.bandFor(60), 'high');
  assert.equal(A.bandFor(100), 'high');
});

test('legit fintech recruiter saying "blockchain" stays low', () => {
  // crypto: blockchain = 5; counter: interview process + greenhouse.io = -20 -> 0
  const r = A.analyze(
    "Hi! I'm hiring for our blockchain payments team. Our interview process has three rounds.",
    ['https://boards.greenhouse.io/acme/jobs/123']);
  assert.equal(r.score, 0);
  assert.equal(r.band, 'low');
  assert.equal(cat(r, 'crypto').points, 5);
  assert.equal(cat(r, 'counter').points, -20);
});

test('classic task/web3 scam message is high, with every reason listed', () => {
  // crypto web3 5 · toogood (no experience needed + $800/day) 20 ·
  // offplatform (telegram + contact me on) 30 · pressure urgent 8 = 63
  const r = A.analyze(
    'We came across your profile. Remote web3 role, $800 per day, no experience needed. ' +
    'Contact me on Telegram. Urgent.', []);
  assert.equal(r.score, 63);
  assert.equal(r.band, 'high');
  assert.equal(r.critical, false);
  assert.equal(cat(r, 'offplatform').points, 30);
  assert.equal(cat(r, 'toogood').points, 20);
  assert.ok(cat(r, 'toogood').matches.some((m) => m.term === '$800/day'));
  assert.equal(cat(r, 'pressure').points, 8);
  assert.equal(cat(r, 'crypto').points, 5);
  // reasons sorted by points, descending
  const pts = plain(r.reasons.map((x) => x.points));
  assert.deepEqual(pts, [...pts].sort((a, b) => b - a));
});

test('a credential/wallet ask alone pushes to high', () => {
  const r = A.analyze('To proceed, please connect your wallet on our portal.', []);
  assert.equal(cat(r, 'credentials').points, 40);
  assert.equal(r.critical, true);
  assert.equal(r.score, 60); // 40 raw, floored to 60
  assert.equal(r.band, 'high');
});

test('credentials cap at 60 however many terms fire', () => {
  const r = A.analyze('Send your seed phrase, private key and a passport copy.', []);
  assert.equal(cat(r, 'credentials').matches.length, 3);
  assert.equal(cat(r, 'credentials').points, 60);
  assert.equal(r.score, 60);
});

test('counter signals are ignored when something near-certain fired', () => {
  const r = A.analyze('Our interview process requires your seed phrase.', []);
  assert.equal(r.score, 60); // 40 floored to 60; the -10 is not applied
  assert.equal(cat(r, 'counter').points, 0);
  assert.match(cat(r, 'counter').note, /ignored/);
});

test('longest term wins: "secret recovery phrase" counts once', () => {
  const r = A.analyze('Enter your secret recovery phrase', []);
  assert.deepEqual(plain(cat(r, 'credentials').matches), [{ term: 'secret recovery phrase', count: 1 }]);
});

test('crypto cluster bonus needs 3+ distinct terms', () => {
  const two = A.analyze('web3 and defi', []);
  assert.equal(two.score, 10);
  const four = A.analyze('web3 defi nft airdrop', []);
  assert.equal(cat(four, 'crypto').points, 40); // 20 capped + 20 bonus
  assert.equal(four.band, 'caution');
});

test('repetition does not escalate a category', () => {
  const r = A.analyze('urgent urgent URGENT', []);
  assert.equal(r.score, 8);
  assert.deepEqual(plain(cat(r, 'pressure').matches), [{ term: 'urgent', count: 3 }]);
});

test('category caps hold', () => {
  const r = A.analyze('Telegram or WhatsApp, add me on t.me/x, contact me on wa.me/1555', []);
  assert.equal(cat(r, 'offplatform').points, 30);
});

test('unrealistic-pay heuristic and its thresholds', () => {
  assert.equal(A.analyze('$40 per hour', []).score, 0);
  assert.equal(A.analyze('$200/hr', []).score, 10);
  const k = A.analyze('earn $5k per week', []);
  assert.equal(k.score, 10);
  assert.equal(cat(k, 'toogood').matches[0].term, '$5,000/week');
});

test('zero-width / fullwidth evasion is normalised', () => {
  assert.equal(A.analyze('tele​gram', []).score, 15);
  assert.equal(A.analyze('ｔｅｌｅｇｒａｍ', []).score, 15); // NFKC
});

test('word boundaries: no matches inside other words', () => {
  assert.equal(A.countTerm('telegrams are old', 'telegram'), 0);
  assert.equal(A.countTerm('an iconic brand', 'ico'), 0);
  assert.equal(A.countTerm('join our ico now', 'ico'), 1);
  assert.equal(A.analyze('the daointerface', []).score, 0);
});

test('CJK: terms match inside unspaced text; Latin terms still need boundaries', () => {
  assert.equal(A.countTerm(A.normalizeText('负责一个全新的区块链基础设施项目'), '区块链'), 1);
  assert.equal(A.countTerm(A.normalizeText('加我telegram聊'), 'telegram'), 1);
  assert.equal(A.countTerm(A.normalizeText('加我Telegram'), 'telegram'), 1);
  assert.equal(A.countTerm('telegrams', 'telegram'), 0);
  assert.equal(A.countTerm('xtelegram', 'telegram'), 0);
  assert.equal(A.analyze('區塊鏈', []).score, 5); // traditional form
  // offplatform 加我微信 15 (the 微信 inside it is consumed by the longer term) + money 押金 15 = 30
  assert.equal(A.analyze('请加我微信，先交押金', []).score, 30);
});

test('real-world zh recruiter thread (anonymised, inbound only): developer-lure + crypto pattern -> caution', () => {
  // Inbound messages from a live thread (names/company/links replaced). Hand-derived:
  // Keywords alone gave 13 (low); the developer-outreach rule and the
  // crypto + outreach + pressure combination lift this pattern to caution.
  const inbound = '您好， https://linkedin.com/in/me-fixture 我关注了您的 GitHub 账号，也看到了您在一个开源项目中的贡献，' +
    '非常令人印象深刻。我是 nexachain 的技术招聘负责人，我们目前正在组建团队，负责一个全新的区块链基础设施项目。' +
    '我们正在寻找像您这样具备相关经验的人才。该职位支持远程办公，提供全职或兼职机会。您看本周是否方便进行一次简短的沟通，互相了解一下？ ' +
    '感谢您的关注。我想为您安排一场与我们工程负责人的面试。 https://calendly.com/lead-nexachain/30min 预约好时间后，请告知我。 ' +
    '嗨， Lead 正在会议中等你。 你好 我知道你很忙。 能否请你安排一个对你方便的时间，我们开个会？';
  const r = A.analyze(inbound, ['https://calendly.com/lead-nexachain/30min', 'https://linkedin.com/in/me-fixture']);
  assert.equal(cat(r, 'crypto').points, 5);
  assert.equal(cat(r, 'pressure').points, 8);
  // devlure: 您的 github / github 账号 overlap -> one term, 10; crypto + devlure + pressure pattern +15
  assert.equal(cat(r, 'devlure').points, 10);
  assert.equal(cat(r, 'pattern').points, 15);
  assert.match(cat(r, 'pattern').matches[0].term, /GitHub-sourced outreach \+ pressure/);
  assert.equal(cat(r, 'impersonation'), undefined); // the claimed company isn't in the brand list
  assert.equal(r.score, 38); // 5 + 8 + 10 + 15
  assert.equal(r.band, 'caution');
});

test('terms are literal: regex metacharacters are escaped', () => {
  assert.equal(A.countTerm('tame/x', 't.me/'), 0);
  assert.equal(A.countTerm('see t.me/x', 't.me/'), 1);
  assert.equal(A.countTerm('aaaa', '(a+)+$'), 0);
  assert.equal(A.countTerm('x (a+)+$ y', '(a+)+$'), 1);
  assert.equal(A.countTerm('a-b', 'a-b'), 1); // "-" stays valid under the u flag
});

test('blocklist hit alone is high, and disables counter-softening', () => {
  const hit = [{ kind: 'domain', value: 'evil.xyz', entry: 'evil.xyz' }];
  const r = A.analyze('Our interview process starts here', [], { blocklistHits: hit });
  assert.equal(r.score, 60);
  assert.equal(r.band, 'high');
  assert.equal(cat(r, 'blocklist').matches[0].term, 'domain evil.xyz');
  assert.equal(cat(r, 'counter').points, 0);
});

test('score is clamped to 100', () => {
  const r = A.analyze('seed phrase private key telegram whatsapp registration fee gift card usdt ' +
    'web3 defi nft no interview easy money passive income urgent asap act now',
  [], { blocklistHits: [{ kind: 'wallet', value: '0xabc' }] });
  assert.equal(r.score, 100);
});

test('no UI-facing copy asserts someone is a scammer', () => {
  for (const rule of Object.values(A.RULES)) assert.doesNotMatch(rule.label, /scammer|fraudster|criminal/i);
});

test('large/adversarial input stays fast (no catastrophic backtracking)', () => {
  const inputs = ['a'.repeat(200000), 'a.'.repeat(100000), '@'.repeat(200000), '$1'.repeat(100000),
    '+1 '.repeat(60000), ('x'.repeat(60) + '.').repeat(3000)];
  for (const s of inputs) {
    const t0 = Date.now();
    A.analyze(s, []);
    A.extractIndicators(s, []);
    assert.ok(Date.now() - t0 < 2000, 'took ' + (Date.now() - t0) + 'ms on ' + s.slice(0, 10));
  }
});

// ---------------------------------------------------------------------------
// indicators + blocklist
// ---------------------------------------------------------------------------
test('extractIndicators: links, LinkedIn redirect unwrap, text, handles, wallets, emails', () => {
  const ind = A.extractIndicators(
    'Apply at careers-acme.xyz or https://www.Evil.com/login/ . Ping t.me/HRJane or +1 (555) 010-0199, ' +
    '@hr_desk, mail hr@mailinator.com. Pay 0xAbCdEf0123456789abcdef0123456789ABCDEF01 or ' +
    'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    ['https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fphish.example%2Fapply', 'mailto:Boss@Throwaway.io']);
  for (const d of ['careers-acme.xyz', 'evil.com', 'phish.example', 'mailinator.com', 'throwaway.io']) {
    assert.ok(ind.domains.includes(d), 'missing domain ' + d);
  }
  assert.ok(ind.urls.includes('evil.com/login'));
  assert.ok(ind.urls.includes('phish.example/apply'));
  for (const h of ['@hrjane', '+15550100199', '@hr_desk']) assert.ok(ind.handles.includes(h), 'missing ' + h);
  assert.ok(!ind.handles.includes('@mailinator.com'), 'email domain must not become a handle');
  assert.ok(ind.wallets.includes('0xabcdef0123456789abcdef0123456789abcdef01'));
  assert.ok(ind.wallets.includes('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'));
  assert.ok(ind.emails.includes('hr@mailinator.com'));
  assert.ok(ind.emails.includes('boss@throwaway.io'));
});

test('normalizeBlocklist rejects non-objects and unknown schemas', () => {
  for (const bad of [null, 42, 'x', [], [1, 2], {}, { foo: [] }]) {
    const r = A.normalizeBlocklist(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
  }
});

test('normalizeBlocklist validates every entry of our schema', () => {
  const r = A.normalizeBlocklist({
    schema: 'catfishguard-blocklist',
    domains: ['Evil.XYZ', 'www.bad.com', 123, null, '<script>', 'a'.repeat(300), { value: 'obj.com' }, 'evil.xyz', 'xyz'],
    urls: ['https://Evil.com/Login/', 'javascript:alert(1)'],
    handles: ['t.me/HRJane', '+1 (555) 010-0199', 'not a handle!'],
    wallets: ['0xABCDEF0123456789abcdef0123456789abcdef01', 'short'],
    emails: ['@mailinator.com', 'HR@Scam.io', 'nope'],
    extra: 'ignored',
  });
  assert.equal(r.ok, true);
  assert.deepEqual(plain(r.list.domains), ['evil.xyz', 'bad.com', 'obj.com']);
  assert.deepEqual(plain(r.list.urls), ['evil.com/login']);
  assert.deepEqual(plain(r.list.handles), ['@hrjane', '+15550100199']);
  assert.deepEqual(plain(r.list.wallets), ['0xabcdef0123456789abcdef0123456789abcdef01']);
  assert.deepEqual(plain(r.list.emails), ['@mailinator.com', 'hr@scam.io']);
  // 123, null, <script>, too-long, xyz | javascript: | bad handle | short | nope  (dup evil.xyz is not "invalid")
  assert.equal(r.list.rejected, 9);
});

test('normalizeBlocklist: eth-phishing-detect schema, tolerance clamped', () => {
  const r = A.normalizeBlocklist({ version: 2, tolerance: 99, fuzzylist: ['metamask.io'], whitelist: ['metamask.tools'], blacklist: ['scam.io'] });
  assert.equal(r.ok, true);
  assert.equal(r.list.tolerance, 3);
  assert.deepEqual(plain(r.list.sources), ['eth-phishing-detect']);
  assert.equal(A.normalizeBlocklist({ blacklist: [], tolerance: 'abc' }).list.tolerance, 1);
  assert.equal(A.normalizeBlocklist({ blacklist: [], tolerance: -5 }).list.tolerance, 0);
});

test('normalizeBlocklist clamps list sizes', () => {
  const big = Array.from({ length: 300005 }, (_, i) => 'd' + i + '.com');
  const r = A.normalizeBlocklist({ blacklist: big });
  assert.equal(r.list.domains.length, 300000);
  assert.ok(r.list.rejected >= 5);
  const fz = A.normalizeBlocklist({ fuzzylist: Array.from({ length: 1000 }, (_, i) => 'b' + i + '.com') });
  assert.equal(fz.list.fuzzy.length, 500);
});

test('non-array list fields degrade to empty, never throw', () => {
  const r = A.normalizeBlocklist({ schema: 'catfishguard-blocklist', domains: 'evil.com', urls: { a: 1 } });
  assert.equal(r.ok, true);
  assert.equal(r.list.domains.length, 0);
  const m = A.createMatcher({ domains: 'x', fuzzy: null });
  assert.deepEqual(plain(m.match({ domains: ['evil.com'] })), []);
  assert.deepEqual(plain(m.match(null)), []);
});

test('matcher: domain suffixes, whitelist, URL prefixes, handles, wallets, emails', () => {
  const list = A.mergeBlocklists(
    A.normalizeBlocklist({ schema: 'catfishguard-blocklist', domains: ['evil.xyz'], urls: ['evil.com/login'],
      handles: ['t.me/HRJane'], wallets: ['0xABCDEF0123456789abcdef0123456789abcdef01'], emails: ['@mailinator.com'] }).list,
    A.normalizeBlocklist({ blacklist: ['safe-but-listed.io', 'evil.xyz'], whitelist: ['safe-but-listed.io'] }).list);
  const m = A.createMatcher(list);
  const kinds = (ind) => plain(m.match(ind)).map((h) => h.kind + ':' + h.value);

  assert.deepEqual(kinds({ domains: ['login.evil.xyz'] }), ['domain:login.evil.xyz']);
  assert.deepEqual(kinds({ domains: ['notevil.xyz', 'xyz', 'safe-but-listed.io'] }), []);
  assert.deepEqual(kinds({ urls: ['https://www.evil.com/login/step2?x=1'] }), ['url:evil.com/login/step2?x=1']);
  assert.deepEqual(kinds({ urls: ['https://evil.com/loginx'] }), []);
  assert.deepEqual(kinds({ handles: ['@HRJane'] }), ['handle:@hrjane']);
  assert.deepEqual(kinds({ wallets: ['0xabcdef0123456789ABCDEF0123456789abcdef01'] }),
    ['wallet:0xabcdef0123456789abcdef0123456789abcdef01']);
  assert.deepEqual(kinds({ emails: ['hr@mailinator.com', 'hr@gmail.com'] }), ['email:hr@mailinator.com']);
});

test('matcher: eth-phishing-detect fuzzylist lookalikes', () => {
  const m = A.createMatcher(A.normalizeBlocklist({ tolerance: 1, fuzzylist: ['metamask.io'], blacklist: [] }).list);
  const look = (d) => plain(m.match({ domains: [d] })).map((h) => h.kind + ':' + h.entry);
  assert.deepEqual(look('metamask.com'), ['lookalike:metamask.io']);  // same name, other TLD
  assert.deepEqual(look('metamusk.io'), ['lookalike:metamask.io']);   // distance 1
  assert.deepEqual(look('rnetamask.io'), []);                          // distance 2 > tolerance
  assert.deepEqual(look('metamask.io'), []);                           // the real one
  assert.deepEqual(look('app.metamask.io'), []);                       // its subdomain
  assert.deepEqual(look('google.com'), []);
});

test('end to end: page text -> indicators -> matcher -> analyze', () => {
  const m = A.createMatcher(A.normalizeBlocklist({ schema: 'catfishguard-blocklist', domains: ['careers-acme.xyz'] }).list);
  const text = 'Please fill the form at careers-acme.xyz today.';
  const r = A.analyze(text, [], { blocklistHits: m.match(A.extractIndicators(text, [])) });
  assert.equal(r.score, 60);
  assert.equal(r.band, 'high');
});

const MM = process.env.CFG_METAMASK_JSON;
test('real MetaMask eth-phishing-detect list parses and matches quickly', { skip: !MM || !fs.existsSync(MM) }, () => {
  const raw = JSON.parse(fs.readFileSync(path.resolve(MM), 'utf8'));
  let t0 = Date.now();
  const r = A.normalizeBlocklist(raw);
  const normMs = Date.now() - t0;
  assert.equal(r.ok, true);
  assert.ok(r.list.domains.length > 50000, 'domains: ' + r.list.domains.length);
  t0 = Date.now();
  const m = A.createMatcher(A.mergeBlocklists(null, r.list));
  const buildMs = Date.now() - t0;
  const sample = raw.blacklist.find((d) => A.normalizeDomain(d));
  assert.equal(m.match({ domains: ['www.' + sample] }).length, 1);
  assert.equal(m.match({ domains: ['linkedin.com', 'google.com'] }).length, 0);
  assert.ok(normMs < 3000 && buildMs < 3000, `normalize ${normMs}ms, build ${buildMs}ms`);
  console.log(`  metamask: ${r.list.domains.length} domains, ${r.list.rejected} rejected, normalize ${normMs}ms, matcher ${buildMs}ms`);
});

// ---------------------------------------------------------------------------
// domain / impersonation module (roadmap #2)
// ---------------------------------------------------------------------------
test('registrableDomain follows the Public Suffix List', () => {
  const R = (h) => A.registrableDomain(h);
  assert.equal(R('login.google.com.evil.ru'), 'evil.ru');
  assert.equal(R('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(R('evil.vercel.app'), 'evil.vercel.app');   // private section
  assert.equal(R('someone.github.io'), 'someone.github.io');
  assert.equal(R('www.ck'), 'www.ck');                      // exception rule !www.ck
  assert.equal(R('a.foo.ck'), 'a.foo.ck');                  // wildcard *.ck
  assert.equal(R('WWW.Coinbase.COM.'), 'coinbase.com');
  assert.equal(R('co.uk'), null);
  assert.equal(R('localhost'), null);
  assert.equal(R('192.168.1.10'), null);
  assert.equal(R('<script>'), null);
});

test('punyDecode reveals what an xn-- label spells', () => {
  assert.equal(A.punyDecode('pypal-4ve'), 'pаypal');   // Cyrillic а
  assert.equal(A.punyDecode('ggle-55da'), 'gооgle');
  assert.doesNotThrow(() => A.punyDecode('zzzzzzzzzzzzzzzzzzzz'));
  assert.doesNotThrow(() => A.punyDecode('-'.repeat(70)));
});

test('impersonation: each lookalike shape scores 35 (caution on its own)', () => {
  const imp = (url) => { const r = A.analyze('details', [url]); return [r.score, (cat(r, 'impersonation') || { matches: [] }).matches.map((m) => m.term)[0]]; };
  let [s, t] = imp('https://coinbase-careers.com/apply');
  assert.equal(s, 35); assert.match(t, /contains "Coinbase"/);
  [s, t] = imp('https://www.linkedln.com/jobs/view/1');
  assert.equal(s, 35); assert.match(t, /one letter away from LinkedIn/);
  [s, t] = imp('https://coinbase.hr-portal.io/x');
  assert.equal(s, 35); assert.match(t, /puts "Coinbase" in front of an unrelated domain \(hr-portal\.io\)/);
  [s, t] = imp('https://xn--pypal-4ve.com/login');
  assert.equal(s, 35); assert.match(t, /displays as "pаypal"\) imitates PayPal/);
  [s, t] = imp('https://google.com.evil.ru/signin');
  assert.equal(s, 35); assert.match(t, /"Google" in front of an unrelated domain \(evil\.ru\)/);
  [s, t] = imp('https://paypa1.com/');
  assert.equal(s, 35); assert.match(t, /imitates PayPal/);
});

test('impersonation: official and look-alike-but-innocent domains stay clean', () => {
  for (const url of ['https://www.coinbase.com/careers', 'https://www.google.de/', 'https://motion.com/',
    'https://level.co/', 'https://boards.greenhouse.io/acme/jobs/1', 'https://calendly.com/someone/30min',
    'https://someone.github.io/portfolio', 'https://media.licdn.com/x.png', 'https://www.linkedin.com/in/x']) {
    const r = A.analyze('details', [url]);
    assert.equal(cat(r, 'impersonation'), undefined, url);
  }
});

test('same brand name on another TLD: 35 + cheap TLD 5', () => {
  const r = A.analyze('apply', ['https://coinbase.xyz/apply']);
  assert.equal(cat(r, 'impersonation').points, 35);
  assert.equal(cat(r, 'linkrisk').points, 5);
  assert.equal(r.score, 40);
});

test('link-risk heuristics and their weights', () => {
  const score = (links, text = 'see link') => A.analyze(text, links).score;
  assert.equal(score(['http://192.168.1.10/login']), 25);
  assert.equal(score(['https://bit.ly/abc123']), 10);
  assert.equal(score(['https://coinbase.com@evil.example/']), 25);   // userinfo trick
  assert.equal(score(['https://files.example.org/MeetingApp.dmg']), 40);
  assert.equal(score(['https://files.example.org/test-project.zip']), 15);
  assert.equal(score(['https://acme.vercel.app/']), 5);
  assert.equal(score([], 'Email me at hr.team@gmail.com'), 10);
  assert.equal(score(['http://10.0.0.1/Setup.exe']), 40);             // 25 + 40 capped at 40
});

test('claimed employer vs where the links go', () => {
  const claim = 'Hi, I’m a recruiter at Coinbase. Pick a time: https://calendly.com/some-lead/30min';
  const r = A.analyze(claim, []);
  assert.equal(r.score, 15);
  assert.match(cat(r, 'impersonation').matches[0].term, /claims to recruit for Coinbase, but no link goes to Coinbase/);
  assert.equal(A.analyze("I'm a recruiter at Coinbase: https://www.coinbase.com/careers", []).score, 0);
  // talking about the candidate's past employer is not a claim
  assert.equal(A.analyze('I saw you worked at Coinbase. Book: https://calendly.com/x/30min', []).score, 0);
  assert.equal(A.analyze('We are recruiting for Binance, see https://jobs.example.org/1', []).score, 15);
  assert.equal(A.analyze('我是 Coinbase 的技术招聘负责人 https://calendly.com/x/30min', []).score, 15);
  // no links at all -> nothing to compare
  assert.equal(A.analyze("I'm a recruiter at Coinbase.", []).score, 0);
});

test('impersonation disables counter-softening', () => {
  const r = A.analyze('Our interview process starts here', ['https://coinbase-careers.com/']);
  assert.equal(r.score, 35);
  assert.equal(cat(r, 'counter').points, 0);
});

test('developer lures: outreach is weak, run/install is strong, combinations escalate', () => {
  // devlure your github profile 10 · execlure clone the repo + npm install 40 · crypto web3 5 · pattern 15 = 70
  const r = A.analyze('Saw your GitHub profile. Our web3 team needs you to clone the repo and run npm install.', []);
  assert.equal(cat(r, 'devlure').points, 10);
  assert.equal(cat(r, 'execlure').points, 40);
  assert.equal(cat(r, 'pattern').points, 15);
  assert.equal(r.score, 70);
  assert.equal(r.band, 'high');
  // false-positive guards (legit hiring language) stay low
  assert.equal(A.analyze('We use a take-home exercise.', []).score, 10);
  assert.equal(A.analyze('We are a fintech building on blockchain. Take-home exercise follows.', []).score, 15);
  assert.equal(A.analyze('I saw your GitHub profile and your contributions to an open-source project.', []).score, 20);
  // ClickFix-style ask on its own is already notable: 20 + 20 = 40 caution
  assert.equal(A.analyze('Your camera is broken, paste this command in your terminal to fix the camera.', []).score, 40);
});

test('every new label stays a "signal", never a verdict', () => {
  const r = A.analyze("I'm a recruiter at Coinbase https://coinbase-careers.com/x http://1.2.3.4/a.exe your github web3", []);
  for (const x of r.reasons) assert.doesNotMatch(x.label + x.matches.map((m) => m.term).join(' '), /scam(mer)?\b|fraud/i);
});
