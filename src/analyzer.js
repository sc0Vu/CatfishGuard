/*
 * CatfishGuard analyzer — the scoring engine.
 *
 * Pure and dependency-free: text + links + blocklist hits in, {score, band,
 * reasons[]} out. Also owns blocklist validation/normalisation and indicator
 * matching so the service worker and the tests share one implementation.
 *
 * Attaches `self.HRScam` (works in content scripts, the service worker via
 * importScripts, and a Node `vm` sandbox that provides `self` + `URL`).
 *
 * Invariants honoured here:
 *  - Terms are matched as LITERAL strings (regex metachars escaped). No regex
 *    is ever compiled from external data.
 *  - External blocklists are treated as hostile: schema-checked, every entry
 *    validated, counts and lengths clamped; garbage degrades to "ignored".
 *  - Output is risk signals with reasons, never a verdict about a person.
 */
(function (root) {
  'use strict';

  const VERSION = '0.1.0';
  const MAX_TEXT = 200000;

  // ---------------------------------------------------------------------------
  // Keyword rules (bundled on purpose — see CLAUDE.md "Why this split").
  // Each distinct term that fires adds `weight` once (repetition doesn't
  // escalate); the category total is clamped to `cap`.
  // ---------------------------------------------------------------------------
  const RULES = {
    credentials: {
      label: 'Asks for keys, logins or identity documents',
      weight: 40,
      cap: 60,
      critical: true,
      terms: [
        'seed phrase', 'recovery phrase', 'secret recovery phrase', 'mnemonic phrase',
        'private key', '12-word phrase', '12 word phrase', '24-word phrase', '24 word phrase',
        'connect your wallet', 'connect wallet', 'walletconnect', 'wallet connect',
        'sync your wallet', 'validate your wallet', 'verify your wallet',
        'copy of your passport', 'photo of your passport', 'scan of your passport',
        'passport copy', 'passport photo', 'selfie with your id', 'photo of your id',
        'copy of your id', "driver's license photo", 'social security number',
        'bank login', 'online banking login', 'bank account details', 'bank details',
        'routing number', 'card number', 'cvv', 'verification code',
        'one-time code', 'otp code', '2fa code',
        // zh (simplified / traditional)
        '助记词', '助記詞', '私钥', '私鑰', '连接钱包', '連接錢包', '连接你的钱包', '連接你的錢包',
        '护照照片', '護照照片', '护照复印件', '護照影本', '验证码', '驗證碼', '网银密码', '網銀密碼',
        '银行卡号', '銀行卡號',
      ],
    },
    offplatform: {
      label: 'Pushes the conversation off LinkedIn',
      weight: 15,
      cap: 30,
      terms: [
        'telegram', 'whatsapp', 't.me/', 'wa.me/', 'chat.whatsapp.com', 'signal app',
        'contact me on', 'add me on', 'message me on', 'text me on', 'text me at',
        'reach me on', 'move this conversation', 'skype id',
        'wechat', 'kakaotalk', 'line app',
        '微信', '加我微信', '电报', '電報', '飞机号', '飛機號',
      ],
    },
    money: {
      label: 'Mentions fees, deposits or payment flows',
      weight: 15,
      cap: 40,
      terms: [
        'registration fee', 'training fee', 'equipment fee', 'onboarding fee',
        'activation fee', 'processing fee', 'application fee', 'security deposit',
        'refundable deposit', 'upfront payment', 'pay upfront', 'pay for the training',
        'purchase equipment', 'buy equipment', "cashier's check", 'send you a check',
        'deposit the check', 'gift card', 'western union', 'moneygram', 'bitcoin atm',
        'crypto atm', 'usdt', 'usdc', 'trc20', 'erc20', 'recharge your account',
        'top up your account', 'top-up', 'commission per task', 'complete tasks',
        'task-based', 'optimize orders', 'order grabbing', 'prepayment',
        '押金', '保证金', '保證金', '培训费', '培訓費', '手续费', '手續費', '入职费', '入職費',
        '充值', '刷单', '刷單', '垫付', '墊付', '返佣', '泰达币', '泰達幣',
      ],
    },
    crypto: {
      label: 'Crypto / web3 bait vocabulary',
      weight: 5,
      cap: 20,
      clusterMin: 3,     // 3+ distinct terms ...
      clusterBonus: 20,  // ... adds this on top of the capped total
      terms: [
        'web3', 'defi', 'blockchain', 'nft', 'rwa', 'real world assets',
        'real-world assets', 'tokenomics', 'airdrop', 'staking', 'liquidity pool',
        'yield farming', 'smart contract', 'dapp', 'metaverse', 'memecoin',
        'meme coin', 'presale', 'token sale', 'ico', 'dao',
        '区块链', '區塊鏈', '加密货币', '加密貨幣', '去中心化', '代币', '代幣', '智能合约', '智能合約',
        '空投', '质押', '質押', '链上', '鏈上', '数字资产', '數字資產', '币圈', '幣圈',
      ],
    },
    toogood: {
      label: 'Pay or process that sounds too good',
      weight: 10,
      cap: 30,
      terms: [
        'no experience needed', 'no experience required', 'no interview',
        'without an interview', 'hired immediately', 'guaranteed income',
        'guaranteed salary', 'easy money', 'make money fast', 'passive income',
        'only 1-2 hours a day', '1-2 hours a day', '1 hour a day', 'one hour a day',
        "you've been selected", 'you have been selected', 'you have been shortlisted',
        'work from your phone', 'daily payout', 'paid daily', 'weekly payout',
        '无需经验', '無需經驗', '无需面试', '無需面試', '日结', '日結', '轻松赚钱', '輕鬆賺錢',
        '躺赚', '躺賺', '稳赚', '穩賺',
      ],
    },
    pressure: {
      label: 'Urgency or secrecy pressure',
      weight: 8,
      cap: 24,
      terms: [
        'urgent', 'urgently', 'asap', 'act fast', 'act now', 'limited slots',
        'limited spots', 'only a few spots', 'within 24 hours', 'within 24h',
        'today only', 'offer expires', 'respond immediately', 'reply immediately',
        'keep this confidential', 'keep it confidential', "don't tell", 'do not tell',
        'do not share this', "don't share this", 'between us',
        'waiting for you in the meeting', 'is waiting in the meeting', 'already in the meeting',
        'join the meeting now', 'waiting for you on the call',
        '尽快', '盡快', '紧急', '緊急', '立即回复', '立即回覆', '保密', '不要告诉', '不要告訴',
        '会议中等你', '會議中等你', '正在等你',
      ],
    },
    devlure: {
      // Weak on its own: real recruiters mention GitHub and take-homes too.
      label: 'Developer-targeted outreach (GitHub, coding test)',
      weight: 10,
      cap: 20,
      terms: [
        'your github', 'your github profile', 'your github account', 'your github repo', 'your contributions',
        'coding test', 'coding challenge', 'take-home', 'take home test', 'technical assessment', 'test project',
        'github 账号', 'github账号', 'github 帳號', 'github帳號', '你的 github', '您的 github',
        '代码测试', '代碼測試', '测试项目', '測試項目',
      ],
    },
    execlure: {
      // Strong: a recruiter almost never needs you to run code or install software.
      label: 'Asks you to run, install or download something',
      weight: 20,
      cap: 40,
      terms: [
        'clone the repo', 'clone the repository', 'clone this repo', 'git clone', 'run the project', 'run the code',
        'run it locally', 'npm install', 'npm start', 'yarn install', 'pip install',
        'install the app', 'download the app', 'meeting app', 'install the meeting', 'update zoom', 'zoom update',
        'update teams', 'camera driver', 'audio driver', 'microphone driver', 'fix your camera', 'fix the camera',
        'run this command', 'paste this command', 'paste the command', 'terminal command',
        '克隆', '运行项目', '運行項目', '安装软件', '安裝軟體', '会议软件', '會議軟體', '摄像头驱动', '攝像頭驅動',
      ],
    },
    counter: {
      label: 'Normal hiring-process signals (lowers the score)',
      weight: -10,
      cap: -20,
      terms: [
        'greenhouse.io', 'lever.co', 'myworkdayjobs.com', 'smartrecruiters.com',
        'ashbyhq.com', 'icims.com', 'workable.com', 'jobvite.com', 'bamboohr.com',
        'interview process', 'technical interview', 'hiring manager', 'job id',
        'apply through our careers page', 'our careers page', 'background check',
        '面试流程', '面試流程', '招聘官网', '招聘官網',
      ],
    },
  };

  // Our own, fixed (not externally supplied) pay pattern + thresholds.
  const PAY_RE = /(?:\$|us\$|usd ?)\s?(\d{1,3}(?:,\d{3})+|\d{1,7})(?:\.\d{1,2})?\s?(k)?\s?(?:\/|per |an |a )\s?(hour|hr|day|week|wk|month)\b/g;
  const PAY_LIMITS = { hour: 150, hr: 150, day: 800, week: 4000, wk: 4000, month: 20000 };
  const PAY_UNIT = { hour: 'hour', hr: 'hour', day: 'day', week: 'week', wk: 'week', month: 'month' };

  const BLOCKLIST_FLOOR = 60;  // a blocklist hit alone is "high"
  const BLOCKLIST_POINTS = 60;
  const CRITICAL_FLOOR = 60;   // a credential/wallet ask alone is "high"

  // ---------------------------------------------------------------------------
  // Text helpers
  // ---------------------------------------------------------------------------
  function normalizeText(s) {
    return String(s == null ? '' : s)
      .slice(0, MAX_TEXT)
      .normalize('NFKC')
      // zero-width / soft-hyphen splitting is a cheap evasion ("tele​gram")
      .replace(/[​-‍⁠﻿­]/g, '')
      .replace(/[‘’ʼ′]/g, "'")
      .replace(/[“”]/g, '"')
      .replace(/[‐-―−]/g, '-')
      .toLowerCase()
      .replace(/\s+/g, ' ');
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&'); // no '-': invalid escape under the u flag
  }

  // Scripts written without spaces between words: a CJK/Thai character is never
  // a word boundary *barrier*. Otherwise "区块链" could never match inside
  // "全新的区块链项目", and "telegram" could never match in "加我telegram".
  const NO_SPACE = '\\p{Script=Han}\\p{Script=Hiragana}\\p{Script=Katakana}\\p{Script=Thai}';
  const BOUNDARY_CHAR = '(?:(?![' + NO_SPACE + '])[\\p{L}\\p{N}_])';
  const NEEDS_BOUNDARY = new RegExp('^' + BOUNDARY_CHAR + '$', 'u');
  const termRegexCache = new Map();

  /** Build a regex that matches `term` literally, with word boundaries only on
   *  the sides where the term itself starts/ends with a space-delimited word
   *  character. */
  function termRegex(term) {
    let re = termRegexCache.get(term);
    if (!re) {
      const chars = Array.from(term);
      const pre = NEEDS_BOUNDARY.test(chars[0]) ? '(?<!' + BOUNDARY_CHAR + ')' : '';
      const post = NEEDS_BOUNDARY.test(chars[chars.length - 1]) ? '(?!' + BOUNDARY_CHAR + ')' : '';
      re = new RegExp(pre + escapeRegex(term) + post, 'gu');
      termRegexCache.set(term, re);
    }
    re.lastIndex = 0;
    return re;
  }

  /** Count literal, boundary-aware occurrences of `term` in normalised `text`. */
  function countTerm(text, term) {
    if (!term) return 0;
    const m = text.match(termRegex(term));
    return m ? m.length : 0;
  }

  function blankTerm(text, term) {
    return text.replace(termRegex(term), (m) => ' '.repeat(m.length));
  }

  /** Distinct terms of a category found in `text`. Longer terms win, and their
   *  spans are blanked so "secret recovery phrase" doesn't also count as
   *  "recovery phrase". */
  function matchCategory(text, terms) {
    const sorted = [...new Set(terms.map(normalizeText))].sort((a, b) => b.length - a.length);
    let work = text;
    const out = [];
    for (const t of sorted) {
      const n = countTerm(work, t);
      if (n > 0) {
        out.push({ term: t, count: n });
        work = blankTerm(work, t);
      }
    }
    return out;
  }

  function findUnrealisticPay(text) {
    const out = [];
    PAY_RE.lastIndex = 0;
    let m;
    while ((m = PAY_RE.exec(text)) && out.length < 10) {
      let amount = Number(m[1].replace(/,/g, ''));
      if (m[2]) amount *= 1000;
      if (amount >= PAY_LIMITS[m[3]]) {
        out.push({ term: '$' + amount.toLocaleString('en-US') + '/' + PAY_UNIT[m[3]], count: 1 });
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Scoring
  // ---------------------------------------------------------------------------
  function bandFor(score) {
    if (score >= 60) return 'high';
    if (score >= 30) return 'caution';
    return 'low';
  }

  /**
   * @param {string} text     visible page text
   * @param {string[]} links  hrefs on the page
   * @param {{blocklistHits?: Array<{kind:string,value:string,entry?:string}>, overrides?: object}} [opts]
   *        overrides: the user's local rule tuning (validated here; see normalizeOverrides)
   */
  function analyze(text, links, opts) {
    const ov = compileOverrides(opts && opts.overrides);
    const linkList = Array.isArray(links) ? links.filter((l) => typeof l === 'string').slice(0, 1000) : [];
    const hay = normalizeText(String(text == null ? '' : text) + ' \n ' + linkList.join(' '));
    const hits = (opts && Array.isArray(opts.blocklistHits)) ? opts.blocklistHits.slice(0, 50) : [];

    const reasons = [];
    let critical = false;
    let raw = 0;
    let counterReason = null;

    for (const [id, rule] of Object.entries(ov.rules)) {
      const matches = matchCategory(hay, rule.terms);
      if (id === 'toogood') matches.push(...findUnrealisticPay(hay));
      if (!matches.length) continue;

      let points = matches.length * rule.weight;
      points = rule.cap < 0 ? Math.max(points, rule.cap) : Math.min(points, rule.cap);
      let bonus = 0;
      if (rule.clusterMin && matches.length >= rule.clusterMin) bonus = rule.clusterBonus;

      const reason = {
        category: id,
        label: rule.label,
        points: points + bonus,
        matches,
      };
      if (bonus) reason.note = matches.length + ' distinct terms together (+' + bonus + ')';
      if (id === 'counter') { counterReason = reason; continue; }
      if (rule.critical) critical = true;
      raw += reason.points;
      reasons.push(reason);
    }

    // Domain / impersonation / link-shape signals (computed from the raw links + text).
    let impersonated = false;
    for (const d of domainReasons(text, linkList, ov)) {
      if (d.category === 'impersonation') impersonated = true;
      raw += d.points;
      reasons.push(d);
    }

    // Combination: each piece is weak alone (real web3 recruiters mention GitHub,
    // real teams send take-homes). Together they match the documented
    // fake-interview campaign against crypto developers: crypto role + either
    // "run/install this", or GitHub-sourced outreach followed by meeting pressure.
    const fired = (id) => reasons.some((r) => r.category === id);
    if (fired('crypto') && (fired('execlure') || (fired('devlure') && fired('pressure')))) {
      reasons.push({
        category: 'pattern',
        label: 'Matches a known fake-interview pattern against developers',
        points: 15,
        matches: [{
          term: fired('execlure') ? 'crypto role + asks you to run or install something'
            : 'crypto role + GitHub-sourced outreach + pressure to meet',
          count: 1,
        }],
      });
      raw += 15;
    }

    if (hits.length) {
      reasons.push({
        category: 'blocklist',
        label: 'Matches a known scam-infrastructure indicator',
        points: BLOCKLIST_POINTS,
        matches: hits.map((h) => ({ term: describeHit(h), count: 1 })),
      });
      raw += BLOCKLIST_POINTS;
    }

    // Legit-process signals only soften the score when nothing near-certain fired.
    if (counterReason) {
      if (!critical && !hits.length && !impersonated) {
        raw += counterReason.points;
      } else {
        counterReason.points = 0;
        counterReason.note = 'ignored: a near-certain signal also fired';
      }
      reasons.push(counterReason);
    }

    let score = Math.max(0, Math.min(100, raw));
    if (critical) score = Math.max(score, CRITICAL_FLOOR);
    if (hits.length) score = Math.max(score, BLOCKLIST_FLOOR);

    reasons.sort((a, b) => b.points - a.points);
    return {
      score,
      band: bandFor(score),
      critical,
      reasons,
      scannedChars: hay.length,
      version: VERSION,
      custom: ov.active,
    };
  }

  function describeHit(h) {
    const kind = String(h.kind || 'indicator');
    const value = String(h.value || '').slice(0, 200);
    if (kind === 'lookalike') return 'domain ' + value + ' resembles ' + String(h.entry || '').slice(0, 200);
    return kind + ' ' + value;
  }

  // ---------------------------------------------------------------------------
  // Indicator normalisation (shared by list entries and page candidates)
  // ---------------------------------------------------------------------------
  const DOMAIN_RE = /^(?=.{3,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
  const ETH_RE = /^0x[0-9a-f]{40}$/;
  const OTHER_WALLET_RE = /^[A-Za-z0-9]{25,90}$/;
  const EMAIL_RE = /^[a-z0-9._%+-]{1,64}@((?:[a-z0-9-]{1,63}\.){1,8}[a-z]{2,63})$/;

  function normalizeDomain(s) {
    if (typeof s !== 'string') return null;
    let d = s.trim().toLowerCase();
    if (!d || d.length > 300) return null;
    d = d.replace(/^\*\./, '').replace(/\.$/, '');
    if (/[^\x00-\x7f]/.test(d)) {
      try { d = new URL('http://' + d).hostname; } catch (_) { return null; }
    }
    if (d.startsWith('www.')) d = d.slice(4);
    return DOMAIN_RE.test(d) ? d : null;
  }

  /** "https://www.Evil.com/a/b/?x#y" -> "evil.com/a/b?x" (no scheme, no www,
   *  no trailing slash, no fragment). */
  function normalizeUrl(s) {
    if (typeof s !== 'string' || s.length > 2048) return null;
    let str = s.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(str)) str = 'https://' + str;
    let u;
    try { u = new URL(str); } catch (_) { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = normalizeDomain(u.hostname);
    if (!host) return null;
    const path = u.pathname.replace(/\/+$/, '');
    return (host + path + u.search).toLowerCase();
  }

  function normalizeHandle(s) {
    if (typeof s !== 'string' || s.length > 200) return null;
    let h = s.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '');
    let m;
    if ((m = h.match(/^(?:t\.me|telegram\.me|telegram\.dog)\/([a-z0-9_]{3,64})\/?$/))) return '@' + m[1];
    if ((m = h.match(/^wa\.me\/\+?(\d{7,15})\/?$/))) return '+' + m[1];
    if (/^\+[\d\s().-]{7,25}$/.test(h)) {
      const digits = h.replace(/\D/g, '');
      return digits.length >= 7 && digits.length <= 15 ? '+' + digits : null;
    }
    if ((m = h.match(/^@?([a-z0-9_.]{3,64})$/))) return '@' + m[1];
    return null;
  }

  function normalizeWallet(s) {
    if (typeof s !== 'string') return null;
    const w = s.trim();
    if (ETH_RE.test(w.toLowerCase())) return w.toLowerCase();
    return OTHER_WALLET_RE.test(w) ? w : null;
  }

  /** Full address, or a whole throwaway domain written as "@domain.tld". */
  function normalizeEmail(s) {
    if (typeof s !== 'string' || s.length > 320) return null;
    const e = s.trim().toLowerCase().replace(/^mailto:/, '');
    if (e.startsWith('@')) {
      const d = normalizeDomain(e.slice(1));
      return d ? '@' + d : null;
    }
    return EMAIL_RE.test(e) ? e : null;
  }

  // ---------------------------------------------------------------------------
  // Indicator extraction from a page (fixed, bounded regexes — our own)
  // ---------------------------------------------------------------------------
  const MAX_CANDIDATES = 500;

  function unwrapLinkedInRedirect(href) {
    try {
      const u = new URL(href);
      if (/(^|\.)linkedin\.com$/.test(u.hostname) && /^\/(redir\/redirect|safety\/go)/.test(u.pathname)) {
        const inner = u.searchParams.get('url');
        if (inner) return inner;
      }
    } catch (_) { /* ignore */ }
    return href;
  }

  function extractIndicators(text, links) {
    const domains = new Set();
    const urls = new Set();
    const handles = new Set();
    const wallets = new Set();
    const emails = new Set();
    const add = (set, v) => { if (v && set.size < MAX_CANDIDATES) set.add(v); };

    const rawText = String(text == null ? '' : text).slice(0, MAX_TEXT).normalize('NFKC')
      .replace(/[​-‍⁠﻿­]/g, '');
    const low = rawText.toLowerCase();

    for (const l of (Array.isArray(links) ? links.slice(0, 1000) : [])) {
      if (typeof l !== 'string') continue;
      const href = unwrapLinkedInRedirect(l);
      if (/^mailto:/i.test(href)) {
        const e = normalizeEmail(href.split('?')[0]);
        if (e) { add(emails, e); add(domains, normalizeDomain(e.split('@')[1])); }
        continue;
      }
      const nu = normalizeUrl(href);
      if (!nu) continue;
      add(urls, nu);
      add(domains, nu.split(/[/?]/)[0]);
      add(handles, normalizeHandle(nu.split('?')[0]));
    }

    let m;
    const emailRe = /[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,8}[a-z]{2,24}/g;
    while ((m = emailRe.exec(low))) {
      const e = normalizeEmail(m[0]);
      if (e) { add(emails, e); add(domains, normalizeDomain(e.split('@')[1])); }
    }
    const urlRe = /\bhttps?:\/\/[^\s<>"'()]{1,2000}/g;
    while ((m = urlRe.exec(rawText))) {
      const nu = normalizeUrl(m[0].replace(/[.,;:!?]+$/, ''));
      if (nu) { add(urls, nu); add(domains, nu.split(/[/?]/)[0]); add(handles, normalizeHandle(nu.split('?')[0])); }
    }
    const domRe = /(?<![a-z0-9@._-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}(?![a-z0-9-])/g;
    while ((m = domRe.exec(low))) add(domains, normalizeDomain(m[0]));
    const tgRe = /(?:t\.me|telegram\.me)\/([a-z0-9_]{3,64})/g;
    while ((m = tgRe.exec(low))) add(handles, '@' + m[1]);
    const waRe = /wa\.me\/\+?(\d{7,15})/g;
    while ((m = waRe.exec(low))) add(handles, '+' + m[1]);
    const atRe = /(?<![a-z0-9._%+-])@([a-z0-9_.]{3,32})(?![a-z0-9_]*\.[a-z]{2,})/g;
    while ((m = atRe.exec(low))) add(handles, '@' + m[1].replace(/\.+$/, ''));
    const phoneRe = /\+\d[\d\s().-]{6,20}\d/g;
    while ((m = phoneRe.exec(low))) add(handles, normalizeHandle(m[0]));
    const ethRe = /\b0x[0-9a-f]{40}\b/g;
    while ((m = ethRe.exec(low))) add(wallets, m[0]);
    const btcRe = /\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
    while ((m = btcRe.exec(rawText))) add(wallets, m[0]);
    const trxRe = /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g;
    while ((m = trxRe.exec(rawText))) add(wallets, m[0]);

    return {
      domains: [...domains], urls: [...urls], handles: [...handles],
      wallets: [...wallets], emails: [...emails],
    };
  }

  // ---------------------------------------------------------------------------
  // Blocklist: validate + normalise (our schema and eth-phishing-detect)
  // ---------------------------------------------------------------------------
  const LIST_KINDS = ['domains', 'urls', 'handles', 'wallets', 'emails'];
  const NORMALIZERS = {
    domains: normalizeDomain, urls: normalizeUrl, handles: normalizeHandle,
    wallets: normalizeWallet, emails: normalizeEmail,
  };
  const MAX_PER_LIST = 300000;
  const MAX_TOTAL = 500000;
  const MAX_FUZZY = 500;
  const MAX_WHITELIST = 50000;

  function emptyCompiled() {
    return {
      domains: [], urls: [], handles: [], wallets: [], emails: [],
      fuzzy: [], whitelist: [], tolerance: 1, sources: [], rejected: 0,
    };
  }

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  /**
   * Validate an untrusted parsed-JSON blocklist. Never throws.
   * @returns {{ok:boolean, error?:string, list:object}}
   */
  function normalizeBlocklist(raw) {
    const out = emptyCompiled();
    if (!isPlainObject(raw)) return { ok: false, error: 'not a JSON object', list: out };

    let total = 0;
    const take = (arr, normalize, dest, max) => {
      if (!Array.isArray(arr)) return;
      const seen = new Set(dest);
      for (let i = 0; i < arr.length && dest.length < max && total < MAX_TOTAL; i++) {
        let v = arr[i];
        if (isPlainObject(v)) v = v.value;          // {value, note} form
        const n = normalize(v);
        if (n && !seen.has(n)) { seen.add(n); dest.push(n); total++; } else if (!n) out.rejected++;
      }
      if (arr.length > max) out.rejected += arr.length - max;
    };

    const ours = raw.schema === 'catfishguard-blocklist' || LIST_KINDS.some((k) => Array.isArray(raw[k]));
    const eth = Array.isArray(raw.blacklist) || Array.isArray(raw.fuzzylist) || Array.isArray(raw.whitelist);
    if (!ours && !eth) return { ok: false, error: 'unrecognised schema', list: out };

    if (ours) {
      for (const k of LIST_KINDS) take(raw[k], NORMALIZERS[k], out[k], MAX_PER_LIST);
      out.sources.push('catfishguard');
    }
    if (eth) {
      take(raw.blacklist, normalizeDomain, out.domains, MAX_PER_LIST);
      take(raw.fuzzylist, normalizeDomain, out.fuzzy, MAX_FUZZY);
      take(raw.whitelist, normalizeDomain, out.whitelist, MAX_WHITELIST);
      out.sources.push('eth-phishing-detect');
    }
    const tol = Number(raw.tolerance);
    out.tolerance = Number.isFinite(tol) ? Math.max(0, Math.min(3, Math.floor(tol))) : 1;
    return { ok: true, list: out };
  }

  /** Union two compiled lists (seed under remote). Inputs are re-validated. */
  function mergeBlocklists(a, b) {
    const out = emptyCompiled();
    for (const src of [a, b]) {
      if (!isPlainObject(src)) continue;
      for (const k of [...LIST_KINDS, 'fuzzy', 'whitelist']) {
        if (!Array.isArray(src[k])) continue;
        const norm = (k === 'fuzzy' || k === 'whitelist') ? normalizeDomain : NORMALIZERS[k];
        const seen = new Set(out[k]);
        for (const v of src[k]) {
          const n = norm(v);
          if (n && !seen.has(n)) { seen.add(n); out[k].push(n); }
        }
      }
      if (Array.isArray(src.sources)) out.sources.push(...src.sources.filter((s) => typeof s === 'string'));
      if (Number.isFinite(src.tolerance)) out.tolerance = Math.max(0, Math.min(3, Math.floor(src.tolerance)));
      if (Number.isFinite(src.rejected)) out.rejected += src.rejected;
    }
    out.sources = [...new Set(out.sources)];
    return out;
  }

  function countsOf(list) {
    const c = {};
    for (const k of [...LIST_KINDS, 'fuzzy', 'whitelist']) c[k] = Array.isArray(list && list[k]) ? list[k].length : 0;
    return c;
  }

  function levenshteinWithin(a, b, max) {
    if (Math.abs(a.length - b.length) > max) return false;
    let prev = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      let rowMin = i;
      for (let j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        if (cur[j] < rowMin) rowMin = cur[j];
      }
      if (rowMin > max) return false;
      prev = cur;
    }
    return prev[b.length] <= max;
  }

  // eth-phishing-detect's fuzzy form: the domain with its last label dropped.
  const fuzzyForm = (d) => d.split('.').slice(0, -1).join('.');

  /** Build Set-backed lookups from a compiled list. */
  function createMatcher(list) {
    const L = isPlainObject(list) ? list : emptyCompiled();
    const set = (k) => new Set(Array.isArray(L[k]) ? L[k] : []);
    const domains = set('domains'); const urls = set('urls'); const handles = set('handles');
    const wallets = set('wallets'); const emails = set('emails'); const whitelist = set('whitelist');
    const fuzzy = (Array.isArray(L.fuzzy) ? L.fuzzy : []).map((d) => ({ d, f: fuzzyForm(d) }));
    const tolerance = Number.isFinite(L.tolerance) ? L.tolerance : 1;

    // Walk "a.b.evil.com" -> "b.evil.com" -> "evil.com" (never a bare TLD).
    const suffixHit = (host, s) => {
      const parts = host.split('.');
      for (let i = 0; i <= parts.length - 2; i++) {
        const cand = parts.slice(i).join('.');
        if (s.has(cand)) return cand;
      }
      return null;
    };

    function match(ind) {
      const hits = [];
      const I = isPlainObject(ind) ? ind : {};
      const arr = (k) => (Array.isArray(I[k]) ? I[k].slice(0, MAX_CANDIDATES) : []);
      const seen = new Set();
      const push = (kind, value, entry) => {
        const key = kind + '|' + value;
        if (!seen.has(key) && hits.length < 50) { seen.add(key); hits.push({ kind, value, entry }); }
      };

      for (const raw of arr('domains')) {
        const host = normalizeDomain(raw);
        if (!host || suffixHit(host, whitelist)) continue;
        const e = suffixHit(host, domains);
        if (e) { push('domain', host, e); continue; }
        if (!fuzzy.length || tolerance <= 0) continue;
        const form = fuzzyForm(host);
        for (const { d, f } of fuzzy) {
          if (host === d || host.endsWith('.' + d)) break; // it IS the real brand
          if (form && f && levenshteinWithin(form, f, tolerance)) { push('lookalike', host, d); break; }
        }
      }
      for (const raw of arr('urls')) {
        const u = normalizeUrl(raw);
        if (!u) continue;
        // exact (with query), then each path prefix at "/" boundaries
        if (urls.has(u)) { push('url', u, u); continue; }
        const parts = u.split('?')[0].split('/');
        for (let i = parts.length; i >= 2; i--) {
          const p = parts.slice(0, i).join('/');
          if (urls.has(p)) { push('url', u, p); break; }
        }
      }
      for (const raw of arr('handles')) {
        const h = normalizeHandle(raw);
        if (h && handles.has(h)) push('handle', h, h);
      }
      for (const raw of arr('wallets')) {
        const w = normalizeWallet(raw);
        if (w && wallets.has(w)) push('wallet', w, w);
      }
      for (const raw of arr('emails')) {
        const e = normalizeEmail(raw);
        if (!e) continue;
        if (emails.has(e)) { push('email', e, e); continue; }
        const at = e.indexOf('@');
        if (at > 0 && emails.has(e.slice(at))) push('email', e, e.slice(at));
      }
      return hits;
    }

    return { match, size: domains.size + urls.size + handles.size + wallets.size + emails.size };
  }

  // ---------------------------------------------------------------------------
  // Domain / brand-impersonation module (roadmap #2)
  //
  // Infrastructure is the signal that is expensive to fake: a scammer can swap
  // vocabulary for free, but the link has to point *somewhere*. Everything here
  // is computed from the bundled Public Suffix List and bundled brand list; no
  // lookups leave the browser.
  // ---------------------------------------------------------------------------
  let PSL = null;
  function psl() {
    if (PSL) return PSL;
    const src = typeof root.HRScamPSL === 'string' ? root.HRScamPSL : '';
    const rules = new Set();
    const wild = new Set();
    const except = new Set();
    for (const r of src.split('\n')) {
      if (!r) continue;
      if (r[0] === '!') except.add(r.slice(1));
      else if (r.startsWith('*.')) wild.add(r.slice(2));
      else rules.add(r);
    }
    PSL = { rules, wild, except, loaded: rules.size > 0 };
    return PSL;
  }

  const HOST_RE = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}))*$/;
  const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  /** Lowercased ASCII (punycode) hostname, or null. Keeps "www." — the PSL needs it. */
  function hostOf(s) {
    if (typeof s !== 'string' || !s || s.length > 300) return null;
    let h = s.trim().toLowerCase().replace(/\.$/, '');
    if (/[^\x00-\x7f]/.test(h)) {
      try { h = new URL('http://' + h).hostname; } catch (_) { return null; }
    }
    return HOST_RE.test(h) ? h : null;
  }

  /** The public suffix of a host, per the PSL algorithm (longest rule wins,
   *  exceptions beat wildcards, unknown TLDs fall back to the implicit "*"). */
  function publicSuffix(host) {
    const labels = host.split('.');
    const p = psl();
    if (p.loaded) {
      for (let i = 0; i < labels.length; i++) {
        const cand = labels.slice(i).join('.');
        if (p.except.has(cand)) return labels.slice(i + 1).join('.');
        if (p.rules.has(cand)) return cand;
        if (i + 1 < labels.length && p.wild.has(labels.slice(i + 1).join('.'))) return cand;
      }
    }
    return labels[labels.length - 1];
  }

  /** "login.google.com.evil.ru" -> "evil.ru"; "a.example.co.uk" -> "example.co.uk";
   *  "evil.vercel.app" -> "evil.vercel.app" (private PSL section). */
  function registrableDomain(input) {
    const h = hostOf(input);
    if (!h || IPV4_RE.test(h) || !h.includes('.')) return null;
    const suffix = publicSuffix(h);
    if (h === suffix || !h.endsWith('.' + suffix)) return null;
    const rest = h.slice(0, h.length - suffix.length - 1);
    return rest.split('.').pop() + '.' + suffix;
  }

  // RFC 3492 punycode decode, to see what an "xn--" label really spells.
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    if (typeof input !== 'string' || input.length > 63) return null;
    const out = [];
    let n = 128, i = 0, bias = 72;
    let b = input.lastIndexOf('-');
    if (b < 0) b = 0;
    for (let j = 0; j < b; j++) {
      const c = input.charCodeAt(j);
      if (c >= 0x80) return null;
      out.push(c);
    }
    const adapt = (delta, numPoints, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) return null;
        const c = input.charCodeAt(idx++);
        const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base;
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
        if (w > 1e9 || i > 1e9) return null;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      if (n > 0x10ffff) return null;
      out.splice(i++, 0, n);
      if (out.length > 63) return null;
    }
    try { return String.fromCodePoint(...out); } catch (_) { return null; }
  }

  // Visual skeleton: fold common Cyrillic/Greek homoglyphs and digit swaps so
  // "pаypal" (Cyrillic а), "paypa1" and "rnicrosoft" all compare as the brand.
  const CONFUSABLE = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ԁ': 'd',
    'ѕ': 's', 'һ': 'h', 'ɡ': 'g', 'ӏ': 'l', 'ⅼ': 'l', 'ο': 'o', 'α': 'a', 'ν': 'v', 'κ': 'k', 'ι': 'i',
    'τ': 't', 'ρ': 'p', 'ε': 'e', 'υ': 'u', 'ı': 'i', 'ł': 'l', '0': 'o', '1': 'l', '3': 'e', '5': 's',
  };
  function skeleton(label) {
    const s = String(label).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase();
    return Array.from(s).map((c) => CONFUSABLE[c] || c).join('')
      .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[-_.]/g, '');
  }

  // Frequently impersonated in recruiting/crypto scams. `fuzzy`: name is
  // distinctive enough for typo/containment/subdomain checks (common words like
  // "notion", "lever", "meta" are not — "motion.com" is not a Notion phish).
  // `anyTld`: the brand legitimately uses many country TLDs.
  const BRANDS = [
    { name: 'LinkedIn', tokens: ['linkedin'], fuzzy: true, domains: ['linkedin.com', 'lnkd.in', 'licdn.com', 'linkedin.cn'] },
    { name: 'Google', tokens: ['google'], fuzzy: true, anyTld: true,
      domains: ['google.com', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'withgoogle.com', 'goo.gl', 'g.co', 'youtube.com', 'google.dev'] },
    { name: 'Microsoft', tokens: ['microsoft', 'microsoftonline', 'sharepoint'], fuzzy: true,
      domains: ['microsoft.com', 'microsoftonline.com', 'sharepoint.com', 'live.com', 'office.com', 'outlook.com', 'azure.com', 'skype.com', 'bing.com'] },
    { name: 'Apple', tokens: ['apple', 'icloud'], sub: true, anyTld: true, domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', tokens: ['amazon'], fuzzy: true, anyTld: true, domains: ['amazon.com', 'amazon.jobs', 'amazonaws.com', 'a2z.com'] },
    { name: 'Meta', tokens: ['facebook', 'metacareers'], fuzzy: true,
      domains: ['meta.com', 'meta.ai', 'facebook.com', 'fb.com', 'metacareers.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net'] },
    { name: 'PayPal', tokens: ['paypal'], fuzzy: true, anyTld: true, domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
    { name: 'Coinbase', tokens: ['coinbase'], fuzzy: true, domains: ['coinbase.com'] },
    { name: 'Binance', tokens: ['binance'], fuzzy: true, domains: ['binance.com', 'binance.us', 'bnbchain.org'] },
    { name: 'Kraken', tokens: ['kraken'], domains: ['kraken.com'] },
    { name: 'MetaMask', tokens: ['metamask'], fuzzy: true, domains: ['metamask.io', 'consensys.io', 'consensys.net'] },
    { name: 'OpenSea', tokens: ['opensea'], fuzzy: true, domains: ['opensea.io'] },
    { name: 'Uniswap', tokens: ['uniswap'], fuzzy: true, domains: ['uniswap.org'] },
    { name: 'Ledger', tokens: ['ledger'], domains: ['ledger.com'] },
    { name: 'Trezor', tokens: ['trezor'], fuzzy: true, domains: ['trezor.io'] },
    { name: 'Bybit', tokens: ['bybit'], fuzzy: true, domains: ['bybit.com'] },
    { name: 'Crypto.com', tokens: ['cryptocom'], domains: ['crypto.com'] },
    { name: 'Zoom', tokens: ['zoom'], domains: ['zoom.us', 'zoom.com', 'zoomgov.com'] },
    { name: 'Calendly', tokens: ['calendly'], fuzzy: true, domains: ['calendly.com'] },
    { name: 'DocuSign', tokens: ['docusign'], fuzzy: true, domains: ['docusign.com', 'docusign.net'] },
    { name: 'Dropbox', tokens: ['dropbox'], fuzzy: true, domains: ['dropbox.com', 'dropboxusercontent.com'] },
    { name: 'Indeed', tokens: ['indeed'], anyTld: true, domains: ['indeed.com'] },
    { name: 'Glassdoor', tokens: ['glassdoor'], fuzzy: true, anyTld: true, domains: ['glassdoor.com'] },
    { name: 'Greenhouse', tokens: ['greenhouse'], fuzzy: true, domains: ['greenhouse.io'] },
    { name: 'Lever', tokens: ['lever'], domains: ['lever.co'] },
    { name: 'Workday', tokens: ['workday', 'myworkdayjobs'], fuzzy: true, domains: ['workday.com', 'myworkdayjobs.com', 'myworkday.com'] },
    { name: 'Upwork', tokens: ['upwork'], fuzzy: true, domains: ['upwork.com'] },
    { name: 'Fiverr', tokens: ['fiverr'], fuzzy: true, domains: ['fiverr.com'] },
    { name: 'Toptal', tokens: ['toptal'], fuzzy: true, domains: ['toptal.com'] },
    { name: 'Deel', tokens: ['deel'], domains: ['deel.com'] },
    { name: 'GitHub', tokens: ['github'], fuzzy: true, domains: ['github.com', 'github.io', 'githubusercontent.com', 'github.dev', 'githubassets.com'] },
    { name: 'GitLab', tokens: ['gitlab'], fuzzy: true, domains: ['gitlab.com', 'gitlab.io'] },
    { name: 'Discord', tokens: ['discord'], fuzzy: true, domains: ['discord.com', 'discord.gg', 'discordapp.com'] },
    { name: 'Telegram', tokens: ['telegram'], fuzzy: true, domains: ['telegram.org', 't.me', 'telegram.me'] },
    { name: 'Netflix', tokens: ['netflix'], fuzzy: true, domains: ['netflix.com'] },
    { name: 'Revolut', tokens: ['revolut'], fuzzy: true, domains: ['revolut.com'] },
    { name: 'Optiver', tokens: ['optiver'], fuzzy: true, domains: ['optiver.com'] },
    // Reported 2026-11: fake web3 "technical recruiter" claiming peaq, scheduling
    // via a calendly.com/<name>-peaq link. Not fuzzy: one edit from "peak".
    { name: 'peaq', tokens: ['peaq'], domains: ['peaq.xyz', 'peaq.network'] },
  ];
  const OFFICIAL = new Map();
  for (const b of BRANDS) for (const d of b.domains) OFFICIAL.set(d, b);

  const NEUTRAL = new Set(['linkedin.com', 'lnkd.in', 'licdn.com']);
  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rebrand.ly', 'is.gd', 'shorturl.at', 'rb.gy',
    't.ly', 'tiny.cc', 'ow.ly', 'buff.ly', 's.id', 'v.gd', 'bl.ink', 'short.io', 'tinyurl.is', 'goo.su', 'clck.ru']);
  const CHEAP_TLDS = new Set(['xyz', 'top', 'click', 'icu', 'buzz', 'rest', 'cfd', 'sbs', 'monster', 'quest', 'gq',
    'tk', 'ml', 'cf', 'ga', 'zip', 'mov', 'lol', 'online', 'site', 'live', 'cyou', 'bond', 'beauty', 'hair', 'skin']);
  const FREE_HOSTS = new Set(['vercel.app', 'netlify.app', 'github.io', 'pages.dev', 'web.app', 'firebaseapp.com',
    'herokuapp.com', 'glitch.me', 'replit.app', 'repl.co', 'onrender.com', 'wixsite.com', 'weebly.com',
    'blogspot.com', 'notion.site', 'carrd.co', 'framer.website', 'webflow.io', 'surge.sh', 'ngrok.io', 'ngrok-free.app']);
  const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com',
    'icloud.com', 'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.ru',
    'yandex.com', 'qq.com', '163.com', '126.com', 'foxmail.com', 'zoho.com', 'tutanota.com', 'hushmail.com']);
  const EXEC_EXT = /\.(?:exe|msi|msix|dmg|pkg|apk|bat|cmd|scr|ps1|vbs|jar|iso|appimage|deb|rpm|command)$/i;
  const ARCHIVE_EXT = /\.(?:zip|rar|7z|tar\.gz|tgz)$/i;

  /** Brand-impersonation finding for one host, or null. */
  function brandFinding(host, ov) {
    const h = hostOf(host);
    const reg = h && registrableDomain(h);
    if (!reg || ov.official.has(reg) || ov.neutral.has(reg)) return null;
    const suffix = publicSuffix(h);
    const label = reg.slice(0, reg.length - suffix.length - 1);
    const puny = label.startsWith('xn--');
    const shown = puny ? (punyDecode(label.slice(4)) || label) : label;
    const sk = skeleton(shown);
    const sub = h.slice(0, h.length - reg.length).split(/[.-]/).filter(Boolean);
    for (const b of ov.brands) {
      for (const t of b.tokens) {
        const tk = skeleton(t);
        if (b.anyTld && label === t) return null; // e.g. google.de
        if (label === t && b.fuzzy) return { term: reg + ' uses the name "' + b.name + '" on a different domain', points: 35 };
        if (sk === tk && label !== t) {
          return { term: reg + (puny ? ' (displays as "' + shown + '")' : '') + ' imitates ' + b.name, points: 35 };
        }
        if (b.fuzzy && tk.length >= 6 && sk.length >= 5 && levenshteinWithin(sk, tk, 1)) {
          return { term: reg + ' is one letter away from ' + b.name, points: 35 };
        }
        if (b.fuzzy && tk.length >= 5 && sk.includes(tk)) {
          return { term: reg + ' contains "' + b.name + '" but is not ' + b.name + '’s domain', points: 35 };
        }
        if ((b.fuzzy || b.sub) && sub.some((piece) => skeleton(piece) === tk)) {
          return { term: h + ' puts "' + b.name + '" in front of an unrelated domain (' + reg + ')', points: 35 };
        }
      }
    }
    return null;
  }

  // "I'm a recruiter at X", "on behalf of X", "我是 X 的…": built only from our
  // own bundled brand names (escaped), never from external data.
  const claimRegexCache = new WeakMap();
  function claimRegex(b) {
    if (claimRegexCache.has(b)) return claimRegexCache.get(b);
    const names = [b.name, ...b.tokens].map((x) => escapeRegex(normalizeText(x)));
    const a = '(?:' + [...new Set(names)].join('|') + ')';
    const end = '(?![\\p{L}\\p{N}])';
    const re = new RegExp([
      "(?:i'?m|i am|we'?re|we are|my name is)[^.!?\\n]{0,60}?\\b(?:at|from|with|for)\\s+(?:the\\s+)?" + a + end,
      '(?:recruit(?:er|ing|ment)?|talent|hr|hiring|sourcer)(?:\\s+[\\p{L}]+){0,3}\\s+(?:at|for|from|with)\\s+' + a + end,
      '(?:on behalf of|here at|role at|position at|opportunit(?:y|ies) (?:at|with)|join(?:ing)?(?: us at)?)\\s+' + a + end,
      a + "(?:'s)?\\s+(?:is hiring|talent|recruit[\\p{L}]*|hr team|hiring team)",
      '我是\\s*' + a + '\\s*的', '(?:来自|來自)\\s*' + a, a + '\\s*的\\s*(?:技术|技術)?\\s*(?:招聘|人才|hr)',
    ].join('|'), 'u');
    claimRegexCache.set(b, re);
    return re;
  }

  function collectUrls(text, links) {
    const out = [];
    const seen = new Set();
    const add = (s) => {
      if (out.length >= 200 || typeof s !== 'string') return;
      let u;
      try { u = new URL(unwrapLinkedInRedirect(s)); } catch (_) { return; }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      if (!seen.has(u.href)) { seen.add(u.href); out.push(u); }
    };
    for (const l of links) add(l);
    const re = /\bhttps?:\/\/[^\s<>"'()]{1,2000}/gi;
    let m;
    const t = String(text == null ? '' : text).slice(0, MAX_TEXT);
    while ((m = re.exec(t))) add(m[0].replace(/[.,;:!?]+$/, ''));
    return out;
  }

  /** Domain/link reasons for the analyzer: impersonation + risky links. */
  function domainReasons(text, links, ov) {
    const urls = collectUrls(text, links);
    const ind = extractIndicators(text, links);
    const imp = new Map();
    const risk = new Map();
    const note = (map, f) => { if (f && !map.has(f.term)) map.set(f.term, f); };

    // 1) Impersonation: every host we can see (links, URLs, bare domains, email domains).
    const hosts = new Set(urls.map((u) => u.hostname));
    for (const d of ind.domains) hosts.add(d);
    for (const h of hosts) note(imp, brandFinding(h, ov));

    // 2) Claimed employer vs where the links actually go.
    const linkRegs = new Set();
    for (const u of urls) {
      const r = registrableDomain(u.hostname);
      if (r && !ov.neutral.has(r)) linkRegs.add(r);
    }
    if (linkRegs.size) {
      const hay = normalizeText(text);
      for (const b of ov.brands) {
        if (!claimRegex(b).test(hay)) continue;
        if ([...linkRegs].some((r) => ov.official.get(r) === b)) continue;
        note(imp, {
          term: 'claims to recruit for ' + b.name + ', but no link goes to ' + b.name + '’s domain (links: ' +
            [...linkRegs].slice(0, 3).join(', ') + ')',
          points: 15,
        });
      }
    }

    // 3) Risky link shapes.
    for (const u of urls) {
      const host = u.hostname.replace(/^\[|\]$/g, '');
      const reg = registrableDomain(host);
      if (reg && ov.neutral.has(reg)) continue;
      if (IPV4_RE.test(host) || host.includes(':')) note(risk, { term: 'link to a raw IP address (' + host + ')', points: 25 });
      if (u.username || u.password) {
        note(risk, { term: 'link hides its real destination behind "@" (goes to ' + host + ')', points: 25 });
      }
      const file = decodeURIComponent(u.pathname.split('/').pop() || '');
      if (EXEC_EXT.test(file)) note(risk, { term: 'link downloads a program (' + file + ')', points: 40 });
      else if (ARCHIVE_EXT.test(file)) note(risk, { term: 'link downloads an archive (' + file + ')', points: 15 });
      if (!reg) continue;
      if (SHORTENERS.has(reg)) note(risk, { term: 'shortened link hides the destination (' + reg + ')', points: 10 });
      if (host.split('.').some((l) => l.startsWith('xn--')) && !imp.size) {
        note(risk, { term: 'internationalised (punycode) domain ' + host, points: 10 });
      }
      const suffix = publicSuffix(host);
      if (CHEAP_TLDS.has(suffix)) note(risk, { term: 'cheap, frequently abused domain ending .' + suffix + ' (' + reg + ')', points: 5 });
      if (FREE_HOSTS.has(suffix)) note(risk, { term: 'site on free hosting (' + reg + ')', points: 5 });
    }
    for (const e of ind.emails) {
      const d = e.split('@')[1];
      const dr = d && registrableDomain(d);
      if (dr && FREE_MAIL.has(dr) && !ov.neutral.has(dr)) note(risk, { term: 'free email address (' + e + ')', points: 10 });
    }

    const reasons = [];
    const pack = (map, category, label, cap) => {
      if (!map.size) return;
      const matches = [...map.values()].slice(0, 20);
      const points = Math.min(cap, matches.reduce((s, f) => s + f.points, 0));
      reasons.push({ category, label, points, matches: matches.map((f) => ({ term: f.term, count: 1 })) });
    };
    pack(imp, 'impersonation', 'Links or claims that imitate a known brand', 60);
    pack(risk, 'linkrisk', 'Risky links or contact details', 40);
    return reasons;
  }

  // ---------------------------------------------------------------------------
  // Local overrides (roadmap #5): a power user's private tuning for their own
  // install, stored in chrome.storage.local. Never fetched, never synced.
  //
  // Treated as untrusted input (invariant 7) even though the user wrote it:
  // storage can be corrupted and an imported file can come from anywhere.
  // Terms stay literal strings (invariant 4). The credentials category is
  // locked (can't be disabled or muted), and the credential/blocklist score
  // floors are not overridable.
  // ---------------------------------------------------------------------------
  const LOCKED = new Set(['credentials']);
  const OVERRIDE_LIMITS = Object.freeze({
    termsPerCategory: 100, termsTotal: 300, termMin: 2, termMax: 80, mute: 300,
    brands: 50, domainsPerBrand: 10, brandName: 40, trusted: 200,
  });
  const CTRL_RE = /[\u0000-\u001f\u007f]/;

  function clampInt(v, lo, hi) {
    if (v === '' || v === null || v === undefined || typeof v === 'boolean') return null;
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(lo, Math.min(hi, Math.round(n))) : null;
  }

  /** Validate raw overrides. Never throws.
   *  @returns {{overrides: object, warnings: string[]}} */
  function normalizeOverrides(raw) {
    const o = { version: 1, categories: {}, addTerms: {}, muteTerms: [], brands: [], trustedDomains: [] };
    const warnings = [];
    const warn = (m) => { if (warnings.length < 50) warnings.push(m); };
    if (!isPlainObject(raw)) {
      if (raw != null) warn('not a settings object; ignored');
      return { overrides: o, warnings };
    }

    if (isPlainObject(raw.categories)) {
      for (const [id, c] of Object.entries(raw.categories)) {
        if (!RULES[id]) { warn('unknown category "' + String(id).slice(0, 30) + '" ignored'); continue; }
        if (!isPlainObject(c)) continue;
        const neg = RULES[id].weight < 0;
        const out = {};
        // locked categories keep a minimum weight so a credential ask never shows "+0"
        const w = clampInt(c.weight, neg ? -30 : LOCKED.has(id) ? 20 : 0, neg ? 0 : 60);
        const cap = clampInt(c.cap, neg ? -60 : 0, neg ? 0 : 100);
        if (w !== null) out.weight = w;
        if (cap !== null) out.cap = cap;
        if (c.disabled === true) {
          if (LOCKED.has(id)) warn('"' + id + '" can’t be turned off (safety floor)');
          else out.disabled = true;
        }
        if (Object.keys(out).length) o.categories[id] = out;
      }
    }

    const builtin = new Map(); // normalised built-in term -> category
    for (const [id, r] of Object.entries(RULES)) for (const t of r.terms) builtin.set(normalizeText(t), id);
    const cleanTerm = (s) => {
      if (typeof s !== 'string') return null;
      const t = normalizeText(s).trim();
      if (t.length < OVERRIDE_LIMITS.termMin || t.length > OVERRIDE_LIMITS.termMax || CTRL_RE.test(t)) return null;
      return t;
    };

    let total = 0;
    if (isPlainObject(raw.addTerms)) {
      for (const [id, list] of Object.entries(raw.addTerms)) {
        if (!RULES[id] || !Array.isArray(list)) continue;
        const seen = new Set();
        const out = [];
        for (const s of list) {
          const t = cleanTerm(s);
          if (!t) { if (typeof s === 'string' && s.trim()) warn('phrase ignored (2–80 characters): "' + s.slice(0, 30) + '"'); continue; }
          if (seen.has(t) || builtin.get(t) === id) continue;
          if (out.length >= OVERRIDE_LIMITS.termsPerCategory || total >= OVERRIDE_LIMITS.termsTotal) {
            warn('too many custom phrases; extras ignored');
            break;
          }
          seen.add(t); out.push(t); total++;
        }
        if (out.length) o.addTerms[id] = out;
      }
    }

    if (Array.isArray(raw.muteTerms)) {
      const seen = new Set();
      for (const s of raw.muteTerms) {
        const t = cleanTerm(s);
        if (!t || seen.has(t)) continue;
        const id = builtin.get(t);
        if (!id) { warn('"' + t.slice(0, 30) + '" is not a built-in phrase; nothing to mute'); continue; }
        if (LOCKED.has(id)) { warn('"' + t.slice(0, 30) + '" is a credential phrase and can’t be muted'); continue; }
        if (o.muteTerms.length >= OVERRIDE_LIMITS.mute) { warn('too many muted phrases; extras ignored'); break; }
        seen.add(t); o.muteTerms.push(t);
      }
    }

    if (Array.isArray(raw.brands)) {
      for (const b of raw.brands) {
        if (o.brands.length >= OVERRIDE_LIMITS.brands) { warn('too many brands; extras ignored'); break; }
        if (!isPlainObject(b) || typeof b.name !== 'string') continue;
        const name = b.name.trim().replace(/\s+/g, ' ');
        if (!name || name.length > OVERRIDE_LIMITS.brandName || CTRL_RE.test(name)) { warn('brand name ignored: "' + name.slice(0, 30) + '"'); continue; }
        const domains = [];
        for (const d of Array.isArray(b.domains) ? b.domains : []) {
          const r = registrableDomain(String(d).replace(/^https?:\/\//i, '').split(/[/?#]/)[0]);
          if (r && !domains.includes(r) && domains.length < OVERRIDE_LIMITS.domainsPerBrand) domains.push(r);
          else if (!r) warn('"' + String(d).slice(0, 40) + '" is not a valid domain (brand ' + name + ')');
        }
        if (!domains.length) { warn('brand "' + name + '" has no valid domain; ignored'); continue; }
        o.brands.push({ name, domains });
      }
    }

    if (Array.isArray(raw.trustedDomains)) {
      for (const d of raw.trustedDomains) {
        const r = registrableDomain(String(d).replace(/^https?:\/\//i, '').split(/[/?#]/)[0]);
        if (!r) { if (String(d).trim()) warn('"' + String(d).slice(0, 40) + '" is not a valid domain'); continue; }
        if (o.trustedDomains.includes(r)) continue;
        if (o.trustedDomains.length >= OVERRIDE_LIMITS.trusted) { warn('too many trusted domains; extras ignored'); break; }
        o.trustedDomains.push(r);
      }
    }
    return { overrides: o, warnings };
  }

  let COMPILED_DEFAULT = null;
  const compiledCache = new WeakMap();

  /** Merge validated overrides over the bundled rules/brands. Cached per raw object. */
  function compileOverrides(raw) {
    if (!COMPILED_DEFAULT) {
      COMPILED_DEFAULT = Object.freeze({ active: false, rules: RULES, brands: BRANDS, official: OFFICIAL, neutral: NEUTRAL });
    }
    if (!isPlainObject(raw)) return COMPILED_DEFAULT;
    if (compiledCache.has(raw)) return compiledCache.get(raw);
    const { overrides: o } = normalizeOverrides(raw);
    const mute = new Set(o.muteTerms);
    const rules = {};
    for (const [id, base] of Object.entries(RULES)) {
      const c = o.categories[id] || {};
      if (c.disabled) continue;
      rules[id] = Object.assign({}, base, {
        weight: c.weight !== undefined ? c.weight : base.weight,
        cap: c.cap !== undefined ? c.cap : base.cap,
        terms: base.terms.filter((t) => !mute.has(normalizeText(t))).concat(o.addTerms[id] || []),
      });
    }
    const userBrands = o.brands.map((b) => {
      const token = b.domains[0].split('.')[0];
      return { name: b.name, tokens: [token], fuzzy: token.length >= 6, domains: b.domains, custom: true };
    });
    const official = new Map(OFFICIAL);
    for (const b of userBrands) for (const d of b.domains) official.set(d, b);
    const active = Object.keys(o.categories).length > 0 || Object.keys(o.addTerms).length > 0 ||
      o.muteTerms.length > 0 || o.brands.length > 0 || o.trustedDomains.length > 0;
    const compiled = Object.freeze({
      active,
      rules,
      brands: BRANDS.concat(userBrands),
      official,
      neutral: new Set([...NEUTRAL, ...o.trustedDomains]),
    });
    compiledCache.set(raw, compiled);
    return compiled;
  }

  root.HRScam = Object.freeze({
    VERSION, RULES, BRANDS, OVERRIDE_LIMITS, analyze, normalizeOverrides, registrableDomain, publicSuffix, punyDecode, skeleton, bandFor, normalizeText, countTerm, escapeRegex,
    extractIndicators, normalizeBlocklist, mergeBlocklists, createMatcher, countsOf,
    normalizeDomain, normalizeUrl, normalizeHandle, normalizeWallet, normalizeEmail,
  });
})(typeof self !== 'undefined' ? self : globalThis);
