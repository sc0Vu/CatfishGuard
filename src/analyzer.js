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
        '尽快', '盡快', '紧急', '緊急', '立即回复', '立即回覆', '保密', '不要告诉', '不要告訴',
        '会议中等你', '會議中等你', '正在等你',
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
   * @param {{blocklistHits?: Array<{kind:string,value:string,entry?:string}>}} [opts]
   */
  function analyze(text, links, opts) {
    const linkList = Array.isArray(links) ? links.filter((l) => typeof l === 'string').slice(0, 1000) : [];
    const hay = normalizeText(String(text == null ? '' : text) + ' \n ' + linkList.join(' '));
    const hits = (opts && Array.isArray(opts.blocklistHits)) ? opts.blocklistHits.slice(0, 50) : [];

    const reasons = [];
    let critical = false;
    let raw = 0;
    let counterReason = null;

    for (const [id, rule] of Object.entries(RULES)) {
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
      if (!critical && !hits.length) {
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

  root.HRScam = Object.freeze({
    VERSION, RULES, analyze, bandFor, normalizeText, countTerm, escapeRegex,
    extractIndicators, normalizeBlocklist, mergeBlocklists, createMatcher, countsOf,
    normalizeDomain, normalizeUrl, normalizeHandle, normalizeWallet, normalizeEmail,
  });
})(typeof self !== 'undefined' ? self : globalThis);
