# CatfishGuard

A Manifest V3 Chrome extension that flags **recruiter/job-scam and phishing risk
signals on LinkedIn**, and always shows **why**.

It reads the conversation, profile or job post in view, scores it **locally**, and
shows what it found, scaled to the risk level:

- **a thin banner above the open conversation** (caution/high only). It can be
  dismissed per conversation and comes back only if things escalate;
- **dots in the conversation list** for triage. A conversation you opened
  keeps its dot after you leave it (until the tab is reloaded);
- **a corner badge** that's always available. Click it, or the banner's
  "Why?", to see every signal that fired, plus the conversations with risk
  signals seen in this tab;
- **a layout warning** (a "!" on the badge) when the parts of LinkedIn's page
  it reads can't be found, so a LinkedIn redesign shows up as "can't read this
  page" instead of a misleading silence.

The panel can also offer a **reverse image search** of the other person's
profile photo (Google Lens / TinEye). These are plain links: nothing is sent
unless you click, and then only the photo's LinkedIn image address goes to the
service you picked, with no referrer. No match proves nothing, because
AI-generated faces match nothing. The same face under a different name is
worth a closer look. You can turn it off in the popup.

The result is a prompt to look closer, never a verdict about a person.

## Install (unpacked)
1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this folder.
3. Open LinkedIn (reload tabs that were already open).

No build step, no dependencies.

## What it looks at
| Page | Scanned |
|---|---|
| `/messaging/…` | the open thread |
| `/in/…` | the profile |
| `/jobs/…` | the job details |
| anywhere | open (non-minimised) message overlays |

Each open conversation is scored on its own. In conversations, **only messages
from the other person are scored** when LinkedIn marks senders
(`msg-s-event-listitem--other`). Otherwise it falls back to the whole thread
and the panel says so. The feed is deliberately not scored, since it would just
be noise. Your own drafts, form fields and `You: …` list previews are never
read. LinkedIn selectors live in `SEL` at the top of `src/content.js`.

## How scoring works
Two kinds of signal, matched to how easy each is to evade:

**1. Keywords (bundled in `src/analyzer.js` → `RULES`).** Each distinct term
adds its category's weight once, and each category is capped.

| Category | Per term | Cap | Notes |
|---|---|---|---|
| credentials | 40 | 60 | seed phrase, connect wallet, passport copy, bank login… **alone → high** |
| offplatform | 15 | 30 | Telegram / WhatsApp / `t.me/` pushes |
| money | 15 | 40 | fees, deposits, USDT, gift cards, task payments |
| crypto | 5 | 20 | web3/defi bait; **3+ distinct terms → +20** |
| toogood | 10 | 30 | no interview, guaranteed income, pay over $150/h, $800/day, $4k/week or $20k/month |
| pressure | 8 | 24 | urgency, secrecy, "they're waiting for you in the meeting" |
| devlure | 10 | 20 | "your GitHub", coding test, take-home: weak alone, since real recruiters say this |
| execlure | 20 | 40 | clone or run a repo, `npm install`, install a meeting app, camera driver, paste a command |
| pattern | 15 | — | crypto role + (run/install ask, **or** GitHub-sourced outreach + pressure): the fake-interview campaign |
| impersonation | 35 / 15 | 60 | lookalike, typosquat or homograph domain, brand in a subdomain (35); "I'm a recruiter at X" but no link goes to X (15) |
| linkrisk | 5–40 | 40 | executable download (40), IP host or `user@host` trick (25), archive (15), shortener, punycode or free email (10), cheap TLD or free hosting (5) |
| counter | −10 | −20 | ATS hosts, "interview process"… only applied when nothing near-certain fired (credentials, blocklist, impersonation) |

Bands: **0–29 low · 30–59 caution · 60–100 high.**

Text is NFKC-normalised and stripped of zero-width characters before
matching. Terms are matched as literal strings with word boundaries. Rules
cover English and Chinese (simplified and traditional), and Chinese/Japanese/Thai
text, which has no spaces between words, is matched without boundaries.

Keywords are the *most evadable* signal (a public list is a cheat sheet), so
they are compiled into each release and never fetched at runtime.

**2. Domains and links (bundled, `src/analyzer.js` → domain module).** Every
link and domain in the other person's messages is resolved to its
*registrable domain* using the bundled [Public Suffix List](https://publicsuffix.org)
(`src/psl.js`, so `google.com.evil.ru` → `evil.ru` and `evil.vercel.app` stays
separate from `vercel.app`). It is then compared against a bundled list of
frequently impersonated brands (`BRANDS`):
- lookalikes after folding homoglyphs (`pаypal` with a Cyrillic а, `paypa1`, `rnicrosoft`);
- one-letter typos (`linkedln`);
- a brand name inside another domain (`coinbase-careers.com`) or in front of one (`coinbase.hr-portal.io`);
- the same name on another TLD.

Common-word brands (Notion, Lever, Meta…) are only matched exactly, so
`motion.com` isn't flagged. A message that claims an employer ("I'm a
recruiter at Coinbase", "我是 X 的招聘") while no link goes to that employer's
domain is flagged at a lower weight.

Everything runs locally, and nothing is looked up online.

**3. Infrastructure blocklist (remote, optional).** Domains, URLs, handles,
wallet addresses and throwaway emails. A hit adds +60 and on its own puts the
score in the high band. LinkedIn's `/redir/redirect?url=` wrapper is unwrapped
first, and subdomains match their parent domain.

## Blocklist
Set a URL in the popup (GitHub raw or gist only). It is fetched by the service
worker, validated, cached for 6 h in `chrome.storage.local`, and merged over the
bundled seed (`data/blocklist.seed.json`). On failure, the last good list stays in
use. Two schemas are accepted:

**This project's schema**
```json
{
  "schema": "catfishguard-blocklist",
  "version": 1,
  "domains": ["careers-acme.xyz"],
  "urls":    ["evil.example/apply"],
  "handles": ["t.me/hr_jane_web3", "@hr_desk", "+15550100199"],
  "wallets": ["0xabc…", "bc1q…", "T…"],
  "emails":  ["hr@throwaway.io", "@mailinator.com"]
}
```
Entries may also be `{"value": "…", "note": "…"}`. **Infrastructure only:
never names of people.**

**MetaMask [`eth-phishing-detect`](https://github.com/MetaMask/eth-phishing-detect)**
(`blacklist` / `fuzzylist` / `whitelist` / `tolerance`). The popup has a
one-click preset for it. `fuzzylist` entries flag lookalike domains within
`tolerance` edits (e.g. `metamusk.io`).

Lists are treated as hostile. The checks are: an https GitHub host only,
no redirects, a 16 MB cap and a 20 s timeout, JSON must parse, the schema must
be recognised, every entry is validated, list sizes are capped
(300k per list, 500k total, 500 fuzzy), and `tolerance` is clamped to 0–3.
Nothing in a list is ever compiled as a regex.

## Tuning
**For your own install, with no code:** open the popup and choose **Customize
rules…** to open the options page. There you can:
- change each category's per-phrase weight and maximum, or turn it off;
- add your own phrases, in any language;
- mute built-in phrases;
- add your own brands (`peaq = peaq.xyz`) for the lookalike and
  claimed-employer checks;
- list trusted domains;
- preview a message's score with your settings against the built-in ones;
- export, import or reset.

Settings stay in `chrome.storage.local` on that device.

Everything is validated as untrusted input:
- numbers are clamped and phrase count and length are capped;
- phrases always match as plain text, never as patterns;
- the credentials category can't be turned off or muted;
- credential asks and blocklist hits always count as high risk.

The panel says "Custom rules active" whenever your settings are in effect.

**For the project:** edit `RULES` in `src/analyzer.js`, then add a test case in
`test/analyzer.test.js` whose expected score you work out **by hand** from the
weights.

## Tests
```sh
npm test            # unit: analyzer (vm sandbox with only self + URL) + service worker
npm run test:e2e    # real Chrome: loads the extension, fake LinkedIn + GitHub over local HTTPS
```
The e2e run needs Chrome and `openssl`. It loads the unpacked extension through
CDP `Extensions.loadUnpacked` and asserts that the only outbound request is the
blocklist GET, with no cookies, referrer or body. Set
`CFG_METAMASK_JSON=path/to/config.json` to also run the unit test against the
real MetaMask list. Set `CFG_SHOTS=dir` to save e2e screenshots.

## Honest limits
- It's a heuristic. False positives and false negatives both happen. The
  reasons are the useful part, not the number.
- Keyword lists are evadable by construction. The blocklist and (planned)
  domain-impersonation checks are the harder signals to dodge.
- LinkedIn changes its DOM. The conversation, conversation-list, messaging-list
  popup and chat popup selectors were checked against the live site (2026-11)
  and will need re-checking when LinkedIn ships changes.
- Keywords alone miss the developer-targeted "fake interview" pattern
  (GitHub-sourced cold message, web3 role, scheduling link, "they're waiting in
  the meeting"). The planned domain/impersonation check is aimed at it. Fallbacks: `<main>`
  for the page, and the whole thread when senders can't be told apart.
- List dots for unopened conversations score only the short preview, so they are
  a triage hint, not a full check. Opened conversations are matched back to
  their row by the sender's display name (rows carry no conversation id), so two
  people with the same name share a dot.
- The real control is behavioural: verify the recruiter through the company's
  own site, and never enter keys, codes, logins or ID documents on a page reached
  from a message.

## License
CatfishGuard is licensed under the [Apache License 2.0](LICENSE). The licence
covers the code, not the name: "CatfishGuard" and its icon are not licensed
for use by forks (Apache-2.0 §6), so please publish forks under a different
name. Bundled third-party data keeps its own licence (below).

## Third-party data
`src/psl.js` is the Public Suffix List, © Mozilla and contributors, under the
[Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). It is vendored as
data by `npm run psl` (`tools/mk_psl.py`).

## Privacy
See [PRIVACY.md](PRIVACY.md). In short: everything runs locally, and the only
network request is the optional blocklist GET.
